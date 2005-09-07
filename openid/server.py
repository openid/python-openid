from openid.util import (append_args, kvform, DiffieHellman, a2long,
                         from_b64, long2a, sha1, strxor, to_b64, sign_reply)

from openid.errors import ProtocolError, AuthenticationError
from openid.interface import Request, error_page, redirect, response_page
from openid.trustroot import TrustRoot

__all__ = ['OpenIDServer']

_signed_fields = ['mode', 'identity', 'return_to']

class OpenIDServer(object):
    def __init__(self, internal_store, external_store, srand=None):
        """srand should be a cryptographic-quality source of random
        bytes, if Diffie-Helman secret exchange is to be supported.
        On systems where it is available, an instance of
        random.SystemRandom is a good choice."""
        self.istore = internal_store
        self.estore = external_store
        self.srand = srand

    def handle(self, req):
        """Handles an OpenID request.  req should be a Request
        instance, properly initialized with the http arguments given,
        and the method used to make the request.  Returns a Response
        instance with the necessary fields set to indicate the
        appropriate action."""

        try:
            method_name = 'do_' + req.mode

            try:
                method = getattr(self, method_name)
            except AttributeError:
                raise ProtocolError(
                    'Unsupported openid.mode: %s' % (req.mode,))
            else:
                return method(req)
        except ProtocolError, why:
            return_to = req.get('return_to')
            if req.http_method == 'GET' and return_to:
                edict = {
                    'openid.mode': 'error',
                    'openid.error': why[0],
                    }
                return redirect(append_args(return_to, edict))
            else:
                edict = dict(error=why[0])
                return error_page(kvform(edict))

    def do_associate(self, req):
        """Performs the actions needed for openid.mode=associate.  If
        srand was provided when constructing this server instance,
        this method supports the DH-SHA1 openid.session_type when
        requested.  This function requires that self.get_new_secret be
        overriden to function properly.  Returns a Response object
        indicating what should be sent back to the consumer."""
        reply = {}
        assoc_type = req.get('openid.assoc_type', 'HMAC-SHA1')
        assoc = self.estore.get(assoc_type)

        session_type = req.get('session_type')
        if session_type and self.srand is not None:
            if session_type == 'DH-SHA1':
                p = req.get('dh_modulus')
                g = req.get('dh_gen')
                dh = DiffieHellman.fromBase64(p, g, self.srand)
                
                cpub = a2long(from_b64(req.dh_consumer_public))
                dh_shared = dh.decryptKeyExchange(cpub)
                mac_key = strxor(assoc.secret, sha1(long2a(dh_shared)))
                spub = dh.createKeyExchange()

                reply.update({
                    'session_type': session_type,
                    'dh_server_public': to_b64(long2a(spub)),
                    'enc_mac_key': to_b64(mac_key),
                    })
            else:
                raise ProtocolError('session_type must be DH-SHA1')
        else:
            reply['mac_key'] = to_b64(assoc.secret)

        reply.update({
            'assoc_type': assoc_type,
            'assoc_handle': assoc.handle,
            'expires_in': str(assoc.expires_in),
            })
        
        return response_page(kvform(reply))

    def do_checkid_immediate(self, req):
        try:
            return self.checkid(req)
        except AuthenticationError:
            user_setup_url = self.get_user_setup_url(req)
            reply = {
                'openid.mode': 'id_res',
                'openid.user_setup_url': user_setup_url,
                }
            return redirect(append_args(req.return_to, reply))

    def do_checkid_setup(self, req):
        try:
            return self.checkid(req)
        except AuthenticationError:
            return self.get_setup_response(req)

    def checkid(self, req):
        """This function does the logic for the checkid functions.
        Since the only difference in behavior between them is how
        authentication errors are handled, this does all logic for
        dealing with successful authentication, and raises an
        exception for its caller to handle on a failed authentication."""
        tr = TrustRoot.parse(req.trust_root)
        if tr is None:
            raise ProtocolError('Malformed trust_root: %s' % req.trust_root)

        if not tr.validateURL(req.return_to):
            raise ProtocolError('url(%s) not valid against trust_root(%s)' % (
                req.return_to, req.trust_root))

        if not self.is_valid(req):
            raise AuthenticationError

        reply = {
            'openid.mode': 'id_res',
            'openid.return_to': req.return_to,
            'openid.identity': req.identity,
            }

        assoc_handle = req.get('assoc_handle')
        if assoc_handle:
            assoc = self.estore.lookup(assoc_handle, 'HMAC-SHA1')

            # fall back to dumb mode if assoc_handle not found,
            # and send the consumer an invalidate_handle message
            if assoc is None or assoc.expires_in <= 0:
                if assoc is not None and assoc.expires_in <= 0:
                    self.estore.remove(assoc.handle)
                assoc = self.istore.get('HMAC-SHA1')
                reply['openid.invalidate_handle'] = assoc_handle
        else:
            assoc = self.istore.get('HMAC-SHA1')

        reply.update({
            'openid.assoc_handle': assoc.handle,
            })

        signed, sig = sign_reply(reply, assoc.secret, _signed_fields)

        reply.update({
            'openid.signed': signed,
            'openid.sig': sig,
            })

        return redirect(append_args(req.return_to, reply))

    def do_check_authentication(self, req):
        """Last step in dumb mode"""
        assoc = self.istore.lookup(req.assoc_handle, 'HMAC-SHA1')

        if assoc is None:
            raise ProtocolError('no secret found for %r' % req.assoc_handle)

        reply = {}
        if assoc.expires_in > 0:
            token = req.args.copy()
            token['openid.mode'] = 'id_res'

            signed_fields = req.signed.strip().split(',')
            _, v_sig = sign_reply(token, assoc.secret, signed_fields)

            if v_sig == req.sig:
                is_valid = 'true'

                # if an invalidate_handle request is present, verify it
                invalidate_handle = req.get('invalidate_handle')
                if invalidate_handle:
                    if not self.estore.lookup(invalidate_handle, 'HMAC-SHA1'):
                        reply['invalidate_handle'] = invalidate_handle
            else:
                is_valid = 'false'

        else:
            self.istore.remove(req.assoc_handle)
            is_valid = 'false'

        reply['is_valid'] = is_valid
        return response_page(kvform(reply))

    # Callbacks:
    def is_valid(self, req):
        """If a valid authentication is supplied as part of the
        request, and allows the given trust_root to authenticate the
        identity url, this returns True.  Otherwise, it returns False."""
        raise NotImplementedError

    def get_user_setup_url(self, req):
        """If an identity has failed to authenticate for a given
        trust_root in immediate mode, this is called.  It returns the
        URL to include as the user_setup_url in the redirect sent to
        the consumer."""
        raise NotImplementedError

    def get_setup_response(self, req):
        """If an identity has failed to authenticate for a given
        trust_root in setup mode, this is called.  It returns a
        Response object containing either a page to draw or a redirect
        to issue."""
        raise NotImplementedError
