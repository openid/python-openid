import time

from openid.util import (append_args, kvform, DiffieHellman, a2long,
                         from_b64, long2a, sha1, strxor, to_b64, w3cdate,
                         sign_reply, datetime2timestamp, w3c2datetime)
from openid.constants import secret_sizes
from openid.errors import ProtocolError, AuthenticationError
from openid.interface import Request, error_page, redirect, response_page
from openid.trustroot import TrustRoot

__all__ = ['OpenIDServer']

_signed_fields = ['mode', 'issued', 'valid_to', 'identity', 'return_to']

class OpenIDServer(object):
    def __init__(self, srand=None):
        """srand should be a cryptographic-quality source of random
        bytes, if Diffie-Helman secret exchange is to be supported.
        On systems where it is available, an instance of
        random.SystemRandom is a good choice."""
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
            edict = {
                'openid.mode': 'error',
                'openid.error': why[0],
                }
            return_to = req.get('return_to')
            if req.http_method == 'GET' and return_to:
                return redirect(append_args(return_to, edict))
            else:
                return error_page(kvform(edict))

    def do_associate(self, req):
        """Performs the actions needed for openid.mode=associate.  If
        srand was provided when constructing this server instance,
        this method supports the DH-SHA1 openid.session_type when
        requested.  This function requires that self.get_new_secret be
        overriden to function properly.  Returns (False, reply_body),
        where reply_body is the body of the http response that should
        be sent back to the consumer."""
        reply = {}
        assoc_type = req.get('openid.assoc_type', 'HMAC-SHA1')
        assoc = self.get_new_secret(assoc_type)

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
            reply['openid.mac_key'] = to_b64(assoc.secret)

        reply.update({
            'assoc_type': assoc_type,
            'assoc_handle': assoc.handle,
            'issued': w3cdate(assoc.issued),
            'replace_after': w3cdate(assoc.replace_after),
            'expiry': w3cdate(assoc.expiry),
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

        if not tr.isSane():
            raise ProtocolError('trust_root %r makes no sense' % req.trust_root)

        if not tr.validateURL(req.return_to):
            raise ProtocolError('url(%s) not valid against trust_root(%s)' % (
                req.return_to, req.trust_root))

        duration = self.get_auth_range(req)
        if not duration:
            raise AuthenticationError

        now = time.time()
        reply = {
            'openid.mode': 'id_res',
            'openid.issued': w3cdate(now),
            'openid.valid_to': w3cdate(now + duration),
            'openid.identity': req.identity,
            'openid.return_to': req.return_to,
            }

        assoc_handle = req.get('assoc_handle')
        if assoc_handle:
            assoc = self.lookup_secret(assoc_handle)

            # fall back to dumb mode if assoc_handle not found,
            # and send the consumer an invalidate_handle message
            if assoc is None or assoc.expiry < time.time():
                assoc = self.get_server_secret()
                reply['openid.invalidate_handle'] = assoc_handle
        else:
            assoc = self.get_server_secret()

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
        assoc = self.lookup_secret(req.assoc_handle)
        if assoc is None:
            raise ProtocolError('no secret found for %r' % req.assoc_handle)

        if assoc.expiry < time.time():
            raise ProtocolError('using an expired assoc_handle')

        token = req.args.copy()
        token['openid.mode'] = 'id_res'

        signed_fields = req.signed.strip().split(',')
        _, v_sig = sign_reply(token, assoc.secret, signed_fields)

        reply = {}
        if v_sig == req.sig:
            # calculate remaining lifetime
            valid_to = datetime2timestamp(w3c2datetime(req.valid_to))
            lifetime = max(0, int(valid_to - time.time()))

            # if an invalidate_handle request is present, verify it
            invalidate_handle = req.get('invalidate_handle')
            if invalidate_handle and not self.lookup_secret(invalidate_handle):
                reply['invalidate_handle'] = invalidate_handle
        else:
            lifetime = 0

        reply['lifetime'] = str(lifetime)
        return response_page(kvform(reply))

    # Callbacks:
    def get_server_secret(self):
        """Returns an instance of openid.association.ServerAssociation
        for this server to associate with itself.  The returned
        ServerAssociation instance may represent either an existing or
        a newly-created association, as long as it's not expired and
        can be found with lookup_secret."""
        raise NotImplementedError
    
    def get_new_secret(self, assoc_type):
        """Returns an instance of openid.association.ServerAssociation
        to send to a consumer.  The association must be valid for the
        given assoc_type."""
        raise NotImplementedError

    def lookup_secret(self, assoc_handle):
        """Returns an instance of openid.association.ServerAssociation
        for an existing association with a consumer.  If no
        association is found (either it expired and was removed, or
        never existed), this method should return None."""
        raise NotImplementedError

    def get_auth_range(self, req):
        """If a valid authentication is supplied as part of the
        request, and allows the given trust_root to authenticate the
        identity url, this returns the session lifetime in seconds.
        Otherwise, return None."""        
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
        Response object containing either a page to draw or another
        redirect to issue."""
        raise NotImplementedError
