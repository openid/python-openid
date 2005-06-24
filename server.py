import time

from openid.util import *
from openid.constants import secret_sizes, default_dh_modulus, default_dh_gen
from openid.errors import ProtocolError, AuthenticationError
from openid.interface import *
from openid.trustroot import *

__all__ = ['OpenIDServer']

_enc_default_modulus = to_b64(long2a(default_dh_modulus))
_enc_default_gen = to_b64(long2a(default_dh_gen))
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
            print edict
            return_to = req.get('return_to')
            if req.http_method == 'GET' and return_to:
                return redirect(append_args(return_to, edict))
            elif req.http_method == 'GET' and not req.hasOpenIDParams():
                return self.get_openid_page()
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
                enc_dh_mod = req.get('dh_modulus', _enc_default_modulus)
                enc_dh_gen = req.get('dh_gen', _enc_default_gen)
                dh_modulus = a2long(from_b64(enc_dh_mod))
                dh_gen = a2long(from_b64(enc_dh_gen))

                enc_dh_cons_pub = req.dh_consumer_public
                dh_cons_pub = a2long(from_b64(enc_dh_cons_pub))

                dh_server_private = self.srand.randrange(1, dh_modulus - 1)
                dh_server_public = pow(dh_gen, dh_server_private, dh_modulus)
                enc_dh_server_public = to_b64(long2a(dh_server_public))

                dh_shared = pow(dh_cons_pub, dh_server_private, dh_modulus)
                enc_mac_key = to_b64(strxor(assoc.secret, sha1(long2a(dh_shared))))

                reply.update({
                    'session_type': session_type,
                    'dh_server_public': enc_dh_server_public,
                    'enc_mac_key': enc_mac_key,
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
        trust_root = req.get('trust_root', req.return_to)

        tr = TrustRoot.parse(trust_root)
        if tr is None:
            raise ProtocolError('Malformed trust_root: %s' % trust_root)

        if not tr.isSane():
            # XXX: do something here
            pass

        if not tr.validateURL(req.return_to):
            raise ProtocolError('url(%s) not valid against trust_root(%s)' % (
                req.return_to, trust_root))

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

        signed_fields = list(_signed_fields)

        assoc_handle = req.get('assoc_handle')
        if assoc_handle:
            assoc = self.lookup_secret(assoc_handle)

            # fall back to dumb mode if assoc_handle not found,
            # and send the consumer an invalidate_handle message
            if assoc is None or assoc.expiry < time.time():
                assoc = self.get_server_secret()
                reply.update({
                    'openid.invalidate_handle': assoc_handle,
                    })
                signed_fields.append('invalidate_handle')
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
            raise ProtocolError('no secret found for %r' % assoc_handle)

        if assoc.expiry < time.time():
            raise ProtocolError('using an expired assoc_handle')

        token = req.args.copy()
        token['openid.mode'] = 'id_res'

        signed_fields = req.signed.strip().split(',')
        _, v_sig = sign_reply(token, assoc.secret, signed_fields)

        if v_sig == req.sig:
            lifetime = self.get_lifetime(req)
        else:
            lifetime = 0

        return response_page(kvform({'lifetime': lifetime}))

    # Helpers that can easily be overridden:
    def get_openid_page(self):
        """This method is called when the openid server is accessed
        with no openid arguments.  It should return a Response object
        that will paint a simple 'this is an openid server' page."""
        text = """<html>
<head>
  <title>OpenID Server</title>
</head>
<body>
<p>Hello.  You've reached an OpenID server.  See
<a href="http://www.openid.net">openid.net</a> for more
information.</p>
</body>
</html
"""
        return Response(code=200, content_type='text/html', body=text)


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

    def get_lifetime(self, req):
        """In the case the consumer is in dumb mode, and has
        succesfully authenticated, return the lifetime that
        authentication is valid for in seconds."""
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
