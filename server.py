import time

from openid.util import *
from openid.constants import secret_sizes, default_dh_modulus, default_dh_gen
from openid.errors import ProtocolError, AuthenticationError
from openid.interface import Request, redirect, response_page, error_page

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
                raise ProtocolError('Unsupported openid.mode')
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
        ret = self.get_new_secret(assoc_type)
        secret, handle, issued, replace_after, expiry = ret

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
                
                enc_mac_key = to_b64(strxor(secret, sha1(long2a(dh_shared))))

                reply.update({
                    'session_type': session_type,
                    'dh_server_public': enc_dh_server_public,
                    'enc_mac_key': enc_mac_key,
                    })
            else:
                raise ProtocolError('session_type must be DH-SHA1')
        else:
            reply['openid.mac_key'] = to_b64(secret)

        reply.update({
            'assoc_type': assoc_type,
            'handle': handle,
            'issued': w3cdate(issued),
            'replace_after': w3cdate(replace_after),
            'expiry': w3cdate(expiry),
            })
        
        return response_page(kvform(reply))

    def do_checkid_immediate(self, req):
        try:
            return self.checkid(req)
        except AuthenticationError:
            trust_root = req.get('trust_root', req.return_to)
            
            user_setup_url = self.get_user_setup_url(req.identity, trust_root)
            reply = {
                'openid.mode': 'id_res',
                'openid.user_setup_url': user_setup_url,
                }
            return redirect(append_args(req.return_to, reply))

    def do_checkid_setup(self, req):
        try:
            return self.checkid(req)
        except AuthenticationError:
            return self.get_setup_response(req.identity,
                                           req.trust_root,
                                           req.return_to)

    def checkid(self, req):
        """This function does the logic for the checkid functions.
        Since the only difference in behavior between them is how
        authentication errors are handled, this does all logic for
        dealing with successful authentication, and raises an
        exception for its caller to handle on a failed authentication."""
        trust_root = req.get('trust_root', req.return_to)
        if not self.is_sane_trust_root(trust_root):
            raise AuthenticationError

        assoc_handle = req.get('assoc_handle')
        if assoc_handle:
            try:
                secret, expiry = self.lookup_secret(assoc_handle)
            except TypeError:
                raise ProtocolError('no secret found for %r' % assoc_handle)

            if expiry < time.time():
                raise ProtocolError('using an expired handle')
        else:
            secret, assoc_handle = self.get_server_secret()

        try:
            issued, expires = self.get_auth_range(req.identity, trust_root)
        except TypeError:
            raise AuthenticationError

        reply = {
            'openid.mode': 'id_res',
            'openid.issued': w3cdate(issued),
            'openid.valid_to': w3cdate(expires),
            'openid.identity': req.identity,
            'openid.return_to': req.return_to,
            'openid.assoc_handle': assoc_handle,
            }

        signed, sig = sign_reply(reply, secret, _signed_fields)

        reply.update({
            'openid.signed': signed,
            'openid.sig': sig,
            })
    
        return redirect(append_args(req.return_to, reply))

    def do_check_authentication(self, req):
        """Last step in dumb mode"""
        try:
            secret, expiry = self.lookup_secret(req.assoc_handle)
        except TypeError:
            raise ProtocolError('no secret found for %r' % req.assoc_handle)

        if expiry < time.time():
            raise ProtocolError('using an expired assoc_handle')

        token = req.args.copy()
        token['openid.mode'] = 'id_res'

        try:
            _, v_sig = sign_reply(token, secret, _signed_fields)
        except KeyError, why:
            raise ProtocolError('Missing required query arg %r' % why.args)

        if v_sig == req.sig:
            lifetime = self.get_lifetime(req.identity)
        else:
            lifetime = 0

        return response_page(kvform({'lifetime': lifetime}))

    # Helpers that can easily be overridden:
    def is_sane_trust_root(self, trust_root):
        # XXX: do more checking for sane trust_root
        if trust_root in ['*.com', '*.co.uk']:
            return False
        
        return True

    def get_openid_page(self):
        """This method is called when the openid server is accessed
        with no openid arguments.  It should return a Response object
        that will paint a simple 'this is an openid server' page."""
        text = """<html>
<head>
  <title>OpenID Server</title>
</head>
<body>
<p>Hello.  You've reached an OpenId server.  See
<a href="http://www.openid.net">openid.net</a> for more
information.</p>
</body>
</html
"""
        return Response(code=200, content_type='text/html', body=text)


    # Callbacks:
    def get_server_secret(self):
        """Returns a tuple (secret, handle) for this server to
        associate with itself. This will return a new secret or
        existing secret. Either is fine, as long as the handle is
        usable with lookup_secret."""
        raise NotImplementedError
    
    def get_new_secret(self, assoc_type):
        """Returns a tuple (secret, handle, issued, replace_after,
        expiry) for an association with a consumer.  The secret must
        be for an association of assoc_type.  issued, replace_after,
        and expiry are unix timestamps in UTC (like those returned by
        time.time())"""
        raise NotImplementedError

    def lookup_secret(self, assoc_handle):
        """Returns a tuple (secret, expiry) for an existing
        association with a consumer.  If no association is found
        (either it expired and was removed, or never existed), this
        method should return None.  expiry is a unix timestamp in UTC
        (like that returned by time.time())"""
        raise NotImplementedError

    def get_auth_range(self, identity, trust_root):
        """If the given identity exists and allows the given
        trust_root to authenticate, this returns a tuple (issued,
        expires), giving the time the authentication was issued and
        when it expires.  Otherwise, return None.
        
        issued and expires are unix timestamps in UTC (such as those
        returned by time.time())"""
        raise NotImplementedError

    def get_lifetime(self, identity):
        """In the case the consumer is in dumb mode, and has
        succesfully authenticated, return the lifetime that
        authentication is valid for in seconds."""
        raise NotImplementedError

    def get_user_setup_url(self, identity, trust_root):
        """If an identity has failed to authenticate for a given
        trust_root in immediate mode, this is called.  It returns the
        URL to include as the user_setup_url in the redirect sent to
        the consumer."""
        raise NotImplementedError

    def get_setup_response(self, identity, trust_root, return_to):
        """If an identity has failed to authenticate for a given
        trust_root in setup mode, this is called.  It returns a
        Response object containing either a page to draw or another
        redirect to issue."""
        raise NotImplementedError
