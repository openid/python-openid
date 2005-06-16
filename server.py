import time

from util import (sha1, long2a, a2long, w3cdate, to_b64, from_b64,
                  kvform, strxor, sign_reply, append_args)

from constants import secret_sizes, default_dh_modulus, default_dh_gen

__all__ = ['OpenIDServer']

_enc_default_modulus = to_b64(long2a(default_dh_modulus))
_enc_default_gen = to_b64(long2a(default_dh_gen))
_signed_fields = ['mode', 'identity', 'issued', 'valid_to', 'return_to']


class _AuthenticationError(Exception): pass
class _ProtocolError(Exception): pass

class OpenIDServer(object):
    def __init__(self, srand=None):
        """srand should be a cryptographic-quality source of random
        bytes, if Diffie-Helman secret exchange is to be supported.
        On systems where it is available, an instance of
        random.SystemRandom is a good choice."""
        self.srand = srand

    def handle(self, args):
        """Args should be a dictionary-like object for looking up
        either get or post args sent to this server.  Returns a pair,
        (redirect, contents).  redirect is a bool indicating whether
        contents is a redirect url or page contents"""

        try:
            try:
                mode = args['openid.mode']
                method = getattr(self, 'do_' + mode)
            except KeyError:
                raise _ProtocolError(True, 'Expected openid argument missing')
            except AttributeError:
                raise _ProtocolError(True, 'Unsupported openid.mode')
            else:
                return method(args)
        except _ProtocolError, (redirect, message):
            if redirect and 'return_to' in args:
                err = {
                    'openid.mode': 'error',
                    'openid.error': message,
                    }
                return True, append_args(args['return_to'], err)
            else:
                return False, message
            

    def do_associate(self, args):
        """Performs the actions needed for openid.mode=associate.  If
        srand was provided when constructing this server instance,
        this method supports the DH-SHA1 openid.session_type when
        requested.  This function requires that self.get_new_secret be
        overriden to function properly.  Returns (False, reply_body),
        where reply_body is the body of the http response that should
        be sent back to the consumer."""
        reply = {}
        assoc_type = args.get('openid.assoc_type', 'HMAC-SHA1')
        ret = self.get_new_secret(secret_sizes[assoc_type])
        secret, handle, issued, replace_after, expiry = ret
        
        if 'openid.session_type' in args and self.srand is not None:
            session_type = args.get('openid.session_type')

            if session_type == 'DH-SHA1':
                enc_dh_mod = args.get('openid.dh_modulus', _enc_default_modulus)
                enc_dh_gen = args.get('openid.dh_gen', _enc_default_gen)
                dh_modulus = a2long(from_b64(enc_dh_mod))
                dh_gen = a2long(from_b64(enc_dh_gen))

                enc_dh_cons_pub = args.get('openid.dh_consumer_public')
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
                raise _ProtocolError(False, 'session_type must be DH-SHA1')
        else:
            reply['openid.mac_key'] = to_b64(secret)

        reply.update({
            'assoc_type': assoc_type,
            'handle': handle,
            'issued': w3cdate(issued),
            'replace_after': w3cdate(replace_after),
            'expiry': w3cdate(expiry),
            })
        
        return False, kvform(reply)

    def do_checkid_immediate(self, args):
        try:
            return self.checkid_shared(args)
        except _AuthenticationError:
            # XXX: do whatever is correct for auth failure in
            # immediate mode
            raise

    def do_checkid_setup(self, args):
        try:
            return self.checkid_shared(args)
        except _AuthenticationError:
            # XXX: do whatever is correct for auth failure in
            # setup mode
            raise

    def do_check_authentication(self, args):
        raise NotImplementedError

    def checkid_shared(self, args):
        """This function does the logic for the checkid functions.
        Since the only difference in behavior between them is how
        authentication errors are handled, this does all logic for
        dealing with successful authentication, and raises an
        exception for its caller to handle on a failed authentication."""
        
        identity = args.get('openid.identity')
        return_to = args.get('openid.return_to')
        trust_root = args.get('openid.trust_root', return_to)

        if not (identity and return_to and trust_root):
            raise _ProtocolError(True, 'missing arg')

        if not self.is_sane_trust_root(trust_root):
            raise _AuthenticationError

        reply = {
            'openid.return_to': return_to,
            'openid.identity': identity,
            'openid.mode': 'id_res',
            }

        if 'openid.assoc_handle' in args:
            return self.checkid_normal(reply, identity, return_to, trust_root,
                                       args['openid.assoc_handle'])
        else:
            return self.checkid_dumb(reply, identity, return_to, trust_root)

    def checkid_normal(self, reply, identity, return_to, trust_root, assoc_handle):
        ret = self.get_secret(assoc_handle)

        if ret is None:
            raise _ProtocolError(True, 'no such assoc_handle on server')

        secret, expiry = ret
        if expiry < time.time():
            raise _ProtocolError(True, 'using an expired handle')

        ret = self.id_allows_authentication(identity, trust_root)
        if ret:
            issued, expires = ret
            reply.update({
                'openid.issued': w3cdate(issued),
                'openid.assoc_handle': assoc_handle,
                'openid.valid_to': w3cdate(expires),
                })

            signed, sig = sign_reply(reply, secret, _signed_fields)
            reply.update({
                'openid.signed': signed,
                'openid.sig': sig,
                })
            return True, append_args(return_to, reply)
        else:
            raise _AuthenticationError

    def checkid_dumb(self, reply, identity, return_to, trust_root):
        ret = self.get_server_secret(secret_sizes['HMAC-SHA1'])
        secret, handle, issued, valid_to = ret

        ret = self.id_allows_authentication(identity, trust_root)
        if ret:
            auth_issued, auth_expires = ret
            
            reply.update({
                'openid.assoc_handle': handle,
                'openid.issued': w3cdate(issued), # XXX: Is this the right value?
                'openid.valid_to': w3cdate(valid_to),
                })

            signed, sig = sign_reply(reply, secret, _signed_fields)

            reply.update({
                'openid.signed': signed,
                'openid.sig': sig,
                })

            return True, append_args(return_to, reply)
        else:
            raise _AuthenticationError

    # Helpers that can easily be overridden:
    def is_sane_trust_root(self, trust_root):
        # XXX: do more checking for sane trust_root
        if trust_root in ['*.com', '*.co.uk']:
            return False
        
        return True


    # Callbacks:
    def get_server_secret(self, size):
        """Returns a tuple (secret, handle, issued, valid_to) for this
        server to associate with itself.  This might return a new
        secret, or it might return an existing one.  Either behavior
        is fine, as long as three conditions are met.  First, the
        handle must be useable with the get_secret call to retrieve
        the secret at a later time.  Second, the secret returned must
        be of the requested size.  Third, the valid_to value must be
        in the future and a unix timestamp in UTC (such as one
        returned by time.time())"""
        raise NotImplementedError
    
    def get_new_secret(self, size):
        """Returns a tuple (secret, handle, issued, replace_after,
        expiry) for an association with a consumer.  The secret must
        be size bytes long.  issued, replace_after, and expiry are
        unix timestamps in UTC (such as those returned by time.time())"""
        raise NotImplementedError

    def get_secret(self, assoc_handle):
        """Returns a tuple (secret, expiry) for an existing
        association with a consumer.  If no association is found
        (either it expired and was removed, or never existed), this
        method should return None.  expiry is a unix timestamp in UTC
        (such as that returned by time.time())"""
        raise NotImplementedError

    def id_allows_authentication(self, identity, trust_root):
        """If the given identity exists and allows the given
        trust_root to authenticate, this returns a tuple (issued,
        expires), giving the time the authentication was issued and
        when it expires.  Otherwise, return None.
        
        issued and expires are unix timestamps in UTC (such as those
        returned by time.time()) """
        raise NotImplementedError
