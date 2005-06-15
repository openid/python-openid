from util import (sha1, long2a, a2long, w3cdate, to_b64, from_b64,
                  kvform, kvform2, strxor)

from constants import secret_sizes, default_dh_modulus, default_dh_gen

__all__ = ['OpenIDServer']

_enc_default_modulus = to_b64(long2a(default_dh_modulus))
_enc_default_gen = to_b64(long2a(default_dh_gen))

class OpenIDServer(object):
    def __init__(self, srand=None):
        self.srand = srand

    def handle(self, args):
        """Args should be a dictionary-like object for looking up
        either get or post args sent to this server.  Returns a pair,
        (redirect, contents).  redirect is a bool indicating whether
        contents is a redirect url or page contents"""

        mode = args['openid.mode']

        if mode == 'associate':
            return self.doAssociate(args)

        raise NotImplementedError

    def doAssociate(self, args):
        reply = {}
        assoc_type = args.pop('openid.assoc_type', 'HMAC-SHA1')
        ret = self.getNewSecret(secret_sizes[assoc_type])
        secret, handle, issued, replace_after, expiry = ret
        
        if 'openid.session_type' in args and self.srand is not None:
            session_type = args.pop('openid.session_type')

            if session_type == 'DH-SHA1':
                enc_dh_mod = args.pop('openid.dh_modulus', _enc_default_modulus)
                enc_dh_gen = args.pop('openid.dh_gen', _enc_default_gen)
                dh_modulus = a2long(from_b64(enc_dh_mod))
                dh_gen = a2long(from_b64(enc_dh_gen))

                enc_dh_cons_pub = args.pop('openid.dh_consumer_public')
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
                raise NotImplementedError
        else:
            reply['openid.mac_key'] = to_b64(secret)

        reply.update({
            'assoc_type': assoc_type,
            'handle': handle,
            'issued': w3cdate(issued),
            'replace_after': w3cdate(replace_after),
            'expiry': w3cdate(expiry),
            })
        
        if len(args) > 0:
            # this might be a bit strange, but ignoring for the moment
            pass

        return False, kvform(reply)

    def getNewSecret(self, size):
        """Returns a tuple (handle, secret) for an association with a
        consumer.  The secret is size bytes long."""
        raise NotImplementedError

    
