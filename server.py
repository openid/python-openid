from util import (sha1, long2a, a2long, w3cdate, to_b64, from_b64,
                  kvform, kvform2, strxor)

from constants import secret_sizes, default_dh_modulus, default_dh_gen

__all__ = ['OpenIDServer']

_enc_default_modulus = to_b64(long2a(default_dh_modulus))
_enc_default_gen = to_b64(long2a(default_dh_gen))

class OpenIDServer(object):
    def __init__(self, srand=None):
        """srand should be a cryptographic-quality source of random
        bytes, if Diffie-Helman encoding is to be supported.  On
        systems where it is available, an instance of
        random.SystemRandom is a good choice."""
        self.srand = srand

    def handle(self, args):
        """Args should be a dictionary-like object for looking up
        either get or post args sent to this server.  Returns a pair,
        (redirect, contents).  redirect is a bool indicating whether
        contents is a redirect url or page contents"""

        mode = args['openid.mode']
        try:
            method = getattr(self, 'do_' + mode)
        except AttributeError:
            # XXX what does the spec say to do here?
            raise
        else:
            return method(args)

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
        
        return False, kvform(reply)

    def do_checkid_immediate(self, args):
        reply = {}

        identity = args.get('openid.identity')
        return_to = args.get('openid.return_to')
        trust_root = args.get('openid.trust_root', return_to)

        if not (identity and return_to and trust_root):
            # XXX: protocol error of some sort
            pass

        if not self.is_sane_trust_root(trust_root):
            # XXX: authentication error
            pass

        if 'openid.assoc_handle' in args:
            # normal mode
            assoc_handle = args['openid.assoc_handle']
            ret = self.get_secret(assoc_handle)

            if ret is None:
                # XXX: authentication error
                pass
            
            secret, expiry = ret
        else:
            # dumb mode
            pass
        

    def do_checkid_setup(self, args):
        pass

    def do_check_authentication(self, args):
        pass


    # Helpers that can easily be overridden
    def is_sane_trust_root(self, trust_root):
        # XXX: do checking for sane trust_root
        return True


    # Callbacks:
    def get_new_secret(self, size):
        """Returns a tuple (secret, handle, issued, replace_after,
        expiry) for an association with a consumer.  The secret must
        be size bytes long."""
        raise NotImplementedError

    def get_secret(self, assoc_handle):
        """Returns a tuple (secret, expiry) for an existing
        association with a consumer.  If no association is found
        (either it expired and was removed, or never existed), this
        method should return None."""
        raise NotImplementedError
