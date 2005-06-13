import datetime
import pickle
import binascii
import sha

_secret_sizes = {
    'HMAC-SHA1': 20,
    }

def _sha1(s):
    return sha.new(s).digest()

def _long2a(l):
    if l == 0:
        return '\x00'
    
    return ''.join(reversed(pickle.encode_long(l)))

def _a2long(s):
    return pickle.decode_long(''.join(reversed(s)))

def _w3cdate(x):
    """Represent UNIX time x as a W3C UTC timestamp"""
    dt = datetime.datetime.utcfromtimestamp(x)
    dt = dt.replace(microsecond=0)
    return dt.isoformat() + 'Z'

def _to_b64(s):
    """Represent string s as base64, omitting newlines"""
    return binascii.b2a_base64(s)[:-1]

def _from_b64(s):
    return binascii.a2b_base64(s)

def _kvform2(d):
    """Represent dict d as newline-terminated key:value pairs; return
    also order of keys"""
    keys = d.keys()
    return keys, ''.join(['%s:%s\n' % (k, d[k]) for k in keys])

def _kvform(d):
    "Represent dict d as newline-terminated key:value pairs"
    return _kvform2(d)[1]

def _strxor(aa, bb):
    return "".join([chr(ord(a) ^ ord(b)) for a, b in zip(aa, bb)])

_default_modulus = 155172898181473697471232257763715539915724801966915404479707795314057629378541917580651227423698188993727816152646631438561595825688188889951272158842675419950341258706556549803580104870537681476726513255747040765857479291291572334510643245094715007229621094194349783925984760375594985848253359305585439638443L

_default_gen = 2

_enc_default_modulus = _to_b64(_long2a(_default_modulus))
_enc_default_gen = _to_b64(_long2a(_default_gen))

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
        ret = self.getNewSecret(_secret_sizes[assoc_type])
        secret, handle, issued, replace_after, expiry = ret
        
        if 'openid.session_type' in args and self.srand is not None:
            session_type = args.pop('openid.session_type')

            if session_type == 'DH-SHA1':
                enc_dh_mod = args.pop('openid.dh_modulus', _enc_default_modulus)
                enc_dh_gen = args.pop('openid.dh_gen', _enc_default_gen)
                dh_modulus = _a2long(_from_b64(enc_dh_mod))
                dh_gen = _a2long(_from_b64(enc_dh_gen))

                enc_dh_cons_pub = args.pop('openid.dh_consumer_public')
                dh_cons_pub = _a2long(_from_b64(enc_dh_cons_pub))

                dh_server_private = self.srand.randrange(1, dh_modulus - 1)
                dh_server_public = pow(dh_gen, dh_server_private, dh_modulus)
                enc_dh_server_public = _to_b64(_long2a(dh_server_public))

                dh_shared = pow(dh_cons_pub, dh_server_private, dh_modulus)
                
                enc_mac_key = _to_b64(
                    _strxor(secret, _sha1(_long2a(dh_shared))))

                reply.update({
                    'session_type': session_type,
                    'dh_server_public': enc_dh_server_public,
                    'enc_mac_key': enc_mac_key,
                    })
            else:
                raise NotImplementedError
        else:
            reply['openid.mac_key'] = _to_b64(secret)

        reply.update({
            'assoc_type': assoc_type,
            'handle': handle,
            'issued': _w3cdate(issued),
            'replace_after': _w3cdate(replace_after),
            'expiry': _w3cdate(expiry),
            })
        
        if len(args) > 0:
            # this is a bit strange...  but letting it go for now
            pass

        return False, _kvform(reply)

    def getNewSecret(self, size):
        """Returns a tuple (handle, secret) for an association with a
        consumer.  The secret is size bytes long."""
        raise NotImplementedError

    
