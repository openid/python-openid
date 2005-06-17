import time
import datetime
import pickle
import binascii
import sha
import hmac

from urllib import urlencode

from openid.errors import ProtocolError

# XXX: set __all__

def sha1(s):
    return sha.new(s).digest()

def long2a(l):
    if l == 0:
        return '\x00'
    
    return ''.join(reversed(pickle.encode_long(l)))

def a2long(s):
    return pickle.decode_long(''.join(reversed(s)))

def w3cdate(x):
    """Represent UNIX time x as a W3C UTC timestamp"""
    dt = datetime.datetime.utcfromtimestamp(x)
    dt = dt.replace(microsecond=0)
    return dt.isoformat() + 'Z'

def w3c2datetime(x):
    return datetime.datetime(time.strptime(x, '%Y-%m-%dT%H:%M:%SZ'))

def to_b64(s):
    """Represent string s as base64, omitting newlines"""
    return binascii.b2a_base64(s)[:-1]

def from_b64(s):
    return binascii.a2b_base64(s)

def kvform(d):
    "Represent dict d as newline-terminated key:value pairs"
    return ''.join(['%s:%s\n' % (k, v) for k, v in d.iteritems()])

def parsekv(d):
    d = d.strip()
    args = {}
    for line in d.split('\n'):
        pair = line.split(':', 1)
        if len(pair) != 2: continue
        k, v = pair
        args[k.strip()] = v.strip()
    return args

def strxor(aa, bb):
    return "".join([chr(ord(a) ^ ord(b)) for a, b in zip(aa, bb)])

def sign_reply(reply, key, signed_fields):
    """Sign the given fields from the reply with the specified key.
    Return signed and sig"""
    token = []
    for i in signed_fields:
        token.append((i, reply['openid.' + i]))
    
    text = ''.join(['%s:%s\n' % (k, v) for k, v in token])
    return ','.join(signed_fields), to_b64(hmac.new(key, text, sha).digest())

def append_args(url, args):
    if len(args) == 0:
        return url

    return '%s%s%s' % (url, ('?' in url) and '&' or '?', urlencode(args))

def get_arg(name, args):
    arg = args.get("openid." + name)
    if arg is None:
        raise ProtocolError("Missing Argument: %r" % (name,))
    return arg
