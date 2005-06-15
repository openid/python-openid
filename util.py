import datetime
import pickle
import binascii
import sha
import hmac
from urllib import urlencode

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

def to_b64(s):
    """Represent string s as base64, omitting newlines"""
    return binascii.b2a_base64(s)[:-1]

def from_b64(s):
    return binascii.a2b_base64(s)

def kvform2(d):
    """Represent dict d as newline-terminated key:value pairs; return
    also order of keys"""
    keys = d.keys()
    return keys, ''.join(['%s:%s\n' % (k, d[k]) for k in keys])

def kvform(d):
    "Represent dict d as newline-terminated key:value pairs"
    return kvform2(d)[1]

def strxor(aa, bb):
    return "".join([chr(ord(a) ^ ord(b)) for a, b in zip(aa, bb)])

def sign_token(d, s):
    '''Sign the token dict d with key s; return "signed" and "sig"'''
    k, t = kvform2(d)
    return ",".join(k), to_b64(hmac.new(s, t, sha).digest())

def append_args(url, args):
    if len(args) == 0:
        return url

    return '%s%s%s' % (url, ('?' in url) and '&' or '?', urlencode(args))

