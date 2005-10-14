import pickle
import binascii
import sha
import hmac
import sys

from urllib import urlencode
from openid.cryptrand import srand, getBytes

try:
    _ = reversed
except NameError:
    def reversed(seq):
        return map(seq.__getitem__, xrange(len(seq) - 1, -1, -1))
else:
    del _

def log(message, level=0):
    sys.stderr.write(message)
    sys.stderr.write('\n')

def hmacSha1(key, text):
    return hmac.new(key, text, sha).digest()

def sha1(s):
    return sha.new(s).digest()

def longToStr(l):
    if l == 0:
        return '\x00'

    return ''.join(reversed(pickle.encode_long(l)))

def strToLong(s):
    return pickle.decode_long(''.join(reversed(s)))

def toBase64(s):
    """Represent string s as base64, omitting newlines"""
    return binascii.b2a_base64(s)[:-1]

def fromBase64(s):
    try:
        return binascii.a2b_base64(s)
    except binascii.Error:
        return ''

def kvForm(d):
    """Represent dict d as newline-terminated key:value pairs"""
    return ''.join(['%s:%s\n' % (k, v) for k, v in d.iteritems()])

def parsekv(d):
    d = d.strip()
    args = {}
    for line in d.split('\n'):
        pair = line.split(':', 1)
        if len(pair) == 2:
            k, v = pair
            args[k.strip()] = v.strip()
    return args

def strxor(aa, bb):
    if len(aa) != len(bb):
        raise ValueError('Inputs to strxor must have the same length')

    xor = lambda (a, b): chr(ord(a) ^ ord(b))
    return "".join(map(xor, zip(aa, bb)))

def signReply(reply, key, signed_fields):
    """Sign the given fields from the reply with the specified key.
    Return signed and sig"""
    token = []
    for i in signed_fields:
        token.append((i, reply['openid.' + i]))

    text = ''.join(['%s:%s\n' % (k, v) for k, v in token])
    return (','.join(signed_fields), toBase64(hmacSha1(key, text)))

def appendArgs(url, args):
    if len(args) == 0:
        return url

    return '%s%s%s' % (url, ('?' in url) and '&' or '?', urlencode(args))

def randomString(length, chrs=None):
    """Produce a string of length random bytes, chosen from chrs."""
    if chrs is None:
        return getBytes(length)
    else:
        return ''.join([srand.choice(chrs) for _ in xrange(length)])
