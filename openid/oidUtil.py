"""
the strxor functions is written by Paul Crowley and
distributed with this package under separate MIT
license. paul@ciphergoth.org
"""

import pickle
import binascii
import sha
import hmac
import random

from urllib import urlencode

try:
    srand = random.SystemRandom()
except AttributeError:
    # WARNING: This is not a cryptographically safe source of
    # randomness. If you are running on Python 2.2. If you need to use
    # Python 2.1, you should look into using a different random number
    # source, such as the random pool provided with the Python
    # Cryptography Toolkit (pycrypto). pycrypto can be found with a
    # search engine, but is currently found at:
    #
    # http://www.amk.ca/python/code/crypto

    srand = random.Random()
    srand.seed()

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
    return binascii.a2b_base64(s)

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
    return "".join([chr(ord(a) ^ ord(b)) for a, b in zip(aa, bb)])

def signReply(reply, key, signed_fields):
    """Sign the given fields from the reply with the specified key.
    Return signed and sig"""
    token = []
    for i in signed_fields:
        token.append((i, reply['openid.' + i]))

    text = ''.join(['%s:%s\n' % (k, v) for k, v in token])
    return (','.join(signed_fields),
            oidUtil.toBase64(oidUtil.hmacsha1(key, text)))

def appendArgs(url, args):
    if len(args) == 0:
        return url

    return '%s%s%s' % (url, ('?' in url) and '&' or '?', urlencode(args))


_default_chars = map(chr, range(256))

def randomString(length, chrs=_default_chars):
    """Produce a string of length random bytes using srand as a source of
    random numbers."""
    return ''.join([srand.choice(chrs) for _ in xrange(length)])

