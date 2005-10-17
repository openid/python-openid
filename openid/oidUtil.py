import pickle
# Check Python compatiblity by raising an exception on import if the
# needed functionality is not present.
pickle.encode_long
pickle.decode_long

import binascii
import sha
import hmac
import sys
import types

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

def seqToKV(seq):
    """Represent a sequence of pairs of strings as newline-terminated
    key:value pairs. The pairs are generated in the order given.

    @param seq: The pairs
    @type seq: [(str, str)]

    @return: A string representation of the sequence
    @rtype: str
    """
    def err(msg):
        log('seqToKV warning: %s: %r' % (msg, seq))

    lines = []
    for k, v in seq:
        if not isinstance(k, types.StringType):
            err('Converting key to string: %r' % k)
            k = str(k)

        if '\n' in k:
            raise ValueError(
                'Invalid input for seqToKV: key contains newline: %r' % (k,))

        if k.strip() != k:
            err('Key has whitespace at beginning or end: %r' % k)

        if not isinstance(v, types.StringType):
            err('Converting value to string: %r' % v)
            v = str(v)

        if '\n' in v:
            raise ValueError(
                'Invalid input for seqToKV: value contains newline: %r' % (v,))

        if v.strip() != v:
            err('Value has whitespace at beginning or end: %r' % v)

        lines.append(k + ':' + v + '\n')

    return ''.join(lines)

def kvToSeq(data):
    """

    After one parse, seqToKV and kvToSeq are inverses, with no warnings:
        seq = kvToSeq(s)

        seqToKV(kvToSeq(seq)) == seq
    """
    def err(msg):
        log('kvToSeq warning: %s: %r' % (msg, data))
    
    lines = data.split('\n')
    if lines[-1]:
        err('Does not end in a newline')
    else:
        del lines[-1]

    pairs = []
    line_num = 0
    for line in lines:
        line_num += 1
        pair = line.split(':', 1)
        if len(pair) == 2:
            k, v = pair
            k_s = k.strip()
            if k_s != k:
                fmt = ('In line %d, ignoring leading or trailing '
                       'whitespace in key %r')
                err(fmt % (line_num, k))

            if not k_s:
                err('In line %d, got empty key' % (line_num,))

            v_s = v.strip()
            if v_s != v:
                fmt = ('In line %d, ignoring leading or trailing '
                       'whitespace in value %r')
                err(fmt % (line_num, v))

            pairs.append((k_s, v_s))
        else:
            err('Line %d does not contain a colon' % line_num)

    return pairs

def dictToKV(d):
    seq = d.items()
    seq.sort()
    return seqToKV(seq)

def kvToDict(s):
    return dict(kvToSeq(s))

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

    text = seqToKV(token)
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
