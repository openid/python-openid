"""Module containing a cryptographic-quality source of randomness and
other cryptographically useful functionality

Other configurations will need a quality source of random bytes and
access to a function that will convert binary strings to long
integers. This module will work with the Python Cryptography Toolkit
(pycrypto) if it is present. pycrypto can be found with a search
engine, but is currently found at:

http://www.amk.ca/python/code/crypto
"""
from __future__ import unicode_literals

import hashlib
import hmac
import os
import random

from openid.oidutil import fromBase64, string_to_text, toBase64

__all__ = [
    'base64ToLong',
    'binaryToLong',
    'hmacSha1',
    'hmacSha256',
    'longToBase64',
    'longToBinary',
    'randrange',
    'sha1',
    'sha256',
]


class HashContainer(object):
    def __init__(self, hash_constructor):
        self.new = hash_constructor
        self.digest_size = hash_constructor().digest_size


sha1_module = HashContainer(hashlib.sha1)
sha256_module = HashContainer(hashlib.sha256)


def hmacSha1(key, text):
    """
    Return a SHA1 HMAC.

    @type key: six.binary_type
    @type text: six.text_type, six.binary_type is deprecated
    @rtype: six.binary_type
    """
    text = string_to_text(text, "Binary values for text are deprecated. Use text input instead.")
    return hmac.new(key, text.encode('utf-8'), sha1_module).digest()


def sha1(s):
    """
    Return a SHA1 hash.

    @type s: six.binary_type
    @rtype: six.binary_type
    """
    return sha1_module.new(s).digest()


def hmacSha256(key, text):
    """
    Return a SHA256 HMAC.

    @type key: six.binary_type
    @type text: six.text_type, six.binary_type is deprecated
    @rtype: six.binary_type
    """
    text = string_to_text(text, "Binary values for text are deprecated. Use text input instead.")
    return hmac.new(key, text.encode('utf-8'), sha256_module).digest()


def sha256(s):
    """
    Return a SHA256 hash.

    @type s: six.binary_type
    @rtype: six.binary_type
    """
    return sha256_module.new(s).digest()


try:
    from Crypto.Util.number import long_to_bytes, bytes_to_long
except ImportError:
    import pickle

    def longToBinary(value):
        if value == 0:
            return b'\x00'

        return pickle.encode_long(value)[::-1]

    def binaryToLong(s):
        return pickle.decode_long(s[::-1])
else:
    # We have pycrypto

    def longToBinary(value):
        if value < 0:
            raise ValueError('This function only supports positive integers')

        output = long_to_bytes(value)
        if isinstance(output[0], int):
            ord_first = output[0]
        else:
            ord_first = ord(output[0])
        if ord_first > 127:
            return b'\x00' + output
        else:
            return output

    def binaryToLong(s):
        if not s:
            raise ValueError('Empty string passed to strToLong')

        if isinstance(s[0], int):
            ord_first = s[0]
        else:
            ord_first = ord(s[0])
        if ord_first > 127:
            raise ValueError('This function only supports positive integers')

        return bytes_to_long(s)

# A cryptographically safe source of random bytes
try:
    getBytes = os.urandom
except AttributeError:
    try:
        from Crypto.Util.randpool import RandomPool
    except ImportError:
        # Fall back on /dev/urandom, if present. It would be nice to
        # have Windows equivalent here, but for now, require pycrypto
        # on Windows.
        try:
            _urandom = open('/dev/urandom', 'rb')
        except IOError:
            raise ImportError('No adequate source of randomness found!')
        else:
            def getBytes(n):
                bytes = []
                while n:
                    chunk = _urandom.read(n)
                    n -= len(chunk)
                    bytes.append(chunk)
                    assert n >= 0
                return ''.join(bytes)
    else:
        _pool = RandomPool()

        def getBytes(n, pool=_pool):
            if pool.entropy < n:
                pool.randomize()
            return pool.get_bytes(n)

# A randrange function that works for longs
try:
    randrange = random.SystemRandom().randrange
except AttributeError:
    # In Python 2.2's random.Random, randrange does not support
    # numbers larger than sys.maxint for randrange. For simplicity,
    # use this implementation for any Python that does not have
    # random.SystemRandom

    _duplicate_cache = {}

    def randrange(start, stop=None, step=1):
        if stop is None:
            stop = start
            start = 0

        r = (stop - start) // step
        try:
            (duplicate, nbytes) = _duplicate_cache[r]
        except KeyError:
            rbytes = longToBinary(r)
            if rbytes[0] == '\x00':
                nbytes = len(rbytes) - 1
            else:
                nbytes = len(rbytes)

            mxrand = (256 ** nbytes)

            # If we get a number less than this, then it is in the
            # duplicated range.
            duplicate = mxrand % r

            if len(_duplicate_cache) > 10:
                _duplicate_cache.clear()

            _duplicate_cache[r] = (duplicate, nbytes)

        while True:
            bytes = '\x00' + getBytes(nbytes)
            n = binaryToLong(bytes)
            # Keep looping if this value is in the low duplicated range
            if n >= duplicate:
                break

        return start + (n % r) * step


def longToBase64(l):
    return toBase64(longToBinary(l))


def base64ToLong(s):
    return binaryToLong(fromBase64(s))


def const_eq(s1, s2):
    if len(s1) != len(s2):
        return False

    result = True
    for i in range(len(s1)):
        result = result and (s1[i] == s2[i])

    return result
