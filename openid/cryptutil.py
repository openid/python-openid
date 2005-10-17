"""Module containing a cryptographic-quality source of randomness.

On Python >= 2.4, just use random.SystemRandom.

Members:

srand - random.Random instance that uses a high-quality source of
        randomness

getBytes - a function that returns a given number of random bytes
"""

__all__ = ['srand', 'getBytes', 'hmacSha1', 'sha1', 'strToLong', 'longToStr',
           'strxor', 'signReply', 'randomString']

import hmac
import os
import random
import sha

from binascii import hexlify

from openid.oidUtil import toBase64, fromBase64, seqToKV

try:
    SystemRandom = random.SystemRandom
except AttributeError:
    from math import log, ceil

    # ByteStreamRandom exists for ease of implementing a good source
    # of randomness for Python versions < 2.4

    # Implementation mostly copied from random.SystemRandom in Python 2.4
    BPF = 53        # Number of bits in a float
    RECIP_BPF = 2**-BPF

    class ByteStreamRandom(random.Random):
        """Generate random numbers based on a random byte stream."""
        def __init__(self, getBytes):
            """Set the source of random bytes.

            Should be a function that takes a number of bytes and returns
            a random string of that length.
            """
            self.getBytes = getBytes

        def _stub(self, *args, **kwds):
            """Stub method.  Not used for a byte stream random number
            generator."""
            return None
        seed = jumpahead = _stub

        def _notimplemented(self, *args, **kwds):
            """Method should not be called for a byte stream random number
            generator."""
            raise NotImplementedError(
                'System entropy source does not have state.')
        getstate = setstate = _notimplemented

        def random(self):
            return (long(hexlify(self.getBytes(7)), 16) >> 3) * RECIP_BPF

        def randrange(self, start, stop, step=None):
            if step is not None:
                self._notimplemented()

            if start != 1:
                self._notimplemented()

            nbytes = int(ceil(log(stop) / log(256)))
            bytes = self.getBytes(nbytes)
            n = binaryToLong(bytes)
            return n - (n % stop)

    # If you are running on Python < 2.4, you can use the random
    # number pool object provided with the Python Cryptography Toolkit
    # (pycrypto). pycrypto can be found with a search engine, but is
    # currently found at:
    #
    # http://www.amk.ca/python/code/crypto
    try:
        from Crypto.Util.randpool import RandomPool
    except ImportError:
        # Fall back on /dev/urandom, if present. It would be nice to
        # have Windows equivalent here, but for now, require pycrypto
        # on Windows.
        try:
            _urandom = file('/dev/urandom', 'rb')
        except OSError:
            raise RuntimeError('No adequate source of randomness found!')
        else:
            def getBytes(n):
                global _urandom
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

    srand = ByteStreamRandom(getBytes)
else:
    srand = SystemRandom()
    getBytes = os.urandom

def hmacSha1(key, text):
    return hmac.new(key, text, sha).digest()

def sha1(s):
    return sha.new(s).digest()

try:
    from Crypto.Util.number import long_to_bytes, bytes_to_long

    def longToBinary(l):
        if l < 0:
            raise ValueError('This function only supports positive integers')

        bytes = long_to_bytes(l)
        if ord(bytes[0]) > 127:
            return '\x00' + bytes
        else:
            return bytes

    def binaryToLong(s):
        if not s:
            raise ValueError('Empty string passed to strToLong')

        if ord(s[0]) > 127:
            raise ValueError('This function only supports positive integers')

        return bytes_to_long(s)

except ImportError:
    import pickle
    try:
        # Check Python compatiblity by raising an exception on import
        # if the needed functionality is not present. Present in
        # Python >= 2.3
        pickle.encode_long
        pickle.decode_long
    except AttributeError:
        raise ImportError(
            'No functionality for serializing long integers found')

    # Present in Python >= 2.4
    try:
        _ = reversed
    except NameError:
        def reversed(seq):
            return map(seq.__getitem__, xrange(len(seq) - 1, -1, -1))
    else:
        del _

    def longToBinary(l):
        if l == 0:
            return '\x00'

        return ''.join(reversed(pickle.encode_long(l)))

    def binaryToLong(s):
        return pickle.decode_long(''.join(reversed(s)))

def longToBase64(l):
    return toBase64(longToBinary(l))

def base64ToLong(s):
    return binaryToLong(fromBase64(s))

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

def randomString(length, chrs=None):
    """Produce a string of length random bytes, chosen from chrs."""
    if chrs is None:
        return getBytes(length)
    else:
        return ''.join([srand.choice(chrs) for _ in xrange(length)])
