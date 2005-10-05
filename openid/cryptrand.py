"""Module containing a cryptographic-quality source of randomness.

On Python >= 2.4, just use random.SystemRandom.

Members:

srand - random.Random instance that uses a high-quality source of
        randomness

getBytes - a function that returns a given number of random bytes
"""
__all__ = ['srand', 'getBytes']
import os
import random
from binascii import hexlify

# ByteStreamRandom exists for ease of implementing a good source of
# randomness for Python versions < 2.4

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

try:
    srand = random.SystemRandom()
    getBytes = os.urandom
except AttributeError:
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
