"""Test `openid.cryptutil` module."""
import os.path
import random
import sys
import unittest

from openid import cryptutil

# Most of the purpose of this test is to make sure that cryptutil can
# find a good source of randomness on this machine.


class TestRandRange(unittest.TestCase):
    """Test `randrange` function."""

    def test_cryptrand(self):
        # It's possible, but HIGHLY unlikely that a correct implementation
        # will fail by returning the same number twice

        s = cryptutil.getBytes(32)
        t = cryptutil.getBytes(32)
        assert len(s) == 32
        assert len(t) == 32
        assert s != t

        a = cryptutil.randrange(2 ** 128)
        b = cryptutil.randrange(2 ** 128)
        assert isinstance(a, long)
        assert isinstance(b, long)
        assert b != a

        # Make sure that we can generate random numbers that are larger
        # than platform int size
        cryptutil.randrange(long(sys.maxsize) + 1)


class TestLongBinary(unittest.TestCase):
    """Test `longToBinary` and `binaryToLong` functions."""

    def test_binaryLongConvert(self):
        MAX = sys.maxsize
        for iteration in xrange(500):
            n = 0
            for i in range(10):
                n += long(random.randrange(MAX))

            s = cryptutil.longToBinary(n)
            assert isinstance(s, str)
            n_prime = cryptutil.binaryToLong(s)
            assert n == n_prime, (n, n_prime)

        cases = [
            ('\x00', 0),
            ('\x01', 1),
            ('\x7F', 127),
            ('\x00\xFF', 255),
            ('\x00\x80', 128),
            ('\x00\x81', 129),
            ('\x00\x80\x00', 32768),
            ('OpenID is cool', 1611215304203901150134421257416556)
        ]

        for s, n in cases:
            n_prime = cryptutil.binaryToLong(s)
            s_prime = cryptutil.longToBinary(n)
            assert n == n_prime, (s, n, n_prime)
            assert s == s_prime, (n, s, s_prime)


class TestLongToBase64(unittest.TestCase):
    """Test `longToBase64` function."""

    def test_longToBase64(self):
        f = file(os.path.join(os.path.dirname(__file__), 'n2b64'))
        try:
            for line in f:
                parts = line.strip().split(' ')
                assert parts[0] == cryptutil.longToBase64(long(parts[1]))
        finally:
            f.close()


class TestBase64ToLong(unittest.TestCase):
    """Test `Base64ToLong` function."""

    def test_base64ToLong(self):
        f = file(os.path.join(os.path.dirname(__file__), 'n2b64'))
        try:
            for line in f:
                parts = line.strip().split(' ')
                assert long(parts[1]) == cryptutil.base64ToLong(parts[0])
        finally:
            f.close()
