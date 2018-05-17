"""Test `openid.cryptutil` module."""
from __future__ import unicode_literals

import os.path
import random
import sys
import unittest

import six

from openid import cryptutil

# Most of the purpose of this test is to make sure that cryptutil can
# find a good source of randomness on this machine.
if six.PY2:
    long_int = long
else:
    assert six.PY3
    long_int = int


class TestRandRange(unittest.TestCase):
    """Test `randrange` function."""

    def test_cryptrand(self):
        # It's possible, but HIGHLY unlikely that a correct implementation
        # will fail by returning the same number twice

        a = cryptutil.randrange(2 ** 128)
        b = cryptutil.randrange(2 ** 128)
        assert isinstance(a, long_int)
        assert isinstance(b, long_int)
        assert b != a

        # Make sure that we can generate random numbers that are larger
        # than platform int size
        cryptutil.randrange(long_int(sys.maxsize) + 1)


class TestLongBinary(unittest.TestCase):
    """Test `longToBinary` and `binaryToLong` functions."""

    def test_binaryLongConvert(self):
        MAX = sys.maxsize
        for iteration in range(500):
            n = 0
            for i in range(10):
                n += long_int(random.randrange(MAX))

            s = cryptutil.longToBinary(n)
            assert isinstance(s, six.binary_type)
            n_prime = cryptutil.binaryToLong(s)
            assert n == n_prime, (n, n_prime)

        cases = [
            (b'\x00', 0),
            (b'\x01', 1),
            (b'\x7F', 127),
            (b'\x00\xFF', 255),
            (b'\x00\x80', 128),
            (b'\x00\x81', 129),
            (b'\x00\x80\x00', 32768),
            (b'OpenID is cool', 1611215304203901150134421257416556)
        ]

        for s, n in cases:
            n_prime = cryptutil.binaryToLong(s)
            s_prime = cryptutil.longToBinary(n)
            assert n == n_prime, (s, n, n_prime)
            assert s == s_prime, (n, s, s_prime)


class TestLongToBase64(unittest.TestCase):
    """Test `longToBase64` function."""

    def test_longToBase64(self):
        f = open(os.path.join(os.path.dirname(__file__), 'n2b64'))
        try:
            for line in f:
                parts = line.strip().split(' ')
                assert parts[0] == cryptutil.longToBase64(long_int(parts[1]))
        finally:
            f.close()


class TestBase64ToLong(unittest.TestCase):
    """Test `Base64ToLong` function."""

    def test_base64ToLong(self):
        f = open(os.path.join(os.path.dirname(__file__), 'n2b64'))
        try:
            for line in f:
                parts = line.strip().split(' ')
                assert long_int(parts[1]) == cryptutil.base64ToLong(parts[0])
        finally:
            f.close()
