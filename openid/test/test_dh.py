"""Test `openid.dh` module."""
from __future__ import unicode_literals

import os.path
import unittest

import six

from openid.dh import DiffieHellman, strxor


class TestStrXor(unittest.TestCase):
    """Test `strxor` function."""

    def test_strxor(self):
        NUL = b'\x00'

        cases = [
            (NUL, NUL, NUL),
            (b'\x01', NUL, b'\x01'),
            (b'a', b'a', NUL),
            (b'a', NUL, b'a'),
            (b'abc', NUL * 3, b'abc'),
            (b'x' * 10, NUL * 10, b'x' * 10),
            (b'\x01', b'\x02', b'\x03'),
            (b'\xf0', b'\x0f', b'\xff'),
            (b'\xff', b'\x0f', b'\xf0'),
        ]

        for aa, bb, expected in cases:
            actual = strxor(aa, bb)
            assert actual == expected, (aa, bb, expected, actual)

        exc_cases = [
            (b'', b'a'),
            (b'foo', b'ba'),
            (NUL * 3, NUL * 4),
        ]
        if six.PY2:
            exc_cases.append((b''.join(chr(i) for i in range(256)), b''.join(chr(i) for i in range(128))))
        else:
            assert six.PY3
            exc_cases.append((bytes(i for i in range(256)), bytes(i for i in range(128))))

        for aa, bb in exc_cases:
            try:
                unexpected = strxor(aa, bb)
            except ValueError:
                pass
            else:
                assert False, 'Expected ValueError, got %r' % (unexpected,)


class TestDiffieHellman(unittest.TestCase):

    def _test_dh(self):
        dh1 = DiffieHellman.fromDefaults()
        dh2 = DiffieHellman.fromDefaults()
        secret1 = dh1.getSharedSecret(dh2.public)
        secret2 = dh2.getSharedSecret(dh1.public)
        assert secret1 == secret2
        return secret1

    def test_exchange(self):
        s1 = self._test_dh()
        s2 = self._test_dh()
        assert s1 != s2

    def test_public(self):
        f = open(os.path.join(os.path.dirname(__file__), 'dhpriv'))
        dh = DiffieHellman.fromDefaults()
        try:
            for line in f:
                parts = line.strip().split(' ')
                dh._setPrivate(long(parts[0]))

                assert dh.public == long(parts[1])
        finally:
            f.close()
