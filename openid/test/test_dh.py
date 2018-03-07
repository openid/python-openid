"""Test `openid.dh` module."""
import os.path
import unittest

from openid.dh import DiffieHellman, strxor


class TestStrXor(unittest.TestCase):
    """Test `strxor` function."""

    def test_strxor(self):
        NUL = '\x00'

        cases = [
            (NUL, NUL, NUL),
            ('\x01', NUL, '\x01'),
            ('a', 'a', NUL),
            ('a', NUL, 'a'),
            ('abc', NUL * 3, 'abc'),
            ('x' * 10, NUL * 10, 'x' * 10),
            ('\x01', '\x02', '\x03'),
            ('\xf0', '\x0f', '\xff'),
            ('\xff', '\x0f', '\xf0'),
        ]

        for aa, bb, expected in cases:
            actual = strxor(aa, bb)
            assert actual == expected, (aa, bb, expected, actual)

        exc_cases = [
            ('', 'a'),
            ('foo', 'ba'),
            (NUL * 3, NUL * 4),
            (''.join(chr(i) for i in range(256)),
             ''.join(chr(i) for i in range(128))),
        ]

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
        f = file(os.path.join(os.path.dirname(__file__), 'dhpriv'))
        dh = DiffieHellman.fromDefaults()
        try:
            for line in f:
                parts = line.strip().split(' ')
                dh._setPrivate(long(parts[0]))

                assert dh.public == long(parts[1])
        finally:
            f.close()
