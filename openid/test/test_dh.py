"""Test `openid.dh` module."""
from __future__ import unicode_literals

import unittest
import warnings

import six
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.dh import DHPrivateNumbers, DHPublicNumbers
from testfixtures import ShouldWarn

from openid.constants import DEFAULT_DH_GENERATOR, DEFAULT_DH_MODULUS
from openid.cryptutil import longToBase64
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
    """Test `DiffieHellman` class."""

    def test_modulus(self):
        dh = DiffieHellman.fromDefaults()
        self.assertEqual(dh.modulus, DEFAULT_DH_MODULUS)

    def test_generator(self):
        dh = DiffieHellman.fromDefaults()
        self.assertEqual(dh.generator, DEFAULT_DH_GENERATOR)

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

    private_key = int(
        '76773183260125655927407219021356850612958916567415386199501281181228346359328609688049646172182310748186340503'
        '26318343789919595649515190982375134969315580266608309203790369036760020471410949003193451675532879428946682852'
        '7087756147962428703119223967577366837042279080006329440425557036807436654929251188437293')
    public_key = int(
        '14830402392262721982219607342625341531794979311088664077137112813385301968870761946911013412944671626402638538'
        '59019114967817783168739766941288204771883652891577627356203670315421489407520844320897873950439171044693921561'
        '24149254347661216215110718681656349527564919668545970743829522251387472714136707262965225')

    def setup_keys(self, dh_object, public_key, private_key):
        """Set up private and public key into DiffieHellman object."""
        public_numbers = DHPublicNumbers(public_key, dh_object.parameter_numbers)
        private_numbers = DHPrivateNumbers(private_key, public_numbers)
        dh_object.private_key = private_numbers.private_key(default_backend())

    def test_public(self):
        dh = DiffieHellman.fromDefaults()
        self.setup_keys(dh, self.public_key, self.private_key)
        warning_msg = "Attribute 'public' is deprecated. Use 'public_key' instead."
        with ShouldWarn(DeprecationWarning(warning_msg)):
            warnings.simplefilter('always')
            self.assertEqual(dh.public, self.server_public_key)

    def test_public_key(self):
        dh = DiffieHellman.fromDefaults()
        self.setup_keys(dh, self.public_key, self.private_key)
        self.assertEqual(dh.public_key, longToBase64(self.public_key))
