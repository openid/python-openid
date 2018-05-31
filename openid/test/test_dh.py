"""Test `openid.dh` module."""
from __future__ import unicode_literals

import os
import unittest
import warnings

import six
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.dh import DHPrivateNumbers, DHPublicNumbers
from testfixtures import ShouldWarn

from openid.constants import DEFAULT_DH_GENERATOR, DEFAULT_DH_MODULUS
from openid.cryptutil import base64ToLong, bytes_to_int, longToBase64, sha256
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

    consumer_private_key = int(
        '76773183260125655927407219021356850612958916567415386199501281181228346359328609688049646172182310748186340503'
        '26318343789919595649515190982375134969315580266608309203790369036760020471410949003193451675532879428946682852'
        '7087756147962428703119223967577366837042279080006329440425557036807436654929251188437293')
    consumer_public_key = int(
        '14830402392262721982219607342625341531794979311088664077137112813385301968870761946911013412944671626402638538'
        '59019114967817783168739766941288204771883652891577627356203670315421489407520844320897873950439171044693921561'
        '24149254347661216215110718681656349527564919668545970743829522251387472714136707262965225')
    server_private_key = int(
        '15467965641543992347841556205070390914637305348154825847599734515099514013537846015402306363308433241908283446'
        '71248072297246966864402013185397179020027880855596392908146308184428215791914057102026401324081917190180806065'
        '52997123133752764540011560986670942115061415865499463644558159755273696690932941082271979')
    server_public_key = int(
        '34503131980021108262326730163610830553875615642061454929962013481368582594793479022634253261703143188115239697'
        '31865012494779720501092100433895935952054678007893102647432613158698447525023861310539814658911402112680185359'
        '5512256481326572078983201034675082346312609787920346766733771767752145619255920370032919'
    )
    shared_secret = (
        b'\x14u\xa1_k\xf6\x83\xfbp#\xc9\x8e\xd4qb#\xdc\xe0D\xfe\xbf\x08\x16\xc9\xd3\xedwr\nC&\xf2\x14\xca\x90\xcdr\xa2'
        b'\xc7\x96A\x89\xb66\x8e\'W"_\xea\xa4\xd8\x97\xf7e\xdby`\x90\xe0\x8aUG\xf9x;\xc7\xb5\x9a\x1duq]\x8cn\xe5\x14'
        b'\xf0\x12\xe3\xf2\x15H\xce\xebe\xd3\xea\xedu\xa8\x9d\xf9>\xfb\xdeL<0\x02\xcb\xfa\xf8\xeb)+\xc1Qn\xa3\n"\x03n'
        b'\x12I\x9a\x145p\xaf\x87J\xca\x16T\xb4\xd8')
    secret = b'Rimmer ordered hot gazpacho soup'
    mac_key = b'\x84\x06)\x1f6\xcf\xbcA\xec\xd0\x9d\xad\xf0\xa6"\xaa\x8cl-)\x91\xccg\xc2Bl\x0c\x83\xdbZ5\xfd'

    def setup_keys(self, dh_object, public_key, private_key):
        """Set up private and public key into DiffieHellman object."""
        public_numbers = DHPublicNumbers(public_key, dh_object.parameter_numbers)
        private_numbers = DHPrivateNumbers(private_key, public_numbers)
        dh_object.private_key = private_numbers.private_key(default_backend())

    def test_public(self):
        dh = DiffieHellman.fromDefaults()
        self.setup_keys(dh, self.server_public_key, self.server_private_key)
        warning_msg = "Attribute 'public' is deprecated. Use 'public_key' instead."
        with ShouldWarn(DeprecationWarning(warning_msg)):
            warnings.simplefilter('always')
            self.assertEqual(dh.public, self.server_public_key)

    def test_public_key(self):
        dh = DiffieHellman.fromDefaults()
        self.setup_keys(dh, self.server_public_key, self.server_private_key)
        self.assertEqual(dh.public_key, longToBase64(self.server_public_key))

    def test_get_shared_secret_server(self):
        server_dh = DiffieHellman.fromDefaults()
        self.setup_keys(server_dh, self.server_public_key, self.server_private_key)
        self.assertEqual(server_dh.get_shared_secret(self.consumer_public_key), self.shared_secret)

    def test_get_shared_secret_consumer(self):
        consumer_dh = DiffieHellman.fromDefaults()
        self.setup_keys(consumer_dh, self.consumer_public_key, self.consumer_private_key)
        self.assertEqual(consumer_dh.get_shared_secret(self.server_public_key), self.shared_secret)

    def test_getSharedSecret(self):
        # Test the deprecated method
        consumer_dh = DiffieHellman.fromDefaults()
        self.setup_keys(consumer_dh, self.consumer_public_key, self.consumer_private_key)
        warning_msg = "Method 'getSharedSecret' is deprecated in favor of 'get_shared_secret'."
        with ShouldWarn(DeprecationWarning(warning_msg)):
            warnings.simplefilter('always')
            self.assertEqual(consumer_dh.getSharedSecret(self.server_public_key), bytes_to_int(self.shared_secret))

    def test_xorSecret(self):
        # Test key exchange - deprecated method
        server_dh = DiffieHellman.fromDefaults()
        self.setup_keys(server_dh, self.server_public_key, self.server_private_key)

        warning_msg = "Method 'xorSecret' is deprecated, use 'xor_secret' instead."
        with ShouldWarn(DeprecationWarning(warning_msg)):
            warnings.simplefilter('always')
            self.assertEqual(server_dh.xorSecret(self.consumer_public_key, self.secret, sha256), self.mac_key)

    def test_exchange_server_static(self):
        # Test key exchange - server part with static values
        server_dh = DiffieHellman.fromDefaults()
        self.setup_keys(server_dh, self.server_public_key, self.server_private_key)

        self.assertEqual(server_dh.xor_secret(self.consumer_public_key, self.secret, hashes.SHA256()), self.mac_key)
        self.assertEqual(server_dh.public_key, longToBase64(self.server_public_key))

    def test_exchange_consumer_static(self):
        # Test key exchange - consumer part with static values
        consumer_dh = DiffieHellman.fromDefaults()
        self.setup_keys(consumer_dh, self.consumer_public_key, self.consumer_private_key)

        shared_secret = consumer_dh.xor_secret(self.server_public_key, self.mac_key, hashes.SHA256())
        # Check secret was negotiated correctly
        self.assertEqual(shared_secret, self.secret)

    def test_exchange_dynamic(self):
        # Test complete key exchange with random values
        # Consumer part
        consumer_dh = DiffieHellman.fromDefaults()
        consumer_public_key = consumer_dh.public_key
        # Server part
        secret = os.urandom(32)
        server_dh = DiffieHellman.fromDefaults()
        mac_key = server_dh.xor_secret(base64ToLong(consumer_public_key), secret, hashes.SHA256())
        server_public_key = server_dh.public_key
        # Consumer part
        shared_secret = consumer_dh.xor_secret(base64ToLong(server_public_key), mac_key, hashes.SHA256())
        # Check secret was negotiated correctly
        self.assertEqual(secret, shared_secret)
