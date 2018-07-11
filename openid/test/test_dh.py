"""Test `openid.dh` module."""
from __future__ import unicode_literals

import base64
import os
import unittest
import warnings

import six
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.dh import DHPrivateNumbers, DHPublicNumbers
from testfixtures import ShouldWarn

from openid.constants import DEFAULT_DH_GENERATOR, DEFAULT_DH_MODULUS
from openid.cryptutil import base64ToLong
from openid.dh import DiffieHellman, strxor
from openid.oidutil import toBase64


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

    def test_init(self):
        dh = DiffieHellman(DEFAULT_DH_MODULUS, DEFAULT_DH_GENERATOR)
        self.assertTrue(dh.usingDefaultValues())

    def test_init_int(self):
        dh = DiffieHellman(base64ToLong(DEFAULT_DH_MODULUS), base64ToLong(DEFAULT_DH_GENERATOR))
        self.assertTrue(dh.usingDefaultValues())

    def test_modulus(self):
        dh = DiffieHellman.fromDefaults()
        modulus = int('155172898181473697471232257763715539915724801966915404479707795314057629378541917580651227423698'
                      '188993727816152646631438561595825688188889951272158842675419950341258706556549803580104870537681'
                      '476726513255747040765857479291291572334510643245094715007229621094194349783925984760375594985848'
                      '253359305585439638443')
        warning_msg = "Modulus property will return base64 encoded string."
        with ShouldWarn(DeprecationWarning(warning_msg)):
            warnings.simplefilter('always')
            self.assertEqual(dh.modulus, modulus)

    def test_generator(self):
        dh = DiffieHellman.fromDefaults()
        warning_msg = "Generator property will return base64 encoded string."
        with ShouldWarn(DeprecationWarning(warning_msg)):
            warnings.simplefilter('always')
            self.assertEqual(dh.generator, 2)

    def test_parameters(self):
        dh = DiffieHellman.fromDefaults()
        self.assertEqual(dh.parameters, (DEFAULT_DH_MODULUS, DEFAULT_DH_GENERATOR))

    consumer_private_key = ('bVQh4Z81F5e57JCT1pmxADRktpYwIwhNjWkiIjg450sfYZOJ9Ntf4YHBhcBpkPyehdq/XL+yEWbZFig4wh2MdqES0X'
                            'aOPRVl7ZzsjTNgztKUYE2mhiYQd4KMmB9uLExM72ntwcdZ3/vlb0Fq8DlIx3FhqeaYsKKTsdUW/KbJcS0=')
    consumer_public_key = ('ANMxIwAeRWw5mZD3+DkoX3G6n/tuBGsjfk6R+vBW2zwve0BSlh1F0EsXlQEUuXJ+s1DQ8nFQLPYOLO0mLexXH0bSscv'
                           'zhBldH+L+fxJfoL9xoTAxk7qqT659QqErhEMtQpBy7hK5L7Qb8R2NAUZ++MPxUNB71IBd6vMG6M6MueXp')
    server_private_key = ('ANxFaZXkCVNESkYKFclilsm7tVIO1CNYy621Y44w19OPk7xE7zEZdttX/KfRSImecPpn+AATLhRZMuXzaq3KDFFTu9Nu'
                          'hSINYml2f7xZd1+lYg6YhWiojfP3YPqLIV9sj/26O1A7pTcq6jajj/8E5P+qkr6+bSQhZ0UlZiBQUyDr')
    server_public_key = ('MSJTx7cMqUBAcpLCan75t+8OSf3SZUSwivlEUYxMaHbbueKp1u4/7Fdw9sTCN3gA0iFE2dTOJpRUT4TmFomHnyIfBExdc'
                         'wbkXiQIhsSnBJkGmPuAPkKFFHtB0pKET6bWZolwP5fp4lZOgM+7FIRte5OZd5XEJIN9vBYxo6NaoRc=')
    shared_secret = ('FHWhX2v2g/twI8mO1HFiI9zgRP6/CBbJ0+13cgpDJvIUypDNcqLHlkGJtjaOJ1ciX+qk2Jf3Zdt5YJDgilVH+Xg7x7WaHXVxX'
                     'Yxu5RTwEuPyFUjO62XT6u11qJ35PvveTDwwAsv6+OspK8FRbqMKIgNuEkmaFDVwr4dKyhZUtNg=')
    secret = toBase64(b'Rimmer ordered hot gazpacho soup')
    mac_key = 'hAYpHzbPvEHs0J2t8KYiqoxsLSmRzGfCQmwMg9taNf0='

    def setup_keys(self, dh_object, public_key, private_key):
        """Set up private and public key into DiffieHellman object."""
        public_numbers = DHPublicNumbers(base64ToLong(public_key), dh_object.parameter_numbers)
        private_numbers = DHPrivateNumbers(base64ToLong(private_key), public_numbers)
        dh_object.private_key = private_numbers.private_key(default_backend())

    def test_public(self):
        dh = DiffieHellman.fromDefaults()
        self.setup_keys(dh, self.server_public_key, self.server_private_key)
        warning_msg = "Attribute 'public' is deprecated. Use 'public_key' instead."
        with ShouldWarn(DeprecationWarning(warning_msg)):
            warnings.simplefilter('always')
            self.assertEqual(dh.public, base64ToLong(self.server_public_key))

    def test_public_key(self):
        dh = DiffieHellman.fromDefaults()
        self.setup_keys(dh, self.server_public_key, self.server_private_key)
        self.assertEqual(dh.public_key, self.server_public_key)

    def test_get_shared_secret_server(self):
        server_dh = DiffieHellman.fromDefaults()
        self.setup_keys(server_dh, self.server_public_key, self.server_private_key)
        self.assertEqual(server_dh.get_shared_secret(self.consumer_public_key), base64.b64decode(self.shared_secret))

    def test_get_shared_secret_consumer(self):
        consumer_dh = DiffieHellman.fromDefaults()
        self.setup_keys(consumer_dh, self.consumer_public_key, self.consumer_private_key)
        self.assertEqual(consumer_dh.get_shared_secret(self.server_public_key), base64.b64decode(self.shared_secret))

    def test_getSharedSecret(self):
        # Test the deprecated method
        consumer_dh = DiffieHellman.fromDefaults()
        self.setup_keys(consumer_dh, self.consumer_public_key, self.consumer_private_key)
        warning_msg = "Method 'getSharedSecret' is deprecated in favor of 'get_shared_secret'."
        with ShouldWarn(DeprecationWarning(warning_msg)):
            warnings.simplefilter('always')
            self.assertEqual(consumer_dh.getSharedSecret(self.server_public_key), base64ToLong(self.shared_secret))

    def test_xorSecret(self):
        # Test key exchange - deprecated method
        server_dh = DiffieHellman.fromDefaults()
        self.setup_keys(server_dh, self.server_public_key, self.server_private_key)

        def sha256(value):
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(value)
            return digest.finalize()

        warning_msg = "Method 'xorSecret' is deprecated, use 'xor_secret' instead."
        with ShouldWarn(DeprecationWarning(warning_msg)):
            warnings.simplefilter('always')
            secret = server_dh.xorSecret(base64ToLong(self.consumer_public_key), base64.b64decode(self.secret), sha256)
            self.assertEqual(secret, base64.b64decode(self.mac_key))

    def test_exchange_server_static(self):
        # Test key exchange - server part with static values
        server_dh = DiffieHellman.fromDefaults()
        self.setup_keys(server_dh, self.server_public_key, self.server_private_key)

        self.assertEqual(server_dh.xor_secret(self.consumer_public_key, self.secret, hashes.SHA256()), self.mac_key)
        self.assertEqual(server_dh.public_key, self.server_public_key)

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
        secret = toBase64(os.urandom(32))
        server_dh = DiffieHellman.fromDefaults()
        mac_key = server_dh.xor_secret(consumer_public_key, secret, hashes.SHA256())
        server_public_key = server_dh.public_key
        # Consumer part
        shared_secret = consumer_dh.xor_secret(server_public_key, mac_key, hashes.SHA256())
        # Check secret was negotiated correctly
        self.assertEqual(secret, shared_secret)
