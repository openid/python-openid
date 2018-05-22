""""Utilities for Diffie-Hellman key exchange."""
from __future__ import unicode_literals

import six
from cryptography.hazmat.primitives.asymmetric.dh import DHParameterNumbers

from openid import cryptutil
from openid.constants import DEFAULT_DH_GENERATOR, DEFAULT_DH_MODULUS


def _xor(a_b):
    # Python 2 only
    a, b = a_b
    return chr(ord(a) ^ ord(b))


def strxor(x, y):
    if len(x) != len(y):
        raise ValueError('Inputs to strxor must have the same length')

    if six.PY2:
        return b"".join(_xor((a, b)) for a, b in zip(x, y))
    else:
        assert six.PY3
        return bytes((a ^ b) for a, b in zip(x, y))


class DiffieHellman(object):
    """Utility for Diffie-Hellman key exchange."""

    def __init__(self, modulus, generator):
        """Create a new instance.

        @type modulus: Union[six.integer_types]
        @type generator: Union[six.integer_types]
        """
        self.parameter_numbers = DHParameterNumbers(modulus, generator)
        self._setPrivate(cryptutil.randrange(1, modulus - 1))

    @classmethod
    def fromDefaults(cls):
        """Create Diffie-Hellman with the default modulus and generator."""
        return cls(DEFAULT_DH_MODULUS, DEFAULT_DH_GENERATOR)

    @property
    def modulus(self):
        """Return the prime modulus value.

        @rtype: Union[six.integer_types]
        """
        return self.parameter_numbers.p

    @property
    def generator(self):
        """Return the generator value.

        @rtype: Union[six.integer_types]
        """
        return self.parameter_numbers.g

    def _setPrivate(self, private):
        """This is here to make testing easier"""
        self.private = private
        self.public = pow(self.generator, self.private, self.modulus)

    def usingDefaultValues(self):
        return (self.modulus == DEFAULT_DH_MODULUS and
                self.generator == DEFAULT_DH_GENERATOR)

    def getSharedSecret(self, composite):
        return pow(composite, self.private, self.modulus)

    def xorSecret(self, composite, secret, hash_func):
        dh_shared = self.getSharedSecret(composite)
        hashed_dh_shared = hash_func(cryptutil.int_to_bytes(dh_shared))
        return strxor(secret, hashed_dh_shared)
