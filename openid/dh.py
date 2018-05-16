from __future__ import unicode_literals

import six

from openid import cryptutil
from openid.constants import DEFAULT_DH_GENERATOR, DEFAULT_DH_MODULUS

if six.PY2:
    long_int = long
else:
    assert six.PY3
    long_int = int


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

    @classmethod
    def fromDefaults(cls):
        return cls(DEFAULT_DH_MODULUS, DEFAULT_DH_GENERATOR)

    def __init__(self, modulus, generator):
        self.modulus = long_int(modulus)
        self.generator = long_int(generator)

        self._setPrivate(cryptutil.randrange(1, modulus - 1))

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
