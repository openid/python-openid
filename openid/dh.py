""""Utilities for Diffie-Hellman key exchange."""
from __future__ import unicode_literals

import base64
import warnings

import six
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.dh import DHParameterNumbers, DHPublicNumbers

from openid import cryptutil
from openid.constants import DEFAULT_DH_GENERATOR, DEFAULT_DH_MODULUS
from openid.oidutil import toBase64


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

        @type modulus: six.text_type, Union[six.integer_types] are deprecated
        @type generator: six.text_type, Union[six.integer_types] are deprecated
        """
        if isinstance(modulus, six.integer_types):
            warnings.warn("Modulus should be passed as base64 encoded string.")
        else:
            modulus = cryptutil.base64ToLong(modulus)
        if isinstance(generator, six.integer_types):
            warnings.warn("Generator should be passed as base64 encoded string.")
        else:
            generator = cryptutil.base64ToLong(generator)

        self.parameter_numbers = DHParameterNumbers(modulus, generator)
        parameters = self.parameter_numbers.parameters(default_backend())
        self.private_key = parameters.generate_private_key()

    @classmethod
    def fromDefaults(cls):
        """Create Diffie-Hellman with the default modulus and generator."""
        return cls(DEFAULT_DH_MODULUS, DEFAULT_DH_GENERATOR)

    @property
    def modulus(self):
        """Return the prime modulus value.

        @rtype: Union[six.integer_types]
        """
        warnings.warn("Modulus property will return base64 encoded string.", DeprecationWarning)
        return self.parameter_numbers.p

    @property
    def generator(self):
        """Return the generator value.

        @rtype: Union[six.integer_types]
        """
        warnings.warn("Generator property will return base64 encoded string.", DeprecationWarning)
        return self.parameter_numbers.g

    @property
    def parameters(self):
        """Return base64 encoded modulus and generator.

        @return: Tuple with modulus and generator
        @rtype: Tuple[six.text_type, six.text_type]
        """
        modulus = self.parameter_numbers.p
        generator = self.parameter_numbers.g
        return cryptutil.longToBase64(modulus), cryptutil.longToBase64(generator)

    @property
    def public(self):
        """Return the public key.

        @rtype: Union[six.integer_types]
        """
        warnings.warn("Attribute 'public' is deprecated. Use 'public_key' instead.", DeprecationWarning)
        return self.private_key.public_key().public_numbers().y

    @property
    def public_key(self):
        """Return base64 encoded public key.

        @rtype: six.text_type
        """
        return cryptutil.longToBase64(self.private_key.public_key().public_numbers().y)

    def usingDefaultValues(self):
        return self.parameters == (DEFAULT_DH_MODULUS, DEFAULT_DH_GENERATOR)

    def getSharedSecret(self, composite):
        """Return a shared secret.

        @param composite: Public key of the other party.
        @type composite: Union[six.integer_types]
        @rtype: Union[six.integer_types]
        """
        warnings.warn("Method 'getSharedSecret' is deprecated in favor of '_get_shared_secret'.", DeprecationWarning)
        return cryptutil.bytes_to_int(self._get_shared_secret(composite))

    def _get_shared_secret(self, public_key):
        """Return a shared secret.

        @param public_key: Base64 encoded public key of the other party.
        @type public_key: six.text_type
        @rtype: six.binary_type
        """
        public_numbers = DHPublicNumbers(cryptutil.base64ToLong(public_key), self.parameter_numbers)
        return self.private_key.exchange(public_numbers.public_key(default_backend()))

    def xorSecret(self, composite, secret, hash_func):
        warnings.warn("Method 'xorSecret' is deprecated, use 'xor_secret' instead.", DeprecationWarning)
        dh_shared = self._get_shared_secret(cryptutil.longToBase64(composite))

        # The DH secret must be `btwoc` compatible.
        # See http://openid.net/specs/openid-authentication-2_0.html#rfc.section.8.2.3 for details.
        dh_shared = cryptutil.fix_btwoc(dh_shared)

        hashed_dh_shared = hash_func(dh_shared)
        return strxor(secret, hashed_dh_shared)

    def xor_secret(self, public_key, secret, algorithm):
        """Return a base64 encoded XOR of a secret key and hash of a DH exchanged secret.

        @param public_key: Base64 encoded public key of the other party.
        @type public_key: six.text_type
        @param secret: Base64 encoded secret
        @type secret: six.text_type
        @type algorithm: hashes.HashAlgorithm
        @rtype: six.text_type
        """
        dh_shared = self._get_shared_secret(public_key)

        # The DH secret must be `btwoc` compatible.
        # See http://openid.net/specs/openid-authentication-2_0.html#rfc.section.8.2.3 for details.
        dh_shared = cryptutil.fix_btwoc(dh_shared)

        digest = hashes.Hash(algorithm, backend=default_backend())
        digest.update(dh_shared)
        hashed_dh_shared = digest.finalize()
        return toBase64(strxor(base64.b64decode(secret), hashed_dh_shared))
