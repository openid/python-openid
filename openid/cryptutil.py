"""Module containing a cryptographic-quality source of randomness and
other cryptographically useful functionality

Other configurations will need a quality source of random bytes and
access to a function that will convert binary strings to long
integers.
"""
from __future__ import unicode_literals

import codecs
import warnings

from openid.oidutil import fromBase64, toBase64

__all__ = [
    'base64ToLong',
    'binaryToLong',
    'longToBase64',
    'longToBinary',
    'int_to_bytes',
    'bytes_to_int',
]


def bytes_to_int(value):
    """
    Convert byte string to integer.

    @type value: six.binary_type
    @rtype: Union[six.integer_types]
    """
    return int(codecs.encode(value, 'hex'), 16)


def fix_btwoc(value):
    """
    Utility function to ensure the output conforms the `btwoc` function output.

    See http://openid.net/specs/openid-authentication-2_0.html#btwoc for details.

    @type value: bytes or bytearray
    @rtype: bytes
    """
    # Conversion to bytearray is python 2/3 compatible
    array = bytearray(value)
    # First bit must be zero. If it isn't, the bytes must be prepended by zero byte.
    if array[0] > 127:
        array = bytearray([0]) + array
    return bytes(array)


def int_to_bytes(value):
    """
    Convert integer to byte string.

    @type value: Union[six.integer_types]
    @rtype: six.binary_type
    """
    hex_value = '{:x}'.format(value)
    if len(hex_value) % 2:
        hex_value = '0' + hex_value
    array = bytearray.fromhex(hex_value)
    # The output must be `btwoc` compatible
    return fix_btwoc(array)


# Deprecated versions of bytes <--> int conversions
def longToBinary(value):
    warnings.warn("Function longToBinary is deprecated in favor of int_to_bytes.", DeprecationWarning)
    return int_to_bytes(value)


def binaryToLong(s):
    warnings.warn("Function binaryToLong is deprecated in favor of bytes_to_int.", DeprecationWarning)
    return bytes_to_int(s)


def longToBase64(value):
    return toBase64(int_to_bytes(value))


def base64ToLong(s):
    return bytes_to_int(fromBase64(s))
