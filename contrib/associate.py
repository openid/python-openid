#!/usr/bin/env python
"""
Make an OpenID association request against an endpoint and print the results.

Usage: associate.py [options] <endpoint>
       associate.py -h | --help

Options:
  -h, --help                    show this help message and exit
  -a, --assoc-type=ASSOC_TYPE   set custom association type [default: HMAC-SHA256]
  -s, --session-type=SES_TYPE   set custom session type [default: DH-SHA256]
  --generate-modulus            generate another modulus (may take some time)
  --generator=GENERATOR         set custom generator value [default: 2]
  -d, --debug                   print debug information
"""
from __future__ import unicode_literals

import base64
import binascii
import codecs
import logging
import sys

import requests
import six
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.dh import DHParameterNumbers, DHPublicNumbers, generate_parameters
from docopt import docopt

# This script is intentionaly and completely independent on the openid library.
# That should prevent any unwanted changes in association establishing.

DEFAULT_DH_MODULUS = int(
    '155172898181473697471232257763715539915724801966915404479707795314057629378541917580651227423698188993727816152646'
    '631438561595825688188889951272158842675419950341258706556549803580104870537681476726513255747040765857479291291572'
    '334510643245094715007229621094194349783925984760375594985848253359305585439638443'
)
DEFAULT_DH_GENERATOR = 2

OPENID2_NS = 'http://specs.openid.net/auth/2.0'


########################################################################################################################
# Utilities copied from the openid library
def int_to_bytes(value):
    """Convert integer -> bytes."""
    hex_value = '{:x}'.format(value)
    if len(hex_value) % 2:
        hex_value = '0' + hex_value
    array = bytearray.fromhex(hex_value)
    # First bit must be zero. If it isn't, the bytes must be prepended by zero byte.
    # See http://openid.net/specs/openid-authentication-2_0.html#btwoc for details.
    if array[0] > 127:
        array = bytearray([0]) + array
    return six.binary_type(array)


def int_to_base64(number):
    """Convert int -> base64."""
    number_bytes = int_to_bytes(number)
    return binascii.b2a_base64(number_bytes)[:-1].decode('utf-8')


def base64_to_int(value):
    binary_value = binascii.a2b_base64(value)
    return int(codecs.encode(binary_value, 'hex'), 16)


def strxor(x, y):
    if len(x) != len(y):
        raise ValueError('Inputs to strxor must have the same length')

    if six.PY2:
        return b"".join(chr(ord(a) ^ ord(b)) for a, b in zip(x, y))
    else:
        assert six.PY3
        return bytes((a ^ b) for a, b in zip(x, y))


def parse_kv_response(response):
    """Parse the key-value response."""
    decoded_data = {}
    for line in response.iter_lines():
        line = line.strip()
        if not line:
            continue
        pair = line.split(':', 1)
        if not len(pair) == 2:
            logging.warn("Not a key-value line: %s", line)
            continue
        key, value = pair
        decoded_data[key.strip()] = value.strip()
    return decoded_data


########################################################################################################################
# The association code itself

def parse_association_response(response):
    """Parse the association response."""
    association_data = parse_kv_response(response)
    if association_data.get('ns') != OPENID2_NS:
        raise ValueError("Response is not an OpenID 2.0 response")
    for key in ('assoc_type', 'session_type', 'assoc_handle', 'expires_in', 'dh_server_public', 'enc_mac_key'):
        if key not in association_data:
            raise ValueError("Required key {} is not in response.".format(key))
    return association_data


def establish_association(endpoint, assoc_type, session_type, generator, generate_modulus):
    """Actually establish the association."""
    generator = int(generator)
    if generate_modulus:
        parameters = generate_parameters(generator=generator, key_size=2048, backend=default_backend())
        parameter_numbers = parameters.parameter_numbers()
    else:
        parameter_numbers = DHParameterNumbers(DEFAULT_DH_MODULUS, generator)
        parameters = parameter_numbers.parameters(default_backend())
    private_key = parameters.generate_private_key()
    public_key = int_to_base64(private_key.public_key().public_numbers().y)
    logging.debug("Private key: %s", private_key.private_numbers().x)
    logging.debug("Public key: %s", private_key.public_key().public_numbers().y)

    data = {'openid.ns': OPENID2_NS,
            'openid.mode': 'associate',
            'openid.assoc_type': assoc_type,
            'openid.session_type': session_type,
            'openid.dh_consumer_public': public_key}
    if parameter_numbers != DHParameterNumbers(DEFAULT_DH_MODULUS, DEFAULT_DH_GENERATOR):
        data['openid.dh_modulus'] = int_to_base64(parameter_numbers.p)
        data['openid.dh_gen'] = int_to_base64(parameter_numbers.g)
    logging.info("Query arguments: %s", data)
    response = requests.post(endpoint, data=data)

    if response.status_code != 200:
        if response.status_code == 400:
            # Is it an error response?
            error_data = parse_kv_response(response)
            if error_data.get('mode') == 'error':
                # It's an error response
                raise ValueError("Server responded with error: {}".format(error_data.get('error')))
        raise ValueError("Response returned incorrect status code: {}".format(response.status_code))

    association_data = parse_association_response(response)
    logging.debug("Association data: %s", association_data)
    if association_data['assoc_type'] != assoc_type:
        raise ValueError(
            "Unexpected assoc_type returned {}, expected {}".format(association_data['assoc_type'], assoc_type))
    if association_data['session_type'] != session_type:
        raise ValueError(
            "Unexpected session_type returned {}, expected {}".format(association_data['session_type'], session_type))

    server_public_key = base64_to_int(association_data['dh_server_public'])
    shared_secret = private_key.exchange(
        DHPublicNumbers(server_public_key, parameter_numbers).public_key(default_backend()))

    # Not an ordinary DH secret is used here.
    # According to http://openid.net/specs/openid-authentication-2_0.html#rfc.section.8.2.3, the first bit of
    # the DH secret must be zero. If it isn't, the bytes must be prepended by zero byte before they're hashed.
    shared_secret = bytearray(shared_secret)
    if shared_secret[0] > 127:
        shared_secret = bytearray([0]) + shared_secret
    shared_secret = bytes(shared_secret)
    logging.debug("DH shared secret: %s", base64.b64encode(shared_secret))

    algorithm = getattr(hashes, assoc_type[5:])
    digest = hashes.Hash(algorithm(), backend=default_backend())
    digest.update(shared_secret)
    hashed_dh_shared = digest.finalize()

    mac_key = strxor(base64.b64decode(association_data['enc_mac_key']), hashed_dh_shared)

    return {'assoc_type': association_data['assoc_type'],
            'session_type': association_data['session_type'],
            'assoc_handle': association_data['assoc_handle'],
            'expires_in': association_data['expires_in'],
            'mac_key': base64.b64encode(mac_key)}


def main():
    """Main script."""
    options = docopt(__doc__)

    # Set up logging
    if options['--debug']:
        level = logging.DEBUG
    else:
        level = logging.WARNING
    logging.basicConfig(level=level, format='%(asctime)s %(levelname)s:%(funcName)s: %(message)s')

    try:
        association = establish_association(options['<endpoint>'], options['--assoc-type'], options['--session-type'],
                                            options['--generator'], options['--generate-modulus'])
    except ValueError as error:
        sys.stderr.write("Association failed.\n{}\n".format(error))
        sys.exit(1)

    for key, value in association.items():
        sys.stdout.write('{}: {}\n'.format(key, value))


if __name__ == '__main__':
    main()
