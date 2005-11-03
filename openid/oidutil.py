__all__ = ['log', 'appendArgs', 'toBase64', 'fromBase64']

import binascii
import sys

from urllib import urlencode

def log(message, unused_level=0):
    sys.stderr.write(message)
    sys.stderr.write('\n')

def appendArgs(url, args):
    if len(args) == 0:
        return url

    if '?' in url:
        sep = '&'
    else:
        sep = '?'

    return '%s%s%s' % (url, sep, urlencode(args))

def toBase64(s):
    """Represent string s as base64, omitting newlines"""
    return binascii.b2a_base64(s)[:-1]

def fromBase64(s):
    try:
        return binascii.a2b_base64(s)
    except binascii.Error:
        return ''
