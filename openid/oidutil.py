__all__ = ['log', 'appendArgs', 'toBase64', 'fromBase64']

import binascii
import sys
import urlparse

from urllib import urlencode

elementtree_modules = [
    'lxml.etree',
    'xml.etree.cElementTree',
    'xml.etree.ElementTree',
    'cElementTree',
    'elementtree.ElementTree',
    ]

def importElementTree():
    for mod_name in elementtree_modules:
        try:
            return __import__(mod_name, None, None, ['unused'])
        except ImportError:
            pass
    else:
        raise

def log(message, unused_level=0):
    sys.stderr.write(message)
    sys.stderr.write('\n')

def appendArgs(url, args):
    if hasattr(args, 'items'):
        args = args.items()
        args.sort()
    else:
        args = list(args)

    if len(args) == 0:
        return url

    if '?' in url:
        sep = '&'
    else:
        sep = '?'

    # Map unicode to UTF-8 if present. Do not make any assumptions
    # about the encodings of plain bytes (str).
    i = 0
    for k, v in args:
        if type(k) is not str:
            k = k.encode('UTF-8')

        if type(v) is not str:
            v = v.encode('UTF-8')

        args[i] = (k, v)
        i += 1

    return '%s%s%s' % (url, sep, urlencode(args))

def toBase64(s):
    """Represent string s as base64, omitting newlines"""
    return binascii.b2a_base64(s)[:-1]

def fromBase64(s):
    try:
        return binascii.a2b_base64(s)
    except binascii.Error, why:
        # Convert to a common exception type
        raise ValueError(why[0])

def isAbsoluteHTTPURL(url):
    """Does this URL look like a http or https URL that has a host?

    @param url: The url to check
    @type url: str

    @return: Whether the URL looks OK
    @rtype: bool
    """
    parts = urlparse.urlparse(url)
    return parts[0] in ['http', 'https'] and parts[1]

class Symbol(object):
    """This class implements an object that compares equal to others
    of the same type that have the same name. These are distict from
    str or unicode objects.
    """

    def __init__(self, name):
        self.name = name

    def __eq__(self, other):
        return type(self) is type(other) and self.name == other.name

    def __ne__(self, other):
        return not (self == other)

    def __hash__(self):
        return hash((self.__class__, self.name))
   
    def __repr__(self):
        return '<Symbol %s>' % (self.name,)
