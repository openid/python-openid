__all__ = ['log', 'appendArgs', 'toBase64', 'fromBase64', 'normalizeUrl']

import binascii
import sys
import urlparse

from urllib import urlencode

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

def quoteMinimal(s):
    """Turn a str or unicode object into an ASCII string

    Replace non-ascii characters with a %-encoded, UTF-8
    encoding. This function will fail if the input is a str and there
    are non-7-bit-safe characters. It is assumed that the caller will
    have already translated the input into a Unicode character
    sequence, according to the encoding of the HTTP POST or GET.

    Do not escape anything that is already 7-bit safe, so we do the
    minimal transform on the input
    """
    res = []
    for c in s:
        if c >= u'\x80':
            for b in c.encode('utf8'):
                res.append('%%%02X' % ord(b))
        else:
            res.append(c)
    return str(''.join(res))

def normalizeUrl(url):
    if not isinstance(url, (str, unicode)):
        return None

    url = url.strip()
    parsed = urlparse.urlparse(url)

    if parsed[0] == '' or parsed[1] == '':
        if parsed[2:] == ('', '', '', ''):
            return None

        url = 'http://' + url
        parsed = urlparse.urlparse(url)

    if isinstance(url, unicode):
        try:
            authority = parsed[1].encode('idna')
        except LookupError:
            authority = parsed[1].encode('us-ascii')
    else:
        authority = str(parsed[1])

    tail = map(quoteMinimal, parsed[2:])
    if tail[0] == '':
        tail[0] = '/'
    encoded = (str(parsed[0]), authority) + tuple(tail)
    url = urlparse.urlunparse(encoded)
    assert type(url) is str

    return url

def isAbsoluteHTTPURL(url):
    """Does this URL look like a http or https URL that has a host?

    @param url: The url to check
    @type url: str

    @return: Whether the URL looks OK
    @rtype: bool
    """
    parts = urlparse.urlparse(url)
    return parts[0] in ['http', 'https'] and parts[1]
