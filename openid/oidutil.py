__all__ = ['log', 'appendArgs', 'toBase64', 'fromBase64']

import binascii
import sys
import urlparse

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


def getOpenIDParameters(query):
    params = {}
    for k, v in query.iteritems():
        if k.startswith('openid.'):
            params[k] = v
    return params


def quoteMinimal(s):
    # Do not escape anything that is already 7-bit safe, so we do the
    # minimal transform on the identity URL
    res = []
    for c in s:
        if c >= u'\x80':
            for b in c.encode('utf8'):
                res.append('%%%02X' % ord(b))
        else:
            res.append(c)
    return str(''.join(res))


def normalizeUrl(url):
    assert isinstance(url, (str, unicode)), type(url)

    url = url.strip()
    parsed = urlparse.urlparse(url)

    if parsed[0] == '' or parsed[1] == '':
        url = 'http://' + url
        parsed = urlparse.urlparse(url)

    if isinstance(url, unicode):
        authority = parsed[1].encode('idna')
    else:
        authority = str(parsed[1])

    tail = map(quoteMinimal, parsed[2:])
    if tail[0] == '':
        tail[0] = '/'
    encoded = (str(parsed[0]), authority) + tuple(tail)
    url = urlparse.urlunparse(encoded)
    assert type(url) is str

    return url

