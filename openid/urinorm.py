"""URI normalization utilities."""
from __future__ import unicode_literals

import string

import six
from six.moves.urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit, urlunsplit

from .oidutil import string_to_text


def remove_dot_segments(path):
    result_segments = []

    while path:
        if path.startswith('../'):
            path = path[3:]
        elif path.startswith('./'):
            path = path[2:]
        elif path.startswith('/./'):
            path = path[2:]
        elif path == '/.':
            path = '/'
        elif path.startswith('/../'):
            path = path[3:]
            if result_segments:
                result_segments.pop()
        elif path == '/..':
            path = '/'
            if result_segments:
                result_segments.pop()
        elif path == '..' or path == '.':
            path = ''
        else:
            i = 0
            if path[0] == '/':
                i = 1
            i = path.find('/', i)
            if i == -1:
                i = len(path)
            result_segments.append(path[:i])
            path = path[i:]

    return ''.join(result_segments)


GEN_DELIMS = ":" + "/" + "?" + "#" + "[" + "]" + "@"
SUB_DELIMS = "!" + "$" + "&" + "'" + "(" + ")" + "*" + "+" + "," + ";" + "="
RESERVED = GEN_DELIMS + SUB_DELIMS
UNRESERVED = string.ascii_letters + string.digits + "-" + "." + "_" + "~"
# Allow "%" as percent encoding character
PERCENT_ENCODING_CHARACTER = "%"


def _check_disallowed_characters(uri_part, part_name):
    # Roughly check the allowed characters. The check in not strict according to URI ABNF, but good enough.
    # Also allow "%" for percent encoding.
    if set(uri_part).difference(set(UNRESERVED + RESERVED + PERCENT_ENCODING_CHARACTER)):
        raise ValueError('Illegal characters in URI {}: {}'.format(part_name, uri_part))


def urinorm(uri):
    """Return normalized URI.

    Normalization if performed according to RFC 3986, section 6 https://tools.ietf.org/html/rfc3986#section-6.
    Supported URIs are URLs and OpenID realm URIs.

    @type uri: six.text_type, six.binary_type deprecated
    @rtype: six.text_type
    @raise ValueError: If URI is invalid.
    """
    uri = string_to_text(uri, "Binary input for urinorm is deprecated. Use text input instead.")

    split_uri = urlsplit(uri)

    # Normalize scheme
    scheme = split_uri.scheme.lower()
    if scheme not in ('http', 'https'):
        raise ValueError('Not an absolute HTTP or HTTPS URI: {!r}'.format(uri))

    # Normalize netloc
    if not split_uri.netloc:
        raise ValueError('Not an absolute URI: {!r}'.format(uri))

    hostname = split_uri.hostname
    if hostname is None:
        hostname = ''
    else:
        hostname = hostname.lower()
    # Unquote percent encoded characters
    hostname = unquote(hostname)
    # Quote IDN domain names
    try:
        # hostname: str --[idna]--> bytes --[utf-8]--> str
        hostname = hostname.encode('idna').decode('utf-8')
    except ValueError as error:
        raise ValueError('Invalid hostname {!r}: {}'.format(hostname, error))
    _check_disallowed_characters(hostname, 'hostname')

    try:
        port = split_uri.port
    except ValueError as error:
        raise ValueError('Invalid port in {!r}: {}'.format(split_uri.netloc, error))
    if port is None:
        port = ''
    elif (scheme == 'http' and port == 80) or (scheme == 'https' and port == 443):
        port = ''

    netloc = hostname
    if port:
        netloc = netloc + ':' + six.text_type(port)
    userinfo_chunks = [i for i in (split_uri.username, split_uri.password) if i is not None]
    if userinfo_chunks:
        userinfo = ':'.join(userinfo_chunks)
        _check_disallowed_characters(userinfo, 'userinfo')
        netloc = userinfo + '@' + netloc

    # Normalize path
    path = split_uri.path
    # Unquote and quote - this normalizes the percent encoding

    # This is hackish. `unquote` and `quote` requires `str` in both py27 and py3+.
    if isinstance(path, str):
        # Python 3 branch
        path = quote(unquote(path), safe='/' + SUB_DELIMS)
    else:
        # Python 2 branch
        path = quote(unquote(path.encode('utf-8')), safe=('/' + SUB_DELIMS).encode('utf-8')).decode('utf-8')

    path = remove_dot_segments(path)
    if not path:
        path = '/'
    _check_disallowed_characters(path, 'path')

    # Normalize query
    data = parse_qsl(split_uri.query)
    query = urlencode(data)
    _check_disallowed_characters(query, 'query')

    # Normalize fragment
    fragment = unquote(split_uri.fragment)
    _check_disallowed_characters(fragment, 'fragment')

    return urlunsplit((scheme, netloc, path, query, fragment))
