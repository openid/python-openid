"""This module contains the HTTP fetcher interface and several implementations."""
from __future__ import unicode_literals

import sys
import time

import six
from six import BytesIO
from six.moves.urllib.error import HTTPError as UrllibHTTPError
from six.moves.urllib.request import Request, urlopen

import openid
import openid.urinorm

__all__ = ['fetch', 'getDefaultFetcher', 'setDefaultFetcher', 'HTTPResponse',
           'HTTPFetcher', 'createHTTPFetcher', 'HTTPFetchingError',
           'HTTPError']

# Try to import httplib2 for caching support
# http://bitworking.org/projects/httplib2/
try:
    import httplib2
except ImportError:
    # httplib2 not available
    httplib2 = None

# try to import pycurl, which will let us use CurlHTTPFetcher
try:
    import pycurl
except ImportError:
    pycurl = None

# try to import requests
try:
    import requests
except ImportError:
    requests = None

USER_AGENT = "python-openid/%s (%s)" % (openid.__version__, sys.platform)
MAX_RESPONSE_KB = 1024


def fetch(url, body=None, headers=None):
    """Invoke the fetch method on the default fetcher. Most users
    should need only this method.

    @raises Exception: any exceptions that may be raised by the default fetcher
    """
    fetcher = getDefaultFetcher()
    return fetcher.fetch(url, body, headers)


def createHTTPFetcher():
    """Create a default HTTP fetcher instance

    Preferences:
     1. requests
     2. curl
     3. httplib2
     4. urllib
    """
    if requests is not None:
        fetcher = RequestsFetcher()
    elif pycurl is not None:
        fetcher = CurlHTTPFetcher()
    elif httplib2 is not None:
        fetcher = HTTPLib2Fetcher()
    else:
        fetcher = Urllib2Fetcher()

    return fetcher


# Contains the currently set HTTP fetcher. If it is set to None, the
# library will call createHTTPFetcher() to set it. Do not access this
# variable outside of this module.
_default_fetcher = None


def getDefaultFetcher():
    """Return the default fetcher instance
    if no fetcher has been set, it will create a default fetcher.

    @return: the default fetcher
    @rtype: HTTPFetcher
    """
    global _default_fetcher

    if _default_fetcher is None:
        setDefaultFetcher(createHTTPFetcher())

    return _default_fetcher


def setDefaultFetcher(fetcher, wrap_exceptions=True):
    """Set the default fetcher

    @param fetcher: The fetcher to use as the default HTTP fetcher
    @type fetcher: HTTPFetcher

    @param wrap_exceptions: Whether to wrap exceptions thrown by the
        fetcher wil HTTPFetchingError so that they may be caught
        easier. By default, exceptions will be wrapped. In general,
        unwrapped fetchers are useful for debugging of fetching errors
        or if your fetcher raises well-known exceptions that you would
        like to catch.
    @type wrap_exceptions: bool
    """
    global _default_fetcher
    if fetcher is None or not wrap_exceptions:
        _default_fetcher = fetcher
    else:
        _default_fetcher = ExceptionWrappingFetcher(fetcher)


def usingCurl():
    """Whether the currently set HTTP fetcher is a Curl HTTP fetcher."""
    fetcher = getDefaultFetcher()
    if isinstance(fetcher, ExceptionWrappingFetcher):
        fetcher = fetcher.fetcher
    return isinstance(fetcher, CurlHTTPFetcher)


class HTTPResponse(object):
    """XXX document attributes

    @type body: six.binary_type
    """
    headers = None
    status = None
    body = None
    final_url = None

    def __init__(self, final_url=None, status=None, headers=None, body=None):
        self.final_url = final_url
        self.status = status
        self.headers = headers
        self.body = body

    def __repr__(self):
        return "<%s status %s for %s>" % (self.__class__.__name__,
                                          self.status,
                                          self.final_url)


class HTTPFetcher(object):
    """
    This class is the interface for openid HTTP fetchers.  This
    interface is only important if you need to write a new fetcher for
    some reason.
    """

    def fetch(self, url, body=None, headers=None):
        """
        This performs an HTTP POST or GET, following redirects along
        the way. If a body is specified, then the request will be a
        POST. Otherwise, it will be a GET.

        @type body: six.binary_type

        @param headers: HTTP headers to include with the request
        @type headers: Dict[six.text_type, six.text_type]

        @return: An object representing the server's HTTP response. If
            there are network or protocol errors, an exception will be
            raised. HTTP error responses, like 404 or 500, do not
            cause exceptions.

        @rtype: L{HTTPResponse}

        @raise Exception: Different implementations will raise
            different errors based on the underlying HTTP library.
        """
        raise NotImplementedError


def _allowedURL(url):
    return url.startswith('http://') or url.startswith('https://')


class HTTPFetchingError(Exception):
    """Exception that is wrapped around all exceptions that are raised
    by the underlying fetcher when using the ExceptionWrappingFetcher

    @ivar why: The exception that caused this exception
    """

    def __init__(self, why=None):
        Exception.__init__(self, why)
        self.why = why


class ExceptionWrappingFetcher(HTTPFetcher):
    """Fetcher wrapper which wraps all exceptions to `HTTPFetchingError`."""

    def __init__(self, fetcher):
        self.fetcher = fetcher

    def fetch(self, *args, **kwargs):
        try:
            return self.fetcher.fetch(*args, **kwargs)
        except Exception:
            exc_cls, exc_inst = sys.exc_info()[:2]
            if exc_inst is None:
                # string exceptions
                exc_inst = exc_cls

            raise HTTPFetchingError(why=exc_inst)


class Urllib2Fetcher(HTTPFetcher):
    """An C{L{HTTPFetcher}} that uses urllib."""

    # Parameterized for the benefit of testing frameworks, see
    # http://trac.openidenabled.com/trac/ticket/85
    urlopen = staticmethod(urlopen)

    def fetch(self, url, body=None, headers=None):
        assert body is None or isinstance(body, six.binary_type)

        if not _allowedURL(url):
            raise ValueError('Bad URL scheme: %r' % (url,))

        if headers is None:
            headers = {}

        headers.setdefault('User-Agent', "%s Python-urllib" % USER_AGENT)

        req = Request(url, data=body, headers=headers)
        try:
            f = self.urlopen(req)
            try:
                return self._makeResponse(f)
            finally:
                f.close()
        except UrllibHTTPError as why:
            try:
                return self._makeResponse(why)
            finally:
                why.close()

    def _makeResponse(self, urllib_response):
        resp = HTTPResponse()
        resp.body = urllib_response.read(MAX_RESPONSE_KB * 1024)
        resp.final_url = urllib_response.geturl()
        resp.headers = dict(urllib_response.info().items())

        if hasattr(urllib_response, 'code'):
            resp.status = urllib_response.code
        else:
            resp.status = 200

        return resp


class HTTPError(HTTPFetchingError):
    """
    This exception is raised by the C{L{CurlHTTPFetcher}} when it
    encounters an exceptional situation fetching a URL.
    """
    pass

# XXX: define what we mean by paranoid, and make sure it is.


class CurlHTTPFetcher(HTTPFetcher):
    """
    An C{L{HTTPFetcher}} that uses pycurl for fetching.
    See U{http://pycurl.sourceforge.net/}.
    """
    ALLOWED_TIME = 20  # seconds

    def __init__(self):
        HTTPFetcher.__init__(self)
        if pycurl is None:
            raise RuntimeError('Cannot find pycurl library')

    def _parseHeaders(self, header_file):
        header_file.seek(0)

        # Remove the status line from the beginning of the input
        unused_http_status_line = header_file.readline().lower()
        if unused_http_status_line.startswith(b'http/1.1 100 '):
            unused_http_status_line = header_file.readline()
            unused_http_status_line = header_file.readline()

        lines = [line.strip() for line in header_file]

        # and the blank line from the end
        empty_line = lines.pop()
        if empty_line:
            raise HTTPError("No blank line at end of headers: %r" % empty_line)

        headers = {}
        for line in lines:
            try:
                name, value = line.split(b':', 1)
            except ValueError:
                raise HTTPError(
                    "Malformed HTTP header line in response: %r" % (line,))

            value = value.strip().decode('utf-8')

            # HTTP headers are case-insensitive
            name = name.lower().decode('utf-8')
            headers[name] = value

        return headers

    def _checkURL(self, url):
        # XXX: document that this can be overridden to match desired policy
        # XXX: make sure url is well-formed and routeable
        return _allowedURL(url)

    def fetch(self, url, body=None, headers=None):
        assert body is None or isinstance(body, six.binary_type)

        stop = int(time.time()) + self.ALLOWED_TIME
        off = self.ALLOWED_TIME

        if headers is None:
            headers = {}

        headers.setdefault('User-Agent',
                           "%s %s" % (USER_AGENT, pycurl.version,))

        header_list = []
        if headers is not None:
            for header_name, header_value in headers.items():
                header_list.append('%s: %s' % (header_name, header_value))

        c = pycurl.Curl()
        try:
            c.setopt(pycurl.NOSIGNAL, 1)

            if header_list:
                c.setopt(pycurl.HTTPHEADER, header_list)

            # Presence of a body indicates that we should do a POST
            if body is not None:
                c.setopt(pycurl.POST, 1)
                c.setopt(pycurl.POSTFIELDS, body)

            while off > 0:
                if not self._checkURL(url):
                    raise HTTPError("Fetching URL not allowed: %r" % (url,))

                data = BytesIO()

                def write_data(chunk):
                    if data.tell() > 1024 * MAX_RESPONSE_KB:
                        return 0
                    else:
                        return data.write(chunk)

                response_header_data = BytesIO()
                c.setopt(pycurl.WRITEFUNCTION, write_data)
                c.setopt(pycurl.HEADERFUNCTION, response_header_data.write)
                c.setopt(pycurl.TIMEOUT, off)
                c.setopt(pycurl.URL, openid.urinorm.urinorm(url))

                c.perform()

                response_headers = self._parseHeaders(response_header_data)
                code = c.getinfo(pycurl.RESPONSE_CODE)
                if code in [301, 302, 303, 307]:
                    url = response_headers.get('location')
                    if url is None:
                        raise HTTPError(
                            'Redirect (%s) returned without a location' % code)

                    # Redirects are always GETs
                    c.setopt(pycurl.POST, 0)

                    # There is no way to reset POSTFIELDS to empty and
                    # reuse the connection, but we only use it once.
                else:
                    resp = HTTPResponse()
                    resp.headers = response_headers
                    resp.status = code
                    resp.final_url = url
                    resp.body = data.getvalue()
                    return resp

                off = stop - int(time.time())

            raise HTTPError("Timed out fetching: %r" % (url,))
        finally:
            c.close()


class HTTPLib2Fetcher(HTTPFetcher):
    """A fetcher that uses C{httplib2} for performing HTTP
    requests. This implementation supports HTTP caching.

    @see: http://bitworking.org/projects/httplib2/
    """

    def __init__(self, cache=None):
        """@param cache: An object suitable for use as an C{httplib2}
            cache. If a string is passed, it is assumed to be a
            directory name.
        """
        if httplib2 is None:
            raise RuntimeError('Cannot find httplib2 library. '
                               'See http://bitworking.org/projects/httplib2/')

        super(HTTPLib2Fetcher, self).__init__()

        # An instance of the httplib2 object that performs HTTP requests
        self.httplib2 = httplib2.Http(cache)

        # We want httplib2 to raise exceptions for errors, just like
        # the other fetchers.
        self.httplib2.force_exception_to_status_code = False

    def fetch(self, url, body=None, headers=None):
        """Perform an HTTP request

        @raises Exception: Any exception that can be raised by httplib2

        @see: C{L{HTTPFetcher.fetch}}
        """
        assert body is None or isinstance(body, six.binary_type)

        if body:
            method = 'POST'
        else:
            method = 'GET'

        if headers is None:
            headers = {}

        # httplib2 doesn't check to make sure that the URL's scheme is
        # 'http' so we do it here.
        if not (url.startswith('http://') or url.startswith('https://')):
            raise ValueError('URL is not a HTTP URL: %r' % (url,))

        httplib2_response, content = self.httplib2.request(
            url, method, body=body, headers=headers)

        # Translate the httplib2 response to our HTTP response abstraction

        # When a 400 is returned, there is no "content-location"
        # header set. This seems like a bug to me. I can't think of a
        # case where we really care about the final URL when it is an
        # error response, but being careful about it can't hurt.
        try:
            final_url = httplib2_response['content-location']
        except KeyError:
            # We're assuming that no redirects occurred
            assert not httplib2_response.previous

            # And this should never happen for a successful response
            assert httplib2_response.status != 200
            final_url = url

        return HTTPResponse(
            body=content,
            final_url=final_url,
            headers=dict(httplib2_response.items()),
            status=httplib2_response.status,
        )


class RequestsFetcher(HTTPFetcher):
    """A fetcher that uses C{requests} for performing HTTP requests."""

    def fetch(self, url, body=None, headers=None):
        """Perform an HTTP request

        @raises Exception: Any exception that can be raised by 'requests'

        @see: C{L{HTTPFetcher.fetch}}
        """
        assert body is None or isinstance(body, six.binary_type)

        if body:
            method = 'POST'
        else:
            method = 'GET'
        response = requests.request(method, url, data=body, headers=headers)
        return HTTPResponse(response.url, response.status_code, response.headers, response.content)
