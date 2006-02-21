"""
This module contains the HTTP fetcher interface and several implementations.
"""
import urllib2
import time
import cStringIO

# try to import pycurl, which will let us use CurlHTTPClient
try:
    import pycurl
except ImportError:
    pycurl = None

class HTTPResponse(object):
    """XXX document attributes"""
    headers = None
    status = None
    body = None
    final_url = None

    def __init__(self, final_url=None, status=None, headers=None, body=None):
        self.final_url = final_url
        self.status = status
        self.headers = headers
        self.body = body

class OpenIDHTTPFetcher(object):
    """
    This class is the interface for HTTP fetchers the OpenID consumer
    library uses.  This interface is only important if you need to
    write a new fetcher for some reason.
    """

    def fetch(self, url, body=None, headers=None):
        """
        This performs an HTTP POST or GET, following redirects along
        the way. If a body is specified, then the request will be a
        POST. Otherwise, it will be a GET.


        @param headers: HTTP headers to include with the request
        @type headers: {str:str}

        @return: This returns a three-tuple on success.  The first value
            is the http return code. The second value is the final url
            that was fetched, after following any redirects.  The third
            value is the data that was retrieved from the site.  If the
            fetch didn't succeed, return C{None}.

        @rtype: L{HTTPResponse}

        @raise Exception: There are also failure conditions where this
            may raise an exception, rather than returning None.  When
            this occurs, the OpenID consumer library doesn't attempt
            to handle the exception at all, leaving it for the user of
            the library to handle.
        """
        raise NotImplementedError

def _getHTTPFetcher(raise_exceptions=False):
    if pycurl is None:
        fetcher = UrllibFetcher()
    else:
        fetcher = CurlHTTPFetcher()

    if not raise_exceptions:
        fetcher = ExceptionCatchingFetcher(fetcher)

    return fetcher

def _allowedURL(url):
    return url.startswith('http://') or url.startswith('https://')

class ExceptionCatchingFetcher(OpenIDHTTPFetcher):
    def __init__(self, fetcher):
        self.fetcher = fetcher

    def fetch(self, *args, **kwargs):
        try:
            return self.fetcher.fetch(*args, **kwargs)
        except (SystemExit, KeyboardInterrupt):
            raise
        except:
            return None

class UrllibFetcher(OpenIDHTTPFetcher):
    """
    A very primitive C{L{OpenIDHTTPFetcher}} that uses urllib2.  Not
    recommended for use if anything else is available.
    """
    def fetch(self, url, body=None, headers=None):
        if not _allowedURL(url):
            raise ValueError('Bad URL scheme: %r' % (url,))

        if headers is None:
            headers = {}

        req = urllib2.Request(url, data=body, headers=headers)
        try:
            f = urllib2.urlopen(req)
            try:
                return self._makeResponse(f)
            finally:
                f.close()
        except urllib2.HTTPError, why:
            try:
                return self._makeResponse(why)
            finally:
                why.close()

    def _makeResponse(self, urllib2_response):
        resp = HTTPResponse()
        resp.body = urllib2_response.read()
        resp.final_url = urllib2_response.geturl()
        resp.headers = dict(urllib2_response.info().items())

        if hasattr(urllib2_response, 'code'):
            resp.status = urllib2_response.code
        else:
            resp.status = 200

        return resp

class OpenIDHTTPError(Exception):
    """
    This exception is raised by the C{L{CurlHTTPFetcher}} when it
    encounters an exceptional situation fetching a URL.
    """
    pass

# XXX: define what we mean by paranoid, and make sure it is.
class CurlHTTPFetcher(OpenIDHTTPFetcher):
    """
    An C{L{OpenIDHTTPFetcher}} that uses pycurl for fetching.
    See U{http://pycurl.sourceforge.net/}.
    """
    ALLOWED_TIME = 20 # seconds

    def __init__(self):
        OpenIDHTTPFetcher.__init__(self)
        if pycurl is None:
            raise RuntimeError('Cannot find pycurl library')

    def _parseHeaders(self, header_file):
        header_file.seek(0)

        # Remove the status line from the beginning of the input
        unused_http_status_line = header_file.readline()
        lines = [line.strip() for line in header_file]

        # and the blank line from the end
        empty_line = lines.pop()
        if empty_line:
            raise OpenIDHTTPError(
                "No blank line at end of headers: %r" % (line,))

        headers = {}
        for line in lines:
            try:
                name, value = line.split(':', 1)
            except ValueError:
                raise OpenIDHTTPError(
                    "Malformed HTTP header line in response: %r" % (line,))

            value = value.strip()

            # HTTP headers are case-insensitive
            name = name.lower()
            headers[name] = value

        return headers

    def _checkURL(self, url):
        # XXX: document that this can be overridden to match desired policy
        # XXX: make sure url is well-formed and routeable
        return _allowedURL(url)

    def fetch(self, url, body=None, headers=None):
        stop = int(time.time()) + self.ALLOWED_TIME
        off = self.ALLOWED_TIME

        header_list = []
        if headers is not None:
            for header_name, header_value in headers.iteritems():
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
                    raise OpenIDHTTPError(
                        "Fetching URL not allowed: %r" % (url,))

                data = cStringIO.StringIO()
                response_header_data = cStringIO.StringIO()
                c.setopt(pycurl.WRITEFUNCTION, data.write)
                c.setopt(pycurl.HEADERFUNCTION, response_header_data.write)
                c.setopt(pycurl.TIMEOUT, off)
                c.setopt(pycurl.URL, url)

                c.perform()

                response_headers = self._parseHeaders(response_header_data)
                code = c.getinfo(pycurl.RESPONSE_CODE)
                if code in [301, 302, 303, 307]:
                    url = response_headers.get('location')
                    if url is None:
                        raise OpenIDHTTPError(
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

            raise OpenIDHTTPError("Timed out fetching: %r" % (url,))
        finally:
            c.close()
