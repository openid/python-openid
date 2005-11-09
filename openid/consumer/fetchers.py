import urllib2
import time
import cStringIO

class OpenIDHTTPFetcher(object):
    """
    This class is the interface for HTTP fetchers the OpenID consumer
    library uses.  This interface is only important if you need to
    write a new fetcher for some reason.
    """

    def get(self, url):
        """
        This performs an HTTP get, following redirects along the way.


        @return: This returns a three-tuple on success.  The first value
            is the http return code. The second value is the final url
            that was fetched, after following any redirects.  The third
            value is the data that was retrieved from the site.  If the
            fetch didn't succeed, return C{None}.

        @rtype: C{None} or (C{int}, C{str}, C{str})


        @raise Exception: There are also failure conditions where this
            may raise an exception, rather than returning None.  When
            this occurs, the OpenID consumer library doesn't attempt
            to handle the exception at all, leaving it for the user of
            the library to handle.
        """
        raise NotImplementedError

    def post(self, url, body):
        """
        This performs an HTTP post.  If it makes sense, it will follow
        redirects along the way.


        @return: This returns a three-tuple on success.  The first value
            is the http return code. The second value is the final url
            that was fetched, after following any redirects.  The third
            value is the data that was retrieved from the site.  If the
            fetch didn't succeed, return C{None}.

        @rtype: C{None} or (C{int}, C{str}, C{str})


        @raise Exception: There are also failure conditions where this
            may raise an exception, rather than returning None.  When
            this occurs, the OpenID consumer library doesn't attempt
            to handle the exception at all, leaving it for the user of
            the library to handle.
        """
        raise NotImplementedError

# try to import pycurl, which will let us use ParanoidHTTPClient
try:
    import pycurl
except ImportError:
    pycurl = None

def getHTTPFetcher(lifetime=60):
    if pycurl is None:
        return UrllibFetcher()
    else:
        return ParanoidHTTPFetcher()


class UrllibFetcher(OpenIDHTTPFetcher):
    def _fetch(self, req):
        try:
            f = urllib2.urlopen(req)
            try:
                data = f.read()
            finally:
                f.close()
        except urllib2.HTTPError, why:
            try:
                data = why.read()
                return (why.code, why.geturl(), data)
            finally:
                why.close()
        else:
            return (f.code, f.geturl(), data)

    def get(self, url):
        return self._fetch(url)

    def post(self, url, body):
        req = urllib2.Request(url, body)
        return self._fetch(req)

class ParanoidHTTPFetcher(OpenIDHTTPFetcher):
    """A paranoid HTTPClient that uses pycurl for fetching.
    See http://pycurl.sourceforge.net/"""
    ALLOWED_TIME = 20 # seconds

    def __init__(self):
        OpenIDHTTPFetcher.__init__(self)
        if pycurl is None:
            raise RuntimeError('Cannot find pycurl library')

    def _findRedirect(self, headers):
        headers.seek(0)
        for line in headers:
            if line.startswith('Location: '):
                return line[9:].strip()
        return None

    def _checkURL(self, url):
        # XXX: make sure url is well-formed and routeable
        return True

    def get(self, url):
        c = pycurl.Curl()
        try:
            c.setopt(pycurl.NOSIGNAL, 1)

            stop = int(time.time()) + self.ALLOWED_TIME
            off = self.ALLOWED_TIME
            while off > 0:
                if not self._checkURL(url):
                    return None
                
                data = cStringIO.StringIO()
                headers = cStringIO.StringIO()
                c.setopt(pycurl.WRITEFUNCTION, data.write)
                c.setopt(pycurl.HEADERFUNCTION, headers.write)
                c.setopt(pycurl.TIMEOUT, off)
                c.setopt(pycurl.URL, url)

                try:
                    c.perform()
                except pycurl.error:
                    return None

                code = c.getinfo(pycurl.RESPONSE_CODE)
                if code in [301, 302, 303, 307]:
                    url = self._findRedirect(headers)
                else:
                    return code, url, data.getvalue()

                off = stop - int(time.time())

            return None
        finally:
            c.close()

    def post(self, url, body):
        if not self._checkURL(url):
            return None

        c = pycurl.Curl()
        try:
            c.setopt(pycurl.NOSIGNAL, 1)
            c.setopt(pycurl.POST, 1)
            c.setopt(pycurl.POSTFIELDS, body)
            c.setopt(pycurl.TIMEOUT, self.ALLOWED_TIME)
            c.setopt(pycurl.URL, url)

            data = cStringIO.StringIO()
            c.setopt(pycurl.WRITEFUNCTION, data.write)

            try:
                c.perform()
            except pycurl.error:
                return None

            code = c.getinfo(pycurl.RESPONSE_CODE)
            return code, url, data.getvalue()
        finally:
            c.close()
