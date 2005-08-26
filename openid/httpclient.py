import urllib2
import time
import cStringIO


class HTTPClient(object):
    """Object used by Consumer to send http messages"""

    def get(self, url):
        """-->(final_url, data)
        Fetch the content of url, following redirects, and return the
        final url and page data as a tuple.  Return None on failure.
        """
        raise NotImplementedError

    def post(self, url, body):
        """-->(final_url, data)
        Post the body string argument to url.
        Reutrn the resulting final url and page data as a
        tuple. Return None on failure.
        """
        raise NotImplementedError

# try to import pycurl, which will let us use ParanoidHTTPClient
try:
    import pycurl
except ImportError:
    pycurl = None

def getHTTPClient():
    if pycurl is None:
        return SimpleHTTPClient()
    return ParanoidHTTPClient()

class SimpleHTTPClient(HTTPClient):
    def get(self, url):
        try:
            f = urllib2.urlopen(url)
            try:
                data = f.read()
            finally:
                f.close()
        except urllib2.HTTPError, why:
            why.close()
            return None

        return (f.geturl(), data)

    def post(self, url, body):
        req = urllib2.Request(url, body)
        try:
            f = urllib2.urlopen(req)
            try:
                data = f.read()
            finally:
                f.close()
        except urllib2.HTTPError, why:
            try:
                if why.code == 400:
                    data = why.read()
                else:
                    return None
            finally:
                why.close()

        return (f.geturl(), data)

class ParanoidHTTPClient(HTTPClient):
    """A paranoid HTTPClient that uses pycurl for fecthing.
    See http://pycurl.sourceforge.net/"""
    ALLOWED_TIME = 20 # seconds

    def __init__(self):
        HTTPClient.__init__(self)
        assert pycurl is not None

    def _findRedirect(self, headers):
        headers.seek(0)
        for line in headers:
            if line.startswith('Location: '):
                return line[9:].strip()
        return None

    def _checkURL(self, url):
        # TODO: make sure url is welformed and route-able
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
                if code in (301, 302):
                    url = self._findRedirect(headers)
                else:
                    return url, data.getvalue()

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

            return url, data.getvalue()
        finally:
            c.close()
