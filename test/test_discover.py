import unittest
from urljr.fetchers import HTTPResponse
from yadis.discover import DiscoveryFailure
from openid.consumer import discover

class SimpleMockFetcher(object):
    def __init__(self, status, url):
        self.status = status
        self.url = url

    def fetch(self, url, body=None, headers=None):
        assert body is None
        assert url == self.url
        return HTTPResponse(url, self.status)

class DidFetch(Exception):
    pass

class ErrorRaisingFetcher(object):
    def fetch(self, url, body=None, headers=None):
        raise DidFetch()

class TestFetch(unittest.TestCase):
    def test_badFetch(self):
        cases = [
            (None, 'http://network.error/'),
            (404, 'http://not.found/'),
            (400, 'http://bad.request/'),
            (500, 'http://server.error/'),
            ]

        for error_code, url in cases:
            fetcher = SimpleMockFetcher(error_code, url)
            try:
                discover.discover(url, fetcher)
            except DiscoveryFailure, why:
                self.failUnlessEqual(why.http_response.status, error_code)
            else:
                self.fail('Did not raise DiscoveryFailure')

    def test_fetchExc(self):
        """Make sure exceptions get passed through discover function
        from fetcher."""
        fetcher = ErrorRaisingFetcher()
        self.failUnlessRaises(DidFetch,
                              discover.discover,
                              'http://doesnt.matter/',
                              fetcher)
