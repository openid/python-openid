import sys
import unittest
import datadriven
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

class TestDiscoveryFailure(datadriven.DataDrivenTestCase):
    cases = [
        (None, 'http://network.error/'),
        (404, 'http://not.found/'),
        (400, 'http://bad.request/'),
        (500, 'http://server.error/'),
        ]

    def __init__(self, url, status):
        datadriven.DataDrivenTestCase.__init__(self, url)
        self.url = url
        self.status = status

    def runTest(self):
        fetcher = SimpleMockFetcher(self.status, self.url)
        try:
            discover.discover(self.url, fetcher)
        except DiscoveryFailure, why:
            self.failUnlessEqual(why.http_response.status, self.status)
        else:
            self.fail('Did not raise DiscoveryFailure')

class ErrorRaisingFetcher(object):
    def __init__(self, thing_to_raise):
        self.thing_to_raise = thing_to_raise

    def fetch(self, url, body=None, headers=None):
        raise self.thing_to_raise

class DidFetch(Exception): pass

class TestFetchException(datadriven.DataDrivenTestCase):
    cases = [
        (Exception(),),
        (DidFetch(),),
        (ValueError(),),
        (RuntimeError(),),
        ('oi!',),
        ]

    def __init__(self, exc):
        datadriven.DataDrivenTestCase.__init__(self, repr(exc))
        self.exc = exc

    def runTest(self):
        """Make sure exceptions get passed through discover function
        from fetcher."""
        fetcher = ErrorRaisingFetcher(self.exc)
        try:
            discover.discover('http://doesnt.matter/', fetcher)
        except:
            exc = sys.exc_info()[1]
            if exc is None:
                # str exception
                self.failUnless(self.exc is sys.exc_info()[0])
            else:
                self.failUnless(self.exc is exc, exc)
        else:
            self.fail('Expected %r', self.exc)



def pyUnitTests():
    return datadriven.loadTests(__name__)
