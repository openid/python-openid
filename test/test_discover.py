import sys
import unittest
import datadriven
from urljr.fetchers import HTTPResponse
from yadis.discover import DiscoveryFailure
from openid.consumer import discover

### Tests for conditions that trigger DiscoveryFailure

class SimpleMockFetcher(object):
    def __init__(self, responses):
        self.responses = list(responses)

    def fetch(self, url, body=None, headers=None):
        response = self.responses.pop(0)
        assert body is None
        assert response.final_url == url
        return response

class TestDiscoveryFailure(datadriven.DataDrivenTestCase):
    cases = [
        ([HTTPResponse('http://network.error/', None)],),
        ([HTTPResponse('http://not.found/', 404)],),
        ([HTTPResponse('http://bad.request/', 400)],),
        ([HTTPResponse('http://server.error/', 500)],),
        ([HTTPResponse('http://header.found/', 200,
                      headers={'x-xrds-location':'http://xrds.missing/'}),
          HTTPResponse('http://xrds.missing/', 404)],),
        ]

    def __init__(self, responses):
        self.url = responses[0].final_url
        datadriven.DataDrivenTestCase.__init__(self, self.url)
        self.responses = responses

    def runTest(self):
        fetcher = SimpleMockFetcher(self.responses)
        expected_status = self.responses[-1].status
        try:
            discover.discover(self.url, fetcher)
        except DiscoveryFailure, why:
            self.failUnlessEqual(why.http_response.status, expected_status)
        else:
            self.fail('Did not raise DiscoveryFailure')


### Tests for raising/catching exceptions from the fetcher through the
### discover function

class ErrorRaisingFetcher(object):
    """Just raise an exception when fetch is called"""

    def __init__(self, thing_to_raise):
        self.thing_to_raise = thing_to_raise

    def fetch(self, url, body=None, headers=None):
        raise self.thing_to_raise

class DidFetch(Exception):
    """Custom exception just to make sure it's not handled differently"""

class TestFetchException(datadriven.DataDrivenTestCase):
    """Make sure exceptions get passed through discover function from
    fetcher."""

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
