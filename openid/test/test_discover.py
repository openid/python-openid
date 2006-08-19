import sys
import unittest
import datadriven
from urljr import fetchers
from urljr.fetchers import HTTPResponse
from yadis.discover import DiscoveryFailure
from openid.consumer import discover
from yadis import xrires
from yadis.xri import XRI
from urlparse import urlsplit

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
        [HTTPResponse('http://network.error/', None)],
        [HTTPResponse('http://not.found/', 404)],
        [HTTPResponse('http://bad.request/', 400)],
        [HTTPResponse('http://server.error/', 500)],
        [HTTPResponse('http://header.found/', 200,
                      headers={'x-xrds-location':'http://xrds.missing/'}),
         HTTPResponse('http://xrds.missing/', 404)],
        ]

    def __init__(self, responses):
        self.url = responses[0].final_url
        datadriven.DataDrivenTestCase.__init__(self, self.url)
        self.responses = responses

    def setUp(self):
        fetcher = SimpleMockFetcher(self.responses)
        fetchers.setDefaultFetcher(fetcher)

    def tearDown(self):
        fetchers.setDefaultFetcher(None)

    def runOneTest(self):
        expected_status = self.responses[-1].status
        try:
            discover.discover(self.url)
        except DiscoveryFailure, why:
            self.failUnlessEqual(why.http_response.status, expected_status)
        else:
            self.fail('Did not raise DiscoveryFailure')


### Tests for raising/catching exceptions from the fetcher through the
### discover function

# Python 2.5 displays a message when running this test, which is
# testing the behaviour in the presence of string exceptions,
# deprecated or not, so tell it no to complain when this particular
# string exception is raised.
import warnings
warnings.filterwarnings('ignore', 'raising a string.*', DeprecationWarning,
                        r'^openid\.test\.test_discover$', 74)

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
        Exception(),
        DidFetch(),
        ValueError(),
        RuntimeError(),
        'oi!',
        ]

    def __init__(self, exc):
        datadriven.DataDrivenTestCase.__init__(self, repr(exc))
        self.exc = exc

    def setUp(self):
        fetcher = ErrorRaisingFetcher(self.exc)
        fetchers.setDefaultFetcher(fetcher, wrap_exceptions=False)

    def tearDown(self):
        fetchers.setDefaultFetcher(None)

    def runOneTest(self):
        try:
            discover.discover('http://doesnt.matter/')
        except:
            exc = sys.exc_info()[1]
            if exc is None:
                # str exception
                self.failUnless(self.exc is sys.exc_info()[0])
            else:
                self.failUnless(self.exc is exc, exc)
        else:
            self.fail('Expected %r', self.exc)


### Tests for openid.consumer.discover.discover


class DiscoveryMockFetcher(object):
    redirect = None

    def __init__(self, documents):
        self.documents = documents
        self.fetchlog = []

    def fetch(self, url, body=None, headers=None):
        self.fetchlog.append((url, body, headers))
        if self.redirect:
            final_url = self.redirect
        else:
            final_url = url

        try:
            ctype, body = self.documents[url]
        except KeyError:
            status = 404
            ctype = 'text/plain'
            body = ''
        else:
            status = 200

        return HTTPResponse(final_url, status, {'content-type': ctype}, body)

# from twisted.trial import unittest as trialtest

class BaseTestDiscovery(unittest.TestCase):
    id_url = "http://someuser.unittest/"

    documents = {}
    fetcherClass = DiscoveryMockFetcher

    def setUp(self):
        self.documents = self.documents.copy()
        self.fetcher = self.fetcherClass(self.documents)
        fetchers.setDefaultFetcher(self.fetcher)

    def tearDown(self):
        fetchers.setDefaultFetcher(None)

yadis_2entries = '''<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS xmlns:xrds="xri://$xrds"
           xmlns="xri://$xrd*($v*2.0)"
           xmlns:openid="http://openid.net/xmlns/1.0"
           >
  <XRD>
    <CanonicalID>=!1000</CanonicalID>

    <Service priority="10">
      <Type>http://openid.net/signon/1.0</Type>
      <URI>http://www.myopenid.com/server</URI>
      <openid:Delegate>http://smoker.myopenid.com/</openid:Delegate>
    </Service>

    <Service priority="20">
      <Type>http://openid.net/signon/1.0</Type>
      <URI>http://www.livejournal.com/openid/server.bml</URI>
      <openid:Delegate>http://frank.livejournal.com/</openid:Delegate>
    </Service>

  </XRD>
</xrds:XRDS>
'''

yadis_another = '''<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS xmlns:xrds="xri://$xrds"
           xmlns="xri://$xrd*($v*2.0)"
           xmlns:openid="http://openid.net/xmlns/1.0"
           >
  <XRD>

    <Service priority="10">
      <Type>http://openid.net/signon/1.0</Type>
      <URI>http://vroom.unittest/server</URI>
      <openid:Delegate>http://smoker.myopenid.com/</openid:Delegate>
    </Service>
  </XRD>
</xrds:XRDS>
'''


yadis_0entries = '''<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS xmlns:xrds="xri://$xrds"
           xmlns="xri://$xrd*($v*2.0)"
           xmlns:openid="http://openid.net/xmlns/1.0"
           >
  <XRD>
    <Service >
      <Type>http://is-not-openid.unittest/</Type>
      <URI>http://noffing.unittest./</URI>
    </Service>
  </XRD>
</xrds:XRDS>
'''

yadis_no_delegate = '''<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS xmlns:xrds="xri://$xrds"
           xmlns="xri://$xrd*($v*2.0)"
           >
  <XRD>
    <Service priority="10">
      <Type>http://openid.net/signon/1.0</Type>
      <URI>http://www.myopenid.com/server</URI>
    </Service>
  </XRD>
</xrds:XRDS>
'''

openid_html = """
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html>
  <head>
    <title>Identity Page for Smoker</title>
<link rel="openid.server" href="http://www.myopenid.com/server" />
<link rel="openid.delegate" href="http://smoker.myopenid.com/" />
  </head><body><p>foo</p></body></html>
"""

openid_html_no_delegate = """
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html>
  <head>
    <title>Identity Page for Smoker</title>
<link rel="openid.server" href="http://www.myopenid.com/server" />
  </head><body><p>foo</p></body></html>
"""

openid_and_yadis_html = """
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html>
  <head>
    <title>Identity Page for Smoker</title>
<meta http-equiv="X-XRDS-Location" content="http://someuser.unittest/xrds" />
<link rel="openid.server" href="http://www.myopenid.com/server" />
<link rel="openid.delegate" href="http://smoker.myopenid.com/" />
  </head><body><p>foo</p></body></html>
"""

class TestDiscovery(BaseTestDiscovery):
    def _usedYadis(self, service):
        self.failUnless(service.used_yadis, "Expected to use Yadis")

    def _notUsedYadis(self, service):
        self.failIf(service.used_yadis, "Expected to use old-style discovery")

    def test_404(self):
        self.failUnlessRaises(DiscoveryFailure,
                              discover.discover, self.id_url + '/404')

    def test_noYadis(self):
        self.documents[self.id_url] = ('text/html', openid_html)
        id_url, services = discover.discover(self.id_url)
        self.failUnlessEqual(self.id_url, id_url)
        self.failUnlessEqual(len(services), 1,
                             "More than one service in %r" % (services,))
        self.failUnlessEqual(services[0].server_url,
                             "http://www.myopenid.com/server")
        self.failUnlessEqual(services[0].delegate,
                             "http://smoker.myopenid.com/")
        self.failUnlessEqual(services[0].identity_url, self.id_url)
        self._notUsedYadis(services[0])

    def test_noOpenID(self):
        self.fetcher.documents = {
            self.id_url: ('text/plain', "junk"),
        }
        id_url, services = discover.discover(self.id_url)
        self.failUnlessEqual(self.id_url, id_url)
        self.failIf(len(services))

    def test_yadis(self):
        self.fetcher.documents = {
            BaseTestDiscovery.id_url: ('application/xrds+xml', yadis_2entries),
        }

        id_url, services = discover.discover(self.id_url)
        self.failUnlessEqual(self.id_url, id_url)
        self.failUnlessEqual(len(services), 2,
                             "Not 2 services in %r" % (services,))
        self.failUnlessEqual(services[0].server_url,
                             "http://www.myopenid.com/server")
        self._usedYadis(services[0])
        self.failUnlessEqual(services[1].server_url,
                             "http://www.livejournal.com/openid/server.bml")
        self._usedYadis(services[1])

    def test_redirect(self):
        expected_final_url = "http://elsewhere.unittest/"
        self.fetcher.redirect = expected_final_url
        self.fetcher.documents = {
            self.id_url: ('text/html', openid_html),
        }
        id_url, services = discover.discover(self.id_url)
        self.failUnlessEqual(expected_final_url, id_url)
        self.failUnlessEqual(len(services), 1,
                             "More than one service in %r" % (services,))
        self.failUnlessEqual(services[0].server_url,
                             "http://www.myopenid.com/server")
        self.failUnlessEqual(services[0].delegate,
                             "http://smoker.myopenid.com/")
        self.failUnlessEqual(services[0].identity_url, expected_final_url)
        self._notUsedYadis(services[0])

    def test_emptyList(self):
        self.fetcher.documents = {
            self.id_url: ('application/xrds+xml', yadis_0entries),
        }
        id_url, services = discover.discover(self.id_url)
        self.failUnlessEqual(self.id_url, id_url)
        self.failIf(services)

    def test_emptyListWithLegacy(self):
        self.fetcher.documents = {
            self.id_url: ('text/html', openid_and_yadis_html),
            self.id_url + 'xrds': ('application/xrds+xml', yadis_0entries),
        }
        id_url, services = discover.discover(self.id_url)
        self.failUnlessEqual(self.id_url, id_url)
        self.failUnlessEqual(len(services), 1,
                             "Not one service in %r" % (services,))
        self.failUnlessEqual(services[0].server_url,
                             "http://www.myopenid.com/server")
        self.failUnlessEqual(services[0].identity_url, self.id_url)
        self._notUsedYadis(services[0])

    def test_yadisNoDelegate(self):
        self.fetcher.documents = {
            self.id_url: ('application/xrds+xml', yadis_no_delegate),
        }
        id_url, services = discover.discover(self.id_url)
        self.failUnlessEqual(self.id_url, id_url)
        self.failUnlessEqual(len(services), 1,
                             "Not 1 service in %r" % (services,))
        self.failUnlessEqual(services[0].server_url,
                             "http://www.myopenid.com/server")
        self.failUnless(services[0].delegate is None,
                        'Delegate should be None. Got %r' %
                        (services[0].delegate,))
        self._usedYadis(services[0])

    def test_openidNoDelegate(self):
        self.fetcher.documents = {
            self.id_url: ('text/html', openid_html_no_delegate),
        }
        id_url, services = discover.discover(self.id_url)
        self.failUnlessEqual(self.id_url, id_url)
        self.failUnlessEqual(services[0].server_url,
                             "http://www.myopenid.com/server")
        self.failUnlessEqual(services[0].identity_url, self.id_url)
        self.failUnless(services[0].delegate is None,
                        'Delegate should be None. Got %r' %
                        (services[0].delegate,))

        self._notUsedYadis(services[0])


class MockFetcherForXRIProxy(object):

    def __init__(self, documents, proxy_url=xrires.DEFAULT_PROXY):
        self.documents = documents
        self.fetchlog = []
        self.proxy_url = None


    def fetch(self, url, body=None, headers=None):
        self.fetchlog.append((url, body, headers))

        u = urlsplit(url)
        proxy_host = u[1]
        xri = u[2]
        query = u[3]

        if not headers and not query:
            raise ValueError("No headers or query; you probably didn't "
                             "mean to do that.")

        if xri.startswith('/'):
            xri = xri[1:]

        try:
            ctype, body = self.documents[xri]
        except KeyError:
            status = 404
            ctype = 'text/plain'
            body = ''
        else:
            status = 200

        return HTTPResponse(url, status, {'content-type': ctype}, body)


class TestXRIDiscovery(BaseTestDiscovery):
    fetcherClass = MockFetcherForXRIProxy

    documents = {'=smoker': ('application/xrds+xml', yadis_2entries) }

    def test_xri(self):
        user_xri, services = discover.discoverXRI('=smoker')
        self.failUnless(services)
        self.failUnlessEqual(services[0].server_url,
                             "http://www.myopenid.com/server")
        self.failUnlessEqual(services[1].server_url,
                             "http://www.livejournal.com/openid/server.bml")
        self.failUnlessEqual(services[0].canonicalID, XRI("=!1000"))

    def test_useCanonicalID(self):
        """When there is no delegate, the CanonicalID should be used with XRI.
        """
        endpoint = discover.OpenIDServiceEndpoint()
        endpoint.identity_url = "=example"
        endpoint.canonicalID = XRI("=!1000")
        self.failUnlessEqual(endpoint.getServerID(), XRI("=!1000"))



def pyUnitTests():
    return datadriven.loadTests(__name__)

if __name__ == '__main__':
    suite = pyUnitTests()
    runner = unittest.TextTestRunner()
    runner.run(suite)
