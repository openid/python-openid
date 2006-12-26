import sys
import unittest
import datadriven
import os.path
from openid import fetchers
from openid.fetchers import HTTPResponse
from openid.yadis.discover import DiscoveryFailure
from openid.consumer import discover
from openid.yadis import xrires
from openid.yadis.xri import XRI
from urlparse import urlsplit
from openid import message

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
                        r'^openid\.test\.test_discover$', 76)

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

class TestNormalization(unittest.TestCase):
    def testAddingProtocol(self):
        f = ErrorRaisingFetcher(RuntimeError())
        fetchers.setDefaultFetcher(f, wrap_exceptions=False)

        try:
            discover.discover('users.stompy.janrain.com:8000/x')
        except DiscoveryFailure, why:
            self.fail('failed to parse url with port correctly')
        except RuntimeError:
            pass #expected

        fetchers.setDefaultFetcher(None)


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

    def _checkService(self, s,
                      server_url,
                      claimed_id=None,
                      local_id=None,
                      canonical_id=None,
                      types=None,
                      used_yadis=False
                      ):
        self.failUnlessEqual(server_url, s.server_url)
        if types == ['2.0 OP']:
            self.failIf(claimed_id)
            self.failIf(local_id)
            self.failIf(s.claimed_id)
            self.failIf(s.local_id)
            self.failIf(s.getLocalID())
        else:
            self.failUnlessEqual(claimed_id, s.claimed_id)
            self.failUnlessEqual(local_id, s.getLocalID())

        if used_yadis:
            self.failUnless(s.used_yadis, "Expected to use Yadis")
        else:
            self.failIf(s.used_yadis,
                        "Expected to use old-style discovery")

        openid_types = {
            '1.1': discover.OPENID_1_1_TYPE,
            '1.0': discover.OPENID_1_0_TYPE,
            '2.0': discover.OPENID_2_0_TYPE,
            '2.0 OP': discover.OPENID_IDP_2_0_TYPE,
            }

        type_uris = [openid_types[t] for t in types]
        self.failUnlessEqual(type_uris, s.type_uris)
        self.failUnlessEqual(canonical_id, s.canonicalID)

    def setUp(self):
        self.documents = self.documents.copy()
        self.fetcher = self.fetcherClass(self.documents)
        fetchers.setDefaultFetcher(self.fetcher)

    def tearDown(self):
        fetchers.setDefaultFetcher(None)

def readDataFile(filename):
    module_directory = os.path.dirname(os.path.abspath(__file__))
    filename = os.path.join(
        module_directory, 'data', 'test_discover', filename)
    return file(filename).read()

class TestDiscovery(BaseTestDiscovery):
    def _discover(self, content_type, data,
                  expected_services, expected_id=None):
        if expected_id is None:
            expected_id = self.id_url

        self.documents[self.id_url] = (content_type, data)
        id_url, services = discover.discover(self.id_url)
        self.failUnlessEqual(expected_services, len(services))
        self.failUnlessEqual(expected_id, id_url)
        return services

    def test_404(self):
        self.failUnlessRaises(DiscoveryFailure,
                              discover.discover, self.id_url + '/404')

    def test_noOpenID(self):
        services = self._discover(content_type='text/plain',
                                  data="junk",
                                  expected_services=0)

        services = self._discover(
            content_type='text/html',
            data=readDataFile('openid_no_delegate.html'),
            expected_services=1,
            )

        self._checkService(
            services[0],
            used_yadis=False,
            types=['1.1'],
            server_url="http://www.myopenid.com/server",
            claimed_id=self.id_url,
            local_id=self.id_url,
            )

    def test_html1(self):
        services = self._discover(
            content_type='text/html',
            data=readDataFile('openid.html'),
            expected_services=1)


        self._checkService(
            services[0],
            used_yadis=False,
            types=['1.1'],
            server_url="http://www.myopenid.com/server",
            claimed_id=self.id_url,
            local_id='http://smoker.myopenid.com/',
            )

    def test_html2(self):
        services = self._discover(
            content_type='text/html',
            data=readDataFile('openid2.html'),
            expected_services=1,
            )

        self._checkService(
            services[0],
            used_yadis=False,
            types=['2.0'],
            server_url="http://www.myopenid.com/server",
            claimed_id=self.id_url,
            local_id='http://smoker.myopenid.com/',
            )

    def test_html1And2(self):
        services = self._discover(
            content_type='text/html',
            data=readDataFile('openid_1_and_2.html'),
            expected_services=2,
            )

        for t, s in zip(['2.0', '1.1'], services):
            self._checkService(
                s,
                used_yadis=False,
                types=[t],
                server_url="http://www.myopenid.com/server",
                claimed_id=self.id_url,
                local_id='http://smoker.myopenid.com/',
                )

    def test_yadisEmpty(self):
        services = self._discover(content_type='application/xrds+xml',
                                  data=readDataFile('yadis_0entries.xml'),
                                  expected_services=0)

    def test_htmlEmptyYadis(self):
        """HTML document has discovery information, but points to an
        empty Yadis document."""
        # The XRDS document pointed to by "openid_and_yadis.html"
        self.documents[self.id_url + 'xrds'] = (
            'application/xrds+xml', readDataFile('yadis_0entries.xml'))

        services = self._discover(content_type='text/html',
                                  data=readDataFile('openid_and_yadis.html'),
                                  expected_services=1)

        self._checkService(
            services[0],
            used_yadis=False,
            types=['1.1'],
            server_url="http://www.myopenid.com/server",
            claimed_id=self.id_url,
            local_id='http://smoker.myopenid.com/',
            )

    def test_yadis1NoDelegate(self):
        services = self._discover(content_type='application/xrds+xml',
                                  data=readDataFile('yadis_no_delegate.xml'),
                                  expected_services=1)

        self._checkService(
            services[0],
            used_yadis=True,
            types=['1.0'],
            server_url="http://www.myopenid.com/server",
            claimed_id=self.id_url,
            local_id=self.id_url,
            )

    def test_yadis2NoLocalID(self):
        services = self._discover(
            content_type='application/xrds+xml',
            data=readDataFile('openid2_xrds_no_local_id.xml'),
            expected_services=1,
            )

        self._checkService(
            services[0],
            used_yadis=True,
            types=['2.0'],
            server_url="http://www.myopenid.com/server",
            claimed_id=self.id_url,
            local_id=self.id_url,
            )

    def test_yadis2(self):
        services = self._discover(
            content_type='application/xrds+xml',
            data=readDataFile('openid2_xrds.xml'),
            expected_services=1,
            )

        self._checkService(
            services[0],
            used_yadis=True,
            types=['2.0'],
            server_url="http://www.myopenid.com/server",
            claimed_id=self.id_url,
            local_id='http://smoker.myopenid.com/',
            )

    def test_yadis2OP(self):
        services = self._discover(
            content_type='application/xrds+xml',
            data=readDataFile('yadis_idp.xml'),
            expected_services=1,
            )

        self._checkService(
            services[0],
            used_yadis=True,
            types=['2.0 OP'],
            server_url="http://www.myopenid.com/server",
            )

    def test_yadis2OPDelegate(self):
        """The delegate tag isn't meaningful for OP entries."""
        services = self._discover(
            content_type='application/xrds+xml',
            data=readDataFile('yadis_idp_delegate.xml'),
            expected_services=1,
            )

        self._checkService(
            services[0],
            used_yadis=True,
            types=['2.0 OP'],
            server_url="http://www.myopenid.com/server",
            )

    def test_yadis2BadLocalID(self):
        self.failUnlessRaises(DiscoveryFailure, self._discover,
            content_type='application/xrds+xml',
            data=readDataFile('yadis_2_bad_local_id.xml'),
            expected_services=1,
            )

    def test_yadis1And2(self):
        services = self._discover(
            content_type='application/xrds+xml',
            data=readDataFile('openid_1_and_2_xrds.xml'),
            expected_services=1,
            )

        self._checkService(
            services[0],
            used_yadis=True,
            types=['2.0', '1.1'],
            server_url="http://www.myopenid.com/server",
            claimed_id=self.id_url,
            local_id='http://smoker.myopenid.com/',
            )

    def test_yadis1And2BadLocalID(self):
        self.failUnlessRaises(DiscoveryFailure, self._discover,
            content_type='application/xrds+xml',
            data=readDataFile('openid_1_and_2_xrds_bad_delegate.xml'),
            expected_services=1,
            )

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

    documents = {'=smoker': ('application/xrds+xml',
                             readDataFile('yadis_2entries_delegate.xml')),
                 '=smoker*bad': ('application/xrds+xml',
                                 readDataFile('yadis_another_delegate.xml')) }

    def test_xri(self):
        user_xri, services = discover.discoverXRI('=smoker')

        self._checkService(
            services[0],
            used_yadis=True,
            types=['1.0'],
            server_url="http://www.myopenid.com/server",
            claimed_id=XRI("=!1000"),
            canonical_id=XRI("=!1000"),
            local_id='http://smoker.myopenid.com/',
            )

        self._checkService(
            services[1],
            used_yadis=True,
            types=['1.0'],
            server_url="http://www.livejournal.com/openid/server.bml",
            claimed_id=XRI("=!1000"),
            canonical_id=XRI("=!1000"),
            local_id='http://frank.livejournal.com/',
            )

    def test_xriNoCanonicalID(self):
        user_xri, services = discover.discoverXRI('=smoker*bad')
        self.failIf(services)

    def test_useCanonicalID(self):
        """When there is no delegate, the CanonicalID should be used with XRI.
        """
        endpoint = discover.OpenIDServiceEndpoint()
        endpoint.claimed_id = XRI("=!1000")
        endpoint.canonicalID = XRI("=!1000")
        self.failUnlessEqual(endpoint.getLocalID(), XRI("=!1000"))


class TestXRIDiscoveryIDP(BaseTestDiscovery):
    fetcherClass = MockFetcherForXRIProxy

    documents = {'=smoker': ('application/xrds+xml',
                             readDataFile('yadis_2entries_idp.xml')) }

    def test_xri(self):
        user_xri, services = discover.discoverXRI('=smoker')
        self.failUnless(services, "Expected services, got zero")
        self.failUnlessEqual(services[0].server_url,
                             "http://www.livejournal.com/openid/server.bml")


class TestPreferredNamespace(datadriven.DataDrivenTestCase):
    def __init__(self, expected_ns, type_uris):
        datadriven.DataDrivenTestCase.__init__(
            self, 'Expecting %s from %s' % (expected_ns, type_uris))
        self.expected_ns = expected_ns
        self.type_uris = type_uris

    def runOneTest(self):
        endpoint = discover.OpenIDServiceEndpoint()
        endpoint.type_uris = self.type_uris
        actual_ns = endpoint.preferredNamespace()
        self.failUnlessEqual(actual_ns, self.expected_ns)

    cases = [
        (message.OPENID1_NS, []),
        (message.OPENID1_NS, ['http://jyte.com/']),
        (message.OPENID1_NS, [discover.OPENID_1_0_TYPE]),
        (message.OPENID1_NS, [discover.OPENID_1_1_TYPE]),
        (message.OPENID2_NS, [discover.OPENID_2_0_TYPE]),
        (message.OPENID2_NS, [discover.OPENID_IDP_2_0_TYPE]),
        (message.OPENID2_NS, [discover.OPENID_2_0_TYPE,
                              discover.OPENID_1_0_TYPE]),
        (message.OPENID2_NS, [discover.OPENID_1_0_TYPE,
                              discover.OPENID_2_0_TYPE]),
        ]

class TestIsOPIdentifier(unittest.TestCase):
    def setUp(self):
        self.endpoint = discover.OpenIDServiceEndpoint()

    def test_none(self):
        self.failIf(self.endpoint.isOPIdentifier())

    def test_openid1_0(self):
        self.endpoint.type_uris = [discover.OPENID_1_0_TYPE]
        self.failIf(self.endpoint.isOPIdentifier())

    def test_openid1_1(self):
        self.endpoint.type_uris = [discover.OPENID_1_1_TYPE]
        self.failIf(self.endpoint.isOPIdentifier())

    def test_openid2(self):
        self.endpoint.type_uris = [discover.OPENID_2_0_TYPE]
        self.failIf(self.endpoint.isOPIdentifier())

    def test_openid2OP(self):
        self.endpoint.type_uris = [discover.OPENID_IDP_2_0_TYPE]
        self.failUnless(self.endpoint.isOPIdentifier())

    def test_multipleMissing(self):
        self.endpoint.type_uris = [discover.OPENID_2_0_TYPE,
                                   discover.OPENID_1_0_TYPE]
        self.failIf(self.endpoint.isOPIdentifier())

    def test_multiplePresent(self):
        self.endpoint.type_uris = [discover.OPENID_2_0_TYPE,
                                   discover.OPENID_1_0_TYPE,
                                   discover.OPENID_IDP_2_0_TYPE]
        self.failUnless(self.endpoint.isOPIdentifier())

def pyUnitTests():
    return datadriven.loadTests(__name__)

if __name__ == '__main__':
    suite = pyUnitTests()
    runner = unittest.TextTestRunner()
    runner.run(suite)
