import socket
import unittest
import urllib2
import warnings
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from cStringIO import StringIO
from urllib import addinfourl

import responses
from mock import Mock

from openid import fetchers

try:
    import requests
except ImportError:
    requests = None
else:
    from requests.exceptions import ConnectionError, InvalidSchema

# XXX: make these separate test cases


def assertResponse(expected, actual):
    assert expected.final_url == actual.final_url, (
        "%r != %r" % (expected.final_url, actual.final_url))
    assert expected.status == actual.status
    assert expected.body == actual.body, "%r != %r" % (expected.body, actual.body)
    got_headers = dict(actual.headers)
    # TODO: Delete these pops
    got_headers.pop('date', None)
    got_headers.pop('server', None)
    for k, v in expected.headers.iteritems():
        assert got_headers[k] == v, (k, v, got_headers[k])


def test_fetcher(fetcher, exc, server):
    def geturl(path):
        return 'http://%s:%s%s' % (socket.getfqdn(server.server_name),
                                   server.socket.getsockname()[1],
                                   path)

    expected_headers = {'content-type': 'text/plain'}

    def plain(path, code):
        path = '/' + path
        expected = fetchers.HTTPResponse(
            geturl(path), code, expected_headers, path)
        return (path, expected)

    expect_success = fetchers.HTTPResponse(
        geturl('/success'), 200, expected_headers, '/success')
    cases = [
        ('/success', expect_success),
        ('/301redirect', expect_success),
        ('/302redirect', expect_success),
        ('/303redirect', expect_success),
        ('/307redirect', expect_success),
        plain('notfound', 404),
        plain('badreq', 400),
        plain('forbidden', 403),
        plain('error', 500),
        plain('server_error', 503),
    ]

    for path, expected in cases:
        fetch_url = geturl(path)
        try:
            actual = fetcher.fetch(fetch_url)
        except Exception:
            print fetcher, fetch_url
            raise
        else:
            assertResponse(expected, actual)

    for err_url in [geturl('/closed'),
                    'http://invalid.janrain.com/',
                    'not:a/url',
                    'ftp://janrain.com/pub/']:
        try:
            result = fetcher.fetch(err_url)
        except fetchers.HTTPError:
            # This is raised by the Curl fetcher for bad cases
            # detected by the fetchers module, but it's a subclass of
            # HTTPFetchingError, so we have to catch it explicitly.
            assert exc
        except fetchers.HTTPFetchingError:
            assert not exc, (fetcher, exc, server)
        except Exception:
            assert exc
        else:
            assert False, 'An exception was expected for %r (%r)' % (fetcher, result)


def run_fetcher_tests(server):
    exc_fetchers = []
    for klass, library_name in [
        (fetchers.CurlHTTPFetcher, 'pycurl'),
        (fetchers.HTTPLib2Fetcher, 'httplib2'),
    ]:
        try:
            exc_fetchers.append(klass())
        except RuntimeError as why:
            if why[0].startswith('Cannot find %s library' % (library_name,)):
                try:
                    __import__(library_name)
                except ImportError:
                    warnings.warn(
                        'Skipping tests for %r fetcher because '
                        'the library did not import.' % (library_name,))
                    pass
                else:
                    assert False, ('%s present but not detected' % (library_name,))
            else:
                raise

    non_exc_fetchers = []
    for f in exc_fetchers:
        non_exc_fetchers.append(fetchers.ExceptionWrappingFetcher(f))

    for f in exc_fetchers:
        test_fetcher(f, True, server)

    for f in non_exc_fetchers:
        test_fetcher(f, False, server)


class FetcherTestHandler(BaseHTTPRequestHandler):
    cases = {
        '/success': (200, None),
        '/301redirect': (301, '/success'),
        '/302redirect': (302, '/success'),
        '/303redirect': (303, '/success'),
        '/307redirect': (307, '/success'),
        '/notfound': (404, None),
        '/badreq': (400, None),
        '/forbidden': (403, None),
        '/error': (500, None),
        '/server_error': (503, None),
    }

    def log_request(self, *args):
        pass

    def do_GET(self):
        if self.path == '/closed':
            self.wfile.close()
        else:
            try:
                http_code, location = self.cases[self.path]
            except KeyError:
                self.errorResponse('Bad path')
            else:
                extra_headers = [('Content-type', 'text/plain')]
                if location is not None:
                    host, port = self.server.server_address
                    base = ('http://%s:%s' % (socket.getfqdn(host), port,))
                    location = base + location
                    extra_headers.append(('Location', location))
                self._respond(http_code, extra_headers, self.path)

    def do_POST(self):
        try:
            http_code, extra_headers = self.cases[self.path]
        except KeyError:
            self.errorResponse('Bad path')
        else:
            if http_code in [301, 302, 303, 307]:
                self.errorResponse()
            else:
                content_type = self.headers.get('content-type', 'text/plain')
                extra_headers.append(('Content-type', content_type))
                content_length = int(self.headers.get('Content-length', '-1'))
                body = self.rfile.read(content_length)
                self._respond(http_code, extra_headers, body)

    def errorResponse(self, message=None):
        req = [
            ('HTTP method', self.command),
            ('path', self.path),
        ]
        if message:
            req.append(('message', message))

        body_parts = ['Bad request:\r\n']
        for k, v in req:
            body_parts.append(' %s: %s\r\n' % (k, v))
        body = ''.join(body_parts)
        self._respond(400, [('Content-type', 'text/plain')], body)

    def _respond(self, http_code, extra_headers, body):
        self.send_response(http_code)
        for k, v in extra_headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)
        self.wfile.close()

    def finish(self):
        if not self.wfile.closed:
            self.wfile.flush()
        self.wfile.close()
        self.rfile.close()


class TestFetchers(unittest.TestCase):
    def test(self):
        server = HTTPServer(("", 0), FetcherTestHandler)

        import threading
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.setDaemon(True)
        server_thread.start()

        run_fetcher_tests(server)


class FakeFetcher(object):
    sentinel = object()

    def fetch(self, *args, **kwargs):
        return self.sentinel


class DefaultFetcherTest(unittest.TestCase):
    def setUp(self):
        """reset the default fetcher to None"""
        fetchers.setDefaultFetcher(None)

    def tearDown(self):
        """reset the default fetcher to None"""
        fetchers.setDefaultFetcher(None)

    def test_getDefaultNotNone(self):
        """Make sure that None is never returned as a default fetcher"""
        self.assertIsNotNone(fetchers.getDefaultFetcher())
        fetchers.setDefaultFetcher(None)
        self.assertIsNotNone(fetchers.getDefaultFetcher())

    def test_setDefault(self):
        """Make sure the getDefaultFetcher returns the object set for
        setDefaultFetcher"""
        sentinel = object()
        fetchers.setDefaultFetcher(sentinel, wrap_exceptions=False)
        self.assertEqual(fetchers.getDefaultFetcher(), sentinel)

    def test_callFetch(self):
        """Make sure that fetchers.fetch() uses the default fetcher
        instance that was set."""
        fetchers.setDefaultFetcher(FakeFetcher())
        actual = fetchers.fetch('bad://url')
        self.assertEqual(actual, FakeFetcher.sentinel)

    def test_wrappedByDefault(self):
        """Make sure that the default fetcher instance wraps
        exceptions by default"""
        default_fetcher = fetchers.getDefaultFetcher()
        self.assertIsInstance(default_fetcher, fetchers.ExceptionWrappingFetcher)

        self.assertRaises(fetchers.HTTPFetchingError, fetchers.fetch, 'http://invalid.janrain.com/')

    def test_notWrapped(self):
        """Make sure that if we set a non-wrapped fetcher as default,
        it will not wrap exceptions."""
        # A fetcher that will raise an exception when it encounters a
        # host that will not resolve
        fetcher = fetchers.Urllib2Fetcher()
        fetchers.setDefaultFetcher(fetcher, wrap_exceptions=False)

        self.assertNotIsInstance(fetchers.getDefaultFetcher(), fetchers.ExceptionWrappingFetcher)

        with self.assertRaises(urllib2.URLError):
            fetchers.fetch('http://invalid.janrain.com/')


class TestHandler(urllib2.BaseHandler):
    """Urllib2 test handler."""

    def __init__(self, http_mock):
        self.http_mock = http_mock

    def http_open(self, req):
        return self.http_mock()


class TestUrllib2Fetcher(unittest.TestCase):
    """Test `Urllib2Fetcher` class."""

    fetcher = fetchers.Urllib2Fetcher()
    invalid_url_error = ValueError

    def setUp(self):
        self.http_mock = Mock(side_effect=[])
        opener = urllib2.OpenerDirector()
        opener.add_handler(TestHandler(self.http_mock))
        urllib2.install_opener(opener)

    def tearDown(self):
        # Uninstall custom opener
        urllib2.install_opener(None)

    def add_response(self, url, status_code, headers, body=None):
        response = addinfourl(StringIO(body or ''), headers, url, status_code)
        responses = list(self.http_mock.side_effect)
        responses.append(response)
        self.http_mock.side_effect = responses

    def test_success(self):
        # Test success response
        self.add_response('http://example.cz/success/', 200, {'Content-Type': 'text/plain'}, 'BODY')
        response = self.fetcher.fetch('http://example.cz/success/')
        expected = fetchers.HTTPResponse('http://example.cz/success/', 200, {'Content-Type': 'text/plain'}, 'BODY')
        assertResponse(expected, response)

    def test_redirect(self):
        # Test redirect response - a final response comes from another URL.
        self.add_response('http://example.cz/success/', 200, {'Content-Type': 'text/plain'}, 'BODY')
        response = self.fetcher.fetch('http://example.cz/redirect/')
        expected = fetchers.HTTPResponse('http://example.cz/success/', 200, {'Content-Type': 'text/plain'}, 'BODY')
        assertResponse(expected, response)

    def test_error(self):
        # Test error responses - returned as obtained
        self.add_response('http://example.cz/error/', 500, {'Content-Type': 'text/plain'}, 'BODY')
        response = self.fetcher.fetch('http://example.cz/error/')
        expected = fetchers.HTTPResponse('http://example.cz/error/', 500, {'Content-Type': 'text/plain'}, 'BODY')
        assertResponse(expected, response)

    def test_invalid_url(self):
        with self.assertRaisesRegexp(self.invalid_url_error, 'Bad URL scheme:'):
            self.fetcher.fetch('invalid://example.cz/')

    def test_connection_error(self):
        # Test connection error
        self.http_mock.side_effect = urllib2.HTTPError('http://example.cz/error/', 500, 'Error message',
                                                       {'Content-Type': 'text/plain'}, StringIO('BODY'))
        response = self.fetcher.fetch('http://example.cz/error/')
        expected = fetchers.HTTPResponse('http://example.cz/error/', 500, {'Content-Type': 'text/plain'}, 'BODY')
        assertResponse(expected, response)


class TestSilencedUrllib2Fetcher(TestUrllib2Fetcher):
    """Test silenced `Urllib2Fetcher` class."""

    fetcher = fetchers.ExceptionWrappingFetcher(fetchers.Urllib2Fetcher())
    invalid_url_error = fetchers.HTTPFetchingError


@unittest.skipUnless(requests, "Requests are not installed")
class TestRequestsFetcher(unittest.TestCase):
    """Test `RequestsFetcher` class."""

    fetcher = fetchers.RequestsFetcher()

    def test_get(self):
        # Test GET response
        with responses.RequestsMock() as rsps:
            rsps.add(responses.GET, 'http://example.cz/', status=200, body='BODY',
                     headers={'Content-Type': 'text/plain'})
            response = self.fetcher.fetch('http://example.cz/')
        expected = fetchers.HTTPResponse('http://example.cz/', 200, {'Content-Type': 'text/plain'}, 'BODY')
        assertResponse(expected, response)

    def test_post(self):
        # Test POST response
        with responses.RequestsMock() as rsps:
            rsps.add(responses.POST, 'http://example.cz/', status=200, body='BODY',
                     headers={'Content-Type': 'text/plain'})
            response = self.fetcher.fetch('http://example.cz/', body='key=value')
        expected = fetchers.HTTPResponse('http://example.cz/', 200, {'Content-Type': 'text/plain'}, 'BODY')
        assertResponse(expected, response)

    def test_redirect(self):
        # Test redirect response - a final response comes from another URL.
        with responses.RequestsMock() as rsps:
            rsps.add(responses.GET, 'http://example.cz/redirect/', status=302,
                     headers={'Location': 'http://example.cz/target/'})
            rsps.add(responses.GET, 'http://example.cz/target/', status=200, body='BODY',
                     headers={'Content-Type': 'text/plain'})
            response = self.fetcher.fetch('http://example.cz/redirect/')
        expected = fetchers.HTTPResponse('http://example.cz/target/', 200, {'Content-Type': 'text/plain'}, 'BODY')
        assertResponse(expected, response)

    def test_error(self):
        # Test error responses - returned as obtained
        with responses.RequestsMock() as rsps:
            rsps.add(responses.GET, 'http://example.cz/error/', status=500, body='BODY',
                     headers={'Content-Type': 'text/plain'})
            response = self.fetcher.fetch('http://example.cz/error/')
        expected = fetchers.HTTPResponse('http://example.cz/error/', 500, {'Content-Type': 'text/plain'}, 'BODY')
        assertResponse(expected, response)

    def test_invalid_url(self):
        invalid_url = 'invalid://example.cz/'
        with self.assertRaisesRegexp(InvalidSchema, "No connection adapters were found for '" + invalid_url + "'"):
            self.fetcher.fetch(invalid_url)

    def test_connection_error(self):
        # Test connection error
        with responses.RequestsMock() as rsps:
            rsps.add(responses.GET, 'http://example.cz/', body=ConnectionError('Name or service not known'))
            with self.assertRaisesRegexp(ConnectionError, 'Name or service not known'):
                self.fetcher.fetch('http://example.cz/')
