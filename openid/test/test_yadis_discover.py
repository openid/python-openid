#!/usr/bin/env python

"""Tests for yadis.discover.

@todo: Now that yadis.discover uses urljr.fetchers, we should be able to do
   tests with a mock fetcher instead of spawning threads with BaseHTTPServer.
"""

import re
import types
import unittest
import urlparse

from openid import fetchers
from openid.yadis.discover import DiscoveryFailure, discover

from . import discoverdata

status_header_re = re.compile(r'Status: (\d+) .*?$', re.MULTILINE)

four04_pat = """\
Content-Type: text/plain

No such file %s
"""


class QuitServer(Exception):
    pass


def mkResponse(data):
    status_mo = status_header_re.match(data)
    headers_str, body = data.split('\n\n', 1)
    headers = {}
    for line in headers_str.split('\n'):
        k, v = line.split(':', 1)
        k = k.strip().lower()
        v = v.strip()
        headers[k] = v
    status = int(status_mo.group(1))
    return fetchers.HTTPResponse(status=status,
                                 headers=headers,
                                 body=body)


class TestFetcher(object):
    def __init__(self, base_url):
        self.base_url = base_url

    def fetch(self, url, headers, body):
        current_url = url
        while True:
            parsed = urlparse.urlparse(current_url)
            path = parsed[2][1:]
            try:
                data = discoverdata.generateSample(path, self.base_url)
            except KeyError:
                return fetchers.HTTPResponse(status=404,
                                             final_url=current_url,
                                             headers={},
                                             body='')

            response = mkResponse(data)
            if response.status in [301, 302, 303, 307]:
                current_url = response.headers['location']
            else:
                response.final_url = current_url
                return response


class TestSecondGet(unittest.TestCase):
    class MockFetcher(object):
        def __init__(self):
            self.count = 0

        def fetch(self, uri, headers=None, body=None):
            self.count += 1
            if self.count == 1:
                headers = {
                    'X-XRDS-Location'.lower(): 'http://unittest/404',
                }
                return fetchers.HTTPResponse(uri, 200, headers, '')
            else:
                return fetchers.HTTPResponse(uri, 404)

    def setUp(self):
        self.oldfetcher = fetchers.getDefaultFetcher()
        fetchers.setDefaultFetcher(self.MockFetcher())

    def tearDown(self):
        fetchers.setDefaultFetcher(self.oldfetcher)

    def test_404(self):
        uri = "http://something.unittest/"
        self.assertRaises(DiscoveryFailure, discover, uri)


class TestDiscover(unittest.TestCase):
    base_url = 'http://invalid.unittest/'

    def setUp(self):
        fetchers.setDefaultFetcher(TestFetcher(self.base_url),
                                   wrap_exceptions=False)

    def tearDown(self):
        fetchers.setDefaultFetcher(None)

    def test(self):
        for success, input_name, id_name, result_name in discoverdata.testlist:
            input_url, expected = discoverdata.generateResult(
                self.base_url,
                input_name,
                id_name,
                result_name,
                success)

            if expected is DiscoveryFailure:
                self.assertRaises(DiscoveryFailure, discover, input_url)
            else:
                result = discover(input_url)
                self.assertEqual(result.request_uri, input_url)

                msg = 'Identity URL mismatch: actual = %r, expected = %r' % (
                    result.normalized_uri, expected.normalized_uri)
                self.assertEqual(result.normalized_uri, expected.normalized_uri, msg)

                msg = 'Content mismatch: actual = %r, expected = %r' % (
                    result.response_text, expected.response_text)
                self.assertEqual(result.response_text, expected.response_text, msg)

                expected_keys = sorted(dir(expected))
                actual_keys = sorted(dir(result))
                self.assertEqual(actual_keys, expected_keys)

                for k in dir(expected):
                    if k.startswith('__') and k.endswith('__'):
                        continue
                    exp_v = getattr(expected, k)
                    if isinstance(exp_v, types.MethodType):
                        continue
                    act_v = getattr(result, k)
                    assert act_v == exp_v, (k, exp_v, act_v)
