"""Test the consumer."""
from __future__ import unicode_literals

import django
from django.test import TestCase
from openid.fetchers import setDefaultFetcher, HTTPResponse
from openid.yadis.constants import YADIS_CONTENT_TYPE

# Allow django tests to run through discover
django.setup()


EXAMPLE_XRDS = b'''<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS xmlns:xrds="xri://$xrds" xmlns="xri://$xrd*($v*2.0)">
  <XRD>
    <Service priority="0">
      <Type>http://specs.openid.net/auth/2.0/server</Type>
      <URI>http://example.com/</URI>
    </Service>
  </XRD>
</xrds:XRDS>'''


class FakeFetcher(object):
    """Fake fetcher for tests."""

    def __init__(self):
        self.response = None

    def fetch(self, *args, **kwargs):
        return self.response


class TestStartOpenID(TestCase):
    """Test 'startOpenID' view."""

    def setUp(self):
        self.fetcher = FakeFetcher()
        setDefaultFetcher(self.fetcher)

    def tearDown(self):
        setDefaultFetcher(None)

    def test_get(self):
        response = self.client.get('/consumer/')
        self.assertContains(response, ' example consumer ')

    def test_post(self):
        self.fetcher.response = HTTPResponse('http://example.com/', 200, {'content-type': YADIS_CONTENT_TYPE},
                                             EXAMPLE_XRDS)

        response = self.client.post('/consumer/', {'openid_identifier': 'http://example.com/'})

        # Renders a POST form
        self.assertContains(response, 'http://example.com/')
        self.assertContains(response, 'openid.identity')
