import unittest

from openid.consumer.discover import OpenIDServiceEndpoint


class TestFromHTML(unittest.TestCase):
    """Test `OpenIDServiceEndpoint.fromHTML`."""

    def test_empty(self):
        self.assertEqual(OpenIDServiceEndpoint.fromHTML('http://example.url/', ''), [])

    def test_invalid_html(self):
        self.assertEqual(OpenIDServiceEndpoint.fromHTML('http://example.url/', "http://not.in.a.link.tag/"), [])

    def test_no_op_url(self):
        html = '<html><head><link rel="openid.server"></head></html>'
        self.assertEqual(OpenIDServiceEndpoint.fromHTML('http://example.url/', html), [])
