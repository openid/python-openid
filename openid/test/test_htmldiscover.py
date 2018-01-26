import unittest

from openid.consumer.discover import OpenIDServiceEndpoint


class BadLinksTestCase(unittest.TestCase):
    cases = [
        '',
        "http://not.in.a.link.tag/",
        '<link rel="openid.server" href="not.in.html.or.head" />',
    ]

    def test_from_html(self):
        for html in self.cases:
            actual = OpenIDServiceEndpoint.fromHTML('http://unused.url/', html)
            self.assertEqual(actual, [])
