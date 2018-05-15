"""Tests for `openid.yadis.parsehtml` module."""
from __future__ import unicode_literals

import unittest

from mock import sentinel
from six import StringIO

from openid.yadis.parsehtml import MetaNotFound, findHTMLMeta, xpath_lower_case


class TestXpathLowerCase(unittest.TestCase):
    """Test `xpath_lower_case` function."""

    def test_lower_case(self):
        self.assertEqual(xpath_lower_case(sentinel.context, ['CaMeLcAsE']), ['camelcase'])


class TestFindHTMLMeta(unittest.TestCase):
    """Test `findHTMLMeta` function."""

    def test_html(self):
        buff = StringIO('<html><head><meta http-equiv="X-XRDS-Location" content="found"></head></html>')
        self.assertEqual(findHTMLMeta(buff), 'found')

    def test_xhtml(self):
        buff = StringIO('<html><head><meta http-equiv="X-XRDS-Location" content="found" /></head></html>')
        self.assertEqual(findHTMLMeta(buff), 'found')

    def test_case_insensitive_header_name(self):
        buff = StringIO('<html><head><meta http-equiv="x-xrds-location" content="found"></head></html>')
        self.assertEqual(findHTMLMeta(buff), 'found')

    def test_missing_end_tags(self):
        buff = StringIO('<html><head><meta http-equiv="X-XRDS-Location" content="found">')
        self.assertEqual(findHTMLMeta(buff), 'found')

    def test_missing_html_header(self):
        buff = StringIO('<meta http-equiv="X-XRDS-Location" content="found">')
        self.assertEqual(findHTMLMeta(buff), 'found')

    def test_missing_head_tag(self):
        buff = StringIO('<html><meta http-equiv="X-XRDS-Location" content="found">')
        self.assertEqual(findHTMLMeta(buff), 'found')

    def test_top_level_bogus(self):
        buff = StringIO('</porky><html><head><meta http-equiv="X-XRDS-Location" content="found">')
        self.assertEqual(findHTMLMeta(buff), 'found')

    def test_missing_html_tag(self):
        buff = StringIO('<head><meta http-equiv="X-XRDS-Location" content="found">')
        self.assertEqual(findHTMLMeta(buff), 'found')

    def test_javascript_in_head(self):
        buff = StringIO('<html><head><script type="text/javascript">document.write("<body>");</script>'
                        '<META http-equiv="X-XRDS-Location" content="found">')
        self.assertEqual(findHTMLMeta(buff), 'found')

    def test_multiple_headers(self):
        buff = StringIO('<html><head>'
                        '<meta http-equiv="X-XRDS-Location" content="found">'
                        '<meta http-equiv="X-XRDS-Location" content="not-found">')
        self.assertEqual(findHTMLMeta(buff), 'found')

    def test_standard_entity(self):
        buff = StringIO('<head><meta http-equiv="X-XRDS-Location" content="&amp;">')
        self.assertEqual(findHTMLMeta(buff), '&')

    def test_hex_entity(self):
        buff = StringIO('<head><meta http-equiv="X-XRDS-Location" content="&#x66;ound">')
        self.assertEqual(findHTMLMeta(buff), 'found')

    def test_decimal_entity(self):
        buff = StringIO('<head><meta http-equiv="X-XRDS-Location" content="&#102;ound">')
        self.assertEqual(findHTMLMeta(buff), 'found')

    def test_empty_string(self):
        buff = StringIO('<head><meta http-equiv="X-XRDS-Location" content="">')
        self.assertEqual(findHTMLMeta(buff), '')

    def test_empty_input(self):
        buff = StringIO('')
        self.assertRaises(MetaNotFound, findHTMLMeta, buff)

    def test_invalid_html(self):
        buff = StringIO('<!bad processing instruction!>')
        self.assertRaises(MetaNotFound, findHTMLMeta, buff)

    def test_meta_in_body(self):
        buff = StringIO('<html><head><body><meta http-equiv="X-XRDS-Location" content="found">')
        self.assertRaises(MetaNotFound, findHTMLMeta, buff)

    def test_no_content(self):
        buff = StringIO('<html><head><meta http-equiv="X-XRDS-Location"></head></html>')
        self.assertRaises(MetaNotFound, findHTMLMeta, buff)

    def test_commented_header(self):
        buff = StringIO('<html><head>'
                        '<!--<meta http-equiv="X-XRDS-Location" content="found">-->'
                        '</head></html>')
        self.assertRaises(MetaNotFound, findHTMLMeta, buff)

    def test_no_yadis_header(self):
        buff = StringIO("<html><head><title>A boring document</title></head>"
                        "<body><h1>A boring document</h1><p>There's really nothing interesting about this</p></body>"
                        "</html>")
        self.assertRaises(MetaNotFound, findHTMLMeta, buff)

    def test_unclosed_tag(self):
        # script tag not closed
        buff = StringIO('<html><head><script type="text/javascript">document.write("<body>");'
                        '<META http-equiv="X-XRDS-Location" content="found">')
        self.assertRaises(MetaNotFound, findHTMLMeta, buff)

    def test_xrds(self):
        # Test parsing XRDS document as HTML
        buff = StringIO('<?xml version="1.0" encoding="UTF-8"?>'
                        '<xrds:XRDS xmlns:xrds="xri://$xrds" xmlns="xri://$xrd*($v*2.0)"><XRD>'
                        '<Service priority="0">'
                        '<Type>http://example.com/</Type><URI>http://www.openidenabled.com/</URI>'
                        '</Service>'
                        '</XRD></xrds:XRDS>')
        self.assertRaises(MetaNotFound, findHTMLMeta, buff)
