# -*- coding: utf-8 -*-
"""Tests for `openid.urinorm` module."""
from __future__ import unicode_literals

import unittest

from openid.urinorm import urinorm


class UrinormTest(unittest.TestCase):
    """Test `urinorm` function."""

    def test_normalized(self):
        self.assertEqual(urinorm('http://example.com/'), 'http://example.com/')
        self.assertEqual(urinorm(b'http://example.com/'), 'http://example.com/')

    def test_lowercase_scheme(self):
        self.assertEqual(urinorm('htTP://example.com/'), 'http://example.com/')

    def test_unsupported_scheme(self):
        self.assertRaisesRegexp(ValueError, 'Not an absolute HTTP or HTTPS URI', urinorm, 'ftp://example.com/')

    def test_lowercase_hostname(self):
        self.assertEqual(urinorm('http://exaMPLE.COm/'), 'http://example.com/')

    def test_idn_hostname(self):
        self.assertEqual(urinorm('http://π.example.com/'), 'http://xn--1xa.example.com/')

    def test_empty_hostname(self):
        self.assertEqual(urinorm('http://username@/'), 'http://username@/')

    def test_invalid_hostname(self):
        self.assertRaisesRegexp(ValueError, 'Invalid hostname', urinorm, 'http://.it/')
        self.assertRaisesRegexp(ValueError, 'Invalid hostname', urinorm, 'http://..it/')
        self.assertRaisesRegexp(ValueError, 'Not an absolute URI', urinorm, 'http:///path/')

    def test_empty_port_section(self):
        self.assertEqual(urinorm('http://example.com:/'), 'http://example.com/')

    def test_default_ports(self):
        self.assertEqual(urinorm('http://example.com:80/'), 'http://example.com/')
        self.assertEqual(urinorm('https://example.com:443/'), 'https://example.com/')

    def test_empty_path(self):
        self.assertEqual(urinorm('http://example.com'), 'http://example.com/')

    def test_path_dots(self):
        self.assertEqual(urinorm('http://example.com/./a'), 'http://example.com/a')
        self.assertEqual(urinorm('http://example.com/../a'), 'http://example.com/a')

        self.assertEqual(urinorm('http://example.com/a/.'), 'http://example.com/a/')
        self.assertEqual(urinorm('http://example.com/a/..'), 'http://example.com/')
        self.assertEqual(urinorm('http://example.com/a/./'), 'http://example.com/a/')
        self.assertEqual(urinorm('http://example.com/a/../'), 'http://example.com/')

        self.assertEqual(urinorm('http://example.com/a/./b'), 'http://example.com/a/b')
        self.assertEqual(urinorm('http://example.com/a/../b'), 'http://example.com/b')

        self.assertEqual(urinorm('http://example.com/a/b/c/./../../g'), 'http://example.com/a/g')
        self.assertEqual(urinorm('http://example.com/mid/content=5/../6'), 'http://example.com/mid/6')

    def test_path_percent_encoding(self):
        self.assertEqual(urinorm('http://example.com/'), 'http://example.com/%08')
        self.assertEqual(urinorm('http://example.com/Λ'), 'http://example.com/%CE%9B')

    def test_path_capitalize_percent_encoding(self):
        self.assertEqual(urinorm('http://example.com/foo%2cbar'), 'http://example.com/foo%2Cbar')

    def test_path_percent_decode_unreserved(self):
        self.assertEqual(urinorm('http://example.com/foo%2Dbar%2dbaz'), 'http://example.com/foo-bar-baz')

    def test_illegal_characters(self):
        self.assertRaisesRegexp(ValueError, 'Illegal characters in URI', urinorm, 'http://<illegal>.com/')

    def test_realms(self):
        # Urinorm supports OpenID realms with * in them
        self.assertEqual(urinorm('http://*.example.com/'), 'http://*.example.com/')
