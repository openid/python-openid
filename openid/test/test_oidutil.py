# -*- coding: utf-8 -*-
"""Test `openid.oidutil` module."""
from __future__ import unicode_literals

import random
import string
import unittest
import warnings

import six
from mock import sentinel
from testfixtures import ShouldWarn

from openid import oidutil
from openid.oidutil import string_to_text


class TestBase64(unittest.TestCase):
    """Test `toBase64` and `fromBase64` functions."""

    def test_base64(self):
        allowed_s = string.ascii_letters + string.digits + '+/='
        allowed_d = {}
        for c in allowed_s:
            allowed_d[c] = None

        def checkEncoded(s):
            for c in s:
                self.assertIn(c, allowed_d, msg=s)

        cases = [
            b'',
            b'x',
            b'\x00',
            b'\x01',
            b'\x00' * 100,
        ]
        if six.PY2:
            cases.append(b''.join(chr(i) for i in range(256)))
        else:
            assert six.PY3
            cases.append(bytes(i for i in range(256)))

        for s in cases:
            b64 = oidutil.toBase64(s)
            checkEncoded(b64)
            s_prime = oidutil.fromBase64(b64)
            assert s_prime == s, (s, b64, s_prime)

        # Randomized test
        for _ in range(50):
            n = random.randrange(2048)
            if six.PY2:
                s = b''.join(chr(random.randrange(256)) for i in range(n))
            else:
                assert six.PY3
                s = bytes(random.randrange(256) for i in range(n))
            b64 = oidutil.toBase64(s)
            checkEncoded(b64)
            s_prime = oidutil.fromBase64(b64)
            assert s_prime == s, (s, b64, s_prime)


simple = 'http://www.example.com/'
append_args_cases = [
    ('empty list',
     (simple, []),
     simple),

    ('empty dict',
     (simple, {}),
     simple),

    ('one list',
     (simple, [('a', 'b')]),
     simple + '?a=b'),

    ('one dict',
     (simple, {'a': 'b'}),
     simple + '?a=b'),

    ('two list (same)',
     (simple, [('a', 'b'), ('a', 'c')]),
     simple + '?a=b&a=c'),

    ('two list',
     (simple, [('a', 'b'), ('b', 'c')]),
     simple + '?a=b&b=c'),

    ('two list (order)',
     (simple, [('b', 'c'), ('a', 'b')]),
     simple + '?b=c&a=b'),

    ('two dict (order)',
     (simple, {'b': 'c', 'a': 'b'}),
     simple + '?a=b&b=c'),

    ('escape',
     (simple, [('=', '=')]),
     simple + '?%3D=%3D'),

    ('escape (URL)',
     (simple, [('this_url', simple)]),
     simple + '?this_url=http%3A%2F%2Fwww.example.com%2F'),

    ('use dots',
     (simple, [('openid.stuff', 'bother')]),
     simple + '?openid.stuff=bother'),

    ('args exist (empty)',
     (simple + '?stuff=bother', []),
     simple + '?stuff=bother'),

    ('args exist',
     (simple + '?stuff=bother', [('ack', 'ack')]),
     simple + '?stuff=bother&ack=ack'),

    ('args exist',
     (simple + '?stuff=bother', [('ack', 'ack')]),
     simple + '?stuff=bother&ack=ack'),

    ('args exist (dict)',
     (simple + '?stuff=bother', {'ack': 'ack'}),
     simple + '?stuff=bother&ack=ack'),

    ('args exist (dict 2)',
     (simple + '?stuff=bother', {'ack': 'ack', 'zebra': 'lion'}),
     simple + '?stuff=bother&ack=ack&zebra=lion'),

    ('three args (dict)',
     (simple, {'stuff': 'bother', 'ack': 'ack', 'zebra': 'lion'}),
     simple + '?ack=ack&stuff=bother&zebra=lion'),

    ('three args (list)',
     (simple, [('stuff', 'bother'), ('ack', 'ack'), ('zebra', 'lion')]),
     simple + '?stuff=bother&ack=ack&zebra=lion'),
]


class AppendArgsTest(unittest.TestCase):
    """Test `appendArgs` function."""

    def runTest(self):
        for name, args, expected in append_args_cases:
            result = oidutil.appendArgs(*args)
            self.assertEqual(expected, result, '{} {}'.format(name, args))


class TestSymbol(unittest.TestCase):
    def testCopyHash(self):
        import copy
        s = oidutil.Symbol("Foo")
        d = {s: 1}
        d_prime = copy.deepcopy(d)
        self.assertIn(s, d_prime, "%r isn't in %r" % (s, d_prime))

        t = oidutil.Symbol("Bar")
        self.assertNotEqual(hash(s), hash(t))


# XXX: there are more functions that could benefit from being better
# specified and tested in oidutil.py These include, but are not
# limited to appendArgs


class TestToText(unittest.TestCase):
    """Test `string_to_text` utility function."""

    def test_text_input(self):
        result = string_to_text('ěščřž', sentinel.msg)
        self.assertIsInstance(result, six.text_type)
        self.assertEqual(result, 'ěščřž')

    def test_binary_input(self):
        warning_msg = 'Conversion warning'
        with ShouldWarn(DeprecationWarning(warning_msg)):
            warnings.simplefilter('always')
            result = string_to_text('ěščřž'.encode('utf-8'), warning_msg)

        self.assertIsInstance(result, six.text_type)
        self.assertEqual(result, 'ěščřž')
