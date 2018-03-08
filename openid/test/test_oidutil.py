# -*- coding: utf-8 -*-
"""Test `openid.oidutil` module."""
import random
import string
import unittest

from openid import oidutil


class TestBase64(unittest.TestCase):
    """Test `toBase64` and `fromBase64` functions."""

    def test_base64(self):
        allowed_s = string.ascii_letters + string.digits + '+/='
        allowed_d = {}
        for c in allowed_s:
            allowed_d[c] = None
        isAllowed = allowed_d.has_key

        def checkEncoded(s):
            for c in s:
                assert isAllowed(c), s

        cases = [
            '',
            'x',
            '\x00',
            '\x01',
            '\x00' * 100,
            ''.join(chr(i) for i in range(256)),
        ]

        for s in cases:
            b64 = oidutil.toBase64(s)
            checkEncoded(b64)
            s_prime = oidutil.fromBase64(b64)
            assert s_prime == s, (s, b64, s_prime)

        # Randomized test
        for _ in xrange(50):
            n = random.randrange(2048)
            s = ''.join(chr(random.randrange(256)) for i in range(n))
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


class TestUnicodeConversion(unittest.TestCase):

    def test_toUnicode(self):
        # Unicode objects pass through
        self.assertIsInstance(oidutil.toUnicode(u'fööbär'), unicode)
        self.assertEquals(oidutil.toUnicode(u'fööbär'), u'fööbär')
        # UTF-8 encoded string are decoded
        self.assertIsInstance(oidutil.toUnicode('fööbär'), unicode)
        self.assertEquals(oidutil.toUnicode('fööbär'), u'fööbär')
        # Other encodings raise exceptions
        self.assertRaises(UnicodeDecodeError, lambda: oidutil.toUnicode(u'fööbär'.encode('latin-1')))


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
