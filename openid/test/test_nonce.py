import re
import unittest

from openid.store.nonce import checkTimestamp, mkNonce, split as splitNonce

nonce_re = re.compile(r'\A\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ')


class NonceTest(unittest.TestCase):
    def test_mkNonce(self):
        nonce = mkNonce()
        self.assertIsNotNone(nonce_re.match(nonce))
        self.assertEqual(len(nonce), 26)

    def test_mkNonce_when(self):
        nonce = mkNonce(0)
        self.assertIsNotNone(nonce_re.match(nonce))
        self.assertTrue(nonce.startswith('1970-01-01T00:00:00Z'))
        self.assertEqual(len(nonce), 26)

    def test_splitNonce(self):
        s = '1970-01-01T00:00:00Z'
        expected_t = 0
        expected_salt = ''
        actual_t, actual_salt = splitNonce(s)
        self.assertEqual(actual_t, expected_t)
        self.assertEqual(actual_salt, expected_salt)

    def test_mkSplit(self):
        t = 42
        nonce_str = mkNonce(t)
        self.assertIsNotNone(nonce_re.match(nonce_str))
        et, salt = splitNonce(nonce_str)
        self.assertEqual(len(salt), 6)
        self.assertEqual(et, t)


class BadSplitTest(unittest.TestCase):
    cases = [
        '',
        '1970-01-01T00:00:00+1:00',
        '1969-01-01T00:00:00Z',
        '1970-00-01T00:00:00Z',
        '1970.01-01T00:00:00Z',
        'Thu Sep  7 13:29:31 PDT 2006',
        'monkeys',
    ]

    def test(self):
        for nonce_str in self.cases:
            self.assertRaises(ValueError, splitNonce, nonce_str)


class CheckTimestampTest(unittest.TestCase):
    cases = [
        # exact, no allowed skew
        ('1970-01-01T00:00:00Z', 0, 0, True),

        # exact, large skew
        ('1970-01-01T00:00:00Z', 1000, 0, True),

        # no allowed skew, one second old
        ('1970-01-01T00:00:00Z', 0, 1, False),

        # many seconds old, outside of skew
        ('1970-01-01T00:00:00Z', 10, 50, False),

        # one second old, one second skew allowed
        ('1970-01-01T00:00:00Z', 1, 1, True),

        # One second in the future, one second skew allowed
        ('1970-01-01T00:00:02Z', 1, 1, True),

        # two seconds in the future, one second skew allowed
        ('1970-01-01T00:00:02Z', 1, 0, False),

        # malformed nonce string
        ('monkeys', 0, 0, False),
    ]

    def test(self):
        for nonce_string, allowed_skew, now, expected in self.cases:
            actual = checkTimestamp(nonce_string, allowed_skew, now)
            self.assertEqual(bool(actual), bool(expected))
