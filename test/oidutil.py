import sys
import string
import random
from openid import oidUtil

def test_reversed():
    if not hasattr(oidUtil, 'reversed'):
        # Make sure that if reversed is not defined in oidUtil, it's
        # provided in builtins.
        _ = reversed
        del _
    else:
        cases = [
            ('', ''),
            ('a', 'a'),
            ('ab', 'ba'),
            ('abc', 'cba'),
            ('abcdefg', 'gfedcba'),
            ([], []),
            ([1], [1]),
            ([1,2], [2,1]),
            ([1,2,3], [3,2,1]),
            (range(1000), range(999, -1, -1)),
            ]

        for case, expected in cases:
            expected = list(expected)
            actual = list(oidUtil.reversed(case))
            assert actual == expected, (case, expected, actual)
            twice = list(oidUtil.reversed(actual))
            assert twice == list(case), (actual, case, twice)

def test_strLongConvert():
    MAX = sys.maxint
    for iteration in xrange(500):
        n = 0L
        for i in range(10):
            n += long(random.randrange(MAX))

        s = oidUtil.longToStr(n)
        assert type(s) is str
        n_prime = oidUtil.strToLong(s)
        assert n == n_prime

    cases = [
        ('\x00', 0L),
        ('\x01', 1L),
        ('\xFF', -1L),
        ('\x80', -128L),
        ('\x81', -127L),
        ('\x80\x00', -32768L),
        ('OpenID is cool', 1611215304203901150134421257416556L)
        ]

    for s, n in cases:
        n_prime = oidUtil.strToLong(s)
        s_prime = oidUtil.longToStr(n)
        assert n == n_prime, (s, n, n_prime)
        assert s == s_prime, (n, s, s_prime)

    assert oidUtil.longToStr(0L) == '\x00'

def test_base64():
    allowed_s = string.letters + string.digits + '+/='
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
        ''.join(map(chr, range(256))),
        ]

    for s in cases:
        b64 = oidUtil.toBase64(s)
        checkEncoded(b64)
        s_prime = oidUtil.fromBase64(b64)
        assert s_prime == s, (s, b64, s_prime)

    # Randomized test
    for iteration in xrange(50):
        n = random.randrange(2048)
        s = ''.join(map(chr, map(lambda _: random.randrange(256), range(n))))
        b64 = oidUtil.toBase64(s)
        checkEncoded(b64)
        s_prime = oidUtil.fromBase64(b64)
        assert s_prime == s, (s, b64, s_prime)

def test_kvform():
    old_log = oidUtil.log
    try:
        def log(w_s):
            log.num_warnings += 1

        oidUtil.log = log

        cases = [
            # (kvform, parsed dictionary, expected warnings)
            ('', {}, 0),
            ('college:harvey mudd\n', {'college':'harvey mudd'}, 0),
            ('city:claremont\nstate:CA\n',
             {'city':'claremont', 'state':'CA'}, 0),
            ('is_valid:true\ninvalidate_handle:{HMAC-SHA1:2398410938412093}\n',
             {'is_valid':'true',
              'invalidate_handle':'{HMAC-SHA1:2398410938412093}'}, 0),

            # Warnings from lines with no colon:
            ('\n', {}, 1),
            ('\n\n', {}, 2),
            ('East is least\n', {}, 1),

            # Warning from empty key
            (':\n', {'':''}, 1),
            (':missing key\n', {'':'missing key'}, 1),

            # Warnings from leading or trailing whitespace in key or value
            (' street:foothill blvd\n', {'street':'foothill blvd'}, 1),
            ('major: computer science\n', {'major':'computer science'}, 1),
            (' dorm : east \n', {'dorm':'east'}, 2),

            # Warnings from missing trailing newline
            ('e^(i*pi)+1:0', {'e^(i*pi)+1':'0'}, 1),
            ('east:west\nnorth:south', {'east':'west', 'north':'south'}, 1),
            ]

        for case_kv, case_d, expected_warnings in cases:
            log.num_warnings = 0
            d = oidUtil.parsekv(case_kv)
            assert case_d == d
            assert log.num_warnings == expected_warnings, (
                case_kv, log.num_warnings, expected_warnings)
            kv = oidUtil.kvForm(d)
            d2 = oidUtil.parsekv(kv)
            assert d == d2

    finally:
        oidUtil.log = old_log

def test_strxor():
    NUL = '\x00'

    cases = [
        (NUL, NUL, NUL),
        ('\x01', NUL, '\x01'),
        ('a', 'a', NUL),
        ('a', NUL, 'a'),
        ('abc', NUL * 3, 'abc'),
        ('x' * 10, NUL * 10, 'x' * 10),
        ('\x01', '\x02', '\x03'),
        ('\xf0', '\x0f', '\xff'),
        ('\xff', '\x0f', '\xf0'),
        ]

    for aa, bb, expected in cases:
        actual = oidUtil.strxor(aa, bb)
        assert actual == expected, (aa, bb, expected, actual)

    exc_cases = [
        ('', 'a'),
        ('foo', 'ba'),
        (NUL * 3, NUL * 4),
        (''.join(map(chr, xrange(256))),
         ''.join(map(chr, xrange(128)))),
        ]

    for aa, bb in exc_cases:
        try:
            unexpected = oidUtil.strxor(aa, bb)
        except ValueError:
            pass
        else:
            assert False, 'Expected ValueError, got %r' % (unexpected,)

def test():
    test_reversed()
    test_strLongConvert()
    test_base64()
    test_kvform()
    test_strxor()

if __name__ == '__main__':
    test()
