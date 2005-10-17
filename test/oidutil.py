import sys
import string
import random
from openid import oidUtil

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
            d = oidUtil.kvToDict(case_kv)
            assert case_d == d
            assert log.num_warnings == expected_warnings, (
                case_kv, log.num_warnings, expected_warnings)
            kv = oidUtil.dictToKV(d)
            d2 = oidUtil.kvToDict(kv)
            assert d == d2

        cases = [
            ([], ''),
            ([('openid', 'useful'),
              ('a', 'b')], 'openid:useful\na:b\n'),
            ([(' openid', 'useful'),
              ('a', 'b')], ' openid:useful\na:b\n'),
            ([(' openid ', ' useful '),
              (' a ', ' b ')], ' openid : useful \n a : b \n'),
            ([(' open id ', ' use ful '),
              (' a ', ' b ')], ' open id : use ful \n a : b \n'),
            ]

        for case, expected in cases:
            actual = oidUtil.seqToKV(case)
            assert actual == expected, (case, expected, actual)

            seq = oidUtil.kvToSeq(actual)

            # Expected to be unchanged, except stripping whitespace
            # from start and end of values (i. e. ordering, case, and
            # internal whitespace is preserved)
            expected_seq = []
            for k, v in case:
                expected_seq.append((k.strip(), v.strip()))

            assert seq == expected_seq, (case, expected_seq, seq)

        log.num_warnings = 0
        result = oidUtil.seqToKV([(1,1)])
        assert result == '1:1\n'
        assert log.num_warnings == 2

        exceptional_cases = [
            [('openid', 'use\nful')],
            [('open\nid', 'useful')],
            [('open\nid', 'use\nful')],
            ]
        for case in exceptional_cases:
            try:
                unexpected = oidUtil.seqToKV(case)
            except ValueError:
                pass
            else:
                assert False, 'Expected ValueError, got %r' % (unexpected,)

    finally:
        oidUtil.log = old_log

# XXX: there are more functions that could benefit from being better
# specified and tested in oidUtil.py These include, but are not
# limited to appendArgs and signReply

def test():
    test_base64()
    test_kvform()

if __name__ == '__main__':
    test()
