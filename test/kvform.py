from openid import kvform
from openid import oidutil

def test_kvform():
    old_log = oidutil.log
    try:
        def log(unused_message, unused_level=None):
            log.num_warnings += 1

        oidutil.log = log

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
            ('x\n', {}, 1),
            ('x\nx\n', {}, 2),

            # But not from blank lines (because LJ generates them)
            ('x\n\n', {}, 1),
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
            d = kvform.kvToDict(case_kv)
            assert case_d == d
            assert log.num_warnings == expected_warnings, (
                case_kv, log.num_warnings, expected_warnings)
            kv = kvform.dictToKV(d)
            d2 = kvform.kvToDict(kv)
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
            actual = kvform.seqToKV(case)
            assert actual == expected, (case, expected, actual)

            seq = kvform.kvToSeq(actual)

            # Expected to be unchanged, except stripping whitespace
            # from start and end of values (i. e. ordering, case, and
            # internal whitespace is preserved)
            expected_seq = []
            for k, v in case:
                expected_seq.append((k.strip(), v.strip()))

            assert seq == expected_seq, (case, expected_seq, seq)

        log.num_warnings = 0
        result = kvform.seqToKV([(1,1)])
        assert result == '1:1\n'
        assert log.num_warnings == 2

        exceptional_cases = [
            [('openid', 'use\nful')],
            [('open\nid', 'useful')],
            [('open\nid', 'use\nful')],
            ]
        for case in exceptional_cases:
            try:
                unexpected = kvform.seqToKV(case)
            except ValueError:
                pass
            else:
                assert False, 'Expected ValueError, got %r' % (unexpected,)

    finally:
        oidutil.log = old_log

def test():
    test_kvform()

if __name__ == '__main__':
    test()
