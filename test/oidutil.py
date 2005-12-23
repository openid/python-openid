import codecs
import string
import random
from openid import oidutil

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
        b64 = oidutil.toBase64(s)
        checkEncoded(b64)
        s_prime = oidutil.fromBase64(b64)
        assert s_prime == s, (s, b64, s_prime)

    # Randomized test
    for _ in xrange(50):
        n = random.randrange(2048)
        s = ''.join(map(chr, map(lambda _: random.randrange(256), range(n))))
        b64 = oidutil.toBase64(s)
        checkEncoded(b64)
        s_prime = oidutil.fromBase64(b64)
        assert s_prime == s, (s, b64, s_prime)

def test_normalizeUrl():
    n = oidutil.normalizeUrl

    assert 'http://foo.com/' == n('foo.com')

    assert 'http://foo.com/' == n('http://foo.com')
    assert 'https://foo.com/' == n('https://foo.com')
    assert 'http://foo.com/bar' == n('foo.com/bar')
    assert 'http://foo.com/bar' == n('http://foo.com/bar')

    assert 'http://foo.com/' == n('http://foo.com/')
    assert 'https://foo.com/' == n('https://foo.com/')
    assert 'https://foo.com/bar'  == n('https://foo.com/bar')

    assert 'http://foo.com/%E8%8D%89' == n(u'foo.com/\u8349')
    assert 'http://foo.com/%E8%8D%89' == n(u'http://foo.com/\u8349')

    non_ascii_domain_cases = [
        ('http://xn--vl1a.com/', u'\u8349.com'),
        ('http://xn--vl1a.com/', u'http://\u8349.com'),
        ('http://xn--vl1a.com/', u'\u8349.com/'),
        ('http://xn--vl1a.com/', u'http://\u8349.com/'),
        ('http://xn--vl1a.com/%E8%8D%89', u'\u8349.com/\u8349'),
        ('http://xn--vl1a.com/%E8%8D%89', u'http://\u8349.com/\u8349'),
        ]

    try:
        codecs.getencoder('idna')
    except LookupError:
        # If there is no idna codec, these cases with
        # non-ascii-representable domain names should fail.
        should_raise = True
    else:
        should_raise = False

    for expected, case in non_ascii_domain_cases:
        try:
            actual = n(case)
        except UnicodeError:
            assert should_raise
        else:
            assert not should_raise and actual == expected, case

    assert n(None) is None
    assert n('') is None
    assert n('http://') is None

# XXX: there are more functions that could benefit from being better
# specified and tested in oidutil.py These include, but are not
# limited to appendArgs

def test():
    test_base64()
    test_normalizeUrl()

if __name__ == '__main__':
    test()
