import unittest
import codecs
import string
import random
from openid import oidutil

def test_base64():
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

class AppendArgsTest(unittest.TestCase):
    def __init__(self, desc, args, expected):
        unittest.TestCase.__init__(self)
        self.desc = desc
        self.args = args
        self.expected = expected

    def runTest(self):
        result = oidutil.appendArgs(*self.args)
        self.assertEqual(self.expected, result, self.args)

    def shortDescription(self):
        return self.desc

def buildAppendTests():
    simple = 'http://www.example.com/'
    cases = [
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
         (simple, {'a':'b'}),
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
         (simple, {'b':'c', 'a':'b'}),
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
         (simple + '?stuff=bother', {'ack': 'ack', 'zebra':'lion'}),
         simple + '?stuff=bother&ack=ack&zebra=lion'),

        ('three args (dict)',
         (simple, {'stuff': 'bother', 'ack': 'ack', 'zebra':'lion'}),
         simple + '?ack=ack&stuff=bother&zebra=lion'),

        ('three args (list)',
         (simple, [('stuff', 'bother'), ('ack', 'ack'), ('zebra', 'lion')]),
         simple + '?stuff=bother&ack=ack&zebra=lion'),
        ]

    tests = []

    for name, args, expected in cases:
        test = AppendArgsTest(name, args, expected)
        tests.append(test)

    return unittest.TestSuite(tests)

def pyUnitTests():
    return buildAppendTests()

def test_appendArgs():
    suite = buildAppendTests()
    runner = unittest.TextTestRunner()
    result = runner.run(suite)
    assert result.wasSuccessful()

# XXX: there are more functions that could benefit from being better
# specified and tested in oidutil.py These include, but are not
# limited to appendArgs

def test(skipPyUnit=True):
    test_base64()
    test_normalizeUrl()
    if not skipPyUnit:
        test_appendArgs()

if __name__ == '__main__':
    test(skipPyUnit=False)
