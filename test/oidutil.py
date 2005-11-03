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

# XXX: there are more functions that could benefit from being better
# specified and tested in oidutil.py These include, but are not
# limited to appendArgs

def test():
    test_base64()

if __name__ == '__main__':
    test()
