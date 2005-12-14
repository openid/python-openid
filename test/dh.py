import os.path
from openid.dh import DiffieHellman

def test1():
    dh1 = DiffieHellman()
    dh2 = DiffieHellman()
    secret1 = dh1.getSharedSecret(dh2.public)
    secret2 = dh2.getSharedSecret(dh1.public)
    assert secret1 == secret2
    return secret1

def test():
    s1 = test1()
    s2 = test1()
    assert s1 != s2

def test_public():
    f = file(os.path.join(os.path.dirname(__file__), 'dhpriv'))
    dh = DiffieHellman()
    try:
        for line in f:
            parts = line.strip().split(' ')
            dh._setPrivate(long(parts[0]))

            assert dh.public == long(parts[1])
    finally:
        f.close()

if __name__ == '__main__':
    test()
    test_public()
