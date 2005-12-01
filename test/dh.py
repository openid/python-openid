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

if __name__ == '__main__':
    test()
