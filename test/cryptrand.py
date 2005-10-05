from openid import cryptrand

# Most of the purpose of this test is to make sure that cryptrand can
# find a good source of randomness on this machine.

def test():
    # It's possible, but HIGHLY unlikely that a correct implementation
    # will fail by returning the same number twice (probability 2 **
    # -53 for the random() test, 2 ** -256 for getBytes)

    x = cryptrand.srand.random()
    y = cryptrand.srand.random()
    assert x != y

    s = cryptrand.getBytes(32)
    t = cryptrand.getBytes(32)
    assert len(s) == 32
    assert len(t) == 32
    assert s != t

if __name__ == '__main__':
    test()
