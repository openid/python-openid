from openid import association
import time

def test():
    issued = time.time()
    lifetime = 600
    assoc = association.Association(
        'handle', 'secret', issued, lifetime, 'HMAC-SHA1')
    s = assoc.serialize()
    assoc2 = association.Association.deserialize(s)

if __name__ == '__main__':
    test()
