from openid.consumer.stores import ConsumerAssociation
from openid import util

import string
import random

allowed_handle = []
for c in string.printable:
    if c not in string.whitespace:
        allowed_handle.append(c)
allowed_handle = ''.join(allowed_handle)

allowed_secret = ''.join(map(chr, range(256)))

allowed_nonce = string.letters + string.digits

rand = random.SystemRandom()

def rnd(n, pop):
    chars = []
    for _ in xrange(n):
        chars.append(rand.choice(pop))
    return ''.join(chars)

def generateHandle(n):
    return rnd(n, allowed_handle)

def generateSecret(n):
    return rnd(n, allowed_secret)

def generateNonce():
    return rnd(8, allowed_nonce)

def testStore(store):
    server_url = 'http://www.myopenid.com/openid'
    secret = generateSecret(20)
    handle = generateHandle(128)

    assoc = ConsumerAssociation.fromExpiresIn(600, server_url, handle, secret)

    missing_assoc = store.getAssociation(server_url, handle)

    assert missing_assoc is None

    store.storeAssociation(assoc)
    retrieved_assoc = store.getAssociation(server_url, handle)
    assert retrieved_assoc.secret == assoc.secret
    assert retrieved_assoc.handle == assoc.handle
    assert retrieved_assoc.server_url == assoc.server_url

    retrieved_assoc = store.getAssociation(server_url, handle)
    assert retrieved_assoc.secret == assoc.secret
    assert retrieved_assoc.handle == assoc.handle
    assert retrieved_assoc.server_url == assoc.server_url

    store.storeAssociation(assoc)
    retrieved_assoc = store.getAssociation(server_url, handle)
    assert retrieved_assoc.secret == assoc.secret
    assert retrieved_assoc.handle == assoc.handle
    assert retrieved_assoc.server_url == assoc.server_url

    wrong_handle = generateHandle(128)
    retrieved_assoc = store.getAssociation(server_url, wrong_handle)
    assert retrieved_assoc is None

    present = store.removeAssociation(server_url, wrong_handle)
    assert not present

    present = store.removeAssociation(server_url, handle)
    assert present

    present = store.removeAssociation(server_url, handle)
    assert not present

    # Nonce functions

    # Random nonce (not in store)
    nonce1 = generateNonce()

    # A nonce is not present by default
    present = store.useNonce(nonce1)
    assert not present

    # Storing once causes useNonce to return True the first, and only
    # the first, time it is called after the store.
    store.storeNonce(nonce1)
    present = store.useNonce(nonce1)
    assert present
    present = store.useNonce(nonce1)
    assert not present

    # Storing twice has the same effect as storing once.
    store.storeNonce(nonce1)
    store.storeNonce(nonce1)
    present = store.useNonce(nonce1)
    assert present
    present = store.useNonce(nonce1)
    assert not present

if __name__ == '__main__':
    from openid.consumer import filestore
    import tempfile
    import shutil
    temp_dir = tempfile.mkdtemp()
    try:
        store = filestore.FilesystemOpenIDStore(temp_dir)
        testStore(store)
    finally:
        shutil.rmtree(temp_dir)
