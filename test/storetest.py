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
    ### Association functions

    server_url = 'http://www.myopenid.com/openid'
    secret = generateSecret(20)
    handle = generateHandle(128)

    assoc = ConsumerAssociation.fromExpiresIn(600, server_url, handle, secret)

    # Make sure that a missing association returns no result
    missing_assoc = store.getAssociation(server_url, handle)
    assert missing_assoc is None

    # Check that after storage, getting returns the same result
    store.storeAssociation(assoc)
    retrieved_assoc = store.getAssociation(server_url, handle)
    assert retrieved_assoc.secret == assoc.secret
    assert retrieved_assoc.handle == assoc.handle
    assert retrieved_assoc.server_url == assoc.server_url

    # more than once
    retrieved_assoc = store.getAssociation(server_url, handle)
    assert retrieved_assoc.secret == assoc.secret
    assert retrieved_assoc.handle == assoc.handle
    assert retrieved_assoc.server_url == assoc.server_url

    # Storing more than once has no ill effect
    store.storeAssociation(assoc)
    retrieved_assoc = store.getAssociation(server_url, handle)
    assert retrieved_assoc.secret == assoc.secret
    assert retrieved_assoc.handle == assoc.handle
    assert retrieved_assoc.server_url == assoc.server_url

    # Getting with the same url but a wrong handle returns no result
    wrong_handle = generateHandle(128)
    retrieved_assoc = store.getAssociation(server_url, wrong_handle)
    assert retrieved_assoc is None

    # and does not affect the existing data
    retrieved_assoc = store.getAssociation(server_url, handle)
    assert retrieved_assoc.secret == assoc.secret
    assert retrieved_assoc.handle == assoc.handle
    assert retrieved_assoc.server_url == assoc.server_url

    # Removing an association that does not exist returns not present
    present = store.removeAssociation(server_url, wrong_handle)
    assert not present

    # Removing an association that is present returns present
    present = store.removeAssociation(server_url, handle)
    assert present

    # but not present on subsequent calls
    present = store.removeAssociation(server_url, handle)
    assert not present

    # One association with server_url
    store.storeAssociation(assoc)
    assoc2 = ConsumerAssociation.fromExpiresIn(
        600, server_url, wrong_handle, secret)
    store.storeAssociation(assoc2)

    # After storing an association with a different handle, but the
    # same server_url, the most recent association is available. There
    # is no guarantee either way about the first association.
    retrieved_assoc = store.getAssociation(server_url, wrong_handle)
    assert retrieved_assoc.server_url == server_url
    assert retrieved_assoc.handle == wrong_handle
    assert retrieved_assoc.secret == secret

    ### Nonce functions

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

    ### Auth key functions

    # There is no key to start with, so generate a new key and return it.
    key = store.getAuthKey()

    # The second time around should return the same as last time.
    key2 = store.getAuthKey()
    assert key == key2
    assert len(key) == store.AUTH_KEY_LEN

    # The store rejects keys of the wrong length
    bad_auth_key = ''
    try:
        store.setAuthKey(bad_auth_key)
    except ValueError:
        pass
    else:
        assert False, 'Bad auth key set successfully'

    # The store allows you to set a specific key even if there is
    # already a key present.
    new_key = generateSecret(store.AUTH_KEY_LEN)
    store.setAuthKey(new_key)
    key = store.getAuthKey()
    assert key == new_key

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
