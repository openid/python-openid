from openid.consumer.stores import ConsumerAssociation
from openid import util

import string
import random

allowed_handle = []
for c in string.printable:
    if c not in string.whitespace:
        allowed_handle.append(c)
allowed_handle = ''.join(allowed_handle)

rand = random.SystemRandom()

def generateHandle(n):
    handle_chars = []
    for _ in xrange(n):
        handle_chars.append(rand.choice(allowed_handle))
    return ''.join(handle_chars)

def generateSecret(n):
    return util.random_string(n, rand)

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
