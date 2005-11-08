from openid.association import Association
from openid.cryptutil import randomString

import string
import time

allowed_handle = []
for c in string.printable:
    if c not in string.whitespace:
        allowed_handle.append(c)
allowed_handle = ''.join(allowed_handle)

def generateHandle(n):
    return randomString(n, allowed_handle)

generateSecret = randomString

allowed_nonce = string.letters + string.digits
def generateNonce():
    return randomString(8, allowed_nonce)

def testStore(store):
    """Make sure a given store has a minimum of API compliance. Call
    this function with an empty store.

    Raises AssertionError if the store does not work as expected.

    OpenIDStore -> NoneType
    """

    ### Association functions
    now = int(time.time())

    server_url = 'http://www.myopenid.com/openid'
    def genAssoc(issued=0, lifetime=600):
        sec = generateSecret(20)
        hdl = generateHandle(128)
        return Association(hdl, sec, now + issued, lifetime, 'HMAC-SHA1')

    def checkRetrieve(url, handle=None, expected=None):
        retrieved_assoc = store.getAssociation(url, handle)
        if expected is None or store.isDumb():
            assert retrieved_assoc is None
        else:
            assert retrieved_assoc == expected, (retrieved_assoc, expected)
            if retrieved_assoc is expected:
                print ('Unexpected: retrieved a reference to the expected '
                       'value instead of a new object')
            assert retrieved_assoc.handle == expected.handle
            assert retrieved_assoc.secret == expected.secret

    def checkRemove(url, handle, expected):
        present = store.removeAssociation(url, handle)
        expectedPresent = (not store.isDumb()) and expected
        assert ((not expectedPresent and not present) or
                (expectedPresent and present))

    assoc = genAssoc()

    # Make sure that a missing association returns no result
    checkRetrieve(server_url)

    # Check that after storage, getting returns the same result
    store.storeAssociation(server_url, assoc)
    checkRetrieve(server_url, None, assoc)

    # more than once
    checkRetrieve(server_url, None, assoc)

    # Storing more than once has no ill effect
    store.storeAssociation(server_url, assoc)
    checkRetrieve(server_url, None, assoc)

    # Removing an association that does not exist returns not present
    checkRemove(server_url, assoc.handle + 'x', False)

    # Removing an association that does not exist returns not present
    checkRemove(server_url + 'x', assoc.handle, False)

    # Removing an association that is present returns present
    checkRemove(server_url, assoc.handle, True)

    # but not present on subsequent calls
    checkRemove(server_url, assoc.handle, False)

    # Put assoc back in the store
    store.storeAssociation(server_url, assoc)

    # More recent and expires after assoc
    assoc2 = genAssoc(issued=1)
    store.storeAssociation(server_url, assoc2)

    # After storing an association with a different handle, but the
    # same server_url, the handle with the later expiration is returned.
    checkRetrieve(server_url, None, assoc2)

    # We can still retrieve the older association
    checkRetrieve(server_url, assoc.handle, assoc)

    # Plus we can retrieve the association with the later expiration
    # explicitly
    checkRetrieve(server_url, assoc2.handle, assoc2)

    # More recent, but expires earlier than assoc2 or assoc
    assoc3 = genAssoc(issued=2, lifetime=100)
    store.storeAssociation(server_url, assoc3)

    checkRetrieve(server_url, None, assoc2)
    checkRetrieve(server_url, assoc.handle, assoc)
    checkRetrieve(server_url, assoc2.handle, assoc2)
    checkRetrieve(server_url, assoc3.handle, assoc3)

    checkRemove(server_url, assoc2.handle, True)

    checkRetrieve(server_url, None, assoc)
    checkRetrieve(server_url, assoc.handle, assoc)
    checkRetrieve(server_url, assoc2.handle, None)
    checkRetrieve(server_url, assoc3.handle, assoc3)

    checkRemove(server_url, assoc2.handle, False)
    checkRemove(server_url, assoc.handle, True)

    checkRetrieve(server_url, None, assoc3)
    checkRetrieve(server_url, assoc.handle, None)
    checkRetrieve(server_url, assoc2.handle, None)
    checkRetrieve(server_url, assoc3.handle, assoc3)

    checkRemove(server_url, assoc2.handle, False)
    checkRemove(server_url, assoc.handle, False)
    checkRemove(server_url, assoc3.handle, True)

    checkRetrieve(server_url, None, None)
    checkRetrieve(server_url, assoc.handle, None)
    checkRetrieve(server_url, assoc2.handle, None)
    checkRetrieve(server_url, assoc3.handle, None)

    ### Nonce functions

    def testUseNonce(nonce, expected):
        actual = store.useNonce(nonce)
        expected = store.isDumb() or expected
        assert (actual and expected) or (not actual and not expected)

    # Random nonce (not in store)
    nonce1 = generateNonce()

    # A nonce is not present by default
    testUseNonce(nonce1, False)

    # Storing once causes useNonce to return True the first, and only
    # the first, time it is called after the store.
    store.storeNonce(nonce1)
    testUseNonce(nonce1, True)
    testUseNonce(nonce1, False)

    # Storing twice has the same effect as storing once.
    store.storeNonce(nonce1)
    store.storeNonce(nonce1)
    testUseNonce(nonce1, True)
    testUseNonce(nonce1, False)

    ### Auth key functions

    # There is no key to start with, so generate a new key and return it.
    key = store.getAuthKey()

    # The second time around should return the same as last time.
    key2 = store.getAuthKey()
    assert key == key2
    assert len(key) == store.AUTH_KEY_LEN

def test_filestore():
    print 'Testing fs'
    from openid.stores import filestore
    import tempfile
    import shutil
    try:
        temp_dir = tempfile.mkdtemp()
    except AttributeError:
        import os
        temp_dir = os.tmpnam()
        os.mkdir(temp_dir)

    store = filestore.FileOpenIDStore(temp_dir)
    try:
        testStore(store)
    except:
        print 'Test was in', temp_dir
        raise
    else:
        shutil.rmtree(temp_dir)

def test_sqlite():
    from openid.stores import sqlstore
    try:
        from pysqlite2 import dbapi2 as sqlite
    except ImportError:
        pass
    else:
        print 'Testing sqlite'
        conn = sqlite.connect(':memory:')
        store = sqlstore.SQLiteStore(conn)
        store.createTables()
        testStore(store)

def test_mysql():
    from openid.stores import sqlstore
    try:
        import MySQLdb
    except ImportError:
        pass
    else:
        print 'Testing mysql'
        db_user = 'openid_test'
        db_passwd = ''
        db_name = 'openid_test'

        from MySQLdb.constants import ER

        # Change this connect line to use the right user and password
        conn = MySQLdb.connect(user=db_user, passwd=db_passwd)

        # Clean up from last time, if the final drop database did not work
        try:
            conn.query('DROP DATABASE %s;' % db_name)
        except conn.OperationalError, why:
            if why[0] == ER.DB_DROP_EXISTS:
                pass # It's OK that the database did not exist. We're
                     # just cleaning up from last time in case we
                     # failed to clean up at the end.
            else:
                raise

        conn.query('CREATE DATABASE %s;' % db_name)
        try:
            conn.query('USE %s;' % db_name)

            # OK, we're in the right environment. Create store and
            # create the tables.
            store = sqlstore.MySQLStore(conn)
            store.createTables()

            # At last, we get to run the test.
            testStore(store)
        finally:
            # Remove the database. If you want to do post-mortem on a
            # failing test, comment out this line.
            conn.query('DROP DATABASE %s;' % db_name)

def test_memcache():
    from openid.stores import memcachestore
    try:
        import memcache
    except ImportError:
        pass
    else:
        print 'Testing memcache'
        import time
        import memcache
        cache = memcache.Client(['localhost:11211'], debug=1)
        cache.flush_all()
        # let the flush_all take effect
        time.sleep(1)
        store = memcachestore.MemCacheOpenIDStore(cache)
        testStore(store)

def test_dumbstore():
    print 'Testing dumbstore'
    from openid.stores import dumbstore
    store = dumbstore.DumbStore('bad secret; do not use')
    testStore(store)

def test_memstore():
    print 'Testing _memstore'
    import _memstore
    testStore(_memstore.MemoryStore())

def test():
    test_filestore()
    test_sqlite()
    test_mysql()
    test_memcache()
    test_dumbstore()
    test_memstore()

if __name__ == '__main__':
    test()
