from openid import util
from openid.consumer.stores import ConsumerAssociation

# The size of the secret field will not be any larger than 20 bytes
# for the current implementation of the spec. 128 should provide a
# good degree of future-proofing.

class SQLiteStore(object):
    AUTH_KEY_LEN = 20

    def __init__(self, conn):
        self.conn = conn

    def _exec(self, func, *args, **kwargs):
        """Execute the given function inside of a transaction"""
        # No nesting of transactions
        self.conn.rollback()

        try:
            cur = self.conn.cursor()
            try:
                ret = func(cur, *args, **kwargs)
            finally:
                cur.close()
        except:
            self.conn.rollback()
            raise
        else:
            self.conn.commit()

        return ret

    def _createTables(self, cur):
        """see createTables

        DBApi Cursor -> NoneType"""
        cur.execute("CREATE TABLE nonces ( nonce CHAR(8) PRIMARY KEY )")

        cur.execute("""
        CREATE TABLE associations
        (
        server_url VARCHAR(2047) PRIMARY KEY,
        handle VARCHAR(255),
        secret BLOB(128),
        issued INTEGER,
        lifetime INTEGER
        )""")

        cur.execute("""
        CREATE TABLE settings
        (
        key VARCHAR(128) UNIQUE PRIMARY KEY,
        value CHAR(20)
        )""")

    def createTables(self):
        """Create the database tables.
        This method should only be called once.

        () -> NoneType
        """
        self._exec(self._createTables)

    def _setAuthKey(self, cur, auth_key):
        """see setAuthKey

        (DBApi Cursor, str) -> NoneType"""
        if len(auth_key) != self.AUTH_KEY_LEN:
            fmt = ('Attempted to set invalid auth key. Expected %d byte '
                   'string. Got: %r')
            raise ValueError(fmt % (self.AUTH_KEY_LEN, auth_key))
            
        cur.execute('INSERT OR REPLACE INTO settings VALUES ("auth_key", ?)',
                    (buffer(auth_key),))

    def setAuthKey(self, auth_key):
        """Set the auth key for this consumer to use to sign its own
        communications.

        str -> NoneType"""
        self._exec(self._setAuthKey, auth_key)
        
    def _createAuthKey(self, cur):
        """Create a new, random key for this consumer to use to sign
        its own communications.

        DBApi Cursor -> str"""
        import random
        rand = random.SystemRandom()
        auth_key = util.random_string(self.AUTH_KEY_LEN, rand)

        # Differs from _setAuthKey by not using OR REPLACE
        cur.execute('INSERT INTO settings VALUES ("auth_key", ?)',
                    (buffer(auth_key),))

        return auth_key

    def _getAuthKey(self, cur):
        """see getAuthKey

        DBApi Cursor -> str
        """
        cur.execute('SELECT value FROM settings WHERE key = "auth_key"')
        val = cur.fetchone()
        if val is None:
            auth_key = self._createAuthKey(cur)
        else:
            (auth_key,) = val
            auth_key = str(auth_key)

        if len(auth_key) != self.AUTH_KEY_LEN:
            fmt = 'Expected %d-byte string for auth key. Got %r'
            raise ValueError(fmt % (self.AUTH_KEY_LEN, auth_key))

        return auth_key

    def getAuthKey(self):
        """Get the key for this consumer to use to sign its own
        communications. This function will create a new key if one
        does not yet exist.

        () -> str
        """
        return self._exec(self._getAuthKey)

    def _storeAssociation(self, cur, association):
        """see storeAssociation

        (DBApi Cursor, ConsumerAssociation) -> NoneType
        """
        a = association
        cur.execute(
            'INSERT OR REPLACE INTO associations VALUES (?, ?, ?, ?, ?)',
            (a.server_url, a.handle, buffer(a.secret), a.issued, a.lifetime))

    def storeAssociation(self, association):
        """Set the association for the server URL.

        ConsumerAssociation -> NoneType
        """
        self._exec(self._storeAssociation, association)

    def _getAssociation(self, cur, server_url):
        """see getAssociation

        (DBApi Cursor, str) -> ConsumerAssociation or NoneType
        """
        cur.execute('SELECT * FROM associations WHERE server_url = ?',
                    (server_url,))

        rows = cur.fetchall()
        if len(rows) == 0:
            return None
        else:
            (values,) = rows
            assoc = ConsumerAssociation(*values)
            assoc.secret = str(assoc.secret)
            return assoc

    def getAssociation(self, server_url):
        """Get the most recent association that has been set for this
        server URL.

        str -> NoneType or ConsumerAssociation
        """
        return self._exec(self._getAssociation, server_url)

    def _removeAssociation(self, cur, server_url, handle):
        """see removeAssociation

        (DBApi Cursor, str, str) -> bool
        """
        cur.execute(
            'DELETE FROM associations WHERE server_url = ? AND handle = ?',
            (server_url, handle))
        return cur.rowcount > 0 # -1 is undefined

    def removeAssociation(self, server_url, handle):
        """Remove the association for the given server URL and handle,
        returning whether the association existed at all.

        (str, str) -> bool
        """
        return self._exec(self._removeAssociation, server_url, handle)

    def _storeNonce(self, cur, nonce):
        """see storeNonce

        (DBApi Cursor, str) -> NoneType
        """
        cur.execute('INSERT OR IGNORE INTO nonces VALUES (?)', (nonce,))

    def storeNonce(self, nonce):
        """Add this nonce to the set of extant nonces, ignoring if it
        is already present.

        str -> NoneType
        """
        self._exec(self._storeNonce, nonce)

    def _useNonce(self, cur, nonce):
        """see useNonce

        (DBApi Cursor, str) -> bool"""
        cur.execute('SELECT * FROM nonces WHERE nonce = ?', (nonce,))
        present = cur.fetchone() is not None
        if present:
            cur.execute('DELETE FROM nonces WHERE nonce = ?', (nonce,))
        return present

    def useNonce(self, nonce):
        """Return whether this nonce is present, and if it is, then
        remove it from the set.

        str -> bool"""
        return self._exec(self._useNonce, nonce)
