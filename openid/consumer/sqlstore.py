from openid import oidUtil
from openid.consumer.stores import ConsumerAssociation, OpenIDStore

def inTxn(func):
    def wrapped(self, *args, **kwargs):
        return self._callInTransaction(func, *args, **kwargs)
    return wrapped

class SQLStore(OpenIDStore):
    def __init__(self, conn):
        self.conn = conn
        self.cur = None

    def __getattr__(self, attr):
        # if the attribute starts with db_, use a default
        # implementation that looks up the appropriate SQL statement
        # as an attribute of this object and executes it.
        if attr[:3] == 'db_':
            sql_name = attr[3:] + '_sql'
            sql = getattr(self, sql_name)
            def func(*args):
                self.cur.execute(sql, args)
            setattr(self, attr, func)
            return func
        else:
            raise AttributeError('Attribute %r not found' % (attr,))

    def _callInTransaction(self, func, *args, **kwargs):
        """Execute the given function inside of a transaction, with an
        open cursor. If no exception is raised, the transaction is
        comitted, otherwise it is rolled back."""
        # No nesting of transactions
        self.conn.rollback()

        try:
            self.cur = self.conn.cursor()
            try:
                ret = func(self, *args, **kwargs)
            finally:
                self.cur.close()
                self.cur = None
        except:
            self.conn.rollback()
            raise
        else:
            self.conn.commit()

        return ret

    def _createTables(self):
        """Create the database tables.
        This method should only be called once.

        () -> NoneType
        """
        self.db_create_nonce()
        self.db_create_assoc()
        self.db_create_settings()

    createTables = inTxn(_createTables)

    def _getAuthKey(self):
        """Get the key for this consumer to use to sign its own
        communications. This function will create a new key if one
        does not yet exist.

        () -> str
        """
        self.db_get_auth()
        val = self.cur.fetchone()
        if val is None:
            auth_key = oidUtil.randomString(self.AUTH_KEY_LEN)
            self.db_create_auth(auth_key)
        else:
            (auth_key,) = val

        if len(auth_key) != self.AUTH_KEY_LEN:
            fmt = 'Expected %d-byte string for auth key. Got %r'
            raise ValueError(fmt % (self.AUTH_KEY_LEN, auth_key))

        return auth_key

    getAuthKey = inTxn(_getAuthKey)

    def _storeAssociation(self, association):
        """Set the association for the server URL.

        ConsumerAssociation -> NoneType
        """
        a = association
        self.db_set_assoc(
            a.server_url,
            a.handle,
            a.secret,
            a.issued,
            a.lifetime)

    storeAssociation = inTxn(_storeAssociation)

    def _getAssociation(self, server_url):
        """Get the most recent association that has been set for this
        server URL.

        str -> NoneType or ConsumerAssociation
        """
        self.db_get_assoc(server_url)
        rows = self.cur.fetchall()
        if len(rows) == 0:
            return None
        else:
            (values,) = rows
            return ConsumerAssociation(*values)

    getAssociation = inTxn(_getAssociation)

    def _removeAssociation(self, server_url, handle):
        """Remove the association for the given server URL and handle,
        returning whether the association existed at all.

        (str, str) -> bool
        """
        self.db_remove_assoc(server_url, handle)
        return self.cur.rowcount > 0 # -1 is undefined

    removeAssociation = inTxn(_removeAssociation)

    def _storeNonce(self, nonce):
        """Add this nonce to the set of extant nonces, ignoring if it
        is already present.

        str -> NoneType
        """
        self.db_add_nonce(nonce)

    storeNonce = inTxn(_storeNonce)

    def _useNonce(self, nonce):
        """Return whether this nonce is present, and if it is, then
        remove it from the set.

        str -> bool"""
        self.db_get_nonce(nonce)
        present = self.cur.fetchone() is not None
        if present:
            self.db_remove_nonce(nonce)
        return present

    useNonce = inTxn(_useNonce)

class SQLiteStore(SQLStore):
    """SQLite-specific specialization of SQLStore"""
    
    create_nonce_sql = """
    CREATE TABLE nonces
    (
        nonce CHAR(8) UNIQUE PRIMARY KEY
    );
    """

    create_assoc_sql = """
    CREATE TABLE associations
    (
        server_url VARCHAR(2047) UNIQUE PRIMARY KEY,
        handle VARCHAR(255),
        secret BLOB(128),
        issued INTEGER,
        lifetime INTEGER
    );
    """

    create_settings_sql = """
    CREATE TABLE settings
    (
        key VARCHAR(128) UNIQUE PRIMARY KEY,
        value CHAR(20)
    );
    """

    create_auth_sql = 'INSERT INTO settings VALUES ("auth_key", ?);'
    get_auth_sql = 'SELECT value FROM settings WHERE key = "auth_key";'

    set_assoc_sql = ('INSERT OR REPLACE INTO associations '
                     'VALUES (?, ?, ?, ?, ?);')
    get_assoc_sql = 'SELECT * FROM associations WHERE server_url = ?;'
    remove_assoc_sql = ('DELETE FROM associations '
                        'WHERE server_url = ? AND handle = ?;')

    add_nonce_sql = 'INSERT OR IGNORE INTO nonces VALUES (?);'
    get_nonce_sql = 'SELECT * FROM nonces WHERE nonce = ?;'
    remove_nonce_sql = 'DELETE FROM nonces WHERE nonce = ?;'

    # These methods needed to be overridden because SQLite will not
    # store str objects as binary data. It needs a buffer type.

    def db_create_auth(self, auth_key):
        self.cur.execute(self.create_auth_sql, (buffer(auth_key),))

    def db_set_assoc(self, server_url, handle, secret, issued, lifetime):
        self.cur.execute(
            self.set_assoc_sql,
            (server_url, handle, buffer(secret), issued, lifetime))

    def _getAuthKey(self):
        auth_key = SQLStore._getAuthKey(self)
        if type(auth_key) is buffer:
            auth_key = str(auth_key)
        return auth_key

    getAuthKey = inTxn(_getAuthKey)

    def _getAssociation(self, server_url):
        assoc = SQLStore._getAssociation(self, server_url)
        if assoc is not None:
            # Convert from buffer() to str()
            assoc.secret = str(assoc.secret)
        return assoc

    getAssociation = inTxn(_getAssociation)

from array import array
class MySQLStore(SQLStore):
    """MySQL-specific specialization of SQLStore

    Uses InnoDB tables for transaction support.
    """

    create_nonce_sql = """
    CREATE TABLE nonces
    (
        nonce CHAR(8) UNIQUE PRIMARY KEY
    )
    TYPE=InnoDB;
    """

    create_assoc_sql = """
    CREATE TABLE associations
    (
        server_url VARCHAR(1024) UNIQUE PRIMARY KEY,
        handle VARCHAR(255),
        secret BLOB(128),
        issued INTEGER,
        lifetime INTEGER
    )
    TYPE=InnoDB;
    """

    create_settings_sql = """
    CREATE TABLE settings
    (
        skey VARCHAR(128) UNIQUE PRIMARY KEY,
        value VARCHAR(20)
    )
    TYPE=InnoDB;
    """

    create_auth_sql = 'INSERT INTO settings VALUES ("auth_key", %s);'
    get_auth_sql = 'SELECT value FROM settings WHERE skey = "auth_key";'

    set_assoc_sql = 'REPLACE INTO associations VALUES (%s, %s, %s, %s, %s);'
    get_assoc_sql = 'SELECT * FROM associations WHERE server_url = %s;'
    remove_assoc_sql = ('DELETE FROM associations '
                        'WHERE server_url = %s AND handle = %s;')

    add_nonce_sql = 'REPLACE INTO nonces VALUES (%s);'
    get_nonce_sql = 'SELECT * FROM nonces WHERE nonce = %s;'
    remove_nonce_sql = 'DELETE FROM nonces WHERE nonce = %s;'

    # These methods needed to be overridden because MySQL returns
    # array() instead of str for binary values.

    def _getAuthKey(self):
        auth_key = SQLStore._getAuthKey(self)
        if type(auth_key) is array:
            auth_key = auth_key.tostring()
        return auth_key

    getAuthKey = inTxn(_getAuthKey)

    def _getAssociation(self, server_url):
        assoc = SQLStore._getAssociation(self, server_url)
        if assoc is not None:
            # Convert from array() to str()
            assoc.secret = assoc.secret.tostring()
        return assoc

    getAssociation = inTxn(_getAssociation)

