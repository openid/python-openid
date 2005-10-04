import time

from openid import oidUtil
from openid.consumer.stores import ConsumerAssociation, OpenIDStore

def inTxn(func):
    def wrapped(self, *args, **kwargs):
        return self._callInTransaction(func, self, *args, **kwargs)
    return wrapped

class SQLStore(OpenIDStore):
    settings_table = 'oidc_settings'
    associations_table = 'oidc_associations'
    nonces_table = 'oidc_nonces'

    def __init__(self, conn):
        self.conn = conn
        self.cur = None
        self._statement_cache = {}
        self._table_names = {
            'settings':self.settings_table,
            'associations':self.associations_table,
            'nonces':self.nonces_table,
            }
        self.max_nonce_age = 6 * 60 * 60 # Six hours, in seconds

    def blobDecode(self, blob):
        """Convert a blob as returned by the SQL engine into a str object.

        str -> str"""
        return blob

    def blobEncode(self, s):
        """Convert a str object into the necessary object for storing
        in the database as a blob."""
        return s

    def _getSQL(self, sql_name):
        try:
            return self._statement_cache[sql_name]
        except KeyError:
            sql = getattr(self, sql_name)
            sql %= self._table_names
            self._statement_cache[sql_name] = sql
            return sql

    def _execSQL(self, sql_name, *args):
        sql = self._getSQL(sql_name)
        self.cur.execute(sql, args)

    def __getattr__(self, attr):
        # if the attribute starts with db_, use a default
        # implementation that looks up the appropriate SQL statement
        # as an attribute of this object and executes it.
        if attr[:3] == 'db_':
            sql_name = attr[3:] + '_sql'
            def func(*args):
                return self._execSQL(sql_name, *args)
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
                ret = func(*args, **kwargs)
            finally:
                self.cur.close()
                self.cur = None
        except:
            self.conn.rollback()
            raise
        else:
            self.conn.commit()

        return ret

    def txn_createTables(self):
        """Create the database tables.
        This method should only be called once.

        () -> NoneType
        """
        self.db_create_nonce()
        self.db_create_assoc()
        self.db_create_settings()

    createTables = inTxn(txn_createTables)

    def txn_getAuthKey(self):
        """Get the key for this consumer to use to sign its own
        communications. This function will create a new key if one
        does not yet exist.

        () -> str
        """
        self.db_get_auth()
        val = self.cur.fetchone()
        if val is None:
            auth_key = oidUtil.randomString(self.AUTH_KEY_LEN)
            auth_key_s = self.blobEncode(auth_key)
            self.db_create_auth(auth_key_s)
        else:
            (auth_key_s,) = val
            auth_key = self.blobDecode(auth_key_s)

        if len(auth_key) != self.AUTH_KEY_LEN:
            fmt = 'Expected %d-byte string for auth key. Got %r'
            raise ValueError(fmt % (self.AUTH_KEY_LEN, auth_key))

        return auth_key

    getAuthKey = inTxn(txn_getAuthKey)

    def txn_storeAssociation(self, association):
        """Set the association for the server URL.

        ConsumerAssociation -> NoneType
        """
        a = association
        self.db_set_assoc(
            a.server_url,
            a.handle,
            self.blobEncode(a.secret),
            a.issued,
            a.lifetime)

    storeAssociation = inTxn(txn_storeAssociation)

    def txn_getAssociation(self, server_url):
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
            assoc = ConsumerAssociation(*values)
            assoc.secret = self.blobDecode(assoc.secret)
            return assoc

    getAssociation = inTxn(txn_getAssociation)

    def txn_removeAssociation(self, server_url, handle):
        """Remove the association for the given server URL and handle,
        returning whether the association existed at all.

        (str, str) -> bool
        """
        self.db_remove_assoc(server_url, handle)
        return self.cur.rowcount > 0 # -1 is undefined

    removeAssociation = inTxn(txn_removeAssociation)

    def txn_storeNonce(self, nonce):
        """Add this nonce to the set of extant nonces, ignoring if it
        is already present.

        str -> NoneType
        """
        now = int(time.time())
        self.db_add_nonce(nonce, now)

    storeNonce = inTxn(txn_storeNonce)

    def txn_useNonce(self, nonce):
        """Return whether this nonce is present, and if it is, then
        remove it from the set.

        str -> bool"""
        self.db_get_nonce(nonce)
        row = self.cur.fetchone()
        if row is not None:
            (nonce, timestamp) = row
            nonce_age = int(time.time()) - timestamp
            if nonce_age > self.max_nonce_age:
                present = False
            else:
                present = True

            self.db_remove_nonce(nonce)
        else:
            present = False

        return present

    useNonce = inTxn(txn_useNonce)

class SQLiteStore(SQLStore):
    """SQLite-specific specialization of SQLStore"""
    
    create_nonce_sql = """
    CREATE TABLE %(nonces)s
    (
        nonce CHAR(8) UNIQUE PRIMARY KEY,
        expires INTEGER
    );
    """

    create_assoc_sql = """
    CREATE TABLE %(associations)s
    (
        server_url VARCHAR(2047) UNIQUE PRIMARY KEY,
        handle VARCHAR(255),
        secret BLOB(128),
        issued INTEGER,
        lifetime INTEGER
    );
    """

    create_settings_sql = """
    CREATE TABLE %(settings)s
    (
        setting VARCHAR(128) UNIQUE PRIMARY KEY,
        value BLOB(20)
    );
    """

    create_auth_sql = 'INSERT INTO %(settings)s VALUES ("auth_key", ?);'
    get_auth_sql = 'SELECT value FROM %(settings)s WHERE setting = "auth_key";'

    set_assoc_sql = ('INSERT OR REPLACE INTO %(associations)s '
                     'VALUES (?, ?, ?, ?, ?);')
    get_assoc_sql = 'SELECT * FROM %(associations)s WHERE server_url = ?;'
    remove_assoc_sql = ('DELETE FROM %(associations)s '
                        'WHERE server_url = ? AND handle = ?;')

    add_nonce_sql = 'INSERT OR REPLACE INTO %(nonces)s VALUES (?, ?);'
    get_nonce_sql = 'SELECT * FROM %(nonces)s WHERE nonce = ?;'
    remove_nonce_sql = 'DELETE FROM %(nonces)s WHERE nonce = ?;'

    def blobDecode(self, buf):
        return str(buf)

    def blobEncode(self, s):
        return buffer(s)

class MySQLStore(SQLStore):
    """MySQL-specific specialization of SQLStore

    Uses InnoDB tables for transaction support.
    """

    create_nonce_sql = """
    CREATE TABLE %(nonces)s
    (
        nonce CHAR(8) UNIQUE PRIMARY KEY,
        expires INTEGER
    )
    TYPE=InnoDB;
    """

    create_assoc_sql = """
    CREATE TABLE %(associations)s
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
    CREATE TABLE %(settings)s
    (
        setting VARCHAR(128) UNIQUE PRIMARY KEY,
        value BLOB(20)
    )
    TYPE=InnoDB;
    """

    create_auth_sql = 'INSERT INTO %(settings)s VALUES ("auth_key", %%s);'
    get_auth_sql = 'SELECT value FROM %(settings)s WHERE setting = "auth_key";'

    set_assoc_sql = ('REPLACE INTO %(associations)s '
                     'VALUES (%%s, %%s, %%s, %%s, %%s);')
    get_assoc_sql = 'SELECT * FROM %(associations)s WHERE server_url = %%s;'
    remove_assoc_sql = ('DELETE FROM %(associations)s '
                        'WHERE server_url = %%s AND handle = %%s;')

    add_nonce_sql = 'REPLACE INTO %(nonces)s VALUES (%%s, %%s);'
    get_nonce_sql = 'SELECT * FROM %(nonces)s WHERE nonce = %%s;'
    remove_nonce_sql = 'DELETE FROM %(nonces)s WHERE nonce = %%s;'

    def blobDecode(self, blob):
        return blob.tostring()
