import time

from openid import cryptutil
from openid.association import Association
from openid.stores.interface import OpenIDStore

def inTxn(func):
    def wrapped(self, *args, **kwargs):
        return self._callInTransaction(func, self, *args, **kwargs)

    if hasattr(func, '__name__'):
        try:
            wrapped.__name__ = func.__name__[4:]
        except TypeError:
            pass

    if hasattr(func, '__doc__'):
        wrapped.__doc__ = func.__doc__

    return wrapped

class SQLStore(OpenIDStore):
    """
    This is the parent class for the SQL stores, which contains the
    logic common to all of the SQL stores.

    The table names used are determined by the class variables
    C{L{settings_table}}, C{L{associations_table}}, and
    C{L{nonces_table}}.  To change the name of the tables used, pass
    new table names into the constructor.

    To create the tables with the proper schema, see the
    C{L{createTables}} method.

    This class shouldn't be used directly.  Use one of its subclasses
    instead, as those contain the code necessary to use a specific
    database.

    All methods other than C{L{__init__}} and C{L{createTables}}
    should be considered implementation details.


    @cvar settings_table: This is the default name of the table to
        keep this store's settings in.
    
    @cvar associations_table: This is the default name of the table to
        keep associations in
    
    @cvar nonces_table: This is the default name of the table to keep
        nonces in.


    @sort: __init__, createTables
    """

    settings_table = 'oid_settings'
    associations_table = 'oid_associations'
    nonces_table = 'oid_nonces'

    def __init__(self, conn, settings_table=None, associations_table=None,
                 nonces_table=None):
        """
        This creates a new SQLStore instance.  It requires an
        established database connection be given to it, and it allows
        overriding the default table names.


        @param conn: This must be an established connection to a
            database of the correct type for the SQLStore subclass
            you're using.

        @type conn: A python database API compatible connection
            object.


        @param settings_table: This is an optional parameter to
            specify the name of the table used for this store's
            settings.  The default value is specified in
            C{L{SQLStore.settings_table}}.

        @type settings_table: C{str}


        @param associations_table: This is an optional parameter to
            specify the name of the table used for storing
            associations.  The default value is specified in
            C{L{SQLStore.associations_table}}.

        @type associations_table: C{str}


        @param nonces_table: This is an optional parameter to specify
            the name of the table used for storing nonces.  The
            default value is specified in C{L{SQLStore.nonces_table}}.

        @type nonces_table: C{str}
        """
        self.conn = conn
        self.cur = None
        self._statement_cache = {}
        self._table_names = {
            'settings': settings_table or self.settings_table,
            'associations': associations_table or self.associations_table,
            'nonces': nonces_table or self.nonces_table,
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
        """
        This method creates the database tables necessary for this
        store to work.  It should not be called if the tables already
        exist.
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
            auth_key = cryptutil.randomString(self.AUTH_KEY_LEN)
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

    def txn_storeAssociation(self, server_url, association):
        """Set the association for the server URL.

        Association -> NoneType
        """
        a = association
        self.db_set_assoc(
            server_url,
            a.handle,
            self.blobEncode(a.secret),
            a.issued,
            a.lifetime,
            a.assoc_type)

    storeAssociation = inTxn(txn_storeAssociation)

    def txn_getAssociation(self, server_url, handle=None):
        """Get the most recent association that has been set for this
        server URL and handle.

        str -> NoneType or Association
        """
        if handle is not None:
            self.db_get_assoc(server_url, handle)
        else:
            self.db_get_assocs(server_url)

        rows = self.cur.fetchall()
        if len(rows) == 0:
            return None
        else:
            associations = []
            for values in rows:
                assoc = Association(*values)
                assoc.secret = self.blobDecode(assoc.secret)
                expires = assoc.getExpiresIn()
                if expires == 0:
                    self.txn_removeAssociation(server_url, assoc.handle)
                else:
                    associations.append((expires, assoc))

            if associations:
                associations.sort()
                return associations[-1][1]
            else:
                return None

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
                present = 0
            else:
                present = 1

            self.db_remove_nonce(nonce)
        else:
            present = 0

        return present

    useNonce = inTxn(txn_useNonce)

class SQLiteStore(SQLStore):
    """
    This is an SQLite-based specialization of C{L{SQLStore}}.

    To create an instance, see C{L{SQLStore.__init__}}.  To create the
    tables it will use, see C{L{SQLStore.createTables}}.

    All other methods are implementation details.
    """
    
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
        server_url VARCHAR(2047),
        handle VARCHAR(255),
        secret BLOB(128),
        issued INTEGER,
        lifetime INTEGER,
        assoc_type VARCHAR(64),
        PRIMARY KEY (server_url, handle)
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
                     'VALUES (?, ?, ?, ?, ?, ?);')
    get_assocs_sql = ('SELECT handle, secret, issued, lifetime, assoc_type '
                      'FROM %(associations)s WHERE server_url = ?;')
    get_assoc_sql = (
        'SELECT handle, secret, issued, lifetime, assoc_type '
        'FROM %(associations)s WHERE server_url = ? AND handle = ?;')

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
    """
    This is a MySQL-based specialization of SQLStore

    Uses InnoDB tables for transaction support.

    To create an instance, see C{L{SQLStore.__init__}}.  To create the
    tables it will use, see C{L{SQLStore.createTables}}.

    All other methods are implementation details.
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
        server_url VARCHAR(768),
        handle VARCHAR(255),
        secret BLOB(128),
        issued INTEGER,
        lifetime INTEGER,
        assoc_type VARCHAR(64),
        PRIMARY KEY (server_url, handle)
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
                     'VALUES (%%s, %%s, %%s, %%s, %%s, %%s);')
    get_assocs_sql = ('SELECT handle, secret, issued, lifetime, assoc_type'
                      ' FROM %(associations)s WHERE server_url = %%s;')
    get_assoc_sql = (
        'SELECT handle, secret, issued, lifetime, assoc_type'
        ' FROM %(associations)s WHERE server_url = %%s AND handle = %%s;')
    remove_assoc_sql = ('DELETE FROM %(associations)s '
                        'WHERE server_url = %%s AND handle = %%s;')

    add_nonce_sql = 'REPLACE INTO %(nonces)s VALUES (%%s, %%s);'
    get_nonce_sql = 'SELECT * FROM %(nonces)s WHERE nonce = %%s;'
    remove_nonce_sql = 'DELETE FROM %(nonces)s WHERE nonce = %%s;'

    def blobDecode(self, blob):
        return blob.tostring()
