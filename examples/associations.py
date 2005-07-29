from openid.consumer import SimpleHTTPClient
from openid.util import to_b64, from_b64
from openid.association import (ConsumerAssociation,
                                AbstractConsumerAssociationManager,
                                DiffieHelmanAssociator)

_qstrs = [
    'insert into openid_consumer_assocs values(%(m)s, %(m)s, %(m)s, %(m)s, %(m)s)',
    'select * from openid_consumer_assocs where url = %(m)s',
    'delete from openid_consumer_assocs where url = %(m)s and handle = %(m)s',
    ]

_styles = {
    'qmark': '?',
    'format': '%s',
    }

class SQLConsumerAssociationManager(AbstractConsumerAssociationManager):
    """This class implements a ConsumerAssociationManager using an SQL
    backing.  It should work with any Python DB API 2.0 compliant
    implementation, but it hasn't been extensively tested.

    This implementation requires that the DB that it's connected to
    have a table created by something like:
    CREATE TABLE openid_consumer_assocs
    (
        url CHAR(255),
        handle CHAR(255),
        secret CHAR(255),
        issued INT,
        lifetime INT
    );
    """

    def __init__(self, connection, paramstyle):
        """Connection should be an open DB API 2.0 compliant
        connection to a database with a table as described above.  The
        paramstyle argument should be the argstyle used by the
        connection.  At the moment, only 'qmark' and 'format' are
        supported.  The value necessary for a particular DB is in that
        DB module's paramstyle global."""
        AbstractConsumerAssociationManager.__init__(
            self, DiffieHelmanAssociator(SimpleHTTPClient()))
        self.connection = connection
        self.qstrs = [q % {'m':_styles[paramstyle]} for q in _qstrs]

    def update(self, new_assoc, expired):
        if new_assoc is not None:
            cur = self.connection.cursor()
            cur.execute(self.qstrs[0], (new_assoc.server_url,
                                        new_assoc.handle,
                                        to_b64(new_assoc.secret),
                                        new_assoc.issued,
                                        new_assoc.lifetime))

            self.connection.commit()

        for assoc in expired:
            self.invalidate(assoc.server_url, assoc.handle)


    def get_all(self, server_url):
        """Subclasses should return a list of ConsumerAssociation
        objects whose server_url attribute is equal to server_url."""
        result = []

        cur = self.connection.cursor()
        cur.execute(self.qstrs[1], (server_url,))
        for url, handle, secret, issued, lifetime in cur:
            result.append(ConsumerAssociation(url,
                                              handle,
                                              from_b64(secret),
                                              issued,
                                              lifetime))
        self.connection.commit()

        return result

    def invalidate(self, server_url, assoc_handle):
        cur = self.connection.cursor()
        cur.execute(self.qstrs[2], (server_url, assoc_handle))
        self.connection.commit()

def getSQLiteConsumerAssociationManager(filename):
    """This function returns an instance of the above store using an
    SQLite database.  It requires SQLite and the pysqlite bindings to
    be installed to use.  The filename passed in is the filename to
    open for the database.  If the specified file doesn't exist, it's
    created and the necessary table is created inside of it."""
    import os.path
    from pysqlite2 import dbapi2

    if os.path.exists(filename):
        con = dbapi2.connect(filename)
    else:
        con = dbapi2.connect(filename)
        cur = con.cursor()
        cur.execute("""
        CREATE TABLE openid_consumer_assocs
        (
            url CHAR(255),
            handle CHAR(255),
            secret CHAR(255),
            issued INT,
            lifetime INT
        );
        """)
        con.commit()

    return SQLConsumerAssociationManager(con, dbapi2.paramstyle)
