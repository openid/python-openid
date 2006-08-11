# SQL Store Upgrade Script
# doesn't depend on the openid library, so you can run this python
# script to update databases for ruby or php as well

import os
import getpass
import sys
from optparse import OptionParser


def askForPassword():
    return getpass.getpass("DB Password: ")

def askForConfirmation(dbname,tablename):
    print """The table %s from the database %s will be dropped, and 
    an empty table with the new nonce table schema will replace it."""%(
    tablename, dbname)
    return raw_input("Continue? ").lower().startswith('y')

def doSQLiteUpgrade(db_conn, nonce_table_name='oid_nonces'):
    cur = db_conn.cursor()
    cur.execute('DROP TABLE %s'%nonce_table_name)
    sql = """
    CREATE TABLE %s (
        server_url VARCHAR,
        timestamp INTEGER,
        salt CHAR(40),
        UNIQUE(server_url, timestamp, salt)
    );
    """%nonce_table_name
    cur.execute(sql)
    cur.close()
    
def doMySQLUpgrade(db_conn, nonce_table_name='oid_nonces'):
    cur = db_conn.cursor()
    cur.execute('DROP TABLE %s'%nonce_table_name)
    sql = """
    CREATE TABLE %s (
        server_url BLOB,
        timestamp INTEGER,
        salt CHAR(40),
        PRIMARY KEY (server_url(255), timestamp, salt)
    )
    TYPE=InnoDB;
    """%nonce_table_name
    cur.execute(sql)
    cur.close()

def doPostgreSQLUpgrade(db_conn, nonce_table_name='oid_nonces'):
    cur = db_conn.cursor()
    cur.execute('DROP TABLE %s'%nonce_table_name)
    sql = """
    CREATE TABLE %s (
        server_url VARCHAR(2047),
        timestamp INTEGER,
        salt CHAR(40),
        PRIMARY KEY (server_url, timestamp, salt)
    );
    """%nonce_table_name
    cur.execute(sql)
    cur.close()
    conn.commit()

    

if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option("-u", "--user", dest="username", default=os.environ.get('USER'),
                    help="User name to use to connect to the DB. Defaults to USER environment variable.")
    parser.add_option('-t', '--table', dest='tablename', default='oid_nonces',
                    help='The name of the nonce table to drop and recreate. defaults to "oid_nonces", the default table name for the openid stores.')
    parser.add_option('--mysql', dest='mysql_db_name', 
                    help='Upgrade a table from this MySQL database. Requires username for database.')
    parser.add_option('--pg', '--postgresql', dest='postgres_db_name',
                    help='Upgrade a table from this PostgreSQL database. Requires username for database.')
    parser.add_option('--sqlite', dest='sqlite_db_name',
                    help='Upgrade a table from this SQLite database file')
    parser.add_option('--host', dest='db_host',
                    help='Host on which to find MySQL or PostgreSQL DB', default='localhost')
    (options, args) = parser.parse_args()

    db_conn = None

    if options.sqlite_db_name:
        try:
            from pysqlite2 import dbapi2 as sqlite
        except ImportError:
            print "You must have pysqlite2 installed in your PYTHONPATH."
            sys.exit(1)
        try:
            db_conn = sqlite.connect(options.sqlite_db_name)
        except Exception, e:
            print "Could not connect to SQLite database:", str(e)
            sys.exit(1)

        if askForConfirmation(options.sqlite_db_name, options.tablename):
            doSQLiteUpgrade(db_conn, nonce_table_name=options.tablename)
            
    if options.postgres_db_name:
        if not options.username:
            print "A username is required to open a PostgreSQL Database."
            sys.exit(1)
        password = askForPassword()
        try:
            import psycopg
        except ImportError:
            print "You need psycopg installed to update a postgres DB."
            sys.exit(1)

        try:
            db_conn = psycopg.connect(database = options.postgres_db_name,
                                      user = options.username,
                                      host = options.db_host,
                                      passwd = password)
        except Exception, e:
            print "Could not connect to PostgreSQL database:", str(e)
            sys.exit(1)

        if askForConfirmation(options.postgres_db_name, options.tablename):
            doPostgreSQLUpgrade(db_conn, nonce_table_name=options.tablename)
    
    if options.mysql_db_name:
        if not options.username:
            print "A username is required to open a MySQL Database."
            sys.exit(1)
        password = askForPassword()
        try:
            import MySQLdb
        except ImportError:
            print "You must have MySQLdb installed to update a MySQL DB."
            sys.exit(1)

        try:
            db_conn = MySQLdb.connect(options.db_host, options.username, password, options.mysql_db_name)
        except Exception, e:
            print "Could not connect to MySQL database:", str(e)
            sys.exit(1)

        if askForConfirmation(options.mysql_db_name, options.tablename):
            doMySQLUpgrade(db_conn, nonce_table_name=options.tablename)
        
    if db_conn:
        db_conn.close()
    else:
        parser.print_help()
