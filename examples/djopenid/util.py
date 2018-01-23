"""
Utility code for the Django example consumer and server.
"""
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.db import connection
from django.shortcuts import render
from openid.store import sqlstore
from openid.store.filestore import FileOpenIDStore
from openid.yadis.constants import YADIS_CONTENT_TYPE


def getOpenIDStore(filestore_path, table_prefix):
    """
    Returns an OpenID association store object based on the database
    engine chosen for this Django application.

    * If no database engine is chosen, a filesystem-based store will
      be used whose path is filestore_path.

    * If a database engine is chosen, a store object for that database
      type will be returned.

    * If the chosen engine is not supported by the OpenID library,
      raise ImproperlyConfigured.

    * If a database store is used, this will create the tables
      necessary to use it.  The table names will be prefixed with
      table_prefix.  DO NOT use the same table prefix for both an
      OpenID consumer and an OpenID server in the same database.

    The result of this function should be passed to the Consumer
    constructor as the store parameter.
    """
    if not settings.DATABASES.get('default', {'ENGINE': None}).get('ENGINE'):
        return FileOpenIDStore(filestore_path)

    # Possible side-effect: create a database connection if one isn't
    # already open.
    connection.cursor()

    # Create table names to specify for SQL-backed stores.
    tablenames = {
        'associations_table': table_prefix + 'openid_associations',
        'nonces_table': table_prefix + 'openid_nonces',
    }

    types = {
        'django.db.backends.postgresql': sqlstore.PostgreSQLStore,
        'django.db.backends.mysql': sqlstore.MySQLStore,
        'django.db.backends.sqlite3': sqlstore.SQLiteStore,
    }

    engine = settings.DATABASES.get('default', {'ENGINE': None}).get('ENGINE')
    try:
        s = types[engine](connection.connection, **tablenames)
    except KeyError:
        raise ImproperlyConfigured("Database engine %s not supported by OpenID library" % engine)

    try:
        s.createTables()
    except Exception:
        # XXX This is not the Right Way to do this, but because the
        # underlying database implementation might differ in behavior
        # at this point, we can't reliably catch the right
        # exception(s) here.  Ideally, the SQL store in the OpenID
        # library would catch exceptions that it expects and fail
        # silently, but that could be bad, too.  More ideally, the SQL
        # store would not attempt to create tables it knows already
        # exists.
        pass

    return s


def normalDict(request_data):
    """
    Converts a django request MutliValueDict (e.g., request.GET,
    request.POST) into a standard python dict whose values are the
    first value from each of the MultiValueDict's value lists.  This
    avoids the OpenID library's refusal to deal with dicts whose
    values are lists, because in OpenID, each key in the query arg set
    can have at most one value.
    """
    return dict((k, v) for k, v in request_data.iteritems())


def renderXRDS(request, type_uris, endpoint_urls):
    """Render an XRDS page with the specified type URIs and endpoint
    URLs in one service block, and return a response with the
    appropriate content-type.
    """
    context = {'type_uris': type_uris, 'endpoint_urls': endpoint_urls}
    return render(request, 'xrds.xml', context, content_type=YADIS_CONTENT_TYPE)
