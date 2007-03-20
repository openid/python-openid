
"""
Based on the Django backend type in use, return a reference to an
OpenID association store which uses that backend.
"""

from django.db import connection
from django.template.context import RequestContext
from django.template import loader
from django import http
from django.core.exceptions import ImproperlyConfigured

from django.conf import settings

from openid.store.filestore import FileOpenIDStore
from openid.store import sqlstore

def getOpenIDStore(filestore_path, table_prefix):
    if not settings.DATABASE_ENGINE:
        return FileOpenIDStore(filestore_path)

    # Possible side-effect: create a database connection if one isn't
    # already open.
    connection.cursor()

    tablenames = {
        'settings_table': table_prefix + 'openid_settings',
        'associations_table': table_prefix + 'openid_associations',
        'nonces_table': table_prefix + 'openid_nonces',
        }

    types = {
        'postgresql': sqlstore.PostgreSQLStore,
        'mysql': sqlstore.MySQLStore,
        'sqlite3': sqlstore.SQLiteStore,
        }

    try:
        s = types[settings.DATABASE_ENGINE](connection.connection,
                                            **tablenames)
    except KeyError:
        raise ImproperlyConfigured, \
              "Database engine %s not supported by OpenID library" % \
              (settings.DATABASE_ENGINE,)

    try:
        s.createTables()
    except (SystemExit, KeyboardInterrupt, MemoryError), e:
        raise
    except:
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

def sendResponse(func):
    def _responseWrapper(request, *args, **kwargs):
        result = func(request, *args, **kwargs)

        if isinstance(result, http.HttpResponse):
            return result
        else:
            template_name, response_data = result
            context = RequestContext(request, response_data)
            template = loader.get_template(template_name)

            response_class = response_data.get('response_class', http.HttpResponse)
            return response_class(template.render(context))
    return _responseWrapper

def getTrustRoot(req):
    name = req.META['HTTP_HOST']
    try:
        name = name[:name.index(':')]
    except:
        pass

    try:
        port = int(req.META['SERVER_PORT'])
    except:
        port = 80

    proto = req.META['SERVER_PROTOCOL']

    if 'HTTPS' in proto:
        proto = 'https'
    else:
        proto = 'http'

    if port in [80, 443] or not port:
        port = ''
    else:
        port = ':%s' % (port,)

    url = "%s://%s%s/" % (proto, name, port)
    return url

def normalDict(request_data):
    return dict((k, v[0]) for k, v in request_data.iteritems())
