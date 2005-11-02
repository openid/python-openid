#!/usr/bin/env python

__copyright__ = 'Copyright 2005, Janrain, Inc.'

from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from urlparse import urlparse

import time
import random
import Cookie
import cgi
import cgitb
import sys

from xml.sax.saxutils import quoteattr, escape

from openid import cryptutil
from openid import oidutil
from openid.association import Association
from openid.server import interface
from openid.server.stores import ServerAssociationStore

class Store(ServerAssociationStore):
    """
    This is a simple, in-memory store.  Any server using it will be
    generating transient secrets that will only be available to the
    process that generated them.
    """
    def __init__(self):
        self.count = 0
        self.assocs = {}
        self.lifespan = 60 * 60 * 2

    def get(self, assoc_type):
        assert assoc_type == 'HMAC-SHA1'
        handle = '{%s}%d/%d' % (assoc_type, time.time(), self.count)
        self.count += 1
        secret = cryptutil.randomString(20)
        assoc = Association.fromExpiresIn(self.lifespan, handle, secret)
        self.assocs[handle] = assoc
        return assoc

    def lookup(self, assoc_handle, assoc_type):
        if not assoc_handle.startswith('{%s}' % assoc_type):
            return None
        return self.assocs.get(assoc_handle)

    def remove(self, handle):
        if handle in self.assocs:
            del self.assocs[handle]

class OpenIDHTTPServer(HTTPServer):
    """
    http server that contains a reference to an OpenID Server and
    knows its base URL.
    """
    def __init__(self, server, *args, **kwargs):
        HTTPServer.__init__(self, *args, **kwargs)

        if self.server_port != 80:
            self.base_url = ('http://%s:%s/' %
                             (self.server_name, self.server_port))
        else:
            self.base_url = 'http://%s/' % (self.server_name,)

        self.openid = server
        self.approved = {}

class ServerHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)


    def do_GET(self):
        try:
            self.parsed_uri = urlparse(self.path)
            self.query = {}
            for k, v in cgi.parse_qsl(self.parsed_uri[4]):
                self.query[k] = v

            path = self.parsed_uri[2].lower()

            cookies = self.headers.get('Cookie')
            if cookies:
                morsel = Cookie.BaseCookie(cookies).get('user')
                if morsel:
                    user = morsel.value
                else:
                    user = None
            else:
                user = None

            if path == '/':
                self.showMainPage()
            elif path == '/openidserver':
                self.doOpenIDGet(user)
            elif path == '/login':
                self.showLoginPage('/', '/')
            elif path == '/loginsubmit':
                self.doLogin()
            elif path == '/whoami':
                self.showWhoAmI(user)
            else:
                self.showIdPage(path)

        except (KeyboardInterrupt, SystemExit):
            raise
        except:
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(cgitb.html(sys.exc_info(), context=10))

    def do_POST(self):
        try:
            self.parsed_uri = urlparse(self.path)

            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)

            self.query = {}
            for k, v in cgi.parse_qsl(post_data):
                self.query[k] = v

            path = self.parsed_uri[2]
            if path == '/openidserver':
                status, body = self.server.openid.processPost(self.query)
                if status == interface.OK:
                    self.send_response(200)
                elif status == interface.ERROR:
                    self.send_response(400)
                else:
                    assert 0, 'should be unreachable %r' % (status,)

                self.end_headers()
                self.wfile.write(body)

            elif path == '/allow':
                if 'yes' in self.query:
                    identity = self.query['identity']
                    trust_root = self.query['trust_root']
                    self.server.approved[(identity, trust_root)] = 1

                    self.send_response(302)
                    self.send_header('Location', self.query['success_to'])
                    self.end_headers()

                elif 'no' in self.query:
                    self.send_response(302)
                    self.send_header('Location', self.query['fail_to'])
                    self.end_headers()

                else:
                    assert 0, 'strange allow post.  %r' % (self.query,)

            else:
                self.send_response(404)
                self.end_headers()

        except (KeyboardInterrupt, SystemExit):
            raise
        except:
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(cgitb.html(sys.exc_info(), context=10))


    def doOpenIDGet(self, user):
        identity, trust_root = self.server.openid.getAuthData(self.query)

        # check all three important parts
        authorized = identity and \
                     identity == self.server.base_url + user and \
                     (identity, trust_root) in self.server.approved

        status, info = self.server.openid.processGet(authorized, self.query)

        if status == interface.REDIRECT:
            self.send_response(302)
            self.send_header('Location', info)
            self.end_headers

        elif status == interface.DO_AUTH:
            retry, cancel = info

            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

            if identity and identity == self.server.base_url + user:
                self.wfile.write(decidepage % (identity,
                                               trust_root,
                                               identity,
                                               trust_root,
                                               retry,
                                               cancel))
            else:
                self.wfile.write(loginpage % (retry, cancel))

        elif status == interface.DO_ABOUT:
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(openidpage)

        elif status == interface.ERROR:
            self.send_response(400)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(errorpage % (info,))

        else:
            assert 0, 'should be unreachable %r' % (status,)

    def doLogin(self):
        self.send_response(302)
        if 'submit' in self.query:
            self.send_header('Location', self.query['success_to'])
            self.send_header('Set-Cookie', 'user=%s' % self.query['user'])
        elif 'cancel' in self.query:
            self.send_header('Location', self.query['fail_to'])
        else:
            assert 0, 'strange login %r' % (self.query,)
        self.end_headers()

    def showWhoAmI(self, user):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

        self.wfile.write(whoamipage % (quoteattr(user), escape(user)))

    def showIdPage(self, path):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

        ident = self.server.base_url + path[1:]
        self.wfile.write(identitypage % (self.server.base_url, ident))

    def showMainPage(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

        self.wfile.write(mainpage)

    def showLoginPage(self, success_to, fail_to):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

        self.wfile.write(loginpage % (success_to, fail_to))

identitypage = """<html>
<head>
  <title>This is an identity page</title>
  <link rel="openid.server" href="%sopenidserver">
</head>
<body style='background-color: #CCCCFF;'>
  <p>This is an identity page for %r.</p>
  <p><a href="/">home</a></p>
</body>
</html>
"""

mainpage = """<html>
<head>
  <title>Simple OpenID server</title>
</head>
<body style='background-color: #CCCCFF;'>
<h1>This is a simple OpenID server</h1>
<p>
  <a href="/login">login</a><br />
  <a href="/whoami">who am I?</a>
</p>
</body>
</html>
"""

decidepage = """<html>
<head>
  <title>Allow Authorization?</title>
</head>
<body style='background-color: #CCCCFF;'>
  <h1>Allow Authorization?</h1>
  <table>
    <tr><td>Identity:</td><td>%s</td></tr>
    <tr><td>Trust Root:</td><td>%s</td></tr>
  </table>
  <form method="POST" action="/allow">
    <input type="hidden" name="identity" value="%s" />
    <input type="hidden" name="trust_root" value="%s" />
    <input type="hidden" name="success_to" value="%s" />
    <input type="hidden" name="fail_to" value="%s" />
    <input type="submit" name="yes" value="yes" />
    <input type="submit" name="no" value="no" />
  </form>
</body>
</html>
"""

loginpage = """<html>
<head>
  <title>Log In!</title>
</head>
<body style='background-color: #CCCCFF;'>
  <h1>Log In!</h1>
  <p>No password used because this is just an example.</p>
  <form method="GET" action="/loginsubmit">
    <input type="hidden" name="success_to" value="%s" />
    <input type="hidden" name="fail_to" value="%s" />
    <input type="text" name="user" value="" />
    <input type="submit" name="submit" value="Log In" />
    <input type="submit" name="cancel" value="Cancel" />
  </form>
</body>
</html>
"""

whoamipage = """<html>
<head>
  <title>Who are you?</title>
</head>
<body style='background-color: #CCCCFF;'>
  <h1>Who are you?</h1>
  <p>You seem to be <a href=%s>%s<a>...</p>
  <p><a href="/">home</a></p>
</body>
</html>
"""

openidpage = """<html>
<head>
  <title>You've found an openid server</title>
</head>
<body style='background-color: #CCCCFF;'>
  <h1>This is an OpenID server</h1>
  <p>See <a href="http://www.openid.net/">openid.net</a>
  for more information.</p>
</body>
</html>
"""

errorpage =  """<html>
<head>
  <title>Something went wrong</title>
</head>
<body style='background-color: #CCCCFF;'>
  <h1>There was some sort of error processing the request:</h1>
  <p>%s</p>
<!--

This is a large comment.  It exists to make this page larger.
That is unfortunately necessary because of IE's 'smart'
handling of pages returned with an error code.

*************************************************************
*************************************************************
*************************************************************
*************************************************************
*************************************************************
*************************************************************
*************************************************************
*************************************************************
*************************************************************
*************************************************************
*************************************************************
*************************************************************
*************************************************************
*************************************************************
*************************************************************
*************************************************************
*************************************************************
*************************************************************
*************************************************************
*************************************************************
*************************************************************
*************************************************************
*************************************************************

-->
</body>
</html>
"""

def main(host, port, data_path):
    # Instantiate OpenID consumer store and OpenID consumer.  If you
    # were connecting to a database, you would create the database
    # connection and instantiate an appropriate store here.
    if port == 80:
        server_url = 'http://%s/openidserver' % host
    else:
        server_url = 'http://%s:%s/openidserver' % (host, port)
    istore = Store()
    estore = Store()
    server = interface.OpenIDServer(server_url, istore, estore)

    addr = (host, port)
    server = OpenIDHTTPServer(server, addr, ServerHandler)

    print 'Server running at:'
    print server.base_url
    server.serve_forever()

if __name__ == '__main__':
    host = 'localhost'
    data_path = 'sstore'
    port = 8000

    try:
        import optparse
    except ImportError:
        pass # Use defaults (for Python 2.2)
    else:
        parser = optparse.OptionParser('Usage:\n %prog [options]')
        parser.add_option(
            '-d', '--data-path', dest='data_path', default=data_path,
            help='Data directory for storing OpenID consumer state. '
            'Defaults to "%default" in the current directory.')
        parser.add_option(
            '-p', '--port', dest='port', type='int', default=port,
            help='Port on which to listen for HTTP requests. '
            'Defaults to port %default.')
        parser.add_option(
            '-s', '--host', dest='host', default=host,
            help='Host on which to listen for HTTP requests. '
            'Also used for generating URLs. Defaults to %default.')

        options, args = parser.parse_args()
        if args:
            parser.error('Expected no arguments. Got %r' % args)

        host = options.host
        port = options.port
        data_path = options.data_path

    main(host, port, data_path)
