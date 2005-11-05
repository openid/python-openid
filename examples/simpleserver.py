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
from openid.stores.filestore import FileOpenIDStore

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
        self.user = None
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
                    self.user = morsel.value
                else:
                    self.user = None
            else:
                self.user = None

            if path == '/':
                self.showMainPage()
            elif path == '/openidserver':
                self.doOpenIDGet()
            elif path == '/login':
                self.showLoginPage('/', '/')
            elif path == '/loginsubmit':
                self.doLogin()
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

                    self.redirect(self.query['success_to'])

                elif 'no' in self.query:
                    self.redirect(self.query['fail_to'])

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


    def doOpenIDGet(self):
        identity, trust_root = self.server.openid.getAuthData(self.query)

        # check all three important parts
        authorized = identity and \
                     identity == self.server.base_url + self.user and \
                     (identity, trust_root) in self.server.approved

        status, info = self.server.openid.getAuthenticationResponse(\
            authorized, self.query)

        if status == interface.REDIRECT:
            self.redirect(info)

        elif status == interface.DO_AUTH:
            retry, cancel = info

            if identity and identity == self.server.base_url + self.user:
                self.showDecidePage(identity, trust_root, retry, cancel)
            else:
                self.showLoginPage(retry, cancel)

        elif status == interface.DO_ABOUT:
            self.showAboutPage(self)

        elif status == interface.ERROR:
            self.showErrorPage(info)

        else:
            assert 0, 'should be unreachable %r' % (status,)

    def doLogin(self):
        if 'submit' in self.query:
            cookie = ('Set-Cookie', 'user=%s' % self.query['user'])
            self.redirect(self.query['success_to'], cookie)
        elif 'cancel' in self.query:
            self.redirect(self.query['fail_to'])
        else:
            assert 0, 'strange login %r' % (self.query,)

    def redirect(self, url, *headers):
        self.send_response(302)
        self.send_header('Location', url)

        for k, v in headers:
            self.send_header(k, v)

        self.end_headers()

    def showAboutPage(self):
        self.showPage(200, 'This is an OpenID server', msg='''\
        <p>This is an OpenID server.  See <a href="/">our main
        page</a> or <a href="http://www.openid.net/">the OpenID
        page<a> for more information.</p>
        ''')

    def showErrorPage(self, error_message):
        self.showPage(400, 'Error Processing Request', err='''\
        <p>%s</p>
        <!--

        This is a large comment.  It exists to make this page larger.
        That is unfortunately necessary because of the "smart"
        handling of pages returned with an error code in IE.

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
        ''' % error_message)

    def showDecidePage(self, identity, trust_root, retry, cancel):
        args = {
            'identity': identity,
            'trust_root': trust_root,
            'retry': retry,
            'cancel': cancel,
            }
        self.showPage(200, 'Allow this login?', msg='''\
        <p>A new site has asked for your identity.  If this login is
        approved, the site represented by the Trust Root below will be
        told that you are the identity listed below.  (If you are
        using a delegated identity, the site will take care of
        reversing the delegation on its own.)</p>        
        ''' % args, form='''\
        <table>
          <tr><td>Identity:</td><td>%(identity)s</td></tr>
          <tr><td>Trust Root:</td><td>%(trust_root)s</td></tr>
        </table>
        <p>Allow this login to proceed?</p>
        <form method="POST" action="/allow">
          <input type="hidden" name="identity" value="%(identity)s" />
          <input type="hidden" name="trust_root" value="%(trust_root)s" />
          <input type="hidden" name="success_to" value="%(retry)s" />
          <input type="hidden" name="fail_to" value="%(cancel)s" />
          <input type="submit" name="yes" value="yes" />
          <input type="submit" name="no" value="no" />
        </form>
        ''' % args)

    def showIdPage(self, path):
        tag = '<link rel="openid.server" href="%sopenidserver">' %\
              self.server.base_url
        ident = self.server.base_url + path[1:]

        self.showPage(200, 'An Identity Page', link_tag=tag, msg='''\
        <p>This is an identity page for %s.  Not much to see here.</p>
        <p><a href="/">Main Page</a></p>
        ''' % ident)

    def showMainPage(self):
        self.showPage(200, 'Main Page', msg='''\
        <p>This is a simple OpenID server using the python OpenID
        server library module.  If you are not logged in, you can go
        to the <a href="/login">login</a> page.</p>
        ''')

    def showLoginPage(self, success_to, fail_to):
        self.showPage(200, 'Login Page', msg='''\
        <p>This is the login page.  You can reach this page in one of
        two ways.  If you chose to manually log in, you know what to
        do. The other way to reach this page is if you are attempting
        to use this server to log in as an identity not currently
        matching the identity you are currently logged in as on this
        server.  In that case, either log in as the identity you specified or
        cancel.</p>

        <p>This server does not use passwords because it is designed
        as a sample only.  Adding in a password mechanism would have
        made it more complicated without adding any benefit to
        understanding.</p>
        ''', form='''\
        <form method="GET" action="/loginsubmit">
          <input type="hidden" name="success_to" value="%s" />
          <input type="hidden" name="fail_to" value="%s" />
          <input type="text" name="user" value="" />
          <input type="submit" name="submit" value="Log In" />
          <input type="submit" name="cancel" value="Cancel" />
        </form>
        ''' % (success_to, fail_to))

    def showPage(self, response_code, title,
                 link_tag='', msg=None, err=None, form=None):

        if self.user is None:
            user_link = '<a href="/login">not logged in<a>'
        else:
            user_link = 'logged in as <a href="/%s">%s</a>' % \
                        (self.user, self.user)

        body = ''

        if err is not None:
            body +=  '''\
            <div class="error">
              %s
            </div>
            ''' % err

        if msg is not None:
            body += '''\
            <div class="message">
              %s
            </div>
            ''' % msg

        if form is not None:
            body += '''\
            <div class="form">
              %s
            </div>
            ''' % form

        contents = {
            'title': 'Python OpenID Server Example - ' + title,
            'link_tag': link_tag,
            'body': body,
            'user_link': user_link,
            }
        
        self.send_response(response_code)

        self.wfile.write('''\
Content-type: text/html

<html>
  <head>
    <title>%(title)s</title>
    %(link_tag)s
  </head>
  <style type="text/css">
      * {
        font-family: verdana,sans-serif;
      }
      body {
        width: 50em;
        margin: 1em;
      }
      div {
        padding: .5em;
      }
      table {
        margin: none;
        padding: none;
      }
      .banner {
        padding: none 1em 1em 1em;
        width: 100%%;
      }
      .leftbanner {
        text-align: left;
      }
      .rightbanner {
        text-align: right;
        font-size: smaller;
      }
      .error {
        border: 1px solid #ff0000;
        background: #ffaaaa;
        margin: .5em;
      }
      .message {
        border: 1px solid #2233ff;
        background: #eeeeff;
        margin: .5em;
      }
      .form {
        border: 1px solid #777777;
        background: #ddddcc;
        margin: .5em;
        margin-top: 1em;
        padding-bottom: 0em;
      }
  </style>
  <body>
    <table class="banner">
      <tr>
        <td class="leftbanner">
          <h1>Sample OpenID Server</h1>
        </td>
        <td class="rightbanner">
          You are %(user_link)s.
        </td>
      </tr>
    </table>
%(body)s
  </body>
</html>
''' % contents)


def main(host, port, data_path):
    # Instantiate OpenID consumer store and OpenID consumer.  If you
    # were connecting to a database, you would create the database
    # connection and instantiate an appropriate store here.
    if port == 80:
        server_url = 'http://%s/openidserver' % host
    else:
        server_url = 'http://%s:%s/openidserver' % (host, port)
    store = FileOpenIDStore('sstore')
    server = interface.OpenIDServer(server_url, store)

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
