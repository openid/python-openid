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
from openid.server import server
from openid.store.filestore import FileOpenIDStore

class OpenIDHTTPServer(HTTPServer):
    """
    http server that contains a reference to an OpenID Server and
    knows its base URL.
    """
    def __init__(self, oidserver, *args, **kwargs):
        HTTPServer.__init__(self, *args, **kwargs)

        if self.server_port != 80:
            self.base_url = ('http://%s:%s/' %
                             (self.server_name, self.server_port))
        else:
            self.base_url = 'http://%s/' % (self.server_name,)

        self.openid = oidserver
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
                if status == server.OK:
                    self.send_response(200)
                elif status == server.ERROR:
                    self.send_response(400)
                else:
                    assert 0, 'should be unreachable %r' % (status,)

                self.end_headers()
                self.wfile.write(body)

            elif path == '/allow':
                if 'yes' in self.query:
                    identity = self.query['identity']
                    trust_root = self.query['trust_root']
                    if self.query.get('remember', 'no') == 'yes':
                        duration = 'always'
                    else:
                        duration = 'once'

                    self.server.approved[(identity, trust_root)] = duration
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
        identity, trust_root = \
                  self.server.openid.getAuthenticationData(self.query)

        identity_ok = self.user and identity == self.server.base_url + self.user
        # check all three important parts
        if identity_ok:
            key = (identity, trust_root)
            approval = self.server.approved.get(key)
            if approval == 'once':
                del self.server.approved[key]

            authorized = approval is not None
        else:
            authorized = False

        status, info = self.server.openid.getAuthenticationResponse(\
            authorized, self.query)

        if status == server.REDIRECT:
            self.redirect(info)

        elif status == server.DO_AUTH:
            retry, cancel = info

            if identity_ok:
                self.showDecidePage(identity, trust_root, retry, cancel)
            else:
                self.showLoginPage(retry, cancel)

        elif status == server.DO_ABOUT:
            self.showAboutPage()

        elif status == server.ERROR:
            self.showErrorPage(info)

        else:
            assert 0, 'should be unreachable %r' % (status,)

    def doLogin(self):
        if 'submit' in self.query:
            if 'user' in self.query:
                cookie = ('Set-Cookie', 'user=%s' % self.query['user'])
            else:
                t1970 = time.gmtime(0)
                expires = time.strftime(
                    'Expires=%a, %d-%b-%y %H:%M:%S GMT', t1970)
                cookie = ('Set-Cookie', 'user=;%s' % expires)
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
        self.showPage(200, 'Approve OpenID request?', msg='''\
        <p>A new site has asked for your identity.  If you approve,
        the site represented by the trust root below will be
        told that you control identity URL listed below. (If you are
        using a delegated identity, the site will take care of
        reversing the delegation on its own.)</p>
        ''', form='''\
        <table>
          <tr><td>Identity:</td><td>%(identity)s</td></tr>
          <tr><td>Trust Root:</td><td>%(trust_root)s</td></tr>
        </table>
        <p>Allow this login to proceed?</p>
        <form method="POST" action="/allow">
          <input type="checkbox" id="remember" name="remember" value="yes"
              checked="checked" /><label for="remember">Remember this
              decision</label><br />
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

        approved_trust_roots = []
        for (aident, trust_root) in self.server.approved.keys():
            if aident == ident:
                trs = '<li><tt>%s</tt></li>\n' % escape(trust_root)
                approved_trust_roots.append(trs)

        if approved_trust_roots:
            prepend = '<p>Approved trust roots:</p>\n<ul>\n'
            approved_trust_roots.insert(0, prepend)
            approved_trust_roots.append('</ul>\n')
            msg = ''.join(approved_trust_roots)
        else:
            msg = ''

        self.showPage(200, 'An Identity Page', link_tag=tag, msg='''\
        <p>This is an identity page for %s.</p>
        %s
        ''' % (ident, msg))

    def showMainPage(self):
        if self.user:
            openid_url = self.server.base_url + self.user
            user_message = """\
            <p>You are logged in as %s. Your OpenID identity URL is
            <tt><a href=%s>%s</a></tt>. Enter that URL at an OpenID
            consumer to test this server.</p>
            """ % (self.user, quoteattr(openid_url), openid_url)
        else:
            user_message = """\
            <p>This server uses a cookie to remember who you are in
            order to simulate a standard Web user experience. You are
            not <a href='/login'>logged in</a>.</p>"""

        self.showPage(200, 'Main Page', msg='''\
        <p>This is a simple OpenID server implemented using the <a
        href="http://openid.schtuff.com/">Python OpenID
        library</a>.</p>

        %s

        <p>To use this server with a consumer, the consumer must be
        able to fetch HTTP pages from this web server. If this
        computer is behind a firewall, you will not be able to use
        OpenID consumers outside of the firewall with it.</p>

        <p>The URL for this server is <a href=%s><tt>%s</tt></a>.</p>
        ''' % (user_message, quoteattr(self.server.base_url), self.server.base_url))

    def showLoginPage(self, success_to, fail_to):
        if self.path == '/login':
            user_message = None
        else:
            if self.user:
                why = '''\
                logged in as <strong>%s</strong>, who does not own the
                identity URL that the consumer is attempting to
                verify''' % (self.user,)
            else:
                why = 'not logged in to this server'

            user_message = """
            <p>This is the login page for the OpenID server.  You are
            attempting to use this server to verify an identity URL
            and you are %s. The server needs to know who you are
            before you can approve the request.</p>

            <p>Click <strong>Cancel</strong> to return to the OpenID
            consumer that initiated this transaction.</p>
            """ % (why,)

        self.showPage(200, 'Login Page', msg=user_message, form='''\
        <h2>Login</h2>
        <p>You may log in with any name. This server does not use
        passwords because it is just a sample of how to use the OpenID
        library.</p>
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
            user_link = '<a href="/login">not logged in</a>.'
        else:
            user_link = 'logged in as <a href="/%s">%s</a>.<br /><a href="/loginsubmit?submit=true&success_to=/login">Log out</a>' % \
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
      h1 a:link {
          color: black;
          text-decoration: none;
      }
      h1 a:visited {
          color: black;
          text-decoration: none;
      }
      h1 a:hover {
          text-decoration: underline;
      }
      body {
        font-family: verdana,sans-serif;
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
          <h1><a href="/">Sample OpenID Server</a></h1>
        </td>
        <td class="rightbanner">
          You are %(user_link)s
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
    store = FileOpenIDStore(data_path)
    oidserver = server.OpenIDServer(server_url, store)

    addr = (host, port)
    httpserver = OpenIDHTTPServer(oidserver, addr, ServerHandler)

    print 'Server running at:'
    print httpserver.base_url
    httpserver.serve_forever()

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
