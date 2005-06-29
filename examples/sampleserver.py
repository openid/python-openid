import BaseHTTPServer
from urlparse import urlparse
import time, random, Cookie

from openid.util import random_string, w3cdate, append_args
from openid.examples import util
from openid.errors import ProtocolError, NoOpenIDArgs
from openid.server import OpenIDServer
from openid.interface import Request, response_page, redirect
from openid.association import ServerAssociation

addr = 'http://localhost:8082/'

class ConcreteServer(OpenIDServer):
    def __init__(self):
        OpenIDServer.__init__(self, random.SystemRandom())
        self.counter = 0
        self.assoc_store = {}
        self.trust_store = set()  # (identity, trust_root)

        self.secret_handle = None
        self.lifespan = 60 * 60 * 24 * 30 # 30 days

    def handle(self, req):
        # This is reimplemented in the subclass so that extra
        # debugging/tracing information can be extracted.  It isn't
        # necessary in the general case.
        print 'handling openid.mode=%r' % (req.get('mode'),)
        return OpenIDServer.handle(self, req)

    def get_new_secret(self, assoc_type):
        tmpl = '{%s}%i/%i'
        if assoc_type == 'HMAC-SHA1':
            self.counter += 1

            secret = random_string(20, self.srand)
            assoc_handle = tmpl % (assoc_type, time.time(), self.counter)
            replace_after_offset = 60 * 60
            expiry_offset = replace_after_offset + 60 * 60

            assoc = ServerAssociation(
                assoc_handle, secret, expiry_offset, replace_after_offset)

            self.assoc_store[assoc_handle] = assoc
            return assoc
        else:
            raise ProtocolError('Unknown assoc_type: %r' % assoc_type)

    def lookup_secret(self, assoc_handle):
        return self.assoc_store.get(assoc_handle)

    def get_server_secret(self):
        if self.secret_handle == None:
            assoc = self.get_new_secret('HMAC-SHA1')
            self.secret_handle = assoc.handle
        else:
            assoc = self.assoc_store[self.secret_handle]
            if time.time() >= assoc.replace_after:
                self.secret_handle = None
                return self.get_server_secret()

        return assoc

    def get_auth_range(self, req):
        if addr + req.authentication != req.identity:
            return None

        if (req.identity, req.trust_root) in self.trust_store:
            return self.lifespan
        else:
            return None

    def add_trust(self, identity, trust_root):
        self.trust_store.add((identity, trust_root))

    def get_user_setup_url(self, req):
        args = {
            'openid.mode': 'checkid_setup',
            'openid.identity': req.identity,
            'openid.trust_root': req.trust_root,
            'openid.return_to': req.return_to,
            'openid.assoc_handle': req.assoc_handle,
            }
        return append_args(addr + '?action=openid', args)

    def get_setup_response(self, req):
        args = {
            'identity': req.identity,
            'trust_root': req.trust_root,
            'fail_to': append_args(req.return_to, {'openid.mode': 'cancel'}),
            'success_to': append_args(addr, req.args),
            'action':'allow',
            }
        return redirect(append_args(addr, args))

server = ConcreteServer()

identitypage = """<html>
<head>
  <title>This is an identity page</title>
  <link rel="openid.server" href="%s?action=openid">
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
  <a href="?action=login">login</a><br />
  <a href="?action=whoami">who am I?</a>
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
    <tr><td>Identity:</td><td>%(identity)s</td></tr>
    <tr><td>Trust Root:</td><td>%(trust_root)s</td></tr>
  </table>
  <form method="POST" action="/">
    <input type="hidden" name="action" value="allow" />
    <input type="hidden" name="identity" value="%(identity)s" />
    <input type="hidden" name="trust_root" value="%(trust_root)s" />
    <input type="hidden" name="fail_to" value="%(fail_to)s" />
    <input type="hidden" name="success_to" value="%(success_to)s" />
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
  <form method="GET" action="/">
    <input type="hidden" name="action" value="login" />
    <input type="hidden" name="fail_to" value="%s" />
    <input type="hidden" name="success_to" value="%s" />
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
  <p>You seem to be <a href="%s">%s<a>...</p>
  <p><a href="/">home</a></p>
</body>
</html>
"""

loggedinpage = """<html>
<head>
  <title>You logged in!</title>
</head>
<body style='background-color: #CCCCFF;'>
  <h1>You've successfully logged in.</h1>
  <p>You have logged in as %r</p>
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

class ServerHandler(util.HTTPHandler):
    def handleOpenIDRequest(self, req):
        try:
            response = server.handle(req)
            if response.code == 302:
                self._redirect(response.redirect_url)
            else:
                self._headers(code=response.code,
                              content_type=response.content_type)

                self.wfile.write(response.body)
        except:
            import sys
            sys.excepthook(*sys.exc_info())
            self._headers(500)

    def user(self):
        try:
            return Cookie.SimpleCookie(self.headers['cookie'])['user'].value
        except:
            return ''

    def allow(self, query):
        user = self.user()
        identity = query['identity']
        if addr + user == identity:
            self._headers()
            self.wfile.write(decidepage % query)
        else:
            self._headers()
            self.wfile.write(
                loginpage % (query['fail_to'], query['success_to']))

    def login(self, query):
        user = query.get('user')
        if 'cancel' in query:
            dest = query.get('fail_to')
            if not dest:
                dest = '/'
            self._redirect(dest)
        elif user:
            dest = query.get('success_to')
            if dest:
                self.send_response(302)
                self.send_header('Set-Cookie', 'user=%s;' % user)
                self.send_header('Location', dest)
                self.end_headers()
            else:
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.send_header('Set-Cookie', 'user=%s;' % user)
                self.end_headers()
                self.wfile.write(loggedinpage % user)
        else:
            self._headers()
            self.wfile.write(loginpage % ('', ''))

    def do_GET(self):
        parsed = urlparse(self.path)
        query = util.parseQuery(parsed[4])
        action = query.get('action')
        if action == 'openid':
            try:
                self.handleOpenIDRequest(Request(query, 'GET', self.user()))
            except NoOpenIDArgs, e:
                self._headers()
                self.wfile.write(openidpage)
        elif action == 'allow':
            self.allow(query)
        elif action == 'login':
            self.login(query)
        elif action == 'whoami':
            self._headers()
            self.wfile.write(whoamipage % (self.user(), self.user()))
        elif len(query) == 0:
            path = parsed[2]
            if path == '/':
                self._headers()
                self.wfile.write(mainpage)
            else:
                self._headers()
                self.wfile.write(identitypage % (addr, path[1:]))
        else:
            self._headers(500)

    def do_POST(self):
        # post data is urlencoded args
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        query = util.parseQuery(post_data)
        query.update(util.parseQuery(urlparse(self.path)[4]))
        action = query.get('action')
        if action is None:
            action = util.parseQuery(urlparse(self.path)[4]).get('action')

        if action == 'openid':
            self.handleOpenIDRequest(Request(query, 'POST'))
        elif action == 'allow':
            if 'yes' in query:
                server.add_trust(query['identity'], query['trust_root'])
                self._redirect(query['success_to'])
            else:
                self._redirect(query['fail_to'])
        else:
            self._headers(500)


if __name__ == '__main__':
    import sys
    try:
        name = sys.argv[1]
    except:
        name = 'localhost'

    try:
        port = sys.argv[2]
    except:
        port = '8082'
    addr = 'http://%s:%s/' % (name, port)

    print 'OpenID Example Server running...'
    BaseHTTPServer.HTTPServer(('', int(port)),
                              ServerHandler).serve_forever()
