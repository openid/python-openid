import BaseHTTPServer
from urlparse import urlparse
import time, random, Cookie

from openid.util import random_string, w3cdate
from openid.examples import util
from openid.errors import ProtocolError
from openid.server import OpenIDServer
from openid.interface import Request, response_page, redirect

class ConcreteServer(OpenIDServer):
    def __init__(self):
        OpenIDServer.__init__(self, random.SystemRandom())
        self.counter = 0
        self.assoc_store = {}
        self.trust_store = set()  # (identity, trust_root)

        self.secret_handle = None
        self.lifespan = 60 * 60 * 24 * 30 # 30 days

    def get_new_secret(self, assoc_type):
        if assoc_type == 'HMAC-SHA1':
            self.counter += 1

            secret = random_string(20, self.srand)
            issued = time.time()
            assoc_handle = '{HMAC-SHA1}%s/%i' % (w3cdate(issued), self.counter)
            replace_after = issued + (60 * 60 * 24 * 28)
            expiry = replace_after + (60 * 60 * 24 * 2)

            self.assoc_store[assoc_handle] = secret, expiry

            return secret, assoc_handle, issued, replace_after, expiry
        else:
            raise ProtocolError('Unknown assoc_type: %r' % assoc_type)

    def lookup_secret(self, assoc_handle):
        return self.assoc_store.get(assoc_handle)

    def get_server_secret(self):
        if self.secret_handle == None:
            ret = self.get_new_secret('HMAC-SHA1')
            secret, issued, assoc_handle, replace_after, expiry = ret
            self.assoc_store[assoc_handle] = secret, expiry
            self.secret_handle = assoc_handle
        else:
            secret, expiry = self.assoc_store[assoc_handle]
            if time.time() + (60 * 60 * 24 * 2) >= expiry:
                self.secret_handle = None
                return self.get_server_secret()

        return secret, self.secret_handle

    def get_auth_range(self, req, identity, trust_root):
        if 'http://localhost:8082/' + req.authorization != identity:
            return None

        if (identity, trust_root) in self.trust_store:
            now = time.time()
            return now, now + self.lifespan
        else:
            return None

    def add_trust(self, identity, trust_root):
        self.trust_store.add((identity, trust_root))

    def get_lifetime(self, identity):
        return self.lifespan

    def get_user_setup_url(self, identity, trust_root, return_to):
        args = {
            'identity': identity,
            'trust_root': trust_root,
            'return_to': return_to,
            }
        return append_args('http://localhost:8082/?action=allow', args)

    def get_setup_response(self, identity, trust_root, return_to):
        return redirect(self.get_user_setup_url(
            identity, trust_root, return_to))


server = ConcreteServer()
server.add_trust('fred', 'http://localhost:8081/')

identitypage = """<html>
<head>
  <title>This is an identity page</title>
  <link rel="openid.server" href="http://localhost:8082/?action=openid">
</head>
<body>
  <p>This is an identity page for %r.</p>
</body>
</html>
"""

mainpage = """<html>
<head>
  <title>Simple OpenID server</title>
</head>
<body>
<p>This is a simple OpenID server</p>
</body>
</html>
"""

decidepage = """<html>
<head>
  <title>Allow Authorization?</title>
</head>
<body>
  <h1>Allow Authorization?</h1>
  <p>In practice, you'd only get this page if you are
     logged in as the listed identity.</p>
  <table>
    <tr><td>Identity:</td><td>%(identity)s</td></tr>
    <tr><td>Trust Root:</td><td>%(trust_root)s</td></tr>
  </table>
  <form method="POST" action="/">
    <input type="hidden" name="action" value="allow" />
    <input type="hidden" name="identity" value="%(identity)s" />
    <input type="hidden" name="trust_root" value="%(trust_root)s" />
    <input type="hidden" name="return_to" value="%(return_to)s" />
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
<body>
  <h1>Log In!</h1>
  <p>This isn't even supposed to be secure, so don't complain.</p>
  <form method="GET" action="/">
    <input type="hidden" name="dest" value="%s" />
    <input type="text" name="user" value="" />
    <input type="submit" name="submit" value="Log In" />
  </form>
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
            self._headers(500)
            raise

    def user(self):
        try:
            return Cookie.SimpleCookie(self.headers['cookie'])['user'].value
        except:
            return ''

    def allow(self, query):
        user = self.user()
        identity = query['identity']
        if 'http://localhost:8082/' + user == identity:
            self._headers()
            self.wfile.write(decidepage % query)
        else:
            self._headers()
            self.wfile.write(loginpage % self.path)
            pass

    def login(self, query):
        user = query['user']
        dest = query.get('dest')
        if dest:
            self.send_response(302)
            self.send_header('Set-Cookie', 'user=%s;' % user)
            self.send_header('Location', dest)
            self.end_headers()
        else:
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.send_header('Set-Cookie', 'user=%s;' % user)
            self.end_headers()
            self.wfile.write('logged in as %r' % user)

    def do_GET(self):
        parsed = urlparse(self.path)
        query = util.parseQuery(parsed[4])
        action = query.get('action')
        if action == 'openid':
            self.handleOpenIDRequest(Request(query, 'GET', self.user()))
        if action == 'allow':
            self.allow(query)
        elif action == 'login':
            self.login(query)
        elif action == 'whoami':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write('you are %r' % self.user())
        elif len(query) == 0:
            path = parsed[2]
            if path == '/':
                self._headers()
                self.wfile.write(mainpage)
            else:
                self._headers()
                self.wfile.write(identitypage % path[1:])
        else:
            self._headers(500)

    def do_POST(self):
        # post data is urlencoded args
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        query = util.parseQuery(post_data)
        action = query.get('action')
        if action == 'openid':
            self.handleOpenIDRequest(Request(query, 'POST'))
        elif action == 'allow':
            if 'yes' in query:
                server.add_trust(query['identity'], query['trust_root'])
            self._redirect(query['return_to'])
        else:
            self._headers(500)


if __name__ == '__main__':
    print 'OpenID Example Server running...'
    BaseHTTPServer.HTTPServer(('', 8082),
                              ServerHandler).serve_forever()
