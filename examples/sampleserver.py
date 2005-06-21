import BaseHTTPServer
from urlparse import urlparse
import time, random

from openid.util import random_string, w3cdate
from openid.examples import util
from openid.errors import ProtocolError
from openid.server import OpenIDServer
from openid.interface import Request, response_page

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
        raise NotImplementedError

    def get_setup_response(self, identity, trust_root, return_to):
        raise NotImplementedError


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
    <tr><td>Identity:</td><td>%s</td></tr>
    <tr><td>Trust Root:</td><td>%s</td></tr>
  </table>
  <form method="POST" action="/">
    <input type="hidden" name="return_to" value="%s">
    <input type="submit" name="yes" value="yes" />
    <input type="submit" name="no" value="no" />
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
        

    def do_GET(self):
        parsed = urlparse(self.path)
        query = util.parseQuery(parsed[4])
        if query.get('action') == 'openid':
            self.handleOpenIDRequest(Request(query, 'GET'))
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
        if query.get('action') == 'openid':
            self.handleOpenIDRequest(Request(query, 'POST'))
        else:
            self._headers(500)


if __name__ == '__main__':
    print 'OpenID Example Server running...'
    print
    BaseHTTPServer.HTTPServer(('', 8082),
                              ServerHandler).serve_forever()
