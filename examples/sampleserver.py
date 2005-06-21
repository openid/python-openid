import BaseHTTPServer
from urlparse import urlparse
import time, random

from openid.examples import util
from openid.errors import ProtocolError
from openid.server import OpenIDServer
from openid.interface import Request, response_page

class ConcreteServer(OpenIDServer):
    def __init__(self):
        OpenIDServer.__init__(self, random.SystemRandom())
        self.secret = '12345678900987654321'
        self.assoc_handle = 'huh'
        self.issued = time.time()
        self.replace_after = self.issued + (60 * 60 * 24 * 29) 
        self.expiry = self.replace_after + (60 * 60 * 24)

    def get_new_secret(self, assoc_type):
        if assoc_type == 'HMAC-SHA1':
            return (self.secret, self.assoc_handle, self.issued,
                    self.replace_after, self.expiry)
        else:
            raise ProtocolError('Unknown assoc_type: %r' % assoc_type)

    def lookup_secret(self, assoc_handle):
        if assoc_handle == self.assoc_handle:
            return self.secret, self.expiry 
        else:
            raise ProtocolError('Unknown assoc_handle: %r' % assoc_handle)

    def get_server_secret(self):
        return self.secret, self.assoc_handle

    def get_auth_range(self, unused_identity, unused_trust_root):
        "Every identity trusts every trust_root!  Yay!"
        now = time.time()
        in_an_hour = now + (60 * 60)
        return now, in_an_hour

    def get_lifetime(self, identity):
        return 60 * 60

    def get_user_setup_url(self, identity, trust_root):
        return ''

    def get_setup_response(self, identity, trust_root, return_to):
        return response_page('')


server = ConcreteServer()
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
        print 'IN GET'
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
