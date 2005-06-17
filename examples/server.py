import BaseHTTPServer
from urlparse import urlparse
import time

from openid.examples import util
from openid.concreteserver import ConcreteServer

_server = None
def getServer():
    global _server
    if _server is None:
        _server = ConcreteServer()
    return _server

class ServerHandler(util.HTTPHandler):

    def handleOpenIDRequest(self, query):
        try:
            server = getServer()
            is_redirect, data = server.handle(query)
            if is_redirect:
                self._redirect(data)
            else:
                self._headers()
                self.wfile.write(data)
        except:
            self._headers(500)
            raise
        

    def do_GET(self):
        print 'IN GET'
        qs = urlparse(self.path)[4]
        query = util.parseQuery(qs)
        self.handleOpenIDRequest(query)

    def do_POST(self):
        # post data is urlencoded args
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        query = util.parseQuery(post_data)
        self.handleOpenIDRequest(query)


if __name__ == '__main__':
    print 'OpenID Example Server running...'
    print
    BaseHTTPServer.HTTPServer(('', 8082),
                              ServerHandler).serve_forever()
