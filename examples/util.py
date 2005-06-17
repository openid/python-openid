import BaseHTTPServer
import cgi

def parseQuery(qs):
    query = cgi.parse_qs(qs)
    for k, v in query.items():
        query[k] = query[k][0]
    return query



class HTTPHandler(BaseHTTPServer.BaseHTTPRequestHandler):

    def _simplePage(self, msg):
        self._headers()
        self.wfile.write("""
        <html>
        <body>
        %s
        </body>
        </html>
        """ % msg)

    def _error(self, msg):
        self._simplePage('Error: '+msg)

    def _headers(self, code=200, content_type='text/html'):
        self.send_response(code)
        self.send_header('Content-type', content_type)
        self.end_headers()        

    def _redirect(self, url):
        self.send_response(302)
        self.send_header('Location', url)
        self.end_headers()

