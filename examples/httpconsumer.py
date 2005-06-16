from BaseHTTPServer import *
from urlparse import urlparse
import cgi
import time

from openid.consumer import OpenIDConsumer

_consumer = None
def getConsumer():    
    global _consumer
    if _consumer is None:
        _consumer = OpenIDConsumer()
    return _consumer

def parseQuery(qs):
    query = cgi.parse_qs(qs)
    for k, v in query.items():
        query[k] = query[k][0]
    return query

class ConsumerHandler(BaseHTTPRequestHandler):

    def _inputForm(self):
        return """
        <html>
        <head><title>Openid Consumer Example</title></head>
        <body>
        <form method="GET" action="/">
        Your Identity URL: <input type="text" name="identity_url" />
        <input type="submit" value="Log in" />
        </form>
        
        </body>
        </html>
        """

    def _simplePage(self, msg):
        self._headers()
        self.wfile.write("""
        <html>
        <head><title>Openid Consumer Example</title></head>
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

    def do_GET(self):
        try:
            # parse the input url
            proto, host, selector, params, qs, frag = urlparse(self.path)
            query = parseQuery(qs)

            # grab the global OpenIDConsumer object - use singleton
            # to maintain same instance across requests
            consumer = getConsumer()

            # dispatch based on query args
            if 'identity_url' in query:
                # this is the entry point for a user.  do the
                # consumer's initailRequest which a server association
                # and then redirect the UA to the server
                identity_url = query['identity_url']
                redirect_url = consumer.initialRequest(identity_url, '/')
                if redirect_url is not None:
                    self._redirect(redirect_url)
                else:
                    self._error('Unable to find openid.server for '
                                + identity_url)

            elif 'openid.mode' in query:
                mode = query['openid.mode']
                if mode == 'id_res':
                    valid_to = consumer.idResponse(query)
                    if valid_to:
                        self._simplePage('Logged in!  Until'+
                                         time.ctime(valid_to))
                    else:
                        self._simplePage('Not logged in. Invalid.')
                else:
                    self._error("Don't know about openid.mode: "+mode)
                    
            else:
                self._headers()
                self.wfile.write(self._inputForm())
                return

        except:
            self._headers(500)
            raise
        
        
if __name__ == '__main__':
    print 'Server running...'
    print 'Go to http://localhost:8081/ in your browser'
    print
    HTTPServer(('', 8081), ConsumerHandler).serve_forever()
