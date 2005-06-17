import BaseHTTPServer
from urlparse import urlparse
import time

from openid.examples import util
from openid.consumer import OpenIDConsumer

_consumer = None
def getConsumer():    
    global _consumer
    if _consumer is None:
        _consumer = OpenIDConsumer()
    return _consumer

class ConsumerHandler(util.HTTPHandler):

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
        
    def do_GET(self):
        try:
            # parse the input url
            proto, host, selector, params, qs, frag = urlparse(self.path)
            query = util.parseQuery(qs)

            # grab the global OpenIDConsumer object - use singleton
            # to maintain same instance across requests
            consumer = getConsumer()

            # dispatch based on query args
            if 'identity_url' in query:
                # this is the entry point for a user.  do the
                # consumer's initailRequest which a server association
                # and then redirect the UA to the server
                identity_url = query['identity_url']
                print 'making initial request'
                
                redirect_url = consumer.handleRequest(identity_url,
                                                      self.headers['Referer'])

                if redirect_url is not None:
                    self._redirect(redirect_url)
                else:
                    self._error('Unable to find openid.server for '
                                + identity_url)

            elif 'openid.mode' in query:
                try:
                    valid_to = consumer.handleResponse(query)
                except Exception, e:
                    self._error('Handling response: '+str(e))
                else:
                    if valid_to:
                        self._simplePage('Logged in!  Until'+
                                         time.ctime(valid_to))
                    else:
                        self._simplePage('Not logged in. Invalid.')

                    
            else:
                self._headers()
                self.wfile.write(self._inputForm())
                return

        except:
            self._headers(500)
            raise
        
        
if __name__ == '__main__':
    print 'Consumer Server running...'
    print 'Go to http://localhost:8081/ in your browser'
    print
    BaseHTTPServer.HTTPServer(('', 8081),
                              ConsumerHandler).serve_forever()
