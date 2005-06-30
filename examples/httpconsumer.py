import BaseHTTPServer
import time

from urlparse import urlparse

import exutil
from openid.consumer import OpenIDConsumer, SimpleHTTPClient
from openid.interface import Request
from openid.association import *
from openid.errors import *

http_client = SimpleHTTPClient()
consumer = None

class DictionaryAssociationManager(BaseAssociationManager):
    def __init__(self):
        associator = DiffieHelmanAssociator(http_client)
        BaseAssociationManager.__init__(self, associator)
        self.associations = [] # inefficient, but ok for a toy example

    def update(self, new_assoc, expired):
        # This is horribly inefficient.  Don't use this code outside
        # of toy examples.
        if new_assoc is not None:
            self.associations.append(new_assoc)

        if expired is not None:
            for assoc1 in expired:
                for i, assoc2 in enumerate(self.associations):
                    if assoc1 == assoc2:
                        del self.associations[i]
                        break

    def get_all(self, server_url):
        results = []
        for assoc in self.associations:
            if assoc.server_url == server_url:
                results.append(assoc)

        return results

    def invalidate(self, server_url, assoc_handle):
        for i, assoc in enumerate(self.associations):
            if assoc.server_url == server_url and assoc.handle == assoc_handle:
                del self.associations[i]
                break

class ConsumerHandler(exutil.HTTPHandler):
    def _simplePage(self, msg):
        self._headers()
        self.wfile.write("""
        <html>
        <body style='background-color: #FFFFCC;'>
        <p>%s</p>
        <p><a href="/">home</a></p>
        </body>
        </html>
        """ % msg)

    def _error(self, msg):
        self._simplePage('Error: '+msg)

    def _inputForm(self):
        return """
        <html>
        <head><title>Openid Consumer Example</title></head>
        <body style='background-color: #FFFFCC;'>
        <form method="GET" action="/">
        Your Identity URL: <input type="text" name="identity_url" size="60"/>
        <br /><input type="submit" value="Log in" />
        </form>
        
        </body>
        </html>
        """
        
    def do_GET(self):
        try:
            # parse the input url
            proto, host, selector, params, qs, frag = urlparse(self.path)
            query = exutil.parseQuery(qs)

            # dispatch based on query args
            if 'identity_url' in query:
                # this is the entry point for a user.  do the
                # consumer's initialRequest which finds a server
                # association (unless in dumb mode) and then redirect
                # the UA to the server
                identity_url = query['identity_url']
                print 'making initial request'
                
                redirect_url = consumer.handle_request(
                    identity_url, self.headers['Referer'])

                if redirect_url is not None:
                    self._redirect(redirect_url)
                else:
                    self._error('Unable to find openid.server for ' +
                                identity_url)

            elif 'openid.mode' in query:
                try:
                    valid_to = consumer.handle_response(Request(query, 'GET'))
                except UserCancelled, e:
                    self._simplePage('Cancelled by user')
                except Exception, e:
                    self._error('Handling response: ' + str(e))
                else:
                    if valid_to:
                        self._simplePage('Logged in!  Until ' +
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
    import sys

    dumb = False
    if 'dumb' in sys.argv:
        dumb = True

    if dumb:
        assoc_mngr = DumbAssociationManager()
    else:
        assoc_mngr = DictionaryAssociationManager()

    consumer = OpenIDConsumer(http_client, assoc_mngr)

    print 'Consumer Server running...'
    print 'Go to http://localhost:8081/ in your browser'
    BaseHTTPServer.HTTPServer(('', 8081),
                              ConsumerHandler).serve_forever()
