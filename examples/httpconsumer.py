import BaseHTTPServer
import time
import sys
import cgitb
import random
import hmac, sha

from urlparse import urlparse

from openid.consumer import OpenIDConsumer, SimpleHTTPClient
from openid.interface import Request
from openid.association import (BaseAssociationManager,
                                DiffieHelmanAssociator,
                                DumbAssociationManager)
from openid.util import random_string, append_args, hmacsha1, to_b64

import exutil

http_client = SimpleHTTPClient()

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

assoc_mngr = None

class SampleConsumer(OpenIDConsumer):
    def __init__(self, *args, **kwargs):
        OpenIDConsumer.__init__(self, *args, **kwargs)
        self.secret = random_string(20, random.SystemRandom())

    def get_assoc_mngr(self):
        return assoc_mngr

    def get_http_client(self):
        return http_client

    def verify_return_to(self, return_to):
        # parse the input url
        proto, host, selector, params, qs, frag = urlparse(return_to)
        if host != 'localhost:8081':
            return False

        query = exutil.parseQuery(qs)
        v = to_b64(hmacsha1(self.secret, query['id'] + query['time']))

        if v != query['v']:
            return False

        # reject really old return_to urls
        if int(query['time']) + 60 * 60 * 6 < int(time.time()):
            return False

        return True

    def create_return_to(self, base, identity):
        args = {
            'id': identity,
            'time': str(int(time.time())),
            }

        args['v'] = to_b64(hmacsha1(self.secret, args['id'] + args['time']))
        return append_args(base, args)

consumer = SampleConsumer()

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
        self._simplePage('Error: ' + msg)

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

    def doValidLogin(self, login):
        if login.verifyIdentity(self.query['id']):
            self._simplePage('Logged in as ' + self.query['id'])
        else:
            self.doInvalidLogin()

    def doInvalidLogin(self):
        self._simplePage('Not logged in. Invalid.')

    def doUserCancelled(self):
        self._simplePage('Cancelled by user')

    def doCheckAuthRequired(self, server_url, return_to, post_data):
        response = consumer.check_auth(server_url, return_to, post_data)
        response.doAction(self)

    def doErrorFromServer(self, message):
        raise RuntimeError(message)

    def doUserSetupNeeded(self, user_setup_url):
        # Not using checkid_immediate, so this shouldn't happen.
        raise RuntimeError(user_setup_url)

    def do_GET(self):
        try:
            # parse the input url
            proto, host, selector, params, qs, frag = urlparse(self.path)
            self.query = query = exutil.parseQuery(qs)

            # dispatch based on query args
            if 'identity_url' in query:
                # this is the entry point for a user.  do the
                # consumer's initialRequest which finds a server
                # association (unless in dumb mode) and then redirect
                # the UA to the server
                identity_url = query['identity_url']
                print 'making initial request'

                ret = consumer.find_identity_info(identity_url)
                if ret is None:
                    fmt = 'Unable to find openid.server for %r. Query was %r.'
                    self._error(fmt % (identity_url, qs))
                else:
                    consumer_id, server_id, server_url = ret

                    return_to = consumer.create_return_to(
                        'http://localhost:8081/', consumer_id)
                    trust_root = 'http://localhost:8081/'

                    redirect_url = consumer.handle_request(
                        server_id, server_url, return_to, trust_root)

                    self._redirect(redirect_url)

            elif 'openid.mode' in query:
                response = consumer.handle_response(Request(query, 'GET'))
                response.doAction(self) # using visitor pattern approach
            else:
                self._headers()
                self.wfile.write(self._inputForm())

        except:
            self._headers(500)
            self.wfile.write(cgitb.html(sys.exc_info(), context=10))
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

    print 'Consumer Server running...'
    BaseHTTPServer.HTTPServer(('', 8081),
                              ConsumerHandler).serve_forever()
