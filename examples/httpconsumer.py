import BaseHTTPServer
import time
import sys
import cgitb
import random
import hmac, sha

from urlparse import urlparse

from openid.consumer import OpenIDConsumer
from openid.interface import ConsumerRequest
from openid.association import (AbstractConsumerAssociationManager,
                                DiffieHelmanAssociator,
                                DumbAssociationManager)
from openid.util import random_string, append_args, hmacsha1, to_b64
from openid import httpclient

import exutil

http_client = httpclient.SimpleHTTPClient()

# flags used to control consumer behavior.
dumb = False
split = False

class DictionaryAssociationManager(AbstractConsumerAssociationManager):
    def __init__(self):
        associator = DiffieHelmanAssociator(http_client)
        AbstractConsumerAssociationManager.__init__(self, associator)
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

consumer = None

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

    def _splitpage(self, server_url, return_to, post_data):
        self._headers()
        self.wfile.write("""
        <html>
        <body style='background-color: #FFFFCC;'>
        <p>If this were a guestbook style application, it would ask you
        to enter your comment now, and use the check_authorization call
        to confirm that you are in fact the user you say you are.</p>
        <p>This is a demo of the flow that would provide, and nothing
        more.</p>
        <form method="GET" action="/">
        <input type="hidden" name="server_url" value="%s" />
        <input type="hidden" name="return_to" value="%s" />
        <input type="hidden" name="post_data" value="%s" />
        <input type="submit" value="Check Authorization" />
        </form>
        </body>
        </html>
        """ % (server_url, return_to, post_data))

    def doValidLogin(self, login):
        self._simplePage('Logged in as ' + self.query['id'])

    def doInvalidLogin(self):
        self._simplePage('Not logged in. Invalid.')

    def doUserCancelled(self):
        self._simplePage('Cancelled by user')

    def doCheckAuthRequired(self, server_url, return_to, post_data):
        if split:
            self._splitpage(server_url, return_to, post_data)
        else:
            response = consumer.check_auth(server_url, return_to, post_data,
                                           self.query['id'])
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
                open_id = query['id']
                req = ConsumerRequest(open_id, query, 'GET')
                response = consumer.handle_response(req)
                response.doAction(self) # using visitor pattern approach
            elif 'post_data' in query:
                # extract necessary information from current query
                su = query['server_url']
                rt = query['return_to']
                pd = query['post_data']

                # replace query with the query from the return_to url
                _, _, _, _, qs, _ = urlparse(rt)
                self.query = query = exutil.parseQuery(qs)

                response = consumer.check_auth(su, rt, pd, query['id'])
                response.doAction(self)
            else:
                self._headers()
                self.wfile.write(self._inputForm())

        except:
            self._headers(500)
            self.wfile.write(cgitb.html(sys.exc_info(), context=10))
            raise

if __name__ == '__main__':
    if 'dumb' in sys.argv:
        dumb = True
    if 'dumbsplit' in sys.argv:
        dumb = True
        split = True

    if dumb:
        assoc_mngr = DumbAssociationManager()
    else:
        assoc_mngr = DictionaryAssociationManager()

    consumer = SampleConsumer(assoc_mngr=assoc_mngr)

    print 'Consumer Server running...'
    BaseHTTPServer.HTTPServer(('', 8081),
                              ConsumerHandler).serve_forever()
