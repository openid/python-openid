#!/usr/bin/env python
# Emacs, this is -*- python -*- code.

# Dumb mode identity verification example.
#
# This example is completely stateless, and just requires a CGI enabled
# webserver to run.  Make sure this file has executable permissions, stick
# it in your cgi-bin directory and go nuts.  Once you understand this example
# you'll know the basics of OpenID and using the Python OpenID library.  You
# can then move on to more robust examples, and integrating OpenID into your.
# app.
#
# Please note that this will not work with Python's built in CGIHTTPServer, as
# the CGIHTTPServer does not support redirects.  Use apache or equivalent.
#
# Copyright 2005, Janrain, Inc.
import urlparse
import cgitb

from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler

# You may need to manually add the openid package into your
# python path if you don't have it installed with your system python.
# If so, uncomment the line below, and change the path where you have
# Python-OpenID.
# import sys
# sys.path.insert(0, '/path/to/openid/')
from openid.consumer import interface, stores

from simpleproxy import ExampleDispatcher, parseQuery, buildRedirect

class Dispatcher(ExampleDispatcher):
    def __init__(self, req, *args, **kwargs):
        ExampleDispatcher.__init__(self, *args, **kwargs)
        self.req = req

    def sendResponse(self, code):
        self.req.send_response(code)

    def write(self, data):
        self.req.wfile.write(data)

    boilerplate = '''\
<h2>BaseHTTPServer Consumer Example</h2>
<p>
  This example consumer uses the <a
      href="http://openid.schtuff.com/">Python OpenID</a> library
  on a CGI platform.  The example just verifies that the URL that
  you enter is your identity URL.
</p>'''

class OpenIDHTTPServer(HTTPServer):
    def __init__(self, *args, **kwargs):
        HTTPServer.__init__(self, *args, **kwargs)
        if self.server_port != 80:
            self.base_url = 'http://%s:%s/' % (
                self.server_name, self.server_port)
        else:
            self.base_url = 'http://%s/' % (self.server_name,)

        # dumb-mode OpenID consumer
        store = stores.DumbStore('This is just a sample, use a better secret.')
        self.openid_consumer = interface.OpenIDConsumerFacade(
            store=store, trust_root=self.base_url)

class OpenIDRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            parsed_uri = urlparse.urlparse(self.path)
            query = parseQuery(parsed_uri[4])
            this_uri = self.server.base_url
            consumer = self.server.openid_consumer
            self.disp = Dispatcher(self, consumer, query, this_uri)
            self.disp.run()
        except (KeyboardInterrupt, SystemExit):
            raise
        except:
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(cgitb.html(sys.exc_info(), context=10))

if __name__ == '__main__':
    server = OpenIDHTTPServer(('localhost', 8000), OpenIDRequestHandler)
    server.serve_forever()
