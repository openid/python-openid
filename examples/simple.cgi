#!/usr/bin/env python
# Emacs, this is -*- python -*- code.

# Please note that this will not work with Python's built in CGIHTTPServer, as
# the CGIHTTPServer does not support redirects.  Use apache or equivalent.
#
# Copyright 2005, Janrain, Inc.
import cgitb ; cgitb.enable()
import os
import urlparse

# Peer module
from simpleproxy import ExampleDispatcher, parseQuery, buildRedirect

# You may need to manually add the openid package into your
# python path if you don't have it installed with your system python.
# If so, uncomment the lines below, and change the path where you have
# Python-OpenID.
# import sys
# sys.path.append('/path/to/openid/')
from openid.consumer import interface, stores

def getBaseURL():
    host = os.environ['HTTP_HOST']
    port = int(os.environ['SERVER_PORT'])
    if os.environ.get('HTTPS', 'off') == 'on':
        proto = 'https'
    else:
        proto = 'http'

    if ((port == 80 and proto == 'http') or
        (port == 443 and proto == 'https')):
        base_url = '%s://%s/' % (proto, host)
    else:
        base_url = '%s://%s:%s/' % (proto, host, port)

    return base_url

class Dispatcher(ExampleDispatcher):
    def write(self, data):
        sys.stdout.write(data)

    def sendResponse(self, code):
        pass

    boilerplate = '''\
<h2>CGI Consumer Example</h2>
<p>
  This example consumer uses the <a
      href="http://openid.schtuff.com/">Python OpenID</a> library
  on a CGI platform.  The example just verifies that the URL that
  you enter is your identity URL.
</p>'''

def main():
    base_url = getBaseURL()

    store = stores.DumbStore(
        'This would be a decent secret phrase, if no one else knew it.')

    openid_consumer = interface.OpenIDConsumerFacade(store=store)

    query = parseQuery(os.environ.get('QUERY_STRING', ''))
    this_uri = urlparse.urljoin(base_url, os.environ['SCRIPT_NAME'])

    dispatcher = Dispatcher(openid_consumer, query, this_uri, base_url)
    dispatcher.run()

if __name__ == '__main__':
    main()
