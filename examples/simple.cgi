#!/usr/bin/env python2.4
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
import cgi
import os
import urlparse

from urllib import quote_plus
from xml.sax.saxutils import escape, quoteattr

# You may need to manually add the openid package into your
# python path if you don't have it installed with your system python.
# If so, uncomment the line below, and change the path where you have
# Python-OpenID.
# sys.path.insert(0, '/home/foo/Python-OpenID-0.0.6/')
from openid.consumer import interface

def parseQuery(qs):
    query = {}
    for k, v in cgi.parse_qsl(qs):
        if type(v) is list:
            query[k] = v[0]
        else:
            query[k] = v
    return query

def redirect(redirect_url):
    print """\
Location: %s
Content-type: text/plain

Redirecting to %s""" % (redirect_url, redirect_url)

class CGIOpenIDProxy(interface.OpenIDProxy):
    def __init__(self):
        self.host = os.environ['HTTP_HOST']
        self.port = int(os.environ['SERVER_PORT'])
        if os.environ.get('HTTPS', 'off') == 'on':
            self.proto = 'https'
        else:
            self.proto = 'http'
        self.req_uri = os.environ['REQUEST_URI']

        if ((self.port == 80 and self.proto == 'http') or
            (self.port == 443 and self.proto == 'https')):
            self.base_url = '%s://%s/' % (self.proto, self.host)
        else:
            self.base_url = '%s://%s:%s/' % (self.proto, self.host, self.port)

        self.full_req_uri = urlparse.urljoin(self.base_url, self.req_uri)
        self.parsed_uri = urlparse.urlparse(self.full_req_uri)
        # URL with query parameters stripped off (the plain address to
        # this script)
        self.script_uri = urlparse.urlunparse(
            self.parsed_uri[:3] + ('', '', ''))

        self.query = parseQuery(self.parsed_uri[4])

        self.step = self.query.get('step', 'start')

        # dumb-mode OpenID consumer
        self.openid_consumer = interface.OpenIDConsumerFacade(
            trust_root=self.base_url)

    def getUserInput(self):
        return self.query['identity_url']

    def getOpenIDParameters(self):
        params = {}
        for k, v in self.query.iteritems():
            if k.startswith('openid.'):
                params[k] = v

        return params

    def getReturnTo(self, token):
        return_to_query = [('step', 'process'), ('token', token)]

        query_elements = []
        for key, value in return_to_query:
            element = '%s=%s' % (quote_plus(key), quote_plus(value))
            query_elements.append(element)
        
        query_string = '&'.join(query_elements)

        return self.script_uri + '?' + query_string

    def verifyReturnTo(self, return_to):
        parsed_uri = urlparse.urlparse(return_to)
        if parsed_uri[:4] != self.parsed_uri[:4]:
            return None

        query = parseQuery(parsed_uri[4])
        if query.get('step') != 'process':
            return None

        token = self.query.get(token, None)
        if query.get('token') != token:
            return None

        return token

    # ======================================================================

    def run(self):
        if self.step == 'start':
            self.doStart()
        elif self.step == 'redirect':
            self.doRedirect()
        elif self.step == 'process':
            self.doProcess()
        else:
            self.doUnknown()

    def doUnknown(self):
        # For unknown step, return to step 0
        redirect(self.script_uri)

    def doStart(self):
        self.pageHeader()
        self.pageFooter()

    def doRedirect(self):
        redirect_url = self.openid_consumer.constructRedirect(self)
        redirect(redirect_url)

    def doProcess(self):
        self.pageHeader()
        print "<div id='alert'>"
        print self.openid_consumer.processServerResponse(self)
        print "</div>"
        self.pageFooter()

    def loginGood(self, normalized_id):
        return "You have successfully verified %s as your identity." % (
            escape(normalized_id),)

    def loginError(self):
        return "There was an error attempting to verify that URL."

    def loginCancelled(self):
        return "Verification cancelled."

    def serverError(self, message):
        return "Error from the server: %s" % escape(message)

    def pageHeader(self, title="Python OpenID Simple Example"):
        print '''\
Content-type: text/html

<html>
  <head><title>%s</title></head>
  <style type="text/css">
      * {font-family:verdana,sans-serif;}
      body {width:50em; margin:1em;}
      div {padding:.5em; }
      table {margin:none;padding:none;}
      #alert {border:1px solid #e7dc2b; background: #fff888;}
      #login {border:1px solid #777; background: #ddd; margin-top:1em;padding-bottom:0em;}
  </style>
  <body>
    <h1>%s</h1>
    <h2>CGI Consumer Example</h2>
    <p>
      This example consumer uses the <a
          href="http://openid.schtuff.com/">Python OpenID</a> library
      in <a href="http://www.openid.net/specs.bml#associate">dumb
      mode</a> on a CGI platform.  The example asserts that the
      URL that you enter is your identity URL.
    </p>
''' % (title, title)

    def pageFooter(self):
        print '''\
    <div id="login">
      <form method="get" action=%s>
        <input type="hidden" name="step" value="redirect" />
        Identity&nbsp;URL:
        <input type="text" name="identity_url" />
        <input type="submit" value="Verify" />
      </form>
    </div>
  </body>
</html>
''' % (quoteattr(self.script_uri),)

if __name__ == '__main__':
    import cgitb; cgitb.enable()
    request = CGIOpenIDProxy()
    request.run()
