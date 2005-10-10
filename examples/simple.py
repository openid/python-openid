#!/usr/bin/env python
"""
Simple example for an OpenID consumer.

Once you understand this example you'll know the basics of OpenID
and using the Python OpenID library. You can then move on to more
robust examples, and integrating OpenID into your application.
"""
__copyright__ = 'Copyright 2005, Janrain, Inc.'

import cgi
import urlparse
import cgitb
import sys
from xml.sax.saxutils import escape, quoteattr

from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler

# You may need to manually add the openid package into your
# python path if you don't have it installed with your system python.
# If so, uncomment the line below, and change the path where you have
# Python-OpenID.
# sys.path.append('/path/to/openid/')

from openid.consumer import interface, filestore
from openid.oidUtil import appendArgs

class OpenIDHTTPServer(HTTPServer):
    def __init__(self, consumer, *args, **kwargs):
        HTTPServer.__init__(self, *args, **kwargs)

        if self.server_port != 80:
            self.base_url = ('http://%s:%s/' %
                             (self.server_name, self.server_port))
        else:
            self.base_url = 'http://%s/' % (self.server_name,)

        self.openid_consumer = consumer

class OpenIDRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            self.parsed_uri = urlparse.urlparse(self.path)
            self.query = {}
            for k, v in cgi.parse_qsl(self.parsed_uri[4]):
                self.query[k] = v

            path = self.parsed_uri[2]
            if path in ['', '/', '/start']:
                self.render()
            elif path == '/verify':
                self.doVerify()
            elif path == '/process':
                self.doProcess()
            else:
                # For unknown step, return to step 0
                self.redirect(self.buildURL('/'))

        except (KeyboardInterrupt, SystemExit):
            raise
        except:
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(cgitb.html(sys.exc_info(), context=10))

    def doVerify(self):
        openid_url = self.query.get('openid_url')
        if not openid_url:
            self.render('Enter an identity URL to verify.',
                        css_class='error', form_contents=openid_url)
            return

        consumer = self.server.openid_consumer
        auth_request = consumer.beginAuth(openid_url)
        if auth_request is None:
            fmt = 'Cannot use <q>%s</q> as an identity URL'
            message = fmt % (escape(openid_url),)
            self.render(message, css_class='error', form_contents=openid_url)
            return

        return_to = self.buildURL('process', token=auth_request.token)
        redirect_url = consumer.constructRedirect(
            auth_request, return_to, trust_root=self.server.base_url)

        self.redirect(redirect_url)

    def doProcess(self):
        consumer = self.server.openid_consumer
        token = self.query.get('token', '')
        status, info = consumer.completeAuth(token, self.query)
        css_class = 'error'
        openid_url = None
        if status == interface.FAILURE and info:
            openid_url = info
            fmt = "Verification of %s failed."
            message = fmt % (escape(openid_url),)
        elif status == interface.SUCCESS:
            css_class = 'alert'
            if info:
                openid_url = info
                fmt = "You have successfully verified %s as your identity."
                message = fmt % (escape(openid_url),)
            else:
                message = 'Verification cancelled'
        else:
            message = 'Verification failed.'
            css_class = 'error'
            
        self.render(message, css_class, openid_url)

    def buildURL(self, action, **query):
        base = urlparse.urljoin(self.server.base_url, action)
        return appendArgs(base, query)

    def redirect(self, redirect_url):
        self.send_response(302)
        response = """\
Location: %s
Content-type: text/plain

Redirecting to %s""" % (redirect_url, redirect_url)
        self.wfile.write(response)

    def render(self, message=None, css_class='alert', form_contents=None):
        self.send_response(200)
        self.pageHeader()
        if message:
            self.wfile.write("<div class='%s'>" % (css_class,))
            self.wfile.write(message)
            self.wfile.write("</div>")
        self.pageFooter(form_contents)

    def pageHeader(self, title="Python OpenID Simple Example"):
        self.wfile.write('''\
Content-type: text/html

<html>
  <head><title>%s</title></head>
  <style type="text/css">
      * {
        font-family: verdana,sans-serif;
      }
      body {
        width: 50em;
        margin: 1em;
      }
      div {
        padding: .5em;
      }
      table {
        margin: none;
        padding: none;
      }
      .alert {
        border: 1px solid #e7dc2b;
        background: #fff888;
      }
      .error {
        border: 1px solid #ff0000;
        background: #ffaaaa;
      }
      #verify-form {
        border: 1px solid #777777;
        background: #dddddd;
        margin-top: 1em;
        padding-bottom: 0em;
      }
  </style>
  <body>
    <h1>%s</h1>
    <p>
      This example consumer uses the <a
      href="http://openid.schtuff.com/">Python OpenID</a> library
      on a CGI platform.  The example just verifies that the URL that
      you enter is your identity URL.
    </p>
''' % (title, title))

    def pageFooter(self, form_contents):
        if not form_contents:
            form_contents = ''

        self.wfile.write('''\
    <div id="verify-form">
      <form method="get" action=%s>
        Identity&nbsp;URL:
        <input type="text" name="openid_url" value=%s />
        <input type="submit" value="Verify" />
      </form>
    </div>
  </body>
</html>
''' % (quoteattr(self.buildURL('verify')), quoteattr(form_contents)))

def main():
    import optparse
    parser = optparse.OptionParser('Usage:\n %prog [options]')
    parser.add_option('-d', '--data-path', dest='data_path', default='store',
                      help='Data directory for storing OpenID consumer state. '
                      'Defaults to "%default" in the current directory.')
    parser.add_option('-p', '--port', dest='port', type='int', default=8000,
                      help='Port on which to listen for HTTP requests. '
                      'Defaults to port %default.')
    parser.add_option('-s', '--host', dest='host', default='localhost',
                      help='Host on which to listen for HTTP requests. '
                      'Also used for generating URLs. Defaults to %default.')

    options, args = parser.parse_args()
    if args:
        parser.error('Expected no arguments. Got %r' % args)

    # Store state data in the directory 'store' relative to here.
    store = filestore.FilesystemOpenIDStore(options.data_path)
    consumer = interface.OpenIDConsumer(store)

    addr = (options.host, options.port)
    server = OpenIDHTTPServer(consumer, addr, OpenIDRequestHandler)

    print 'Server running at:'
    print server.base_url
    server.serve_forever()

if __name__ == '__main__':
    main()
