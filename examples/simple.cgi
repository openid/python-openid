#!/usr/bin/env python2.4

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
import cgitb; cgitb.enable()
import cgi
import sys
import os
import time
import urlparse

# You may need to manually add the openid package into your
# python path if you don't have it installed with your system python.
# If so, uncomment the line below, and change the path where you have
# Python-OpenID.
# sys.path.insert(0, '/home/foo/Python-OpenID-0.0.6/')
sys.path.insert(0, '/home/brian/production')
from openid import consumer, interface, util

HOST = os.environ['HTTP_HOST']
PORT = int(os.environ['SERVER_PORT'])

def redirect(url):
    print 'Location: ' + url + '\n\n'
    print sys.exit(0)

def parseQuery(qs):
    query = cgi.parse_qs(qs)
    for k, v in query.items():
        query[k] = query[k][0]
    return query

def formArgstoDict():
    """Returns a dict of the GET and POST arguments"""
    form = cgi.FieldStorage()
    return dict([(key, form[key].value) for key in form.keys()])

def drawAlert(msg):
    if msg: return '<div id="alert">%s</div>' % (msg,)
    return ''

_message=''
def setAlert(m):
    global _message
    _message += m

# Choose a nonce secret below.  This should be a secret, static string.
# It is used to generate the self-signed nonce used in preventing replay
# attacks. See return_to section of
# http://www.openid.net/specs.bml#mode-checkid_immediate
NONCE_SECRET = 'you must change this string!'

def genNonce(identity, time):
    "returns a nonce string based on the identity and time, using SECRET"
    return util.to_b64(util.hmacsha1(NONCE_SECRET, identity + time))

# Our OpenIDConsumer subclass.  See openid.conumser.OpenIDConsumer
# for more more documentation.
class SampleConsumer(consumer.OpenIDConsumer):
    
    def verify_return_to(self, return_to):        
        proto, host, selector, params, qs, frag = \
               urlparse.urlparse(return_to)

        # verify return_to host:port string match host and port of this server
        if host != HOST:
            return False

        # build nonce from identity and time
        query = parseQuery(qs)
        nonce = genNonce(query['identity'], query['time'])

        # check nonce against the nonce passed through the openid server
        if nonce != query['nonce']:
            return False

        return True

def create_return_to(base_url, identity_url):
    "Create the return_to url for this application, appending the nonce args"
    args = {
        'identity': identity_url,
        'time': str(time.time()),
        }
    
    args['nonce'] = genNonce(identity_url, args['time'])
    return util.append_args(base_url, args)
    

# A handler with application specific callback logic.
class SimpleActionHandler(interface.ActionHandler):

    def __init__(self, query, consumer):
        self.query = query
        self.consumer = consumer
    
    def doValidLogin(self, login):
        identity_url = self.query['identity']
        if login.verifyIdentity(identity_url):
            setAlert('<b>Identity verified!</b> Thanks, ' +
                     '<a href="%(identity)s">%(identity)s</a>' % self.query)
        else:
            self.doInvalidLogin()

    def doInvalidLogin(self):
        setAlert('Identity NOT verified!  Try again.')

    def doUserCancelled(self):
        setAlert('Cancelled by user.')

    def doCheckAuthRequired(self, server_url, return_to, post_data):
        response = self.consumer.check_auth(server_url, return_to, post_data)
        response.doAction(self)

    def doErrorFromServer(self, message):
        setAlert('Error from server: '+message)

def dispatch():
    """Entry point into the script.  Here we create our OpenID objects
    and call into the library based one the input argumets.  We check for
    two specific arguments:

    1) identity_url: this is the url from the form
    on the webpage.  If this is present, our first step is to get more info
    about the identity from the content of it's webpage by calling
    Consumer.find_identity_info

    2) openid.mode: Redirect from the server will have an openid.mode.  In
    this case we create a Request object, and let the Conumer class handle
    the rest.

    If neither of these args are present, we simply render the page w/ the
    input form.
    """
    # generate a dictionary of arguments
    query = formArgstoDict()
    
    # create conusmer and handler objects
    consumer = SampleConsumer()
    handler = SimpleActionHandler(query, consumer)

    # extract identity url from arguments.  Will be None if absent from query.
    identity_url = query.get('identity_url')

    if identity_url is not None:
        ret = consumer.find_identity_info(identity_url)
        if ret is None:
            setAlert('Unable to find openid server for identity url %r' % (
                identity_url,))
        else:
            # found identity server info
            identity_url, server_id, server_url = ret

            # build trust root - this examines the script env and builds
            # based on your running location.  In practice this may be static.
            # Also, we are asking users to trust all scripts on this domain,
            # not just this simple application.
            if PORT == 443:
                trust_root = 'https://' + HOST
            else:
                trust_root = 'http://' + HOST

            # build return_to url
            base_url = trust_root + os.environ['SCRIPT_NAME']
            return_to = create_return_to(base_url, identity_url)

            # handle the request
            redirect_url = consumer.handle_request(
                server_id, server_url, return_to, trust_root)

            # redirect the user-agent to the server
            redirect(redirect_url)
            
    elif 'openid.mode' in query:
        # got a request from the server.  build a Request object and pass
        # it off to the consumer object.  OpendIDActionHandler handles
        # the various end cases (see above).
        req = interface.Request(query, 'GET')
        response = consumer.handle_response(req)

        # let our SimpleActionHandler do the work
        response.doAction(handler)
        

dispatch()

print "Content-Type: text/html\n\n"
print """
<html>
<head>  
  <title>CGI Python OpenID Consumer Example</title>
  <style type="text/css">
  * {font-family:verdana,sans-serif;}
  body {width:50em; margin:1em;}
  div {padding:.5em; }
  table {margin:none;padding:none;}
  #alert {border:1px solid #e7dc2b; background: #fff888;}
  #login {border:1px solid #777; background: #ddd; margin-top:1em;padding-bottom:0em;}
  </style>
</head>
<body>
  <h2>CGI Consumer Example</h3>
  <p>This example consumer uses the <a href="http://openid.schtuff.com/">Python OpenID</a> library in <a href="http://www.openid.net/specs.bml#associate">dumb mode</a> on a CGI platform.  The example asserts that you own the URL typed below; that it is your identity URL.</p>
  %s
  <div id="login">
  Verify an Identity URL
  <hr/>
    <form action="%s" method="get">     
    OpenID: <input type="text" name="identity_url" class="openid_identity" />
    <input type="submit" value="Verify" />
    </form>
  </div>

  <div style="font-size:.8em; margin-top:5em;">
  Note that this example will not work with Python's built in CGIHTTPServer.  Use Apache or an HTTP server that allows redirects.
  </div>
</body>
</html>
""" % (drawAlert(_message), os.environ['SCRIPT_NAME'])
       




