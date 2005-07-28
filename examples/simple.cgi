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
import cgitb
cgitb.enable()

import cgi
import sys
import os
import time
from urlparse import urlparse

# You may need to manually add the openid package into your
# python path if you don't have it installed with your system python.
# If so, uncomment the line below, and change the path where you have
# Python-OpenID.
# sys.path.insert(0, '/home/foo/Python-OpenID-0.0.6/')
from openid.consumer import OpenIDConsumer, SimpleHTTPClient
from openid.interface import Request
from openid.association import DumbAssociationManager
from openid.util import append_args, hmacsha1, to_b64

HOST = os.environ['HTTP_HOST']
PORT = int(os.environ['SERVER_PORT'])

def redirect(url):
    """Redirect User-Agent to given URL"""
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

# A handler with application specific callback logic.
class OpenIDActionHandler(object):

    def __init__(self, query, consumer):
        self.query = query
        self.consumer = consumer
    
    def doValidLogin(self, login):
        if login.verifyIdentity(self.query['id']):
            identity = self.query['id']
            setAlert('<b>Identity verified!</b> Thanks, ' +
                     '<a href="%s">%s</a>'% (identity, identity))
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

# Our OpenIDConsumer subclass.  See openid.conumser.OpenIDConsumer
# for more more documentation.
class SampleConsumer(OpenIDConsumer):
    def __init__(self, *args, **kwargs):
        OpenIDConsumer.__init__(self, *args, **kwargs)

        # Choose your own secret here.  You MUST change this, otherwise
        # malicious users may be able to falsly authenticate.  Your secret
        # must be exactly 20 characters long, and given the nature of CGI,
        # must be static.  Choosing a random secret every time will cause
        # the secret to be different each invocation, and no-one will be able
        # to verify their identity.  
        self.secret = 'x'*20

    def verify_return_to(self, return_to):        
        proto, return_to_host, selector, params, qs, frag = urlparse(return_to)

        # verify host and port of return to match host and port of this server
        host = HOST
        if PORT not in (80, 443):
            host += ':' + PORT

        if return_to_host != host:
            return False
        
        query = parseQuery(qs)
        v = to_b64(hmacsha1(self.secret, query['id'] + query['time']))

        if v != query['v']:
            return False

        return True

    def create_return_to(self, base, identity):
        args = {
            'id': identity,
            'time': str(int(time.time())),
            }

        args['v'] = to_b64(hmacsha1(self.secret, args['id'] + args['time']))
        return append_args(base, args)

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
    handler = OpenIDActionHandler(query, consumer)

    # extract identity url from arguments.  Will be None if absent from query.
    identity_url = query.get('identity_url')

    if identity_url is not None:
        ret = consumer.find_identity_info(identity_url)
        if ret is None:
            setAlert('Unable to find openid server for identity url %r' % (
                identity_url,))
        else:
            # found identity server info
            consumer_id, server_id, server_url = ret

            # build trust root - this examines the script env and builds
            # based on your running location.  In practice this may be static.
            if PORT == 80:
                trust_root = 'http://' + HOST
            elif PORT == 443:
                trust_root = 'https://' + HOST
            else:
                trust_root = 'http://%s:%d' % (HOST, PORT)

            # build return_to url, this is done by consumer object (see above)
            return_to = consumer.create_return_to(
                trust_root+os.environ['SCRIPT_NAME'], consumer_id)

            # handle the request
            redirect_url = consumer.handle_request(
                server_id, server_url, return_to, trust_root)

            # redirect the user-agent to the server
            redirect(redirect_url)
            
    elif 'openid.mode' in query:
        # got a request from the server.  build a Request object and pass
        # it off to the consumer object.  OpendIDActionHandler handles
        # the various end cases (see above).
        req = Request(query, 'GET')
        response = consumer.handle_response(req)
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
""" % (drawAlert(_message),
       os.environ['SCRIPT_NAME'])




