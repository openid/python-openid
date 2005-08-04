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

# Our OpenIDConsumer subclass.  See openid.conumser.OpenIDConsumer
# for more more documentation.
class SimpleConsumer(consumer.OpenIDConsumer):
    
    def verify_return_to(self, return_to):        
        proto, host, selector, params, qs, frag = \
               urlparse.urlparse(return_to)

        # verify return_to host:port string match host and port of this server
        if host != HOST:
            return False

        return True

# A handler with application specific callback logic.
class SimpleActionHandler(interface.ActionHandler):

    def __init__(self, query, consumer):
        self.query = query
        self.consumer = consumer

    # callbacks
    def doValidLogin(self, login):
        # here is where you would do what is necessary to log an openid "user"
        # user into your system.  We just print a message confirming the
        # valid login.
        setAlert('<b>Identity verified!</b> Thanks, ' +
                 '<a href="%(open_id)s">' +
                 '%(open_id)s</a>' % self.query)

    def doInvalidLogin(self):
        setAlert('Identity NOT verified!')

    def doUserCancelled(self):
        setAlert('Cancelled by user.')

    def doCheckAuthRequired(self, server_url, return_to, post_data):
        # do openid.mode=check_authentication call, and then change state
        response = self.consumer.check_auth(server_url, return_to, post_data,
                                            self.getOpenID())
        response.doAction(self)

    def doErrorFromServer(self, message):
        setAlert('Error from server: '+message)

    # helpers
    def createReturnTo(self, base_url, identity_url, args=None):
        if not isinstance(args, dict):
            args = {}
        args['open_id'] = identity_url
        return util.append_args(base_url, args)

    def getOpenID(self):
        "return the openid from the original form"
        return self.query['open_id']


def dispatch():
    # generate a dictionary of arguments
    query = formArgstoDict()
    
    # create conusmer and handler objects
    consumer = SimpleConsumer()
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

            # build url to application for use in creating return_to
            app_url = trust_root + os.environ['SCRIPT_NAME']

            # create return_to url from app_url
            return_to = handler.createReturnTo(app_url, identity_url)

            # handle the request
            redirect_url = consumer.handle_request(
                server_id, server_url, return_to, trust_root)

            # redirect the user-agent to the server
            redirect(redirect_url)
            
    elif 'openid.mode' in query:
        # got a request from the server.  build a Request object and pass
        # it off to the consumer object.  OpendIDActionHandler handles
        # the various end cases (see above).
        openid = handler.getOpenID()
        req = interface.ConsumerRequest(openid, query, 'GET')
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
       




