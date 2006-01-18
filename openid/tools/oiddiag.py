"""OpenID Diagnostic

@todo: new sessions should check to see if they are new sessions
    because they are an expired old session, and explain that is
    the case.

@todo: drill-down views for table rows.
@todo: convert the fetchAndParse and assosciate methods to use Attempts
@todo: add dumb-mode tests
@todo: add more association tests
@todo: document usage, results
@todo: end-user wrapper
@todo: render tables for query args
@todo: add passed/failed message to end of Attempt rendering.
@todo: add summary line: All passed, 3 failures, 2 incompletes, 1 untried.
@todo: keep log of working servers.
@todo: code documentation and cleanup.
@todo: more unit and/or functional tests through HTTP interface, since
    none of the HTML rendering or mod_python-interfacing code is being
    well tested with the current test harness.  (Selenium or Twill?)
@todo: write 'about' page
@todo: document data storage policy.
"""

# Please enter an OpenID URL: [______________]
# "I fetched ..."
# "I was redirected to ..."
# "I received a document..."
# X I got an ERROR RESPONSE.
# "I found a link tag (and a delegate tag?)..."
# X I found NO link tag.
# "I tried to associate with your OpenID server... (URL, IP)"
# X Your OpenID server isn't there / likes to explode / etc.
# X There is an OpenID server there but its Associate reply is broken:
#     assoc_handle must only contain bytes in xx-yy.

# Okay, so far for the identity URL _______ and the server _____,
# we have done:
#  associate:
#    with plaintext secret: OK
#    with DH-SHA1 secret: /!\ The server returned the secret in plaintext!
#       This is permitted by the OpenID specification, but means your server
#       is less secure than it might be.
#  checkid_immediate:
#    positive assertion: not seen [Make this request again?]
#    user_setup_url: OK (2 times)
#    no response: 0 times
#  checkid_setup:
#    positive assertion: OK
#    cancel: not seen [Make this request again?]
#    no response: 2 times I redirected you to make a request and you
#       didn't return.

# and in dumb mode:
#  checkid_immediate:
#    positive assertion: [Try now?]
#    user_setup_url: [Try now?]
#  checkid_setup:
#    positive assertion: /!\ 1 UNVERIFIED response.
#       (You were redirected back from the server, but
#        check_authentication did not complete!)
#    cancel: not seen [Make this request again?]
#    no response: 3 times I redirected you to make a request and you
#       didn't return.
#  check_authentication:
#     valid signature: 0 [Try Again]
#   invalid signature: 0 [Try Again]
# incomplete response: 1

# Miscellaneous error responses:
#   GET with return_to: got code 400, should have been a redirect
#   GET with bad arguments: OK, got HTML saying %blah%
#   GET with no arguments: got code 400, should have been 200.
#   POST: OK, got kvform in response with error "blah"

# Associations:
#  smart mode:
#   aoeuaosihxgah
#   asdfhjklxzilnb
#
#  dumb mode:
#   dzzzzzl9

# You most recently arrived at this page through
#   a normal request
#      with no referrer information.
#      referred by _________.
#   an OpenID response
#      a well-formed OpenID checkid_setup smart mode response
#        authenticating the identity ___________
#        (here is the parameter breakdown: and referrer:)
#      You wanted to test the checkid_setup Cancel response when you
#         made that request.  Try again?
#   an OpenID response, but it's kinda screwy!
#      This response to checkid_setup is missing the return_to parameter.
#      This response to checkid_setup has an incorrect value for [...]
#   an OpenID response with an invalid signature!

# Check a new OpenID: [___________________]
# or server: [___________________]
# or [Reset] this page.

try:
    from mod_python import apache
    from mod_python.util import FieldStorage, redirect
    from mod_python.Session import Session
except ImportError, e:
    # FIXME: If all the Apache stuff were isolated in its own module, there
    # wouldn't be this grossness.
    import sys
    if 'unittest' in sys.modules:
        # the unittest framework will sneak an 'apache' object in to this
        # module's namespace.
        pass
    else:
        raise

from xml.sax.saxutils import escape, quoteattr

from openid.consumer import consumer
from openid.store.sqlstore import SQLiteStore
from openid.dh import DiffieHellman
from openid import oidutil

import pysqlite2.dbapi2
import time, urllib

SESSION_TIMEOUT = 3600 * 24 * 4

# Sometimes an enum type would be nice.
SUCCESS = ('success',)
FAILURE = ('failure',)
INCOMPLETE = ('incomplete',)


PAGE_DONE = ('page_done',)
RENDER_TABLE = ('Show the table!',)

XMLCRAP = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/2002/REC-xhtml1-20020801/DTD/xhtml1-transitional.dtd">
<html lang="en" xmlns="http://www.w3.org/1999/xhtml">'''

def sibpath(one, other):
    import os.path
    if os.path.isabs(other):
        return other
    return os.path.join(os.path.dirname(one), other)

STYLESHEET = file(sibpath(__file__, 'oiddiag.css')).read()

def getBaseURL(req):
    """Return a URL to the base of this script's URLspace.

    e.g. http://openidenabled.com/resources/oiddiag/

    (note the trailing slash.)

    mod_python.Request -> str
    """
    # This code currently doesn't have unit test coverage.
    # It looks like any bug in this code would arise from a failure in my
    # expectations of the attributes of the request object.  However,
    # I don't have a test harness that allows me to use actual apache request
    # objects, so I can't test for that with the current test environment.
    host = req.hostname or req.server.server_hostname
    port = req.connection.local_addr[1]

    # Don't include the default port number in the URL
    # XXX: Do I need to call add_common_vars before checking subprocess_env?
    if req.subprocess_env.get('HTTPS', 'off') == 'on':
        default_port = 443
        proto = 'https'
    else:
        default_port = 80
        proto = 'http'

    if req.path_info:
        script_name = req.uri[:-len(req.path_info)]
    else:
        script_name = req.uri

    if port == default_port:
        base_url = '%s://%s%s/' % (proto, host, script_name)
    else:
        base_url = '%s://%s:%s%s/' % (proto, host, port, script_name)

    return base_url


class IdentityInfo(object):
    consumer = None
    def __init__(self, consumer_id, server_id, server_url):
        self.consumer_id = consumer_id
        self.server_id = server_id
        self.server_url = server_url

    def newAuthRequest(self, a_consumer):
        unused_status, authreq = a_consumer._gotIdentityInfo(
            self.consumer_id, self.server_id, self.server_url)
        return authreq

    def to_html(self):
        s = ('Querying <a href=%(surl_attr)s class="server_url">%(surl)s</a> '
             'about <a href=%(sid_attr)s class="server_url">%(sid)s</a>.' %
             {'sid_attr': quoteattr(self.server_id),
              'sid': escape(self.server_id),
              'surl_attr': quoteattr(self.server_url),
              'surl': escape(self.server_url),
              })
        return s

class Event(object):
    def __init__(self):
        self.time = time.time()

    def to_html(self):
        return escape(str(self))

class TextEvent(Event):
    """An event described by a line of text.

    Used for prototyping, these should be phased out.
    """

    def __init__(self, text):
        Event.__init__(self)
        self.text = text

    def to_html(self):
        return '<span class="event">%s</span>' % (escape(self.text),)

    def __repr__(self):
        return '<%s %r %s>' % (self.__class__.__name__, self.text, self.time)

    def __str__(self):
        return self.text

class IdentityAuthenticated(Event):
    def __init__(self, identity):
        Event.__init__(self)
        self.identity = identity

    def __str__(self):
        return "Identity authenticated as %s" % (self.identity,)

class SetupNeeded(Event):
    def __init__(self, url):
        Event.__init__(self)
        self.url = url

    def __str__(self):
        return "Server requires setup at %s" % (self.url,)

class OpenIDFailure(Event):
    def __init__(self, code, info):
        Event.__init__(self)
        self.code = code
        self.info = info

    def to_html(self):
        return ('<span class="event">Open ID Failure: %s %s</span>'
                % (self.code, self.info))


class OperationCancelled(TextEvent):
    text = "Operation Cancelled."

    def __init__(self):
        TextEvent.__init__(self, self.text)

class ResponseReceived(Event):
    def __init__(self, raw_uri, query):
        Event.__init__(self)
        self.raw_uri = raw_uri
        self.query = query

    def to_html(self):
        return ('<span class="event">Response received: %s</span>'
                % (self.query,))


class FatalEvent(TextEvent):
    pass

class Failure(Exception):
    def event(self):
        return FatalEvent(self.args[0])

class Instruction(object):
    pass

class DoRedirect(Instruction):
    def __init__(self, redirectURL):
        self.redirectURL = redirectURL

class ApacheView(object):
    def __init__(self, req):
        self.req = req
        self.event_log = []
        self._cleanupCalls = []
        self.session = Session(req, timeout=SESSION_TIMEOUT)

    def write(self, bytes):
        if self.fixed_length:
            self._buffer.append(bytes)
        else:
            self.req.write(bytes)

    def redirect(self, url):
        # Will raise apache.SERVER_RETURN
        redirect(self.req, url)

    def finish(self):
        if self._buffer:
            length = reduce(int.__add__, map(len, self._buffer))
            self.req.set_content_length(length)
            self.req.write(''.join(self._buffer))

    def statusMsg(self, msg):
        self.write('<span class="status">%s</span><br \>\n' % (escape(msg),))

    def handle(self, req=None):
        assert (req is None) or (req is self.req)
        self.req.register_cleanup(self.cleanup)
        self.req.content_type = "text/html"
        try:
            try:
                self.go()
            except Failure, e:
                self.record(e.event())
        finally:
            self.finish()
        return apache.OK

    def record(self, event):
        self.event_log.append(event)
        self.displayEvent(event)

    def displayEvent(self, event):
        self.write(event.to_html() + '<br />\n')

    def onCleanup(self, callback):
        self._cleanupCalls.append(callback)

    def log(self, msg):
        self.write('<span class="log">%s</span><br />\n' % (escape(msg),))

    def cleanup(self, unused=None):
        try:
            self.session.save()
        except:
            self.req.log_error("Error saving session: %s" % (self.session,))
            raise
        for c in self._cleanupCalls:
            c()

class Diagnostician(ApacheView):
    # Not really a subclass relationship at all, but for the moment...
    consumer = None
    store = None

    def __init__(self, req):
        ApacheView.__init__(self, req)
        self.fixed_length = False
        self._buffer = []
        storefile = req.get_options().get("OIDDiagStoreFile")
        if storefile is None:
            req.log_error("PythonOption OIDDiagStoreFile not found, using "
                          "in-memory store instead", apache.APLOG_WARNING)
            self.storefile = ":memory:"
        else:
            self.storefile = storefile

        if self.session.is_new():
            self.session['result_table'] = None

        self.trust_root = getBaseURL(req)

    def go(self):
        retval = None
        if self.req.path_info[1:]:
            parts = self.req.path_info[1:].split('/')
            method = getattr(self, 'go_' + parts[0], None)
            if method is not None:
                retval = method()
            elif self.session['result_table'] is not None:
                result_table = self.session['result_table']
                # The table probably lost its reference to me when
                # it was unserialized.
                result_table.diagnostician = self
                retval = result_table.handleRequest(self.req, parts)
            else:
                self.req.log_error("Session %s arrived at %s but had no "
                                   "stored result table." % (self.session.id(),
                                                             parts))
                # , apache.APLOG_DEBUG

        if retval is None:
            if (('result_table' not in self.session) or
                (self.session['result_table'] is None)):
                retval = self.openingPage()
            else:
                self.session['result_table'].diagnostician = self
                retval = self.resultPage()

        if retval is PAGE_DONE:
            return
        elif isinstance(retval, DoRedirect):
            self.redirect(retval.redirectURL)
        elif isinstance(retval, Attempt):
            self.resultPage(retval)

    def openingPage(self):
        self.fixed_length = True
        s = XMLCRAP + '''
<head>
<title>Check your OpenID</title>
<base href=%(baseAttrib)s />
</head>
<body>
<form name="openidcheck" id="openidcheck" action="start" >
<p>Check an OpenID:
  <input type="text" name="openid_url" />
  <input type="submit" value="Check" /><br />
</p>
</form></body></html>''' % {
            'baseAttrib': quoteattr(getBaseURL(self.req)),
            }
        self.write(s)

    def go_start(self):
        f = FieldStorage(self.req)
        openid_url = f.getfirst("openid_url")
        self.record(TextEvent("Working on openid_url %s" % (openid_url,)))
        s = XMLCRAP + '''
<head>
<title>Check your OpenID: %(url)s</title>
<style type="text/css">%(stylesheet)s</style>
<base href=%(baseAttrib)s />
</head>
<body>
<p>Checking <a href=%(urlAttrib)s>%(url)s</a>...</p>
''' % {
            'stylesheet': STYLESHEET,
            'url': escape(openid_url),
            'urlAttrib': quoteattr(openid_url),
            'baseAttrib': quoteattr(getBaseURL(self.req)),
            }
        self.write(s)
        try:
            identity_info = self.fetchAndParse(openid_url)
            self.associate(identity_info)
            rows = [
                TestCheckidSetup,
                TestCheckidSetupCancel,
                TestCheckidImmediate,
                TestCheckidImmediateSetupNeeded,
                ]
            result_table = ResultTable(self, identity_info, rows)
            self.write(result_table.to_html())
            self.session['result_table'] = result_table
        finally:
            self.write('</body></html>')

        return PAGE_DONE

    def go_clear(self):
        self.session.delete()
        return DoRedirect(getBaseURL(self.req))

    def resultPage(self, recent_attempt=None):
        result_table = self.session['result_table']
        identity_info = result_table.identity_info
        if recent_attempt:
            attempt_html = RecentNote(recent_attempt).to_html()
        else:
            attempt_html = ''

        s = XMLCRAP + '''
<head>
<title>Check your OpenID: %(openid)s @ %(server)s</title>
<style type="text/css">%(stylesheet)s</style>
<base href=%(baseAttrib)s />
</head>
<body>
%(attempt)s
<p class="idinfo">%(iinfo)s</p>
%(result_table)s
%(reset_button)s
''' % {
            'stylesheet': STYLESHEET,
            'openid': identity_info.server_id,
            'server': identity_info.server_url,
            'baseAttrib': quoteattr(getBaseURL(self.req)),
            'attempt': attempt_html,
            'iinfo': identity_info.to_html(),
            'result_table': result_table.to_html(highlight=recent_attempt),
            'reset_button': ResetButton().to_html(),
            }
        self.write(s)
        self.write('</body></html>')
        return PAGE_DONE

    def fetchAndParse(self, openid_url):
        consu = self.getConsumer()
        status, info = consu._findIdentityInfo(openid_url)
        if status is consumer.SUCCESS:
            identity_info = IdentityInfo(*info)
            # TODO: Clarify language here.
            s = ("The supplied identity is %(cid)s, the server is at %(serv)s,"
                 " identity at the server is %(sid)s" % {
                'cid': identity_info.consumer_id,
                'sid': identity_info.server_id,
                'serv': identity_info.server_url})
            self.record(TextEvent(s))
            return identity_info

        elif status is consumer.HTTP_FAILURE:
            if info is None:
                raise Failure("Failed to connect to %s" % (openid_url,))
            else:
                http_code = info
                # XXX: That's not quite true - a server *somewhere*
                # returned that error, but it might have been after
                # a redirect.
                raise Failure("Server at %s returned error code %s" %
                              (openid_url, http_code,))

        elif status is consumer.PARSE_ERROR:
            raise Failure("Did not find any OpenID information at %s" %
                          (openid_url,))
        else:
            raise AssertionError("status %r not handled" % (status,))

    def associate(self, identity_info):
        server_url = identity_info.server_url
        self.statusMsg("Associating with %s..." % (server_url,))

        consu = self.getConsumer()
        dh = DiffieHellman()
        body = consu._createAssociateRequest(dh)
        assoc = consu._fetchAssociation(dh, server_url, body)
        self.record(TextEvent("Association made.  "
                              "Handle: %s, issued: %s, lifetime: %s hours" % (
            assoc.handle, time.ctime(assoc.issued), assoc.lifetime / 3600.,)))


    def getConsumer(self):
        if self.consumer is None:
            # Super-Bogosity!
            self._orig_oidutil_log = oidutil.log
            def resetLog():
                oidutil.log = self._orig_oidutil_log
            self.onCleanup(resetLog)
            oidutil.log = self.log

            if self.store is None:
                dbconn = pysqlite2.dbapi2.connect(self.storefile)
                self.store = SQLiteStore(dbconn)
                if self.storefile == ":memory:":
                    self.store.createTables()
            self.consumer = consumer.OpenIDConsumer(self.store)
        return self.consumer


class Attempt:
    parent = None

    t_attempt = '''<div class="attempt"><span class="name">%(name)s</span>
<ul>
%(event_rows)s
</ul>
</div>
'''

    def __init__(self, handle, parent=None):
        self.handle = handle
        self.when = time.time()
        self.event_log = []
        if parent is not None:
            self.parent = parent

    def record(self, event):
        self.event_log.append(event)

    def result(self):
        raise NotImplementedError

    def to_html(self):
        def fmtEvent(event):
            return '<li>%s</li>\n' % (event.to_html(),)
        if self.parent is not None:
            name = self.parent.name
        else:
            name = self.__class__.__name__
        d = {
            'name': name,
            'event_rows': ''.join(map(fmtEvent, self.event_log)),
            }
        return self.t_attempt % d


class CheckidAttemptBase(Attempt):
    authRequest = None
    redirectURL = None

    _resultMap = NotImplementedError

    def result(self):
        responses = filter(lambda e: isinstance(e, ResponseReceived),
                           self.event_log)
        if not responses:
            return INCOMPLETE

        if len(responses) > 1:
            # This is weird case.  Receiving more than one response to a
            # query is a sort of error, even though a 'cancel' followed by
            # an 'id_res' will generally get you logged in.
            # 'id_res' after 'id_res' is treated as an error though,
            # to prevent replays.
            return FAILURE

        last_event = self.event_log[-1]

        for event_type, outcome in self._resultMap.iteritems():
            if isinstance(last_event, event_type):
                return outcome
        else:
            return INCOMPLETE


class CheckidAttempt(CheckidAttemptBase):
    _resultMap = {
        IdentityAuthenticated: SUCCESS,
        OpenIDFailure: FAILURE,
        OperationCancelled: FAILURE,
        SetupNeeded: FAILURE,
        }


class CheckidCancelAttempt(CheckidAttemptBase):
    _resultMap = {
        IdentityAuthenticated: FAILURE,
        OpenIDFailure: FAILURE,
        OperationCancelled: SUCCESS,
        SetupNeeded: FAILURE,
        }


class CheckidImmediateAttempt(CheckidAttemptBase):
    _resultMap = {
        IdentityAuthenticated: SUCCESS,
        OpenIDFailure: FAILURE,
        OperationCancelled: FAILURE,
        SetupNeeded: FAILURE,
        }


class CheckidImmediateSetupNeededAttempt(CheckidAttemptBase):
    _resultMap = {
        IdentityAuthenticated: FAILURE,
        OpenIDFailure: FAILURE,
        OperationCancelled: FAILURE,
        SetupNeeded: SUCCESS,
        }


class ResultRow:
    name = None
    handler = None
    attemptClass = Attempt

    def __init__(self, parent, identity_info):
        self._lastAttemptHandle = 0
        self.attempts = []
        self.shortname = self.__class__.__name__
        self.parent_table = parent
        self.identity_info = identity_info

    def getAttempt(self, handle):
        for a in self.attempts:
            if a.handle == handle:
                return a
        raise KeyError(handle)

    def getSuccesses(self):
        return [r for r in self.attempts if r.result() is SUCCESS]

    def getFailures(self):
        return [r for r in self.attempts if r.result() is FAILURE]

    def getIncompletes(self):
        return [r for r in self.attempts if r.result() is INCOMPLETE]

    def newAttempt(self):
        self._lastAttemptHandle += 1
        a = self.attemptClass(str(self._lastAttemptHandle), parent=self)
        self.attempts.append(a)
        return a

    # Webby bits.

    def getURL(self, action="try"):
        return "%s/?action=%s" % (urllib.quote(self.shortname, safe=''),
                                  urllib.quote(action, safe=''))

    def handleRequest(self, req):
        action = FieldStorage(req).getfirst("action")
        if action:
            method = getattr(self, "request_" + action)
            if method:
                return method(req)
            else:
                # FIXME: return some status message about broken args
                return None

    def getConsumer(self):
        return self.parent_table.diagnostician.getConsumer()


def HACK_constructRedirect(consu, auth_request, return_to, trust_root,
                           immediate_mode=False):
    """Work around Consumer 1.0.3 API

    "Immediate mode" is a property of the request, not the consumer.
    consumer.OpenIDConsumer v.1.0.3 is confused, so we have kludge here.
    """
    if immediate_mode:
        consu.mode = 'checkid_immediate'
    else:
        consu.mode = 'checkid_setup'
    consu.immediate = immediate_mode
    return consu.constructRedirect(auth_request, return_to, trust_root)


class TestCheckid(ResultRow):
    immediate_mode = False

    def request_try(self, req):
        attempt = self.newAttempt()
        consu = self.getConsumer()
        auth_request = self.identity_info.newAuthRequest(consu)
        attempt.authRequest = auth_request
        return_to = "%s%s;attempt=%s" % (
            getBaseURL(req), self.getURL(action="response"),
            urllib.quote(attempt.handle, safe=''))

        redirectURL = HACK_constructRedirect(
            consu, auth_request, return_to,
            self.parent_table.diagnostician.trust_root,
            immediate_mode=self.immediate_mode)

        attempt.redirectURL = redirectURL
        attempt.record(TextEvent("Redirecting to %s" % redirectURL,))
        return DoRedirect(redirectURL)

    def request_response(self, req):
        consu = self.getConsumer()
        fields = FieldStorage(req)
        attempt_handle = fields.getfirst("attempt")
        # FIXME: Handle KeyError here.
        attempt = self.getAttempt(attempt_handle)
        query = {}
        for k in fields.keys():
            query[k] = fields.getfirst(k)
        attempt.record(ResponseReceived(raw_uri=req.unparsed_uri,
                                        query=query))
        status, info = consu.completeAuth(attempt.authRequest.token, query)
        if status is consumer.SUCCESS:
            if info is not None:
                attempt.record(IdentityAuthenticated(info))
            else:
                attempt.record(OperationCancelled())
        elif status is consumer.SETUP_NEEDED:
            attempt.record(SetupNeeded(info))
        else:
            attempt.record(OpenIDFailure(status, info))
        return attempt


class TestCheckidSetup(TestCheckid):
    name = "Successful checkid_setup"
    attemptClass = CheckidAttempt
    immediate_mode = False

class TestCheckidSetupCancel(TestCheckid):
    name = "Cancel checkid_setup"
    attemptClass = CheckidCancelAttempt
    immediate_mode = False

class TestCheckidImmediate(TestCheckid):
    name = "Successful checkid_immediate"
    attemptClass = CheckidImmediateAttempt
    immediate_mode = True

class TestCheckidImmediateSetupNeeded(TestCheckid):
    name = "Setup Needed for checkid_immediate"
    attemptClass = CheckidImmediateSetupNeededAttempt
    immediate_mode = True


class ResultRowHTMLView(object):
    t_result_row = (
        '<tr class=%(rowClass)s>'
        '<th scope="row" class=%(statusClass)s>%(name)s</th>'
        '<td %(hi_succ)s>%(succ)s</td><td %(hi_fail)s>%(fail)s</td>'
        '<td %(hi_incl)s>%(incl)s</td>'
        '<td><a href=%(trylink)s rel="nofollow">Try again?</a></td></tr>'
        '\n')

    t_empty_row = (
        '<tr class=%(rowClass)s><th scope="row">%(name)s</th><td colspan="4">'
        'Not yet attempted -- <a href=%(trylink)s rel="nofollow">try now</a>.'
        '</td></tr>'
        '\n')

    def __init__(self, rrow):
        self.orig = rrow

    def to_html(self, rownum=0, highlight=None):
        if rownum % 2:
            rowclass = "odd"
        else:
            rowclass = "even"
        if self.orig.attempts:
            template = self.t_result_row
            recent_result = self.orig.attempts[-1].result()
            recent_status = {
                FAILURE: 'failed',
                SUCCESS: 'success',
                INCOMPLETE: 'incomplete',
                }[recent_result]
        else:
            template = self.t_empty_row
            recent_status = ''

        cell_highlights = {'hi_succ': '',
                           'hi_fail': '',
                           'hi_incl': '',
                           }
        if highlight is not None:
            rowclass += ' highlight'
            cell = {FAILURE: 'hi_fail',
                    SUCCESS: 'hi_succ',
                    INCOMPLETE: 'hi_incl',
                    }[highlight.result() ]
            cell_highlights[cell] = 'class=%s' % (quoteattr('highlight'),)

        values = {
            'rowClass': quoteattr(rowclass),
            'statusClass': quoteattr(recent_status),
            'name': self.orig.name,
            'succ': len(self.orig.getSuccesses()),
            'fail': len(self.orig.getFailures()),
            'incl': len(self.orig.getIncompletes()),
            'trylink': quoteattr(self.orig.getURL()),
            }
        values.update(cell_highlights)
        return template % values


t_result_table = """
<table class="results">
<colgroup />
<colgroup span="3">
<colgroup />
<thead>
<tr>
<th scope='col'><!-- test name --></th>
<th scope='col' id="success">Success</th>
<th scope='col' id="failure">Failure</th>
<th scope='col' id="incomplete">Incomplete</th>
<th scope='col'><!-- retry link --></th></tr>
</thead>
<tbody>
%(rows)s
</tbody>
</table>
"""

class ResultTable(object):
    t_result_table = t_result_table

    def __init__(self, diagnostician, identity_info, rows):
        self.rows = []
        self.diagnostician = diagnostician
        self.identity_info = identity_info
        for rowclass in rows:
            self.rows.append(rowclass(self, identity_info))

    def getChild(self, key):
        for row in self.rows:
            if row.shortname == key:
                return row
        raise KeyError(key)

    def handleRequest(self, req, parts):
        child = self.getChild(parts[0])
        return child.handleRequest(req)

    def to_html(self, highlight=None):
        template = self.t_result_table
        htmlrows = []
        rownum = 0
        for row in self.rows:
            rownum += 1
            # IHTMLView(row).to_html()
            if (highlight is not None) and (highlight.parent == row):
                htmlrows.append(ResultRowHTMLView(row).to_html(
                    rownum=rownum, highlight=highlight))
            else:
                htmlrows.append(ResultRowHTMLView(row).to_html(rownum=rownum))
        return template % {
            'rows': ''.join(htmlrows),
            }

    def __getstate__(self, state=None):
        s = self.__dict__.copy()
        del s['diagnostician']
        return s

class RecentNote(object):
    t_note = '''<div class="recent_note">Latest response:
%(content)s
<p class="clearnote"><a href="">Clear Message</a></p>
</div>'''

    def __init__(self, content):
        self.content = content

    def to_html(self):
        values = {
            'content': self.content.to_html(),
            }
        return self.t_note % values


class ResetButton(object):
    def to_html(self):
        return ('<form action="clear">'
                '<input type="submit" value="Reset"></form>')
