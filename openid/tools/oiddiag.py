"""OpenID Diagnostic

@todo: new sessions should check to see if they are new sessions
    because they are an expired old session, and explain that is
    the case.

@todo: drill-down views for table rows.
@todo: convert the assosciate methods to use Attempts
@todo: Make sure dumb mode tests give readable results when check_auth fails
@todo: Test out-of-protocol cases such as empty GET to the server URL.
@todo: add more association tests
@todo: test when return_to.startswith(trust_root) is False
@todo: document usage, results
@todo: end-user wrapper
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

from xml.sax.saxutils import escape, quoteattr

from openid.consumer import consumer
from openid.store.sqlstore import SQLiteStore
from openid.dh import DiffieHellman
from openid import oidutil

from openid.tools import events, attempt, cattempt
from openid.tools.attempt import Attempt

import pysqlite2.dbapi2
import time

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

def apacheHandler(req):
    from mod_python import apache
    modpython = apache.import_module("openid.tools.modpython")
    storefile = req.get_options().get("OIDDiagStoreFile")
    face = modpython.ApacheFace(req)
    diag = Diagnostician(face, storefile)
    return face.handle(rendermethod=diag.go)

class EventRecorderMixin(object):
    def __init__(self):
        self.event_log = []

    def record(self, event):
        self.event_log.append(event)
        # XXX: IWebFace(self).displayEvent(event) or something
        if self.webface:
            self.webface.displayEvent(event)

class Diagnostician(EventRecorderMixin):
    consumer = None
    store = None

    def __init__(self, webface, storefile=None):
        EventRecorderMixin.__init__(self)
        self.webface = webface
        if storefile is None:
            self.webface.log_error("PythonOption OIDDiagStoreFile not found, "
                                   "using in-memory store instead.")
            self.storefile = ":memory:"
        else:
            self.storefile = storefile

        if 'result_table' not in self.webface.session:
            self.webface.session['result_table'] = None

        self.result_table = self.webface.session['result_table']
        if self.result_table is not None:
            self.result_table.diagnostician = self

        self.trust_root = self.webface.getBaseURL()

    def go(self, req):
        retval = None
        fields = req.fields
        path_info = req.path_info
        if path_info[1:]:
            parts = path_info[1:].split('/')
            method = getattr(self, 'go_' + parts[0], None)
            if method is not None:
                try:
                    retval = method(req)
                except events.Failure, e:
                    # FIXME: This is too high to handle most errors, I think.
                    self.record(e.event())
                    self.webface.write("</body></html>")
                    retval = PAGE_DONE
            elif self.result_table is not None:
                retval = self.result_table.handleRequest(req, parts)
            else:
                self.webface.log_error("Session %s arrived at %s but had no "
                                       "stored result table." %
                                       (self.webface.session.id(), parts))

        if retval is None:
            if self.result_table is None:
                retval = self.openingPage()
            else:
                retval = self.resultPage()

        if retval is PAGE_DONE:
            return
        elif isinstance(retval, events.DoRedirect):
            self.webface.redirect(retval.redirectURL)
        elif isinstance(retval, Attempt):
            self.resultPage(retval)

    def openingPage(self):
        self.webface.fixedLength(True)
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
            'baseAttrib': quoteattr(self.webface.getBaseURL()),
            }
        self.webface.write(s)

    def go_start(self, req):
        openid_url = req.fields.getfirst("openid_url")
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
            'baseAttrib': quoteattr(self.webface.getBaseURL()),
            }
        self.webface.write(s)

        throwaway_table = ResultTable(
            self, cattempt.IdentityInfo(openid_url, None, None),
            [cattempt.TestIdentityPage])
        fetch_attempt = throwaway_table.rows[0].fetchAndParse(
            subscriber=self.record)
        if fetch_attempt.result() is Attempt.SUCCESS:
            identity_info = fetch_attempt.identity_info
        else:
            self.webface.write('<!-- result is %s -->' %
                               (fetch_attempt.result(),))
            self.webface.write(ResetButton().to_html())
            self.webface.write('</body></html>')
            return PAGE_DONE

        rows = [
            cattempt.TestCheckidSetup,
            cattempt.TestCheckidSetupCancel,
            cattempt.TestCheckidImmediate,
            cattempt.TestCheckidImmediateSetupNeeded,
            # dumb mode tests
            cattempt.TestDumbCheckidSetup,
            cattempt.TestDumbCheckidSetupCancel,
            cattempt.TestDumbCheckidImmediate,
            cattempt.TestDumbCheckidImmediateSetupNeeded,
            ]
        self.result_table = ResultTable(self, identity_info, rows)
        self.webface.session['result_table'] = self.result_table
        self.associate(identity_info)
        self.webface.write('<a href=".">[Clear Message]</a>\n')
        self.webface.write(self.result_table.to_html())
        self.webface.write(ResetButton().to_html())
        self.webface.write(self.result_table.doc_to_html())
        self.webface.write('</body></html>')

        return PAGE_DONE

    def go_clear(self, req):
        self.webface.session.delete()
        return events.DoRedirect(self.webface.getBaseURL())

    def resultPage(self, recent_attempt=None):
        self.webface.fixedLength(True)
        identity_info = self.result_table.identity_info
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
%(docs)s
</body></html>
''' % {
            'stylesheet': STYLESHEET,
            'openid': identity_info.server_id,
            'server': identity_info.server_url,
            'baseAttrib': quoteattr(self.webface.getBaseURL()),
            'attempt': attempt_html,
            'iinfo': identity_info.to_html(),
            'result_table': self.result_table.to_html(highlight=recent_attempt),
            'reset_button': ResetButton().to_html(),
            'docs': self.result_table.doc_to_html(),
            }
        self.webface.write(s)
        return PAGE_DONE

    def associate(self, identity_info):
        server_url = identity_info.server_url
        self.webface.statusMsg("Associating with %s..." % (server_url,))

        consu = self.getConsumer()
        dh = DiffieHellman()
        body = consu._createAssociateRequest(dh)
        assoc = consu._fetchAssociation(dh, server_url, body)
        self.record(events.TextEvent("Association made.  "
                                     "Handle: %s, issued: %s, "
                                     "lifetime: %s hours" % (
            assoc.handle, time.ctime(assoc.issued), assoc.lifetime / 3600.,)))


    def getConsumer(self):
        if self.consumer is None:
            # Super-Bogosity!
            self._orig_oidutil_log = oidutil.log
            def resetLog():
                oidutil.log = self._orig_oidutil_log
            self.webface.onCleanup(resetLog)
            oidutil.log = self.webface.log

            if self.store is None:
                dbconn = pysqlite2.dbapi2.connect(self.storefile)
                self.store = SQLiteStore(dbconn)
                if self.storefile == ":memory:":
                    self.store.createTables()
            self.consumer = consumer.OpenIDConsumer(self.store)
        return self.consumer


    def getBaseURL(self):
        return self.webface.getBaseURL()

    def getTrustRoot(self):
        return self.trust_root

t_result_table = """
<table class="results" summary=%(summary)s>
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

class ResultTable(attempt.ResultTable):
    t_result_table = t_result_table

    t_doc = """<div class="results-doc">
<dl>
%(testdocs)s
</dl>
</div>
"""

    def to_html(self, highlight=None):
        template = self.t_result_table
        htmlrows = []
        rownum = 0
        results = {Attempt.SUCCESS: 0,
                   Attempt.FAILURE: 0,
                   Attempt.INCOMPLETE: 0,
                   None: 0}
        for row in self.rows:
            rownum += 1
            # IHTMLView(row).to_html()
            if (highlight is not None) and (highlight.parent == row):
                htmlrows.append(row.to_html(rownum=rownum, highlight=highlight))
            else:
                htmlrows.append(row.to_html(rownum=rownum))

            if row.attempts:
                results[row.attempts[-1].result()] += 1
            else:
                results[None] += 1

        summary = ["%d tests" % (len(self.rows),)]
        if results[Attempt.SUCCESS]:
            summary.append("%d passing" % (results[Attempt.SUCCESS],))
        if results[Attempt.FAILURE]:
            summary.append("%d failing" % (results[Attempt.FAILURE],))
        if results[Attempt.INCOMPLETE]:
            summary.append("%d incomplete" % (results[Attempt.INCOMPLETE],))
        if results[None]:
            summary.append("%d not yet tried" % (results[None],))

        return template % {
            'summary': quoteattr(', '.join(summary) + '.'),
            'rows': ''.join(htmlrows),
            }

    def doc_to_html(self):
        docs = []
        for row in self.rows:
            docs.append(row.doc_to_html())
        docs = filter(None, docs)
        return self.t_doc % {
            'testdocs': ''.join(docs),
            }


class RecentNote(object):
    t_note = '''<div class="recent_note">Latest response:
%(content)s
<p class="clearnote"><a href=".">Clear Message</a></p>
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
                '<input type="submit" value="Reset" /></form>')
