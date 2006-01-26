"""Attempting to do things as an OpenID consumer might.
"""

# Docs are in ReStructuredText to facilitate inline help in the application.
__docformat__ = "restructuredtext en"

import urllib

from xml.sax.saxutils import escape, quoteattr

from openid.tools.attempt import Attempt, ResultRow
from openid.tools import events

from openid.consumer import consumer
from openid.store import dumbstore

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


class IConsumerInfo:
    def getConsumer():
        """
        @returntype: openid.consumer.consumer.OpenIDConsumer
        """
        pass

    def getBaseURL():
        pass

    def getTrustRoot():
        pass


class CheckidAttemptBase(Attempt):
    authRequest = None
    redirectURL = None

    _resultMap = NotImplementedError

    def result(self):
        responses = filter(lambda e: isinstance(e, events.ResponseReceived),
                           self.event_log)
        if not responses:
            return Attempt.INCOMPLETE

        if len(responses) > 1:
            # This is weird case.  Receiving more than one response to a
            # query is a sort of error, even though a 'cancel' followed by
            # an 'id_res' will generally get you logged in.
            # 'id_res' after 'id_res' is treated as an error though,
            # to prevent replays.
            return Attempt.FAILURE

        last_event = self.event_log[-1]

        for event_type, outcome in self._resultMap.iteritems():
            if isinstance(last_event, event_type):
                return outcome
        else:
            return Attempt.INCOMPLETE


class CheckidAttempt(CheckidAttemptBase):
    _resultMap = {
        events.IdentityAuthenticated: Attempt.SUCCESS,
        events.OpenIDFailure: Attempt.FAILURE,
        events.OperationCancelled: Attempt.FAILURE,
        events.SetupNeeded: Attempt.FAILURE,
        }


class CheckidCancelAttempt(CheckidAttemptBase):
    _resultMap = {
        events.IdentityAuthenticated: Attempt.FAILURE,
        events.OpenIDFailure: Attempt.FAILURE,
        events.OperationCancelled: Attempt.SUCCESS,
        events.SetupNeeded: Attempt.FAILURE,
        }


class CheckidImmediateAttempt(CheckidAttemptBase):
    _resultMap = {
        events.IdentityAuthenticated: Attempt.SUCCESS,
        events.OpenIDFailure: Attempt.FAILURE,
        events.OperationCancelled: Attempt.FAILURE,
        events.SetupNeeded: Attempt.FAILURE,
        }


class CheckidImmediateSetupNeededAttempt(CheckidAttemptBase):
    _resultMap = {
        events.IdentityAuthenticated: Attempt.FAILURE,
        events.OpenIDFailure: Attempt.FAILURE,
        events.OperationCancelled: Attempt.FAILURE,
        events.SetupNeeded: Attempt.SUCCESS,
        }



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
        return_to = "%s%s&attempt=%s" % (
            self.parent_table.diagnostician.getBaseURL(),
            self.getURL(action="response"),
            urllib.quote(attempt.handle, safe=''))

        redirectURL = HACK_constructRedirect(
            consu, auth_request, return_to, self.getTrustRoot(),
            immediate_mode=self.immediate_mode)

        attempt.redirectURL = redirectURL
        attempt.record(events.SentRedirect(redirectURL))
        return events.DoRedirect(redirectURL)

    def request_response(self, req):
        consu = self.getConsumer()
        attempt_handle = req.fields.getfirst("attempt")
        # FIXME: Handle KeyError here.
        attempt = self.getAttempt(attempt_handle)
        query = {}
        query_lists = {}
        for k in req.fields.keys():
            query[k] = req.fields.getfirst(k)
            query_lists[k] = req.fields.getlist(k)
        attempt.record(events.ResponseReceived(raw_uri=req.unparsed_uri,
                                               query=query_lists))
        status, info = consu.completeAuth(attempt.authRequest.token, query)
        if status is consumer.SUCCESS:
            if info is not None:
                attempt.record(events.IdentityAuthenticated(info))
            else:
                attempt.record(events.OperationCancelled())
        elif status is consumer.SETUP_NEEDED:
            attempt.record(events.SetupNeeded(info))
        else:
            attempt.record(events.OpenIDFailure(status, info))
        return attempt


class DumbModeMixin(object):

    def getConsumer(self):
        """You get a dumb consumer."""
        # Don't follow this example and hard-code your secret in the code.
        # I'm only doing it that way here because the consequences of a
        # conversation with the testing program being cracked are pretty
        # minimal.  What are you going to do, inject false positives into
        # the test results for a dumb-mode consumer?
        store = dumbstore.DumbStore("a secret")
        return consumer.OpenIDConsumer(store)


class TestCheckidSetup(TestCheckid):
    """I check the server's positive response to a `checkid_setup` query.

    You will be directed to your OpenID server.  For this test to
    succeed, you should log in and tell the server to allow this site
    to know your identity.

    Specification: checkid_setup_.

    .. _checkid_setup: http://openid.net/specs.bml#mode-checkid_setup
    """
    name = "Successful checkid_setup"
    attemptClass = CheckidAttempt
    immediate_mode = False

class TestCheckidSetupCancel(TestCheckid):
    """I check the server's negative response to a `checkid_setup` query.

    You will be directed to your OpenID server.  For this test to
    succeed, you should cancel the login, typically by pressing a
    "Canel" or "Do Not Trust" button.

    Specification: checkid_setup_.

    .. _checkid_setup: http://openid.net/specs.bml#mode-checkid_setup
    """
    name = "Cancel checkid_setup"
    attemptClass = CheckidCancelAttempt
    immediate_mode = False

class TestCheckidImmediate(TestCheckid):
    """I check the server's positive response to a `checkid_immediate` query.

    Prerequisites: I expect an immediate positive response from the server,
    which typically means your user agent must already be authenticated with
    your server with the given OpenID, and your server must be configured to
    always allow this site to know your identity.  If the test fails with a
    "setup needed" message, follow that link, configure the server,
    and re-run the test.

    Specification: checkid_immediate_.

    .. _checkid_immediate: http://openid.net/specs.bml#mode-checkid_immediate
    """
    name = "Successful checkid_immediate"
    attemptClass = CheckidImmediateAttempt
    immediate_mode = True

class TestCheckidImmediateSetupNeeded(TestCheckid):
    """I check the server's negative response to a `checkid_immediate` query.

    I expect an immediate negative response from the server.  You
    should not have to take any special action or sever configuration.
    If this test unexpectedly gets a positive authentication response,
    your server is perhaps applying an "always trust" preference to my
    `trust_root`.

    Specification: checkid_immediate_.

    .. _checkid_immediate: http://openid.net/specs.bml#mode-checkid_immediate
    """
    name = "Setup Needed for checkid_immediate"
    attemptClass = CheckidImmediateSetupNeededAttempt
    immediate_mode = True


class TestDumbCheckidSetup(DumbModeMixin, TestCheckidSetup):
    name = TestCheckidSetup.name + ' (dumb mode)'

class TestDumbCheckidSetupCancel(DumbModeMixin, TestCheckidSetupCancel):
    name = TestCheckidSetupCancel.name + ' (dumb mode)'

class TestDumbCheckidImmediate(DumbModeMixin, TestCheckidImmediate):
    name = TestCheckidImmediate.name + ' (dumb mode)'

class TestDumbCheckidImmediateSetupNeeded(DumbModeMixin,
                                          TestCheckidImmediateSetupNeeded):
    name = TestCheckidImmediateSetupNeeded.name + ' (dumb mode)'


class FetchAttempt(Attempt):
    openid_url = None
    identity_info = None

    def result(self):
        if not self.event_log:
            outcome= Attempt.INCOMPLETE
        else:
            last_event = self.event_log[-1]
            if isinstance(last_event, events.GotIdentityInfo):
                outcome = Attempt.SUCCESS
            elif isinstance(last_event, events.OpenIDFailure):
                outcome = Attempt.FAILURE
            else:
                outcome = Attempt.INCOMPLETE
        return outcome


class TestIdentityPage(ResultRow):
    attemptClass = FetchAttempt

    def __init__(self, *a, **kw):
        ResultRow.__init__(self, *a, **kw)
        # FIXME: Kludge.  This operation is where the identity_info object
        # is created, so taking one as input is misleading.
        self.openid_url = self.identity_info.consumer_id

    def request_try(self, req):
        return self.fetchAndParse()

    def fetchAndParse(self, subscriber=None):
        attempt = self.newAttempt()
        if subscriber:
            # Oh how the gods of consistent interface are unhappy about this.
            attempt.subscribe(subscriber)
        # I'm starting to wonder if this method doesn't really belong in
        # the Attempt...
        attempt.openid_url = self.openid_url
        consu = self.getConsumer()
        attempt.record(events.TextEvent("Fetching %s" % (self.openid_url,)))
        status, info = consu._findIdentityInfo(self.openid_url)
        if status is consumer.SUCCESS:
            identity_info = IdentityInfo(*info)
            attempt.record(events.GotIdentityInfo(identity_info))
            attempt.identity_info = identity_info

        elif status is consumer.HTTP_FAILURE:
            if info is None:
                attempt.record(
                    events.OpenIDFailure(status, info,
                                         "Failed to connect to %s" %
                                         (self.openid_url,)))
            else:
                http_code = info
                # XXX: That's not quite true - a server *somewhere*
                # returned that error, but it might have been after
                # a redirect.
                attempt.record(
                    events.OpenIDFailure(status, info,
                                         "Server at %s returned error code %s" %
                                         (self.openid_url, http_code,)))

        elif status is consumer.PARSE_ERROR:
            attempt.record(
                events.OpenIDFailure(status, info,
                                     "Did not find any OpenID information "
                                     "at %s" % (self.openid_url,)))

        else:
            attempt.record(events.OpenIDFailure(status, info))

        return attempt
