import urllib

from xml.sax.saxutils import escape, quoteattr

from openid.tools.attempt import Attempt, ResultRow
from openid.tools import events

from openid.consumer import consumer

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
            consu, auth_request, return_to,
            self.parent_table.diagnostician.trust_root,
            immediate_mode=self.immediate_mode)

        attempt.redirectURL = redirectURL
        attempt.record(events.TextEvent("Redirecting to %s" % redirectURL,))
        return events.DoRedirect(redirectURL)

    def request_response(self, req):
        consu = self.getConsumer()
        attempt_handle = req.fields.getfirst("attempt")
        # FIXME: Handle KeyError here.
        attempt = self.getAttempt(attempt_handle)
        query = {}
        for k in req.fields.keys():
            query[k] = req.fields.getfirst(k)
        attempt.record(events.ResponseReceived(raw_uri=req.unparsed_uri,
                                               query=query))
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
