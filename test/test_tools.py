
import unittest
from cStringIO import StringIO
from openid.tools import oiddiag
from openid.consumer import consumer
from openid import association

class DummyApacheModule(object):
    OK = "200 OK"
    APLOG_WARNING = "WARNING"

class DummyFieldStorage(object):
    def __init__(self, req):
        self.req = req

    def getfirst(self, key):
        l = self.req.fields.get(key)
        if not l:
            return None
        else:
            return l[0]

    def keys(self):
        return self.req.fields.keys()

oiddiag.apache = DummyApacheModule()
oiddiag.FieldStorage = DummyFieldStorage

class DummyRequest(object):
    def __init__(self):
        self.options = {}
        self.logmsgs = []
        self.fields = {}
        self.output = StringIO()
        self.uri = "http://unittest.example/myapp"
        self.subprocess_env = {}
        class DummyConnection(object):
            local_addr = ('127.0.0.1', 80)
        self.connection = DummyConnection()
        self.hostname = 'unittest.example'
        self.path_info = ''

    def get_options(self):
        return self.options

    def log_error(self, msg, priority):
        self.logmsgs.append((priority, msg))

    def write(self, bytes):
        return self.output.write(bytes)

class MockConsumer(object):
    def beginAuth(self, url):
        self.url = url
        return consumer.SUCCESS, consumer.OpenIDAuthRequest(
            "token", url, "http://unittest.example/server", "nonce")

    def constructRedirect(self, auth_request, return_to, trust_root):
        return auth_request.server_url + "?blah=blah;blah2=blah3"

    def _findIdentityInfo(self, url):
        self.url = url
        return consumer.SUCCESS, (url, "http://delegated.ident.example/",
                                  "http://unittest.example/server",)

    def _gotIdentityInfo(self, consumer_id, server_id, server_url):
        return consumer.SUCCESS, consumer.OpenIDAuthRequest(
            "token7", server_id, server_url, "nonce8")

    def _createAssociateRequest(self, dh):
        return "kvform association request blah blah blah"

    def _fetchAssociation(self, dh, url, body):
        return association.Association.fromExpiresIn(3600, "assoc handle",
                                                     "s3krit", 'HMAC-SHA1')

    def completeAuth(self, token, query):
        return consumer.SUCCESS, "http://some-guys-id.example"

class TestOidDiag(unittest.TestCase):
    def setUp(self):
        self.req = DummyRequest()
        self.diag = oiddiag.Diagnostician(self.req)
        self.consumer = MockConsumer()
        self.diag.getConsumer = lambda : self.consumer

    def test_supplyOpenID(self):
        self.req.fields["openid_url"] = ["unittest.example/joe"]
        self.diag.go()
        self.failUnlessEqual(len(self.diag.event_log), 3)


class SuccessOrFailureAttempt(oiddiag.Attempt):
    def result(self):
        return self.code

class SuccessOrFailureRow(oiddiag.ResultRow):
    attemptClass = SuccessOrFailureAttempt

class TestResultRow(unittest.TestCase):
    def setUp(self):
        r = self.rrow = SuccessOrFailureRow(None, None)
        results = [
            oiddiag.SUCCESS,
            oiddiag.INCOMPLETE,
            oiddiag.FAILURE,
            oiddiag.SUCCESS,
            oiddiag.INCOMPLETE,
            oiddiag.FAILURE,
            oiddiag.INCOMPLETE,
            oiddiag.FAILURE,
            oiddiag.INCOMPLETE,
            ]
        for result in results:
            a = r.newAttempt()
            a.code = result

    def test_getFailures(self):
        f = self.rrow.getFailures()
        self.failUnlessEqual(len(f), 3)

    def test_getSuccesses(self):
        s = self.rrow.getSuccesses()
        self.failUnlessEqual(len(s), 2)

    def test_getIncompletes(self):
        i = self.rrow.getIncompletes()
        self.failUnlessEqual(len(i), 4)


class TestResultRowWeb(unittest.TestCase):
    def setUp(self):
        class SomeTest(oiddiag.ResultRow):
            name = "Some Unit Test"
            tryCalled = False

            def request_try(self, req):
                self.tryCalled = True
        self.rrow = SomeTest(None, None)

    def test_getURL(self):
        u = self.rrow.getURL()
        self.failUnlessEqual(u, "SomeTest/?action=try")

    def test_handleRequest(self):
        req = DummyRequest()
        req.path_info = "SomeTest/"
        req.fields["action"] = ["try"]
        self.rrow.handleRequest(req)
        self.failUnless(self.rrow.tryCalled)


class TestCheckidTest(unittest.TestCase):
    def setUp(self):
        class MockDiag(object):
            consumer = MockConsumer()
            trust_root = "http://unittest.example/"
            def getConsumer(self):
                return self.consumer
        self.diag = MockDiag()
        self.idinfo = oiddiag.IdentityInfo(
            self.diag.getConsumer(),
            "http://shortname.example/",
            "http://delegated.example/users/long.name",
            "http://some.example/server",)
        self.rrow = oiddiag.TestCheckidSetup(self.diag, self.idinfo)

    def test_handleRequestTry(self):
        req = DummyRequest()
        req.uri = "%s/%s" % (req.uri, self.rrow.shortname)
        req.path_info = '/' + self.rrow.shortname
        req.hostname = 'unittest.example'
        result = self.rrow.request_try(req)
        # 1) a new Attempt is logged
        self.failUnlessEqual(len(self.rrow.attempts), 1)
        # 2) information about the attempt is stored
        attempt = self.rrow.attempts[0]
        self.failUnless(attempt.authRequest)
        self.failUnless(attempt.redirectURL)
        # 3) request gets a redirect
        self.failUnless(isinstance(result, oiddiag.DoRedirect))

    def test_handleRequestResponse(self):
        req = DummyRequest()
        req.uri = "%s/%s" % (req.uri, self.rrow.shortname)
        req.path_info = '/' + self.rrow.shortname
        req.hostname = 'unittest.example'

        attempt_handle = 'a76'
        req.fields = {'attempt': [attempt_handle]}
        attempt = self.rrow.attemptClass(attempt_handle)
        attempt.authRequest = consumer.OpenIDAuthRequest('tokken',
                                                         'server_id',
                                                         'server_url',
                                                         'nonny')
        self.rrow.attempts.append(attempt)
        result = self.rrow.request_response(req)
        last_event = attempt.event_log[-1]
        self.failUnless(isinstance(last_event, oiddiag.IdentityAuthenticated))
        self.failUnlessEqual(attempt.result(), oiddiag.SUCCESS)

if __name__ == '__main__':
    unittest.main()
