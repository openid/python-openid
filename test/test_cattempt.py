import unittest
from openid.tools import attempt, cattempt, events
from openid.consumer import consumer

from tools import DummyRequest

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


class TestCheckidTest(unittest.TestCase):
    def setUp(self):
        class MockDiag(object):
            consumer = MockConsumer()
            trust_root = "http://unittest.example/"
            def getConsumer(self):
                return self.consumer
            def getBaseURL(self):
                return self.trust_root + 'base/'
        self.diag = MockDiag()
        self.idinfo = cattempt.IdentityInfo(
            "http://shortname.example/",
            "http://delegated.example/users/long.name",
            "http://some.example/server",)
        self.rtable = attempt.ResultTable(self.diag, self.idinfo,
                                          [cattempt.TestCheckidSetup])
        self.rrow = self.rtable.rows[0]

    def test_handleRequestTry(self):
        req = DummyRequest()
        req.uri = "%s/%s" % (req.uri, self.rrow.shortname)
        req.path_info = '/' + self.rrow.shortname
        req.hostname = 'unittest.example'
        result = self.rrow.request_try(req)
        # 1) a new Attempt is logged
        self.failUnlessEqual(len(self.rrow.attempts), 1)
        # 2) information about the attempt is stored
        myattempt = self.rrow.attempts[0]
        self.failUnless(myattempt.authRequest)
        self.failUnless(myattempt.redirectURL)
        # 3) request gets a redirect
        self.failUnless(isinstance(result, events.DoRedirect))

    def test_handleRequestResponse(self):
        req = DummyRequest()
        req.uri = "%s/%s" % (req.uri, self.rrow.shortname)
        req.path_info = '/' + self.rrow.shortname
        req.hostname = 'unittest.example'

        attempt_handle = 'a76'
        req._fields = {'attempt': [attempt_handle]}
        myattempt = self.rrow.attemptClass(attempt_handle)
        myattempt.authRequest = consumer.OpenIDAuthRequest('tokken',
                                                           'server_id',
                                                           'server_url',
                                                           'nonny')
        self.rrow.attempts.append(myattempt)
        result = self.rrow.request_response(req)
        last_event = myattempt.event_log[-1]
        self.failUnless(isinstance(last_event, events.IdentityAuthenticated))
        self.failUnlessEqual(myattempt.result(), attempt.Attempt.SUCCESS)


if __name__ == '__main__':
    unittest.main()
