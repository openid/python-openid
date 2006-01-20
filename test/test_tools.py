
import unittest

from cStringIO import StringIO
from openid.tools import oiddiag, events, cattempt
from openid.consumer import consumer
from openid import association
from tools import DummyRequest

class DummyApacheModule(object):
    OK = "200 OK"
    APLOG_WARNING = "WARNING"

class MockSession(dict):
    def __init__(self, unused_req, timeout=None):
        pass

    def is_new(self):
        return True

class SERVER_RETURN(Exception):
    pass

class TestingWebface(object):
    def __init__(self, req):
        self.req = req
        self.session = MockSession(self.req)

    def getBaseURL(self):
        return "http://monkey.innabox/%d/" % (id(self),)

    def log_error(self, message, priority=None):
        import sys
        sys.stderr.write(message)

    def fixedLength(self, fixed):
        pass

    def write(self, bytes):
        pass

    def redirect(self, url):
        raise SERVER_RETURN

    def displayEvent(self, event):
        pass

    def statusMsg(self, msg):
        pass

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
        self.webface = TestingWebface(self.req)
        self.diag = oiddiag.Diagnostician(self.webface, storefile=":memory:")
        self.consumer = MockConsumer()
        self.diag.getConsumer = lambda : self.consumer

    def test_supplyOpenID(self):
        self.req._fields["openid_url"] = ["unittest.example/joe"]
        self.req.path_info = '/start'
        self.diag.go(self.req)
        self.failUnlessEqual(len(self.diag.event_log), 3)



if __name__ == '__main__':
    unittest.main()
