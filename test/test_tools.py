
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

oiddiag.apache = DummyApacheModule()
oiddiag.FieldStorage = DummyFieldStorage

class DummyRequest(object):
    def __init__(self):
        self.options = {}
        self.logmsgs = []
        self.fields = {}
        self.output = StringIO()

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

    def _createAssociateRequest(self, dh):
        return "kvform association request blah blah blah"

    def _fetchAssociation(self, dh, url, body):
        return association.Association.fromExpiresIn(3600, "assoc handle",
                                                     "s3krit", 'HMAC-SHA1')

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


if __name__ == '__main__':
    unittest.main()
