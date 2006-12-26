import cgi
import unittest

from openid.consumer import consumer
from openid import message

class DummyEndpoint(object):
    preferred_namespace = message.OPENID2_NS
    local_id = None
    server_url = None
    is_op_identifier = False

    def preferredNamespace(self):
        return self.preferred_namespace

    def getLocalID(self):
        return self.local_id

    def isOPIdentifier(self):
        return self.is_op_identifier

class DummyAssoc(object):
    handle = "assoc-handle"

class TestAuthRequestBase(unittest.TestCase):
    def setUpEndpoint(self):
        self.endpoint = DummyEndpoint()
        self.endpoint.local_id = 'http://server.unittest/joe'
        self.endpoint.server_url = 'http://server.unittest/'

    def setUp(self):
        self.setUpEndpoint()
        self.assoc = DummyAssoc()
        self.authreq = consumer.AuthRequest(self.endpoint, self.assoc)

class TestAuthRequest(TestAuthRequestBase):
    def test_justConstruct(self):
        """Make sure that constructing an AuthRequest works"""

    def test_addExtensionArg(self):
        self.authreq.addExtensionArg('bag:', 'color', 'brown')
        self.authreq.addExtensionArg('bag:', 'material', 'paper')
        self.failUnless('bag:' in self.authreq.message.namespaces)
        self.failUnlessEqual(self.authreq.message.getArgs('bag:'),
                             {'color': 'brown',
                              'material': 'paper'})
        url = self.authreq.redirectURL('http://7.utest/', 'http://7.utest/r')
        self.failUnless(url.find('openid.ns.0=bag%3A') != -1,
                        'extension bag namespace not found in %s' % (url,))
        self.failUnless(url.find('openid.0.color=brown') != -1,
                        'extension arg not found in %s' % (url,))
        self.failUnless(url.find('openid.0.material=paper') != -1,
                        'extension arg not found in %s' % (url,))

class TestAuthRequestOpenID2(TestAuthRequestBase):
    def test_setAnonymous(self):
        req = consumer.AuthRequest(self.endpoint, self.assoc)
        self.failUnless(req.message.isOpenID2())
        req.setAnonymous(True)
        req.setAnonymous(False)

    def test_userAnonymous(self):
        self.authreq.setAnonymous(True)
        url = self.authreq.redirectURL('http://7.utest/', 'http://7.utest/r')
        self.failUnless(url.find('openid.identity') == -1,
                        'unwanted openid.identity arg appeared in %s' % (url,))

    def test_opAnonymous(self):
        self.endpoint.is_op_identifier = True
        self.authreq.setAnonymous(True)
        url = self.authreq.redirectURL('http://7.utest/', 'http://7.utest/r')
        self.failUnless(url.find('openid.identity') == -1,
                        'unwanted openid.identity arg appeared in %s' % (url,))


    def test_idpEndpoint(self):
        self.endpoint.is_op_identifier = True
        url = self.authreq.redirectURL('http://7.utest/', 'http://7.utest/r')
        _, qstring = url.split('?')
        params = dict(cgi.parse_qsl(qstring))
        self.failUnlessEqual(params['openid.identity'],
                             message.IDENTIFIER_SELECT)

class TestAuthRequestOpenID1(TestAuthRequestBase):
    def setUpEndpoint(self):
        self.endpoint = DummyEndpoint()
        self.endpoint.local_id = 'http://server.unittest/joe'
        self.endpoint.server_url = 'http://server.unittest/'
        self.endpoint.preferred_namespace = message.OPENID1_NS

    def test_setAnonymous(self):
        req = consumer.AuthRequest(self.endpoint, self.assoc)
        self.failUnless(req.message.isOpenID1())
        self.failUnlessRaises(ValueError, req.setAnonymous, True)
        req.setAnonymous(False)

    def test_idpEndpoint(self):
        self.endpoint.is_op_identifier = True
        url = self.authreq.redirectURL('http://7.utest/', 'http://7.utest/r')
        _, qstring = url.split('?')
        params = dict(cgi.parse_qsl(qstring))
        self.failUnlessEqual(params['openid.identity'],
                             message.IDENTIFIER_SELECT)


if __name__ == '__main__':
    unittest.main()
