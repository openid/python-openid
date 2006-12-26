import cgi
import unittest

from openid.consumer import consumer
from openid import message

class DummyEndpoint(object):
    preferred_namespace = None
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

class TestAuthRequestBase(object):
    """Mixin for AuthRequest tests for OpenID 1 and 2"""

    preferred_namespace = None

    def setUp(self):
        self.endpoint = DummyEndpoint()
        self.endpoint.local_id = 'http://server.unittest/joe'
        self.endpoint.server_url = 'http://server.unittest/'
        self.endpoint.preferred_namespace = self.preferred_namespace
        self.realm = 'http://example/'
        self.return_to = 'http://example/return/'
        self.assoc = DummyAssoc()
        self.authreq = consumer.AuthRequest(self.endpoint, self.assoc)

    def failUnlessAnonymous(self, msg):
        self.failUnlessEqual(
            None, msg.getArg(message.OPENID_NS, 'identity'),
            'unwanted openid.identity arg appeared in %r' % (msg,))

    def test_justConstruct(self):
        """Make sure that the internal state of the AuthRequest
        matches what we put in during construction"""
        self.failUnlessEqual(self.preferred_namespace,
                             self.authreq.message.getOpenIDNamespace())

    def test_addExtensionArg(self):
        self.authreq.addExtensionArg('bag:', 'color', 'brown')
        self.authreq.addExtensionArg('bag:', 'material', 'paper')
        self.failUnless('bag:' in self.authreq.message.namespaces)
        self.failUnlessEqual(self.authreq.message.getArgs('bag:'),
                             {'color': 'brown',
                              'material': 'paper'})
        msg = self.authreq.getMessage(self.realm, self.return_to)

        # XXX: this depends on the way that Message assigns
        # namespaces. Really it doesn't care that it has alias "0",
        # but that is tested anyway
        post_args = msg.toPostArgs()
        self.failUnlessEqual('bag:', post_args['openid.ns.0'])
        self.failUnlessEqual('brown', post_args['openid.0.color'])
        self.failUnlessEqual('paper', post_args['openid.0.material'])

class TestAuthRequestOpenID2(TestAuthRequestBase, unittest.TestCase):
    preferred_namespace = message.OPENID2_NS

    def test_setAnonymousWorksForOpenID2(self):
        """OpenID AuthRequests should be able to set 'anonymous' to true."""
        self.failUnless(self.authreq.message.isOpenID2())
        self.authreq.setAnonymous(True)
        self.authreq.setAnonymous(False)

    def test_userAnonymousIgnoresIdentfier(self):
        self.authreq.setAnonymous(True)
        msg = self.authreq.getMessage(self.realm, self.return_to)
        self.failUnlessAnonymous(msg)

    def test_opAnonymousIgnoresIdentifier(self):
        self.endpoint.is_op_identifier = True
        self.authreq.setAnonymous(True)
        msg = self.authreq.getMessage(self.realm, self.return_to)
        self.failUnlessAnonymous(msg)

    def test_opIdentifierSendsIdentifierSelect(self):
        self.endpoint.is_op_identifier = True
        msg = self.authreq.getMessage(self.realm, self.return_to)
        self.failUnlessEqual(message.IDENTIFIER_SELECT,
                             msg.getArg(message.OPENID2_NS, 'identity'))

class TestAuthRequestOpenID1(TestAuthRequestBase, unittest.TestCase):
    preferred_namespace = message.OPENID1_NS

    def setUpEndpoint(self):
        TestAuthRequestBase.setUpEndpoint(self)
        self.endpoint.preferred_namespace = message.OPENID1_NS

    def test_setAnonymousFailsForOpenID1(self):
        """OpenID 1 requests MUST NOT be able to set anonymous to True"""
        self.failUnless(self.authreq.message.isOpenID1())
        self.failUnlessRaises(ValueError, self.authreq.setAnonymous, True)
        self.authreq.setAnonymous(False)

    def test_identifierSelect(self):
        """Identfier select SHOULD NOT be sent, but this pathway is in
        here in case some special discovery stuff is done to trigger
        it with OpenID 1. If it is triggered, it will send
        identifier_select just like OpenID 2.
        """
        self.endpoint.is_op_identifier = True
        msg = self.authreq.getMessage(self.realm, self.return_to)
        self.failUnlessEqual(message.IDENTIFIER_SELECT,
                             msg.getArg(message.OPENID1_NS, 'identity'))

if __name__ == '__main__':
    unittest.main()
