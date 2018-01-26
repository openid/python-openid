import unittest

from openid import message
from openid.consumer import consumer

from .utils import OpenIDTestMixin


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


class AuthRequestTestMixin(OpenIDTestMixin):
    """Mixin for AuthRequest tests for OpenID 1 and 2; DON'T add
    unittest.TestCase as a base class here."""

    preferred_namespace = None
    immediate = False
    expected_mode = 'checkid_setup'

    def setUp(self):
        self.endpoint = DummyEndpoint()
        self.endpoint.local_id = 'http://server.unittest/joe'
        self.endpoint.claimed_id = 'http://joe.vanity.example/'
        self.endpoint.server_url = 'http://server.unittest/'
        self.endpoint.preferred_namespace = self.preferred_namespace
        self.realm = 'http://example/'
        self.return_to = 'http://example/return/'
        self.assoc = DummyAssoc()
        self.authreq = consumer.AuthRequest(self.endpoint, self.assoc)

    def assertAnonymous(self, msg):
        for key in ['claimed_id', 'identity']:
            self.assertOpenIDKeyMissing(msg, key)

    def assertHasRequiredFields(self, msg):
        self.assertEqual(self.authreq.message.getOpenIDNamespace(), self.preferred_namespace)
        self.assertEqual(msg.getOpenIDNamespace(), self.preferred_namespace)

        self.assertOpenIDValueEqual(msg, 'mode',
                                         self.expected_mode)

        # Implement these in subclasses because they depend on
        # protocol differences!
        self.assertHasRealm(msg)
        self.assertIdentifiersPresent(msg)

    # TESTS

    def test_checkNoAssocHandle(self):
        self.authreq.assoc = None
        msg = self.authreq.getMessage(self.realm, self.return_to,
                                      self.immediate)

        self.assertOpenIDKeyMissing(msg, 'assoc_handle')

    def test_checkWithAssocHandle(self):
        msg = self.authreq.getMessage(self.realm, self.return_to,
                                      self.immediate)

        self.assertOpenIDValueEqual(msg, 'assoc_handle',
                                         self.assoc.handle)

    def test_addExtensionArg(self):
        self.authreq.addExtensionArg('bag:', 'color', 'brown')
        self.authreq.addExtensionArg('bag:', 'material', 'paper')
        self.assertIn('bag:', self.authreq.message.namespaces)
        self.assertEqual(self.authreq.message.getArgs('bag:'), {'color': 'brown', 'material': 'paper'})
        msg = self.authreq.getMessage(self.realm, self.return_to,
                                      self.immediate)

        # XXX: this depends on the way that Message assigns
        # namespaces. Really it doesn't care that it has alias "0",
        # but that is tested anyway
        post_args = msg.toPostArgs()
        self.assertEqual(post_args['openid.ext0.color'], 'brown')
        self.assertEqual(post_args['openid.ext0.material'], 'paper')

    def test_standard(self):
        msg = self.authreq.getMessage(self.realm, self.return_to,
                                      self.immediate)

        self.assertIdentifiers(msg, self.endpoint.local_id, self.endpoint.claimed_id)


class TestAuthRequestOpenID2(AuthRequestTestMixin, unittest.TestCase):
    preferred_namespace = message.OPENID2_NS

    def assertHasRealm(self, msg):
        # check presence of proper realm key and absence of the wrong
        # one.
        self.assertOpenIDValueEqual(msg, 'realm', self.realm)
        self.assertOpenIDKeyMissing(msg, 'trust_root')

    def assertIdentifiersPresent(self, msg):
        identity_present = msg.hasKey(message.OPENID_NS, 'identity')
        claimed_present = msg.hasKey(message.OPENID_NS, 'claimed_id')

        self.assertEqual(claimed_present, identity_present)

    def assertIdentifiers(self, msg, op_specific_id, claimed_id):
        self.assertOpenIDValueEqual(msg, 'identity', op_specific_id)
        self.assertOpenIDValueEqual(msg, 'claimed_id', claimed_id)

    # TESTS

    def test_setAnonymousWorksForOpenID2(self):
        """OpenID AuthRequests should be able to set 'anonymous' to true."""
        self.assertTrue(self.authreq.message.isOpenID2())
        self.authreq.setAnonymous(True)
        self.authreq.setAnonymous(False)

    def test_userAnonymousIgnoresIdentfier(self):
        self.authreq.setAnonymous(True)
        msg = self.authreq.getMessage(self.realm, self.return_to,
                                      self.immediate)
        self.assertHasRequiredFields(msg)
        self.assertAnonymous(msg)

    def test_opAnonymousIgnoresIdentifier(self):
        self.endpoint.is_op_identifier = True
        self.authreq.setAnonymous(True)
        msg = self.authreq.getMessage(self.realm, self.return_to,
                                      self.immediate)
        self.assertHasRequiredFields(msg)
        self.assertAnonymous(msg)

    def test_opIdentifierSendsIdentifierSelect(self):
        self.endpoint.is_op_identifier = True
        msg = self.authreq.getMessage(self.realm, self.return_to,
                                      self.immediate)
        self.assertHasRequiredFields(msg)
        self.assertIdentifiers(msg, message.IDENTIFIER_SELECT, message.IDENTIFIER_SELECT)


class TestAuthRequestOpenID1(AuthRequestTestMixin, unittest.TestCase):
    preferred_namespace = message.OPENID1_NS

    def assertIdentifiers(self, msg, op_specific_id, claimed_id):
        """Make sure claimed_is is *absent* in request."""
        self.assertOpenIDValueEqual(msg, 'identity', op_specific_id)
        self.assertOpenIDKeyMissing(msg, 'claimed_id')

    def assertIdentifiersPresent(self, msg):
        self.assertOpenIDKeyMissing(msg, 'claimed_id')
        self.assertTrue(msg.hasKey(message.OPENID_NS, 'identity'))

    def assertHasRealm(self, msg):
        # check presence of proper realm key and absence of the wrong
        # one.
        self.assertOpenIDValueEqual(msg, 'trust_root', self.realm)
        self.assertOpenIDKeyMissing(msg, 'realm')

    # TESTS

    def test_setAnonymousFailsForOpenID1(self):
        """OpenID 1 requests MUST NOT be able to set anonymous to True"""
        self.assertTrue(self.authreq.message.isOpenID1())
        self.assertRaises(ValueError, self.authreq.setAnonymous, True)
        self.authreq.setAnonymous(False)

    def test_identifierSelect(self):
        """Identfier select SHOULD NOT be sent, but this pathway is in
        here in case some special discovery stuff is done to trigger
        it with OpenID 1. If it is triggered, it will send
        identifier_select just like OpenID 2.
        """
        self.endpoint.is_op_identifier = True
        msg = self.authreq.getMessage(self.realm, self.return_to,
                                      self.immediate)
        self.assertHasRequiredFields(msg)
        self.assertEqual(msg.getArg(message.OPENID1_NS, 'identity'), message.IDENTIFIER_SELECT)


class TestAuthRequestOpenID1Immediate(TestAuthRequestOpenID1):
    immediate = True
    expected_mode = 'checkid_immediate'


class TestAuthRequestOpenID2Immediate(TestAuthRequestOpenID2):
    immediate = True
    expected_mode = 'checkid_immediate'


if __name__ == '__main__':
    unittest.main()
