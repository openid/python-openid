"""Tests for consumer handling of association responses

This duplicates some things that are covered by test_consumer, but
this works for now.
"""
from openid import oidutil
from openid.test.test_consumer import CatchLogs
from openid.message import Message, OPENID2_NS, OPENID_NS
from openid.server.server import DiffieHellmanSHA1ServerSession
from openid.consumer.consumer import GenericConsumer, \
     DiffieHellmanSHA1ConsumerSession
from openid.consumer.discover import OpenIDServiceEndpoint, OPENID_1_1_TYPE, OPENID_2_0_TYPE
import _memstore
import unittest

# Some values we can use for convenience (see mkAssocResponse)
association_response_values = {
    'expires_in': 'a time',
    'assoc_handle':'a handle',
    'assoc_type':'a type',
    'session_type':'a session type',
    'ns':OPENID2_NS,
    }

def mkAssocResponse(*keys):
    """Build an association response message that contains the
    specified subset of keys. The values come from
    `association_response_values`.

    This is useful for testing for missing keys and other times that
    we don't care what the values are."""
    args = dict([(key, association_response_values[key]) for key in keys])
    return Message.fromOpenIDArgs(args)

class BaseTestParseAssociationMissingFields(CatchLogs, unittest.TestCase):
    """
    According to 'Association Session Response' subsection 'Common
    Response Parameters', the following fields are required for OpenID
    2.0:

     * ns
     * session_type
     * assoc_handle
     * assoc_type
     * expires_in

    If 'ns' is missing, it will fall back to OpenID 1 checking. In
    OpenID 1, everything except 'session_type' and 'ns' are required.
    """

    def mkTest(keys):
        """Make a test that ensures that an association response that
        is missing required fields will short-circuit return None."""

        def test(self):
            msg = mkAssocResponse(*keys)

            # Store should not be needed
            consumer = GenericConsumer(store=None)

            result = consumer._parseAssociation(msg, None, 'dummy.url')
            self.failUnless(result is None)
            self.failUnlessEqual(len(self.messages), 1)
            self.failUnless(self.messages[0].startswith(
                'Getting association: missing key'))

        return test

    mkTest = staticmethod(mkTest)

class TestParseAssociationMissingFieldsOpenID2(
    BaseTestParseAssociationMissingFields):
    """Test for returning an error upon missing fields in association
    responses for OpenID 2"""
    mkTest = BaseTestParseAssociationMissingFields.mkTest

    test_noFields_openid2 = mkTest(['ns'])

    test_missingExpires_openid2 = mkTest(
        ['assoc_handle', 'assoc_type', 'session_type', 'ns'])

    test_missingHandle_openid2 = mkTest(
        ['expires_in', 'assoc_type', 'session_type', 'ns'])

    test_missingAssocType_openid2 = mkTest(
        ['expires_in', 'assoc_handle', 'session_type', 'ns'])

    test_missingSessionType_openid2 = mkTest(
        ['expires_in', 'assoc_handle', 'assoc_type', 'ns'])

class TestParseAssociationMissingFieldsOpenID1(
    BaseTestParseAssociationMissingFields):
    """Test for returning an error upon missing fields in association
    responses for OpenID 2"""
    mkTest = BaseTestParseAssociationMissingFields.mkTest

    test_noFields_openid1 = mkTest([])

    test_missingExpires_openid1 = mkTest(['assoc_handle', 'assoc_type'])

    test_missingHandle_openid1 = mkTest(['expires_in', 'assoc_type'])

    test_missingAssocType_openid1 = mkTest(['expires_in', 'assoc_handle'])

class DummyAssocationSession(object):
    def __init__(self, session_type, allowed_assoc_types=()):
        self.session_type = session_type
        self.allowed_assoc_types = allowed_assoc_types

class ParseAssociationSessionTypeMismatch(unittest.TestCase):
    def mkTest(requested_session_type, response_session_type, openid1=False):
        def test(self):
            assoc_session = DummyAssocationSession(requested_session_type)
            consumer = GenericConsumer(store=None)
            keys = association_response_values.keys()
            if openid1:
                keys.remove('ns')
            msg = mkAssocResponse(keys)
            msg.setArg(OPENID_NS, 'session_type', response_session_type)
            result = consumer._parseAssociation(
                msg, assoc_session, server_url='dummy.url')
            self.failUnless(result is None)

    test_typeMismatch = mkTest(
        requested_session_type='no-encryption',
        response_session_type='',
        )

    test_typeMismatch = mkTest(
        requested_session_type='DH-SHA1',
        response_session_type='no-encryption',
        )

    test_typeMismatch = mkTest(
        requested_session_type='DH-SHA256',
        response_session_type='no-encryption',
        )

    test_typeMismatch = mkTest(
        requested_session_type='no-encryption',
        response_session_type='DH-SHA1',
        )


class TestOpenID1AssociationResponseSessionType(CatchLogs, unittest.TestCase):
    def mkTest(expected_session_type, session_type_value):
        """Return a test method that will check what session type will
        be used if the OpenID 1 response to an associate call sets the
        'session_type' field to `session_type_value`
        """
        def test(self):
            self._doTest(expected_session_type, session_type_value)
            self.failUnlessEqual(0, len(self.messages))

        return test

    def _doTest(self, expected_session_type, session_type_value):
        # Create a Message with just 'session_type' in it, since
        # that's all this function will use. 'session_type' may be
        # absent if it's set to None.
        args = {}
        if session_type_value is not None:
            args['session_type'] = session_type_value
        message = Message.fromOpenIDArgs(args)
        self.failUnless(message.isOpenID1())

        # Store should not be needed
        consumer = GenericConsumer(store=None)

        actual_session_type = consumer._getOpenID1SessionType(message)
        error_message = ('Returned sesion type parameter %r was expected '
                         'to yield session type %r, but yielded %r' %
                         (session_type_value, expected_session_type,
                          actual_session_type))
        self.failUnlessEqual(
            expected_session_type, actual_session_type, error_message)

    test_none = mkTest(
        session_type_value=None,
        expected_session_type='no-encryption',
        )

    test_empty = mkTest(
        session_type_value='',
        expected_session_type='no-encryption',
        )

    # This one's different because it expects log messages
    def test_explicitNoEncryption(self):
        self._doTest(
            session_type_value='no-encryption',
            expected_session_type='no-encryption',
            )
        self.failUnlessEqual(1, len(self.messages))
        self.failUnless(self.messages[0].startswith(
            'WARNING: OpenID server sent "no-encryption"'))

    test_dhSHA1 = mkTest(
        session_type_value='DH-SHA1',
        expected_session_type='DH-SHA1',
        )

    # DH-SHA256 is not a valid session type for OpenID1, but this
    # function does not test that. This is mostly just to make sure
    # that it will pass-through stuff that is not explicitly handled,
    # so it will get handled the same way as it is handled for OpenID
    # 2
    test_dhSHA256 = mkTest(
        session_type_value='DH-SHA256',
        expected_session_type='DH-SHA256',
        )

class TestAssocTypeInvalidForSession(CatchLogs, unittest.TestCase):
    def _setup(self, assoc_type):
        no_encryption_session = DummyAssocationSession('matching-session-type',
                                                       ['good-assoc-type'])
        msg = mkAssocResponse(*association_response_values.keys())
        msg.setArg(OPENID2_NS, 'session_type', 'matching-session-type')
        msg.setArg(OPENID2_NS, 'assoc_type', assoc_type)

        # Store should not be needed
        consumer = GenericConsumer(store=None)

        result = consumer._parseAssociation(
            msg, no_encryption_session, 'dummy.url')


    def test_badAssocType(self):
        self._setup('unsupported')
        self.failUnlessEqual(1, len(self.messages))
        self.failUnless(self.messages[0].startswith(
            'Unsupported assoc_type for session'))

    def test_badExpiresIn(self):
        self._setup('good-assoc-type')
        self.failUnlessEqual(1, len(self.messages))
        self.failUnless(self.messages[0].startswith(
            'Getting Association: invalid expires_in'))


# XXX: This is what causes most of the imports in this file. It is
# sort of a unit test and sort of a functional test. I'm not terribly
# fond of it.
class TestParseAssociation(unittest.TestCase):
    secret = 'x' * 20

    def setUp(self):
        self.store = _memstore.MemoryStore()
        self.consumer = GenericConsumer(self.store)
        self.endpoint = OpenIDServiceEndpoint()

    def _setUpDH(self):
        sess, args = self.consumer._createAssociateRequest(
            self.endpoint, 'HMAC-SHA1', 'DH-SHA1')

        assert self.endpoint.compatibilityMode() == \
               (args.get('openid.ns') is None), \
               "Endpoint compat mode %r != (openid.ns in args)" % \
               (self.endpoint.compatibilityMode())

        message = Message.fromPostArgs(args)
        server_sess = DiffieHellmanSHA1ServerSession.fromMessage(message)
        server_resp = server_sess.answer(self.secret)
        server_resp['assoc_type'] = 'HMAC-SHA1'
        server_resp['assoc_handle'] = 'handle'
        server_resp['expires_in'] = '1000'
        server_resp['session_type'] = 'DH-SHA1'
        return sess, Message.fromOpenIDArgs(server_resp)

    def test_success(self):
        sess, server_resp = self._setUpDH()
        ret = self.consumer._parseAssociation(server_resp, sess, 'server_url')
        self.failIf(ret is None)
        self.failUnlessEqual(ret.assoc_type, 'HMAC-SHA1')
        self.failUnlessEqual(ret.secret, self.secret)
        self.failUnlessEqual(ret.handle, 'handle')
        self.failUnlessEqual(ret.lifetime, 1000)

    def test_openid2success(self):
        # Use openid 2 type in endpoint so _setUpDH checks
        # compatibility mode state properly
        self.endpoint.type_uris = [OPENID_2_0_TYPE, OPENID_1_1_TYPE]
        self.test_success()

    def test_badAssocType(self):
        sess, server_resp = self._setUpDH()
        server_resp.setArg(OPENID_NS, 'assoc_type', 'Crazy Low Prices!!!')
        ret = self.consumer._parseAssociation(server_resp, sess, 'server_url')
        self.failUnless(ret is None)

    def test_badExpiresIn(self):
        sess, server_resp = self._setUpDH()
        server_resp.setArg(OPENID_NS, 'expires_in', 'Crazy Low Prices!!!')
        ret = self.consumer._parseAssociation(server_resp, sess, 'server_url')
        self.failUnless(ret is None)

    def test_badSessionType(self):
        sess, server_resp = self._setUpDH()
        server_resp.setArg(OPENID_NS, 'session_type', '|/iA6rA')
        ret = self.consumer._parseAssociation(server_resp, sess, 'server_url')
        self.failUnless(ret is None)

    def test_plainFallback(self):
        sess = DiffieHellmanSHA1ConsumerSession()
        server_resp = Message.fromOpenIDArgs({
            'assoc_type': 'HMAC-SHA1',
            'assoc_handle': 'handle',
            'expires_in': '1000',
            'mac_key': oidutil.toBase64(self.secret),
            })
        ret = self.consumer._parseAssociation(server_resp, sess, 'server_url')
        self.failIf(ret is None)
        self.failUnlessEqual(ret.assoc_type, 'HMAC-SHA1')
        self.failUnlessEqual(ret.secret, self.secret)
        self.failUnlessEqual(ret.handle, 'handle')
        self.failUnlessEqual(ret.lifetime, 1000)

    def test_plainFallbackFailure(self):
        sess = DiffieHellmanSHA1ConsumerSession()
        # missing mac_key
        server_resp = Message.fromOpenIDArgs({
            'assoc_type': 'HMAC-SHA1',
            'assoc_handle': 'handle',
            'expires_in': '1000',
            })
        ret = self.consumer._parseAssociation(server_resp, sess, 'server_url')
        self.failUnless(ret is None)

    def test_badDHValues(self):
        sess, server_resp = self._setUpDH()
        server_resp.setArg(OPENID_NS, 'enc_mac_key', '\x00\x00\x00')
        ret = self.consumer._parseAssociation(server_resp, sess, 'server_url')
        self.failUnless(ret is None)
