
import unittest
from support import CatchLogs

from openid.message import Message, OPENID2_NS, OPENID1_NS, OPENID_NS
from openid import association
from openid.consumer.consumer import GenericConsumer, ServerError
from openid.consumer.discover import OpenIDServiceEndpoint

class ErrorRaisingConsumer(GenericConsumer):
    return_messages = []

    def _requestAssociation(self, endpoint, assoc_type, session_type):
        m = self.return_messages.pop(0)
        if isinstance(m, Message):
            raise ServerError(m)
        else:
            return m

class TestOpenID2SessionNegotiation(unittest.TestCase, CatchLogs):
    def setUp(self):
        CatchLogs.setUp(self)
        self.consumer = ErrorRaisingConsumer(store=None)

        self.endpoint = OpenIDServiceEndpoint()
        self.endpoint.type_uris = [OPENID2_NS]
        self.endpoint.server_url = 'bogus'

    def testBadResponse(self):
        self.consumer.return_messages = [Message(self.endpoint.preferredNamespace())]
        self.assertEqual(self.consumer._negotiateAssociation(self.endpoint), None)
        self.failUnlessLogMatches('Server error when requesting an association')

    def testEmptyAssocType(self):
        msg = Message(self.endpoint.preferredNamespace())
        msg.setArg(OPENID_NS, 'error', 'Unsupported type')
        msg.setArg(OPENID_NS, 'error_code', 'unsupported-type')
        msg.setArg(OPENID_NS, 'assoc_type', None)
        msg.setArg(OPENID_NS, 'session_type', 'new-session-type')

        self.consumer.return_messages = [msg]
        self.assertEqual(self.consumer._negotiateAssociation(self.endpoint), None)

        self.failUnlessLogMatches('Unsupported association type',
                                  'Server responded with unsupported association ' +
                                  'session but did not supply a fallback.')

    def testEmptySessionType(self):
        msg = Message(self.endpoint.preferredNamespace())
        msg.setArg(OPENID_NS, 'error', 'Unsupported type')
        msg.setArg(OPENID_NS, 'error_code', 'unsupported-type')
        msg.setArg(OPENID_NS, 'assoc_type', 'new-assoc-type')
        msg.setArg(OPENID_NS, 'session_type', None)

        self.consumer.return_messages = [msg]
        self.assertEqual(self.consumer._negotiateAssociation(self.endpoint), None)

        self.failUnlessLogMatches('Unsupported association type',
                                  'Server responded with unsupported association ' +
                                  'session but did not supply a fallback.')

    def testNotAllowed(self):
        allowed_types = [
            ('assoc_bogus', 'session_bogus'),
            ]

        negotiator = association.SessionNegotiator(allowed_types)
        self.consumer.negotiator = negotiator

        msg = Message(self.endpoint.preferredNamespace())
        msg.setArg(OPENID_NS, 'error', 'Unsupported type')
        msg.setArg(OPENID_NS, 'error_code', 'unsupported-type')
        msg.setArg(OPENID_NS, 'assoc_type', 'not-allowed')
        msg.setArg(OPENID_NS, 'session_type', 'not-allowed')

        self.consumer.return_messages = [msg]
        self.assertEqual(self.consumer._negotiateAssociation(self.endpoint), None)

        self.failUnlessLogMatches('Unsupported association type',
                                  'Server sent unsupported session/association type:')

    def testUnsupportedWithRetry(self):
        msg = Message(self.endpoint.preferredNamespace())
        msg.setArg(OPENID_NS, 'error', 'Unsupported type')
        msg.setArg(OPENID_NS, 'error_code', 'unsupported-type')
        msg.setArg(OPENID_NS, 'assoc_type', 'HMAC-SHA1')
        msg.setArg(OPENID_NS, 'session_type', 'DH-SHA1')

        assoc = association.Association(
            'handle', 'secret', 'issued', 10000, 'HMAC-SHA1')

        self.consumer.return_messages = [msg, assoc]
        self.failUnless(self.consumer._negotiateAssociation(self.endpoint) is assoc)

        self.failUnlessLogMatches('Unsupported association type')

    def testUnsupportedWithRetryAndFail(self):
        msg = Message(self.endpoint.preferredNamespace())
        msg.setArg(OPENID_NS, 'error', 'Unsupported type')
        msg.setArg(OPENID_NS, 'error_code', 'unsupported-type')
        msg.setArg(OPENID_NS, 'assoc_type', 'HMAC-SHA1')
        msg.setArg(OPENID_NS, 'session_type', 'DH-SHA1')

        self.consumer.return_messages = [msg,
             Message(self.endpoint.preferredNamespace())]

        self.failUnlessEqual(self.consumer._negotiateAssociation(self.endpoint), None)

        self.failUnlessLogMatches('Unsupported association type',
                                  'Server %s refused' % (self.endpoint.server_url))

    def testValid(self):
        assoc = association.Association(
            'handle', 'secret', 'issued', 10000, 'HMAC-SHA1')

        self.consumer.return_messages = [assoc]
        self.failUnless(self.consumer._negotiateAssociation(self.endpoint) is assoc)
        self.failUnlessLogEmpty()

class TestOpenID1SessionNegotiation(unittest.TestCase, CatchLogs):
    def setUp(self):
        CatchLogs.setUp(self)
        self.consumer = ErrorRaisingConsumer(store=None)

        self.endpoint = OpenIDServiceEndpoint()
        self.endpoint.type_uris = [OPENID1_NS]
        self.endpoint.server_url = 'bogus'

    def testBadResponse(self):
        self.consumer.return_messages = [Message(self.endpoint.preferredNamespace())]
        self.assertEqual(self.consumer._negotiateAssociation(self.endpoint), None)
        self.failUnlessLogMatches('Server error when requesting an association')

    def testEmptyAssocType(self):
        msg = Message(self.endpoint.preferredNamespace())
        msg.setArg(OPENID_NS, 'error', 'Unsupported type')
        msg.setArg(OPENID_NS, 'error_code', 'unsupported-type')
        msg.setArg(OPENID_NS, 'assoc_type', None)
        msg.setArg(OPENID_NS, 'session_type', 'new-session-type')

        self.consumer.return_messages = [msg]
        self.assertEqual(self.consumer._negotiateAssociation(self.endpoint), None)

        self.failUnlessLogMatches('Server error when requesting an association')

    def testEmptySessionType(self):
        msg = Message(self.endpoint.preferredNamespace())
        msg.setArg(OPENID_NS, 'error', 'Unsupported type')
        msg.setArg(OPENID_NS, 'error_code', 'unsupported-type')
        msg.setArg(OPENID_NS, 'assoc_type', 'new-assoc-type')
        msg.setArg(OPENID_NS, 'session_type', None)

        self.consumer.return_messages = [msg]
        self.assertEqual(self.consumer._negotiateAssociation(self.endpoint), None)

        self.failUnlessLogMatches('Server error when requesting an association')

    def testNotAllowed(self):
        allowed_types = [
            ('assoc_bogus', 'session_bogus'),
            ]

        negotiator = association.SessionNegotiator(allowed_types)
        self.consumer.negotiator = negotiator

        msg = Message(self.endpoint.preferredNamespace())
        msg.setArg(OPENID_NS, 'error', 'Unsupported type')
        msg.setArg(OPENID_NS, 'error_code', 'unsupported-type')
        msg.setArg(OPENID_NS, 'assoc_type', 'not-allowed')
        msg.setArg(OPENID_NS, 'session_type', 'not-allowed')

        self.consumer.return_messages = [msg]
        self.assertEqual(self.consumer._negotiateAssociation(self.endpoint), None)

        self.failUnlessLogMatches('Server error when requesting an association')

    def testUnsupportedWithRetry(self):
        msg = Message(self.endpoint.preferredNamespace())
        msg.setArg(OPENID_NS, 'error', 'Unsupported type')
        msg.setArg(OPENID_NS, 'error_code', 'unsupported-type')
        msg.setArg(OPENID_NS, 'assoc_type', 'HMAC-SHA1')
        msg.setArg(OPENID_NS, 'session_type', 'DH-SHA1')

        assoc = association.Association(
            'handle', 'secret', 'issued', 10000, 'HMAC-SHA1')

        self.consumer.return_messages = [msg, assoc]
        self.failUnless(self.consumer._negotiateAssociation(self.endpoint) is None)

        self.failUnlessLogMatches('Server error when requesting an association')

    def testValid(self):
        assoc = association.Association(
            'handle', 'secret', 'issued', 10000, 'HMAC-SHA1')

        self.consumer.return_messages = [assoc]
        self.failUnless(self.consumer._negotiateAssociation(self.endpoint) is assoc)
        self.failUnlessLogEmpty()

if __name__ == '__main__':
    unittest.main()
