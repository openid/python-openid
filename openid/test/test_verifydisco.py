import unittest

from testfixtures import LogCapture, StringComparison

from openid import message
from openid.consumer import consumer, discover
from openid.test.test_consumer import TestIdRes


def const(result):
    """Return a function that ignores any arguments and just returns
    the specified result"""
    def constResult(*args, **kwargs):
        return result

    return constResult


class DiscoveryVerificationTest(TestIdRes):

    def test_openID1NoLocalID(self):
        endpoint = discover.OpenIDServiceEndpoint()
        endpoint.claimed_id = 'bogus'

        msg = message.Message.fromOpenIDArgs({})
        with LogCapture() as logbook:
            with self.assertRaisesRegexp(consumer.ProtocolError, 'Missing required field openid.identity'):
                self.consumer._verifyDiscoveryResults(msg, endpoint)
        self.assertEqual(logbook.records, [])

    def test_openID1NoEndpoint(self):
        msg = message.Message.fromOpenIDArgs({'identity': 'snakes on a plane'})
        with LogCapture() as logbook:
            self.assertRaises(RuntimeError, self.consumer._verifyDiscoveryResults, msg)
        self.assertEqual(logbook.records, [])

    def test_openID2NoOPEndpointArg(self):
        msg = message.Message.fromOpenIDArgs({'ns': message.OPENID2_NS})
        with LogCapture() as logbook:
            self.assertRaises(KeyError, self.consumer._verifyDiscoveryResults, msg)
        self.assertEqual(logbook.records, [])

    def test_openID2LocalIDNoClaimed(self):
        msg = message.Message.fromOpenIDArgs({'ns': message.OPENID2_NS,
                                              'op_endpoint': 'Phone Home',
                                              'identity': 'Jose Lius Borges'})
        with LogCapture() as logbook:
            with self.assertRaisesRegexp(consumer.ProtocolError, 'openid.identity is present without'):
                self.consumer._verifyDiscoveryResults(msg)
        self.assertEqual(logbook.records, [])

    def test_openID2NoLocalIDClaimed(self):
        msg = message.Message.fromOpenIDArgs({'ns': message.OPENID2_NS,
                                              'op_endpoint': 'Phone Home',
                                              'claimed_id': 'Manuel Noriega'})
        with LogCapture() as logbook:
            with self.assertRaisesRegexp(consumer.ProtocolError, 'openid.claimed_id is present without'):
                self.consumer._verifyDiscoveryResults(msg)
        self.assertEqual(logbook.records, [])

    def test_openID2NoIdentifiers(self):
        op_endpoint = 'Phone Home'
        msg = message.Message.fromOpenIDArgs({'ns': message.OPENID2_NS,
                                              'op_endpoint': op_endpoint})
        with LogCapture() as logbook:
            result_endpoint = self.consumer._verifyDiscoveryResults(msg)
        self.assertTrue(result_endpoint.isOPIdentifier())
        self.assertEqual(result_endpoint.server_url, op_endpoint)
        self.assertIsNone(result_endpoint.claimed_id)
        self.assertEqual(logbook.records, [])

    def test_openID2NoEndpointDoesDisco(self):
        op_endpoint = 'Phone Home'
        sentinel = discover.OpenIDServiceEndpoint()
        sentinel.claimed_id = 'monkeysoft'
        self.consumer._discoverAndVerify = const(sentinel)
        msg = message.Message.fromOpenIDArgs(
            {'ns': message.OPENID2_NS,
             'identity': 'sour grapes',
             'claimed_id': 'monkeysoft',
             'op_endpoint': op_endpoint})
        with LogCapture() as logbook:
            result = self.consumer._verifyDiscoveryResults(msg)
        self.assertEqual(result, sentinel)
        logbook.check(('openid.consumer.consumer', 'INFO', 'No pre-discovered information supplied.'))

    def test_openID2MismatchedDoesDisco(self):
        mismatched = discover.OpenIDServiceEndpoint()
        mismatched.identity = 'nothing special, but different'
        mismatched.local_id = 'green cheese'

        op_endpoint = 'Phone Home'
        sentinel = discover.OpenIDServiceEndpoint()
        sentinel.claimed_id = 'monkeysoft'
        self.consumer._discoverAndVerify = const(sentinel)
        msg = message.Message.fromOpenIDArgs(
            {'ns': message.OPENID2_NS,
             'identity': 'sour grapes',
             'claimed_id': 'monkeysoft',
             'op_endpoint': op_endpoint})
        with LogCapture() as logbook:
            result = self.consumer._verifyDiscoveryResults(msg, mismatched)
        self.assertEqual(result, sentinel)
        logbook.check(('openid.consumer.consumer', 'ERROR', StringComparison('Error attempting to use .*')),
                      ('openid.consumer.consumer', 'INFO', 'Attempting discovery to verify endpoint'))

    def test_openid2UsePreDiscovered(self):
        endpoint = discover.OpenIDServiceEndpoint()
        endpoint.local_id = 'my identity'
        endpoint.claimed_id = 'i am sam'
        endpoint.server_url = 'Phone Home'
        endpoint.type_uris = [discover.OPENID_2_0_TYPE]

        msg = message.Message.fromOpenIDArgs(
            {'ns': message.OPENID2_NS,
             'identity': endpoint.local_id,
             'claimed_id': endpoint.claimed_id,
             'op_endpoint': endpoint.server_url})
        with LogCapture() as logbook:
            result = self.consumer._verifyDiscoveryResults(msg, endpoint)
        self.assertEqual(result, endpoint)
        self.assertEqual(logbook.records, [])

    def test_openid2UsePreDiscoveredWrongType(self):
        text = "verify failed"

        endpoint = discover.OpenIDServiceEndpoint()
        endpoint.local_id = 'my identity'
        endpoint.claimed_id = 'i am sam'
        endpoint.server_url = 'Phone Home'
        endpoint.type_uris = [discover.OPENID_1_1_TYPE]

        def discoverAndVerify(claimed_id, to_match_endpoints):
            self.assertEqual(claimed_id, endpoint.claimed_id)
            for to_match in to_match_endpoints:
                self.assertEqual(claimed_id, to_match.claimed_id)
            raise consumer.ProtocolError(text)

        self.consumer._discoverAndVerify = discoverAndVerify

        msg = message.Message.fromOpenIDArgs(
            {'ns': message.OPENID2_NS,
             'identity': endpoint.local_id,
             'claimed_id': endpoint.claimed_id,
             'op_endpoint': endpoint.server_url})

        with LogCapture() as logbook:
            with self.assertRaisesRegexp(consumer.ProtocolError, text):
                self.consumer._verifyDiscoveryResults(msg, endpoint)

        logbook.check(('openid.consumer.consumer', 'ERROR', StringComparison('Error attempting to use .*')),
                      ('openid.consumer.consumer', 'INFO', 'Attempting discovery to verify endpoint'))

    def test_openid1UsePreDiscovered(self):
        endpoint = discover.OpenIDServiceEndpoint()
        endpoint.local_id = 'my identity'
        endpoint.claimed_id = 'i am sam'
        endpoint.server_url = 'Phone Home'
        endpoint.type_uris = [discover.OPENID_1_1_TYPE]

        msg = message.Message.fromOpenIDArgs(
            {'ns': message.OPENID1_NS,
             'identity': endpoint.local_id})
        with LogCapture() as logbook:
            result = self.consumer._verifyDiscoveryResults(msg, endpoint)
        self.assertEqual(result, endpoint)
        self.assertEqual(logbook.records, [])

    def test_openid1UsePreDiscoveredWrongType(self):
        class VerifiedError(Exception):
            pass

        def discoverAndVerify(claimed_id, _to_match):
            raise VerifiedError

        self.consumer._discoverAndVerify = discoverAndVerify

        endpoint = discover.OpenIDServiceEndpoint()
        endpoint.local_id = 'my identity'
        endpoint.claimed_id = 'i am sam'
        endpoint.server_url = 'Phone Home'
        endpoint.type_uris = [discover.OPENID_2_0_TYPE]

        msg = message.Message.fromOpenIDArgs(
            {'ns': message.OPENID1_NS,
             'identity': endpoint.local_id})

        with LogCapture() as logbook:
            self.assertRaises(VerifiedError, self.consumer._verifyDiscoveryResults, msg, endpoint)
        logbook.check(('openid.consumer.consumer', 'ERROR', StringComparison('Error attempting to use .*')),
                      ('openid.consumer.consumer', 'INFO', 'Attempting discovery to verify endpoint'))

    def test_openid2Fragment(self):
        claimed_id = "http://unittest.invalid/"
        claimed_id_frag = claimed_id + "#fragment"
        endpoint = discover.OpenIDServiceEndpoint()
        endpoint.local_id = 'my identity'
        endpoint.claimed_id = claimed_id
        endpoint.server_url = 'Phone Home'
        endpoint.type_uris = [discover.OPENID_2_0_TYPE]

        msg = message.Message.fromOpenIDArgs(
            {'ns': message.OPENID2_NS,
             'identity': endpoint.local_id,
             'claimed_id': claimed_id_frag,
             'op_endpoint': endpoint.server_url})
        with LogCapture() as logbook:
            result = self.consumer._verifyDiscoveryResults(msg, endpoint)

        self.assertEqual(result.local_id, endpoint.local_id)
        self.assertEqual(result.server_url, endpoint.server_url)
        self.assertEqual(result.type_uris, endpoint.type_uris)
        self.assertEqual(result.claimed_id, claimed_id_frag)

        self.assertEqual(logbook.records, [])

    def test_openid1Fallback1_0(self):
        claimed_id = 'http://claimed.id/'
        endpoint = None
        resp_mesg = message.Message.fromOpenIDArgs({
            'ns': message.OPENID1_NS,
            'identity': claimed_id})
        # Pass the OpenID 1 claimed_id this way since we're passing
        # None for the endpoint.
        resp_mesg.setArg(message.BARE_NS, 'openid1_claimed_id', claimed_id)

        # We expect the OpenID 1 discovery verification to try
        # matching the discovered endpoint against the 1.1 type and
        # fall back to 1.0.
        expected_endpoint = discover.OpenIDServiceEndpoint()
        expected_endpoint.type_uris = [discover.OPENID_1_0_TYPE]
        expected_endpoint.local_id = None
        expected_endpoint.claimed_id = claimed_id

        discovered_services = [expected_endpoint]
        self.consumer._discover = lambda *args: ('unused', discovered_services)

        actual_endpoint = self.consumer._verifyDiscoveryResults(
            resp_mesg, endpoint)
        self.assertEqual(actual_endpoint, expected_endpoint)

# XXX: test the implementation of _discoverAndVerify


class TestVerifyDiscoverySingle(TestIdRes):
    # XXX: more test the implementation of _verifyDiscoverySingle
    def test_endpointWithoutLocalID(self):
        # An endpoint like this with no local_id is generated as a result of
        # e.g. Yadis discovery with no LocalID tag.
        endpoint = discover.OpenIDServiceEndpoint()
        endpoint.server_url = "http://localhost:8000/openidserver"
        endpoint.claimed_id = "http://localhost:8000/id/id-jo"
        to_match = discover.OpenIDServiceEndpoint()
        to_match.server_url = "http://localhost:8000/openidserver"
        to_match.claimed_id = "http://localhost:8000/id/id-jo"
        to_match.local_id = "http://localhost:8000/id/id-jo"
        with LogCapture() as logbook:
            result = self.consumer._verifyDiscoverySingle(endpoint, to_match)
        # result should always be None, raises exception on failure.
        self.assertIsNone(result)
        self.assertEqual(logbook.records, [])


if __name__ == '__main__':
    unittest.main()
