import unittest

from openid.extensions.draft import pape2 as pape
from openid.message import OPENID2_NS, Message
from openid.server import server


class PapeRequestTestCase(unittest.TestCase):
    def setUp(self):
        self.req = pape.Request()

    def test_construct(self):
        self.assertEqual(self.req.preferred_auth_policies, [])
        self.assertIsNone(self.req.max_auth_age)
        self.assertEqual(self.req.ns_alias, 'pape')

        req2 = pape.Request([pape.AUTH_MULTI_FACTOR], 1000)
        self.assertEqual(req2.preferred_auth_policies, [pape.AUTH_MULTI_FACTOR])
        self.assertEqual(req2.max_auth_age, 1000)

    def test_add_policy_uri(self):
        self.assertEqual(self.req.preferred_auth_policies, [])
        self.req.addPolicyURI(pape.AUTH_MULTI_FACTOR)
        self.assertEqual(self.req.preferred_auth_policies, [pape.AUTH_MULTI_FACTOR])
        self.req.addPolicyURI(pape.AUTH_MULTI_FACTOR)
        self.assertEqual(self.req.preferred_auth_policies, [pape.AUTH_MULTI_FACTOR])
        self.req.addPolicyURI(pape.AUTH_PHISHING_RESISTANT)
        self.assertEqual(self.req.preferred_auth_policies, [pape.AUTH_MULTI_FACTOR, pape.AUTH_PHISHING_RESISTANT])
        self.req.addPolicyURI(pape.AUTH_MULTI_FACTOR)
        self.assertEqual(self.req.preferred_auth_policies, [pape.AUTH_MULTI_FACTOR, pape.AUTH_PHISHING_RESISTANT])

    def test_getExtensionArgs(self):
        self.assertEqual(self.req.getExtensionArgs(), {'preferred_auth_policies': ''})
        self.req.addPolicyURI('http://uri')
        self.assertEqual(self.req.getExtensionArgs(), {'preferred_auth_policies': 'http://uri'})
        self.req.addPolicyURI('http://zig')
        self.assertEqual(self.req.getExtensionArgs(), {'preferred_auth_policies': 'http://uri http://zig'})
        self.req.max_auth_age = 789
        self.assertEqual(self.req.getExtensionArgs(),
                         {'preferred_auth_policies': 'http://uri http://zig', 'max_auth_age': '789'})

    def test_parseExtensionArgs(self):
        args = {'preferred_auth_policies': 'http://foo http://bar',
                'max_auth_age': '9'}
        self.req.parseExtensionArgs(args)
        self.assertEqual(self.req.max_auth_age, 9)
        self.assertEqual(self.req.preferred_auth_policies, ['http://foo', 'http://bar'])

    def test_parseExtensionArgs_empty(self):
        self.req.parseExtensionArgs({})
        self.assertIsNone(self.req.max_auth_age)
        self.assertEqual(self.req.preferred_auth_policies, [])

    def test_fromOpenIDRequest(self):
        openid_req_msg = Message.fromOpenIDArgs({
            'mode': 'checkid_setup',
            'ns': OPENID2_NS,
            'ns.pape': pape.ns_uri,
            'pape.preferred_auth_policies': ' '.join([pape.AUTH_MULTI_FACTOR, pape.AUTH_PHISHING_RESISTANT]),
            'pape.max_auth_age': '5476'
        })
        oid_req = server.OpenIDRequest()
        oid_req.message = openid_req_msg
        req = pape.Request.fromOpenIDRequest(oid_req)
        self.assertEqual(req.preferred_auth_policies, [pape.AUTH_MULTI_FACTOR, pape.AUTH_PHISHING_RESISTANT])
        self.assertEqual(req.max_auth_age, 5476)

    def test_fromOpenIDRequest_no_pape(self):
        message = Message()
        openid_req = server.OpenIDRequest()
        openid_req.message = message
        pape_req = pape.Request.fromOpenIDRequest(openid_req)
        assert(pape_req is None)

    def test_preferred_types(self):
        self.req.addPolicyURI(pape.AUTH_PHISHING_RESISTANT)
        self.req.addPolicyURI(pape.AUTH_MULTI_FACTOR)
        pt = self.req.preferredTypes([pape.AUTH_MULTI_FACTOR,
                                      pape.AUTH_MULTI_FACTOR_PHYSICAL])
        self.assertEqual(pt, [pape.AUTH_MULTI_FACTOR])


class DummySuccessResponse:
    def __init__(self, message, signed_stuff):
        self.message = message
        self.signed_stuff = signed_stuff

    def getSignedNS(self, ns_uri):
        return self.signed_stuff


class PapeResponseTestCase(unittest.TestCase):
    def setUp(self):
        self.req = pape.Response()

    def test_construct(self):
        self.assertEqual(self.req.auth_policies, [])
        self.assertIsNone(self.req.auth_time)
        self.assertEqual(self.req.ns_alias, 'pape')
        self.assertIsNone(self.req.nist_auth_level)

        req2 = pape.Response([pape.AUTH_MULTI_FACTOR], "2004-12-11T10:30:44Z", 3)
        self.assertEqual(req2.auth_policies, [pape.AUTH_MULTI_FACTOR])
        self.assertEqual(req2.auth_time, "2004-12-11T10:30:44Z")
        self.assertEqual(req2.nist_auth_level, 3)

    def test_add_policy_uri(self):
        self.assertEqual(self.req.auth_policies, [])
        self.req.addPolicyURI(pape.AUTH_MULTI_FACTOR)
        self.assertEqual(self.req.auth_policies, [pape.AUTH_MULTI_FACTOR])
        self.req.addPolicyURI(pape.AUTH_MULTI_FACTOR)
        self.assertEqual(self.req.auth_policies, [pape.AUTH_MULTI_FACTOR])
        self.req.addPolicyURI(pape.AUTH_PHISHING_RESISTANT)
        self.assertEqual(self.req.auth_policies, [pape.AUTH_MULTI_FACTOR, pape.AUTH_PHISHING_RESISTANT])
        self.req.addPolicyURI(pape.AUTH_MULTI_FACTOR)
        self.assertEqual(self.req.auth_policies, [pape.AUTH_MULTI_FACTOR, pape.AUTH_PHISHING_RESISTANT])

    def test_getExtensionArgs(self):
        self.assertEqual(self.req.getExtensionArgs(), {'auth_policies': 'none'})
        self.req.addPolicyURI('http://uri')
        self.assertEqual(self.req.getExtensionArgs(), {'auth_policies': 'http://uri'})
        self.req.addPolicyURI('http://zig')
        self.assertEqual(self.req.getExtensionArgs(), {'auth_policies': 'http://uri http://zig'})
        self.req.auth_time = "1776-07-04T14:43:12Z"
        self.assertEqual(self.req.getExtensionArgs(),
                         {'auth_policies': 'http://uri http://zig', 'auth_time': "1776-07-04T14:43:12Z"})
        self.req.nist_auth_level = 3
        nist_data = {'auth_policies': 'http://uri http://zig', 'auth_time': "1776-07-04T14:43:12Z",
                     'nist_auth_level': '3'}
        self.assertEqual(self.req.getExtensionArgs(), nist_data)

    def test_getExtensionArgs_error_auth_age(self):
        self.req.auth_time = "long ago"
        self.assertRaises(ValueError, self.req.getExtensionArgs)

    def test_getExtensionArgs_error_nist_auth_level(self):
        self.req.nist_auth_level = "high as a kite"
        self.assertRaises(ValueError, self.req.getExtensionArgs)
        self.req.nist_auth_level = 5
        self.assertRaises(ValueError, self.req.getExtensionArgs)
        self.req.nist_auth_level = -1
        self.assertRaises(ValueError, self.req.getExtensionArgs)

    def test_parseExtensionArgs(self):
        args = {'auth_policies': 'http://foo http://bar',
                'auth_time': '1970-01-01T00:00:00Z'}
        self.req.parseExtensionArgs(args)
        self.assertEqual(self.req.auth_time, '1970-01-01T00:00:00Z')
        self.assertEqual(self.req.auth_policies, ['http://foo', 'http://bar'])

    def test_parseExtensionArgs_empty(self):
        self.req.parseExtensionArgs({})
        self.assertIsNone(self.req.auth_time)
        self.assertEqual(self.req.auth_policies, [])

    def test_parseExtensionArgs_strict_bogus1(self):
        args = {'auth_policies': 'http://foo http://bar',
                'auth_time': 'yesterday'}
        self.assertRaises(ValueError, self.req.parseExtensionArgs, args, True)

    def test_parseExtensionArgs_strict_bogus2(self):
        args = {'auth_policies': 'http://foo http://bar',
                'auth_time': '1970-01-01T00:00:00Z',
                'nist_auth_level': 'some'}
        self.assertRaises(ValueError, self.req.parseExtensionArgs, args, True)

    def test_parseExtensionArgs_strict_good(self):
        args = {'auth_policies': 'http://foo http://bar',
                'auth_time': '1970-01-01T00:00:00Z',
                'nist_auth_level': '0'}
        self.req.parseExtensionArgs(args, True)
        self.assertEqual(self.req.auth_policies, ['http://foo', 'http://bar'])
        self.assertEqual(self.req.auth_time, '1970-01-01T00:00:00Z')
        self.assertEqual(self.req.nist_auth_level, 0)

    def test_parseExtensionArgs_nostrict_bogus(self):
        args = {'auth_policies': 'http://foo http://bar',
                'auth_time': 'when the cows come home',
                'nist_auth_level': 'some'}
        self.req.parseExtensionArgs(args)
        self.assertEqual(self.req.auth_policies, ['http://foo', 'http://bar'])
        self.assertIsNone(self.req.auth_time)
        self.assertIsNone(self.req.nist_auth_level)

    def test_fromSuccessResponse(self):
        openid_req_msg = Message.fromOpenIDArgs({
            'mode': 'id_res',
            'ns': OPENID2_NS,
            'ns.pape': pape.ns_uri,
            'pape.auth_policies': ' '.join([pape.AUTH_MULTI_FACTOR, pape.AUTH_PHISHING_RESISTANT]),
            'pape.auth_time': '1970-01-01T00:00:00Z'
        })
        signed_stuff = {
            'auth_policies': ' '.join([pape.AUTH_MULTI_FACTOR, pape.AUTH_PHISHING_RESISTANT]),
            'auth_time': '1970-01-01T00:00:00Z'
        }
        oid_req = DummySuccessResponse(openid_req_msg, signed_stuff)
        req = pape.Response.fromSuccessResponse(oid_req)
        self.assertEqual(req.auth_policies, [pape.AUTH_MULTI_FACTOR, pape.AUTH_PHISHING_RESISTANT])
        self.assertEqual(req.auth_time, '1970-01-01T00:00:00Z')

    def test_fromSuccessResponseNoSignedArgs(self):
        openid_req_msg = Message.fromOpenIDArgs({
            'mode': 'id_res',
            'ns': OPENID2_NS,
            'ns.pape': pape.ns_uri,
            'pape.auth_policies': ' '.join([pape.AUTH_MULTI_FACTOR, pape.AUTH_PHISHING_RESISTANT]),
            'pape.auth_time': '1970-01-01T00:00:00Z'
        })

        signed_stuff = {}

        class NoSigningDummyResponse(DummySuccessResponse):
            def getSignedNS(self, ns_uri):
                return None

        oid_req = NoSigningDummyResponse(openid_req_msg, signed_stuff)
        resp = pape.Response.fromSuccessResponse(oid_req)
        self.assertIsNone(resp)
