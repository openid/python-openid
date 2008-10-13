
from openid.extensions.draft import pape5 as pape
from openid.message import *
from openid.server import server

import unittest

class PapeRequestTestCase(unittest.TestCase):
    def setUp(self):
        self.req = pape.Request()

    def test_construct(self):
        self.failUnlessEqual([], self.req.preferred_auth_policies)
        self.failUnlessEqual(None, self.req.max_auth_age)
        self.failUnlessEqual('pape', self.req.ns_alias)
        self.failIf(self.req.auth_levels)

        bogus_levels = ['http://janrain.com/our_levels']
        req2 = pape.Request(
            [pape.AUTH_MULTI_FACTOR], 1000, bogus_levels)
        self.failUnlessEqual([pape.AUTH_MULTI_FACTOR],
                             req2.preferred_auth_policies)
        self.failUnlessEqual(1000, req2.max_auth_age)
        self.failUnlessEqual(bogus_levels, req2.auth_levels)

    def test_addAuthLevel(self):
        self.req.addAuthLevel('http://example.com/', 'example')
        self.failUnlessEqual(['http://example.com/'], self.req.auth_levels)
        self.failUnlessEqual('http://example.com/',
                             self.req.auth_level_aliases['example'])

        self.req.addAuthLevel('http://example.com/1', 'example1')
        self.failUnlessEqual(['http://example.com/', 'http://example.com/1'],
                             self.req.auth_levels)

        self.req.addAuthLevel('http://example.com/', 'exmpl')
        self.failUnlessEqual(['http://example.com/', 'http://example.com/1'],
                             self.req.auth_levels)

        self.req.addAuthLevel('http://example.com/', 'example')
        self.failUnlessEqual(['http://example.com/', 'http://example.com/1'],
                             self.req.auth_levels)

        self.failUnlessRaises(KeyError,
                              self.req.addAuthLevel,
                              'http://example.com/2', 'example')

        # alias is None; we expect a new one to be generated.
        uri = 'http://another.example.com/'
        self.req.addAuthLevel(uri)
        self.assertTrue(uri in self.req.auth_level_aliases.values())

        # We don't expect a new alias to be generated if one already
        # exists.
        before_aliases = self.req.auth_level_aliases.keys()
        self.req.addAuthLevel(uri)
        after_aliases = self.req.auth_level_aliases.keys()
        self.assertEqual(before_aliases, after_aliases)

    def test_add_policy_uri(self):
        self.failUnlessEqual([], self.req.preferred_auth_policies)
        self.req.addPolicyURI(pape.AUTH_MULTI_FACTOR)
        self.failUnlessEqual([pape.AUTH_MULTI_FACTOR],
                             self.req.preferred_auth_policies)
        self.req.addPolicyURI(pape.AUTH_MULTI_FACTOR)
        self.failUnlessEqual([pape.AUTH_MULTI_FACTOR],
                             self.req.preferred_auth_policies)
        self.req.addPolicyURI(pape.AUTH_PHISHING_RESISTANT)
        self.failUnlessEqual([pape.AUTH_MULTI_FACTOR,
                              pape.AUTH_PHISHING_RESISTANT],
                             self.req.preferred_auth_policies)
        self.req.addPolicyURI(pape.AUTH_MULTI_FACTOR)
        self.failUnlessEqual([pape.AUTH_MULTI_FACTOR,
                              pape.AUTH_PHISHING_RESISTANT],
                             self.req.preferred_auth_policies)

    def test_getExtensionArgs(self):
        self.failUnlessEqual({'preferred_auth_policies': ''},
                             self.req.getExtensionArgs())
        self.req.addPolicyURI('http://uri')
        self.failUnlessEqual(
            {'preferred_auth_policies': 'http://uri'},
            self.req.getExtensionArgs())
        self.req.addPolicyURI('http://zig')
        self.failUnlessEqual(
            {'preferred_auth_policies': 'http://uri http://zig'},
            self.req.getExtensionArgs())
        self.req.max_auth_age = 789
        self.failUnlessEqual(
            {'preferred_auth_policies': 'http://uri http://zig',
             'max_auth_age': '789'},
            self.req.getExtensionArgs())

    def test_getExtensionArgsWithAuthLevels(self):
        uri = 'http://example.com/auth_level'
        alias = 'my_level'
        self.req.addAuthLevel(uri, alias)

        uri2 = 'http://example.com/auth_level_2'
        alias2 = 'my_level_2'
        self.req.addAuthLevel(uri2, alias2)

        expected_args = {
            ('auth_level.ns.%s' % alias): uri,
            ('auth_level.ns.%s' % alias2): uri2,
            'preferred_auth_level_types': ' '.join([alias, alias2]),
            'preferred_auth_policies': '',
            }

        self.failUnlessEqual(expected_args, self.req.getExtensionArgs())

    def test_parseExtensionArgs(self):
        args = {'preferred_auth_policies': 'http://foo http://bar',
                'max_auth_age': '9'}
        self.req.parseExtensionArgs(args)
        self.failUnlessEqual(9, self.req.max_auth_age)
        self.failUnlessEqual(['http://foo','http://bar'], self.req.preferred_auth_policies)

    def test_parseExtensionArgs_empty(self):
        self.req.parseExtensionArgs({})
        self.failUnlessEqual(None, self.req.max_auth_age)
        self.failUnlessEqual([], self.req.preferred_auth_policies)

    def test_fromOpenIDRequest(self):
        policy_uris = [pape.AUTH_MULTI_FACTOR, pape.AUTH_PHISHING_RESISTANT]
        openid_req_msg = Message.fromOpenIDArgs({
          'mode': 'checkid_setup',
          'ns': OPENID2_NS,
          'ns.pape': pape.ns_uri,
          'pape.preferred_auth_policies': ' '.join(policy_uris),
          'pape.max_auth_age': '5476'
          })
        oid_req = server.OpenIDRequest()
        oid_req.message = openid_req_msg
        req = pape.Request.fromOpenIDRequest(oid_req)
        self.failUnlessEqual(policy_uris, req.preferred_auth_policies)
        self.failUnlessEqual(5476, req.max_auth_age)

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
        self.failUnlessEqual([pape.AUTH_MULTI_FACTOR], pt)

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
        self.failUnlessEqual([], self.req.auth_policies)
        self.failUnlessEqual(None, self.req.auth_time)
        self.failUnlessEqual('pape', self.req.ns_alias)
        self.failUnlessEqual(None, self.req.nist_auth_level)

        req2 = pape.Response([pape.AUTH_MULTI_FACTOR],
                             "2004-12-11T10:30:44Z", 3)
        self.failUnlessEqual([pape.AUTH_MULTI_FACTOR], req2.auth_policies)
        self.failUnlessEqual("2004-12-11T10:30:44Z", req2.auth_time)
        self.failUnlessEqual(3, req2.nist_auth_level)

    def test_add_policy_uri(self):
        self.failUnlessEqual([], self.req.auth_policies)
        self.req.addPolicyURI(pape.AUTH_MULTI_FACTOR)
        self.failUnlessEqual([pape.AUTH_MULTI_FACTOR], self.req.auth_policies)
        self.req.addPolicyURI(pape.AUTH_MULTI_FACTOR)
        self.failUnlessEqual([pape.AUTH_MULTI_FACTOR], self.req.auth_policies)
        self.req.addPolicyURI(pape.AUTH_PHISHING_RESISTANT)
        self.failUnlessEqual([pape.AUTH_MULTI_FACTOR,
                              pape.AUTH_PHISHING_RESISTANT],
                             self.req.auth_policies)
        self.req.addPolicyURI(pape.AUTH_MULTI_FACTOR)
        self.failUnlessEqual([pape.AUTH_MULTI_FACTOR,
                              pape.AUTH_PHISHING_RESISTANT],
                             self.req.auth_policies)

    def test_getExtensionArgs(self):
        self.failUnlessEqual({'auth_policies': 'none'},
                             self.req.getExtensionArgs())
        self.req.addPolicyURI('http://uri')
        self.failUnlessEqual({'auth_policies': 'http://uri'},
                             self.req.getExtensionArgs())
        self.req.addPolicyURI('http://zig')
        self.failUnlessEqual({'auth_policies': 'http://uri http://zig'},
                             self.req.getExtensionArgs())
        self.req.auth_time = "1776-07-04T14:43:12Z"
        self.failUnlessEqual(
            {'auth_policies': 'http://uri http://zig',
             'auth_time': "1776-07-04T14:43:12Z"},
            self.req.getExtensionArgs())
        self.req.nist_auth_level = 3
        self.failUnlessEqual(
            {'auth_policies': 'http://uri http://zig',
             'auth_time': "1776-07-04T14:43:12Z",
             'nist_auth_level': '3'},
            self.req.getExtensionArgs())

    def test_getExtensionArgs_error_auth_age(self):
        self.req.auth_time = "long ago"
        self.failUnlessRaises(ValueError, self.req.getExtensionArgs)

    def test_getExtensionArgs_error_nist_auth_level(self):
        self.req.nist_auth_level = "high as a kite"
        self.failUnlessRaises(ValueError, self.req.getExtensionArgs)
        self.req.nist_auth_level = 5
        self.failUnlessRaises(ValueError, self.req.getExtensionArgs)
        self.req.nist_auth_level = -1
        self.failUnlessRaises(ValueError, self.req.getExtensionArgs)

    def test_parseExtensionArgs(self):
        args = {'auth_policies': 'http://foo http://bar',
                'auth_time': '1970-01-01T00:00:00Z'}
        self.req.parseExtensionArgs(args)
        self.failUnlessEqual('1970-01-01T00:00:00Z', self.req.auth_time)
        self.failUnlessEqual(['http://foo','http://bar'],
                             self.req.auth_policies)

    def test_parseExtensionArgs_empty(self):
        self.req.parseExtensionArgs({})
        self.failUnlessEqual(None, self.req.auth_time)
        self.failUnlessEqual([], self.req.auth_policies)
      
    def test_parseExtensionArgs_strict_bogus1(self):
        args = {'auth_policies': 'http://foo http://bar',
                'auth_time': 'yesterday'}
        self.failUnlessRaises(ValueError, self.req.parseExtensionArgs,
                              args, True)

    def test_parseExtensionArgs_strict_bogus2(self):
        args = {'auth_policies': 'http://foo http://bar',
                'auth_time': '1970-01-01T00:00:00Z',
                'nist_auth_level': 'some'}
        self.failUnlessRaises(ValueError, self.req.parseExtensionArgs,
                              args, True)
      
    def test_parseExtensionArgs_strict_good(self):
        args = {'auth_policies': 'http://foo http://bar',
                'auth_time': '1970-01-01T00:00:00Z',
                'nist_auth_level': '0'}
        self.req.parseExtensionArgs(args, True)
        self.failUnlessEqual(['http://foo','http://bar'],
                             self.req.auth_policies)
        self.failUnlessEqual('1970-01-01T00:00:00Z', self.req.auth_time)
        self.failUnlessEqual(0, self.req.nist_auth_level)

    def test_parseExtensionArgs_nostrict_bogus(self):
        args = {'auth_policies': 'http://foo http://bar',
                'auth_time': 'when the cows come home',
                'nist_auth_level': 'some'}
        self.req.parseExtensionArgs(args)
        self.failUnlessEqual(['http://foo','http://bar'],
                             self.req.auth_policies)
        self.failUnlessEqual(None, self.req.auth_time)
        self.failUnlessEqual(None, self.req.nist_auth_level)

    def test_fromSuccessResponse(self):
        policy_uris = [pape.AUTH_MULTI_FACTOR, pape.AUTH_PHISHING_RESISTANT]
        openid_req_msg = Message.fromOpenIDArgs({
          'mode': 'id_res',
          'ns': OPENID2_NS,
          'ns.pape': pape.ns_uri,
          'pape.auth_policies': ' '.join(policy_uris),
          'pape.auth_time': '1970-01-01T00:00:00Z'
          })
        signed_stuff = {
          'auth_policies': ' '.join(policy_uris),
          'auth_time': '1970-01-01T00:00:00Z'
        }
        oid_req = DummySuccessResponse(openid_req_msg, signed_stuff)
        req = pape.Response.fromSuccessResponse(oid_req)
        self.failUnlessEqual(policy_uris, req.auth_policies)
        self.failUnlessEqual('1970-01-01T00:00:00Z', req.auth_time)

    def test_fromSuccessResponseNoSignedArgs(self):
        policy_uris = [pape.AUTH_MULTI_FACTOR, pape.AUTH_PHISHING_RESISTANT]
        openid_req_msg = Message.fromOpenIDArgs({
          'mode': 'id_res',
          'ns': OPENID2_NS,
          'ns.pape': pape.ns_uri,
          'pape.auth_policies': ' '.join(policy_uris),
          'pape.auth_time': '1970-01-01T00:00:00Z'
          })

        signed_stuff = {}

        class NoSigningDummyResponse(DummySuccessResponse):
            def getSignedNS(self, ns_uri):
                return None

        oid_req = NoSigningDummyResponse(openid_req_msg, signed_stuff)
        resp = pape.Response.fromSuccessResponse(oid_req)
        self.failUnless(resp is None)

if __name__ == '__main__':
    unittest.main()
