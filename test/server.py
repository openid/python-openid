"""Tests for openid.server.
"""
from openid.server import server
from openid import cryptutil, kvform
import _memstore
import cgi
import urllib

import unittest

# In general, if you edit or add tests here, try to move in the direction
# of testing smaller units.  For testing the external interfaces, we'll be
# developing an implementation-agnostic testing suite.

class ConstReturningApp(server.AppIface):
    def __init__(self, truth, http_method, args,
                 additional_args=None, signed=None):
        self.truth = truth
        self.args = args
        self.http_method = http_method
        if additional_args:
            self.additional_args = additional_args
        else:
            self.additional_args = {}
        self.signed = signed

    def isAuthorized(self, unused, unused_):
        return self.truth

    def additionalFields(self):
        return self.additional_args

    def signedFields(self):
        if self.signed is None:
            return server.AppIface.signedFields(self)
        else:
            return self.signed

class ServerTestCase(unittest.TestCase):
    oidServerClass = server.OpenIDServer
    def setUp(self):
        self.sv_url = 'http://id.server.url/'
        self.id_url = 'http://foo.com/'
        self.rt_url = 'http://return.to/rt'
        self.tr_url = 'http://return.to/'

        self.store = _memstore.MemoryStore()
        self.server = self.oidServerClass(self.sv_url, self.store)


class LLServerTestCase(ServerTestCase):
    oidServerClass = server.LowLevelServer

class TestServerErrors(ServerTestCase):

    def test_getWithReturnTo(self):
        args = {
            'openid.mode': 'monkeydance',
            'openid.identity': self.id_url,
            'openid.return_to': self.rt_url,
            }

        status, info = self.server.getOpenIDResponse(
            ConstReturningApp(False, 'GET', args))
        self.failUnlessEqual(status, server.REDIRECT)
        rt_base, resultArgs = info.split('?', 1)
        resultArgs = cgi.parse_qs(resultArgs)
        ra = resultArgs
        self.failUnlessEqual(rt_base, self.rt_url)
        self.failUnlessEqual(ra['openid.mode'], ['error'])
        self.failUnless(ra['openid.error'])

    def test_getBadArgs(self):
        args = {
            'openid.mode': 'zebradance',
            'openid.identity': self.id_url,
            }

        status, info = self.server.getOpenIDResponse(
            ConstReturningApp(False, 'GET', args))
        self.failUnlessEqual(status, server.LOCAL_ERROR)
        self.failUnless(info)

    def test_getNoArgs(self):
        status, info = self.server.getOpenIDResponse(
            ConstReturningApp(False, 'GET', {}))
        self.failUnlessEqual(status, server.DO_ABOUT)

    def test_post(self):
        args = {
            'openid.mode': 'pandadance',
            'openid.identity': self.id_url,
            }

        status, info = self.server.getOpenIDResponse(
            ConstReturningApp(False, 'POST', args))
        self.failUnlessEqual(status, server.REMOTE_ERROR)
        resultArgs = kvform.kvToDict(info)
        self.failUnless(resultArgs['error'])


class TestLowLevel_Associate(LLServerTestCase):
    def test_associatePlain(self):
        args = {}
        status, info = self.server.associate(args)
        self.failUnlessEqual(status, server.REMOTE_OK)

        resultArgs = kvform.kvToDict(info)
        ra = resultArgs
        self.failUnlessEqual(ra['assoc_type'], 'HMAC-SHA1')
        self.failUnlessEqual(ra.get('session_type', None), None)
        self.failUnless(ra['assoc_handle'])
        self.failUnless(ra['mac_key'])
        self.failUnless(int(ra['expires_in']))

    def test_associateDHdefaults(self):
        from openid.dh import DiffieHellman
        dh = DiffieHellman()
        cpub = cryptutil.longToBase64(dh.public)
        args = {'openid.session_type': 'DH-SHA1',
                'openid.dh_consumer_public': cpub,
                }
        status, info = self.server.associate(args)
        resultArgs = kvform.kvToDict(info)
        self.failUnlessEqual(status, server.REMOTE_OK, resultArgs)

        ra = resultArgs
        self.failUnlessEqual(ra['assoc_type'], 'HMAC-SHA1')
        self.failUnlessEqual(ra['session_type'], 'DH-SHA1')
        self.failUnless(ra['assoc_handle'])
        self.failUnless(ra['dh_server_public'])
        self.failUnlessEqual(ra.get('mac_key', None), None)
        self.failUnless(int(ra['expires_in']))

        enc_key = ra['enc_mac_key'].decode('base64')
        spub = cryptutil.base64ToLong(ra['dh_server_public'])
        secret = dh.xorSecret(spub, enc_key)
        self.failUnless(secret)


    # TODO: test DH with non-default values for modulus and gen.
    # (important to do because we actually had it broken for a while.)

    def test_associateDHnoKey(self):
        args = {'openid.session_type': 'DH-SHA1',
                # Oops, no key.
                }
        status, info = self.server.associate(args)
        self.failUnlessEqual(status, server.REMOTE_ERROR)

        resultArgs = kvform.kvToDict(info)
        ra = resultArgs
        self.failUnless(ra['error'])


# TODO: Test the invalidate_handle cases

class TestLowLevelGetAuthResponse_Dumb(LLServerTestCase):

    def test_insaneReturnTo(self):
        args = {
            'openid.mode': 'checkid_immediate',
            'openid.identity': self.id_url,
            'openid.return_to': 'not a url',
            }

        status, info = self.server.getAuthResponse(False, args)

        self.failUnlessEqual(status, server.LOCAL_ERROR, info)

    def test_checkidImmediateFailure(self):
        args = {
            'openid.mode': 'checkid_immediate',
            'openid.identity': self.id_url,
            'openid.return_to': self.rt_url,
            }

        status, info = self.server.getAuthResponse(
            ConstReturningApp(False, None, args))

        self.failUnlessEqual(status, server.REDIRECT)

        eargs = [
            ('openid.identity', self.id_url),
            ('openid.mode', 'checkid_setup'),
            ('openid.return_to', self.rt_url),
            ]
        setup_url = self.sv_url + '?' + urllib.urlencode(eargs)
        expected_pat = '%s?openid.mode=id_res&openid.user_setup_url=%s'
        expected = expected_pat % (self.rt_url, urllib.quote_plus(setup_url))

        self.failUnlessEqual(info, expected)

    def _test_checkidImmediate(self, additional):
        args = {
            'openid.mode': 'checkid_immediate',
            'openid.identity': self.id_url,
            'openid.return_to': self.rt_url,
            }

        app = ConstReturningApp(True, None, args, additional)

        status, info = self.server.getAuthResponse(app)

        self.failUnlessEqual(status, server.REDIRECT)

        rt_base, resultArgs = info.split('?', 1)
        resultArgs = cgi.parse_qs(resultArgs)
        ra = resultArgs
        self.failUnlessEqual(rt_base, self.rt_url)
        self.failUnlessEqual(ra['openid.mode'], ['id_res'])
        self.failUnlessEqual(ra['openid.identity'], [self.id_url])
        self.failUnlessEqual(ra['openid.return_to'], [self.rt_url])
        signed_fields = ['mode', 'identity', 'return_to']
        if additional:
            signed_fields.extend(additional.keys())
        signed_fields.sort()
        expected_signed = [','.join(signed_fields)]
        self.failUnlessEqual(expected_signed, ra['openid.signed'])

        assoc = self.store.getAssociation(self.server.dumb_key,
                                          ra['openid.assoc_handle'][0])
        self.failUnless(assoc)
        to_sign = [('identity', self.id_url),
                   ('mode', 'id_res'),
                   ('return_to', self.rt_url)]
        if additional:
            to_sign.extend(additional.items())
        to_sign.sort()
        expectSig = assoc.sign(to_sign)
        sig = ra['openid.sig'][0]
        sig = sig.decode('base64')
        self.failUnlessEqual(sig, expectSig)

    def test_checkIdImmediate(self):
        self._test_checkidImmediate(None)

    def test_checkIdImmediateData(self):
        self._test_checkidImmediate({'foo.blah':'bar'})

    def test_checkIdSetup(self):
        args = {
            'openid.mode': 'checkid_setup',
            'openid.identity': self.id_url,
            'openid.return_to': self.rt_url,
            }

        status, info = self.server.getAuthResponse(
            ConstReturningApp(True, None, args))

        self.failUnlessEqual(status, server.REDIRECT)

        rt_base, resultArgs = info.split('?', 1)
        resultArgs = cgi.parse_qs(resultArgs)
        ra = resultArgs
        self.failUnlessEqual(rt_base, self.rt_url)
        self.failUnlessEqual(ra['openid.mode'], ['id_res'])
        self.failUnlessEqual(ra['openid.identity'], [self.id_url])
        self.failUnlessEqual(ra['openid.return_to'], [self.rt_url])
        self.failUnlessEqual(ra['openid.signed'], ['identity,mode,return_to'])

        assoc = self.store.getAssociation(self.server.dumb_key,
                                          ra['openid.assoc_handle'][0])
        self.failUnless(assoc)
        expectSig = assoc.sign([('identity', self.id_url),
                                ('mode', 'id_res'),
                                ('return_to', self.rt_url)])
        sig = ra['openid.sig'][0]
        sig = sig.decode('base64')
        self.failUnlessEqual(sig, expectSig)


    def test_checkIdSetupNeedAuth(self):
        args = {
            'openid.mode': 'checkid_setup',
            'openid.identity': self.id_url,
            'openid.return_to': self.rt_url,
            'openid.trust_root': self.tr_url,
            }

        status, info = self.server.getAuthResponse(
            ConstReturningApp(False, None, args))

        self.failUnlessEqual(status, server.DO_AUTH)
        self.failUnlessEqual(info.getTrustRoot(), self.tr_url)
        self.failUnlessEqual(info.getIdentityURL(), self.id_url)

    def test_checkIdSetupCancel(self):
        args = {
            'openid.mode': 'checkid_setup',
            'openid.identity': self.id_url,
            'openid.return_to': self.rt_url,
            }

        status, info = self.server.getAuthResponse(
            ConstReturningApp(False, None, args))

        self.failUnlessEqual(status, server.DO_AUTH)
        status, info = info.cancel()

        self.failUnlessEqual(status, server.REDIRECT)

        rt_base, resultArgs = info.split('?', 1)
        resultArgs = cgi.parse_qs(resultArgs)
        ra = resultArgs
        self.failUnlessEqual(rt_base, self.rt_url)
        self.failUnlessEqual(ra['openid.mode'], ['cancel'])


class TestLowLevelCheckAuthentication(LLServerTestCase):
    def test_checkAuthentication(self):
        # Perform an initial dumb-mode request to make sure an association
        # exists.
        uncheckedArgs = self.dumbRequest()
        args = {}
        for k, v in uncheckedArgs.iteritems():
            args[k] = v[0]
        args['openid.mode'] = 'check_authentication'

        status, info = self.server.checkAuthentication(args)
        self.failUnlessEqual(status, server.REMOTE_OK)

        resultArgs = kvform.kvToDict(info)
        self.failUnlessEqual(resultArgs['is_valid'], 'true')

    def test_checkAuthenticationPreventReplay(self):
        # Perform an initial dumb-mode request to make sure an association
        # exists.
        uncheckedArgs = self.dumbRequest()
        args = {}
        for k, v in uncheckedArgs.iteritems():
            args[k] = v[0]
        args['openid.mode'] = 'check_authentication'

        status, info = self.server.checkAuthentication(args)
        self.failUnlessEqual(status, server.REMOTE_OK)

        resultArgs = kvform.kvToDict(info)
        self.failUnlessEqual(resultArgs['is_valid'], 'true')

        status, info = self.server.checkAuthentication(args)
        self.failUnlessEqual(status, server.REMOTE_OK)

        resultArgs = kvform.kvToDict(info)
        self.failUnlessEqual(resultArgs['is_valid'], 'false')

    def test_checkAuthenticationFailSig(self):
        # Perform an initial dumb-mode request to make sure an association
        # exists.
        uncheckedArgs = self.dumbRequest()
        args = {}
        for k, v in uncheckedArgs.iteritems():
            args[k] = v[0]
        args['openid.mode'] = 'check_authentication'
        args['openid.sig'] = args['openid.sig'].encode('rot13')

        status, info = self.server.checkAuthentication(args)
        self.failUnlessEqual(status, server.REMOTE_OK)

        resultArgs = kvform.kvToDict(info)
        self.failUnlessEqual(resultArgs['is_valid'], 'false')

    def test_checkAuthenticationFailHandle(self):
        # Perform an initial dumb-mode request to make sure an association
        # exists.
        uncheckedArgs = self.dumbRequest()
        args = {}
        for k, v in uncheckedArgs.iteritems():
            args[k] = v[0]
        args['openid.mode'] = 'check_authentication'
        # Corrupt the assoc_handle.
        args['openid.assoc_handle'] = args['openid.assoc_handle'].encode('hex')

        status, info = self.server.checkAuthentication(args)
        self.failUnlessEqual(status, server.REMOTE_OK)

        resultArgs = kvform.kvToDict(info)
        self.failUnlessEqual(resultArgs['is_valid'], 'false')

    def dumbRequest(self):
        args = {
            'openid.mode': 'checkid_immediate',
            'openid.identity': self.id_url,
            'openid.return_to': self.rt_url,
            }

        status, info = self.server.getAuthResponse(
            ConstReturningApp(True, None, args))

        self.failUnlessEqual(status, server.REDIRECT)

        rt_base, resultArgs = info.split('?', 1)
        resultArgs = cgi.parse_qs(resultArgs)
        return resultArgs

if __name__ == '__main__':
    unittest.main()
