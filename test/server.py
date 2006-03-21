"""Tests for openid.server.
"""
from openid.server import server
from openid import cryptutil, kvform
import _memstore
import cgi
import urllib

import unittest

from urlparse import urlparse

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

        status, info = self.server.getAuthResponse(
            ConstReturningApp(False, None, args))

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


def exampleBitsUsage(http_method, args):
    request = server.decode(http_method, args)
    if not request:
        if http_method == 'GET':
            do_about()
        else:
            do_kvform_error_thing()
        return
    sreg_request = sreg.decode(http_method, args)
    if request.mode in ["checkid_immediate", "checkid_setup"]:
        request.identity_url # logged in?
        request.trust_root # trusted?
        if True:
            if sreg_request:
                sreg_response = sreg.sauce({'zip': '97219'})
            response = request.answer(True)
            response += sreg_response
        else:
            response = request.answer(False)
    else:
        # check_auth and associate response logic is implemented by the
        # library, and needs no input from the app ?
        response = server.handle(request)

    webresponse = server.encode(response)

class TestDecode(unittest.TestCase):
    def setUp(self):
        self.id_url = "http://decoder.am.unittest/"
        self.rt_url = "http://rp.unittest/foobot/?qux=zam"
        self.tr_url = "http://rp.unittest/"
        self.assoc_handle = "{assoc}{handle}"

    def test_none(self):
        args = {}
        r = server.decode(args)
        self.failUnlessEqual(r, None)

    def test_irrelevant(self):
        args = {
            'pony': 'spotted',
            'sreg.mutant_power': 'decaffinator',
            }
        r = server.decode(args)
        self.failUnlessEqual(r, None)

    def test_bad(self):
        args = {
            'openid.mode': 'twos-compliment',
            'openid.pants': 'zippered',
            }
        self.failUnlessRaises(server.ProtocolError, server.decode, args)

    def test_checkidImmediate(self):
        args = {
            'openid.mode': 'checkid_immediate',
            'openid.identity': self.id_url,
            'openid.assoc_handle': self.assoc_handle,
            'openid.return_to': self.rt_url,
            'openid.trust_root': self.tr_url,
            # should be ignored
            'openid.some.extension': 'junk',
            }
        r = server.decode(args)
        self.failUnless(isinstance(r, server.CheckIDRequest))
        self.failUnlessEqual(r.mode, "checkid_immediate")
        self.failUnlessEqual(r.immediate, True)
        self.failUnlessEqual(r.identity, self.id_url)
        self.failUnlessEqual(r.trust_root, self.tr_url)
        self.failUnlessEqual(r.return_to, self.rt_url)

    def test_checkidSetup(self):
        args = {
            'openid.mode': 'checkid_setup',
            'openid.identity': self.id_url,
            'openid.assoc_handle': self.assoc_handle,
            'openid.return_to': self.rt_url,
            'openid.trust_root': self.tr_url,
            }
        r = server.decode(args)
        self.failUnless(isinstance(r, server.CheckIDRequest))
        self.failUnlessEqual(r.mode, "checkid_setup")
        self.failUnlessEqual(r.immediate, False)
        self.failUnlessEqual(r.identity, self.id_url)
        self.failUnlessEqual(r.trust_root, self.tr_url)
        self.failUnlessEqual(r.return_to, self.rt_url)

    def test_checkidSetupNoIdentity(self):
        args = {
            'openid.mode': 'checkid_setup',
            'openid.assoc_handle': self.assoc_handle,
            'openid.return_to': self.rt_url,
            'openid.trust_root': self.tr_url,
            }
        self.failUnlessRaises(server.ProtocolError, server.decode, args)

    def test_checkidSetupNoReturn(self):
        args = {
            'openid.mode': 'checkid_setup',
            'openid.identity': self.id_url,
            'openid.assoc_handle': self.assoc_handle,
            'openid.trust_root': self.tr_url,
            }
        self.failUnlessRaises(server.ProtocolError, server.decode, args)

    def test_checkAuth(self):
        args = {
            'openid.mode': 'check_authentication',
            'openid.assoc_handle': '{dumb}{handle}',
            'openid.sig': 'sigblob',
            'openid.signed': 'foo,bar',
            'openid.foo': 'signedval1',
            'openid.bar': 'signedval2',
            'openid.baz': 'unsigned',
            }
        r = server.decode(args)
        self.failUnless(isinstance(r, server.CheckAuthRequest))
        self.failUnlessEqual(r.mode, 'check_authentication')
        self.failUnlessEqual(r.sig, 'sigblob')
        self.failUnlessEqual(r.signed, [
            ('foo', 'signedval1'),
            ('bar', 'signedval2'),
            ])
        # XXX: and invalidate_handle, which is optional
        # XXX: test error cases (missing required fields,
        # missing fields that are in the signed list).

    def test_associateDH(self):
        args = {
            'openid.mode': 'associate',
            'openid.session_type': 'DH-SHA1',
            'openid.dh_consumer_public': "my public keeey",
            }
        r = server.decode(args)
        self.failUnless(isinstance(r, server.AssociateRequest))
        self.failUnlessEqual(r.mode, "associate")
        self.failUnlessEqual(r.session_type, "DH-SHA1")
        self.failUnlessEqual(r.assoc_type, "HMAC-SHA1")

    def test_associateDHMissingKey(self):
        """Trying DH assoc w/o public key"""
        args = {
            'openid.mode': 'associate',
            'openid.session_type': 'DH-SHA1',
            }
        # Using DH-SHA1 without supplying dh_consumer_public is an error.
        self.failUnlessRaises(server.ProtocolError, server.decode, args)

    def test_associatePlain(self):
        args = {
            'openid.mode': 'associate',
            }
        r = server.decode(args)
        self.failUnless(isinstance(r, server.AssociateRequest))
        self.failUnlessEqual(r.mode, "associate")
        self.failUnlessEqual(r.session_type, "cleartext")
        self.failUnlessEqual(r.assoc_type, "HMAC-SHA1")

    def test_nomode(self):
        args = {
            'openid.session_type': 'DH-SHA1',
            'openid.dh_consumer_public': "my public keeey",
            }
        self.failUnlessRaises(server.ProtocolError, server.decode, args)

class TestEncode(unittest.TestCase):
    def test_id_res(self):
        request = server.CheckIDRequest(
            mode = 'checkid_setup',
            identity_url = 'http://bombom.unittest/',
            trust_root = 'http://burr.unittest/',
            return_to = 'http://burr.unittest/999',
            )
        response = server.CheckIDResponse(request)
        response.fields = {
            'openid.mode': 'id_res',
            'openid.identity': request.identity,
            'openid.return_to': request.return_to,
            }
        webresponse = server.encode(response)
        self.failUnlessEqual(webresponse.code, server.HTTP_REDIRECT)
        self.failUnless(webresponse.headers.has_key('location'))

        location = webresponse.headers['location']
        self.failUnless(location.startswith(request.return_to),
                        "%s does not start with %s" % (location,
                                                       request.return_to))
        query = cgi.parse_qs(urlparse(location)[4])
        self.failUnlessEqual(query, response.fields)

    def test_cancel(self):
        request = server.CheckIDRequest(
            mode = 'checkid_setup',
            identity_url = 'http://bombom.unittest/',
            trust_root = 'http://burr.unittest/',
            return_to = 'http://burr.unittest/999'
            )
        response = server.CheckIDResponse(request)
        response.fields = {
            'openid.mode': 'cancel',
            }
        webresponse = server.encode(response)
        self.failUnlessEqual(webresponse.code, server.HTTP_REDIRECT)
        self.failUnless(webresponse.headers.has_key('location'))

    def test_assocReply(self):
        raise NotImplementedError

    def test_checkauthReply(self):
        raise NotImplementedError


class TestCheckID(unittest.TestCase):
    def setUp(self):
        self.request = server.CheckIDRequest(
            mode = 'checkid_setup',
            identity_url = 'http://bambam.unittest/',
            trust_root = 'http://bar.unittest/',
            return_to = 'http://bar.unittest/999'
            )

    def test_trustRootInvalid(self):
        self.request.trust_root = "http://foo.unittest/17"
        self.request.return_to = "http://foo.unittest/39"
        self.failIf(self.request.trustRootValid())

    def test_trustRootValid(self):
        self.request.trust_root = "http://foo.unittest/"
        self.request.return_to = "http://foo.unittest/39"
        self.failUnless(self.request.trustRootValid())

    def test_answerToInvalidRoot(self):
        """Attempting to answer to a bad trust root"""
        self.request.trust_root = "http://foo.unittest/17"
        self.request.return_to = "http://foo.unittest/39"
        self.failUnlessRaises(server.UntrustedReturnURL,
                              self.request.answer, True)
        self.failUnless(self.request.answer(False))

    def test_answerAllow(self):
        answer = self.request.answer(True)
        self.failUnlessEqual(answer.request, self.request)
        self.failUnlessEqual(answer.fields, {
            'openid.mode': 'id_res',
            'openid.identity': self.request.identity,
            'openid.return_to': self.request.return_to,
            })
        self.failUnlessEqual(answer.signed, ["mode", "identity", "return_to"])

    def test_answerImmediateDeny(self):
        self.request.mode = 'checkid_immediate'
        self.request.immediate = False
        setup_url = "http://setup-url.unittest/"
        # crappiting setup_url, you dirty my interface with your presence!
        answer = self.request.answer(False, setup_url=setup_url)
        self.failUnlessEqual(answer.request, self.request)
        self.failUnlessEqual(answer.fields, {
            'openid.mode': 'id_res',
            'openid.user_setup_url': setup_url,
            })

    def test_answerSetupDeny(self):
        answer = self.request.answer(False)
        self.failUnlessEqual(answer.fields, {
            'openid.mode': 'cancel',
            })

class Counter(object):
    def __init__(self):
        self.count = 0

    def inc(self):
        self.count += 1

class TestServer(unittest.TestCase):
    def setUp(self):
        self.store = _memstore.MemoryStore()
        self.server = server.OpenIDServer2(self.store)

    def test_dispatch(self):
        monkeycalled = Counter()
        def monkeyDo(self, request):
            monkeycalled.inc()
            r = server.OpenIDResponse(request)
            return r
        self.server.openid_monkeymode = monkeyDo
        request = server.OpenIDRequest()
        request.mode = "monkeycalled"
        webresult = self.server.handle(request)
        self.failUnlessEqual(monkeycalled.count, 1)

    def test_associate(self):
        request = server.AssociateRequest()
        response = self.server.openid_associate(request)

    def test_checkAuth(self):
        request = server.CheckAuthRequest()
        response = self.server.openid_check_authentication(request)

class TestSignatory(unittest.TestCase):
    def setUp(self):
        self.store = _memstore.MemoryStore()
        self.signatory = server.Signatory(self.store)

    def test_sign(self):
        request = server.OpenIDRequest()
        assoc_handle = '{assoc}{lookatme}'
        request.assoc_handle = assoc_handle
        response = server.CheckIDResponse(request)
        response.fields = {
            'foo': 'amsigned',
            'bar': 'notsigned',
            'azu': 'alsosigned',
            }
        response.signed = ['foo', 'azu']
        sresponse = self.signatory.sign(response)
        self.failUnlessEqual(sresponse.fields.get('openid.assoc_handle'),
                             assoc_handle)
        self.failUnlessEqual(sresponse.fields.get('openid.signed'),
                             ['foo', 'azu'])
        self.failUnless(sresponse.fields.get('openid.sig'))

    def test_signDumb(self):
        request = server.OpenIDRequest()
        request.assoc_handle = None
        response = server.CheckIDResponse(request)
        response.fields = {
            'foo': 'amsigned',
            'bar': 'notsigned',
            'azu': 'alsosigned',
            }
        response.signed = ['foo', 'azu']
        sresponse = self.signatory.sign(response)
        self.failUnlessEqual(sresponse.fields.get('openid.signed'),
                             ['foo', 'azu'])
        self.failUnless(sresponse.fields.get('openid.assoc_handle'))
        self.failUnless(sresponse.fields.get('openid.sig'))

    def test_verify(self):
        assoc_handle = sig = signed = "FIXME"
        verified = self.signatory.verify(assoc_handle, sig, signed)
        self.failUnless(verified)

    def test_verifyBad(self):
        assoc_handle = sig = signed = "FIXME"
        verified = self.signatory.verify(assoc_handle, sig, signed)
        self.failIf(verified)

if __name__ == '__main__':
    unittest.main()
