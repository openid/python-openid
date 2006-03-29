"""Tests for openid.server.
"""
from openid.server import server
from openid import association, cryptutil, kvform, oidutil
import _memstore
import cgi
import urllib

import unittest

from urlparse import urlparse

# In general, if you edit or add tests here, try to move in the direction
# of testing smaller units.  For testing the external interfaces, we'll be
# developing an implementation-agnostic testing suite.

class CatchLogs(object):
    def setUp(self):
        self.old_logger = oidutil.log
        oidutil.log = self.gotLogMessage
        self.messages = []

    def gotLogMessage(self, message):
        self.messages.append(message)

    def tearDown(self):
        oidutil.log = self.old_logger

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
        request.identity # logged in?
        request.trust_root # trusted?
        if True:
            if sreg_request:
                sreg_response = sreg.sauce({'zip': '97219'})
            response = request.answer(True)
            response += sreg_response
            response = my_signatory.sign(response)
        else:
            response = request.answer(False)
    else:
        # check_auth and associate response logic is implemented by the
        # library, and needs no input from the app ?
        response = my_server.handle(request)

    webresponse = server.encode(response)

class TestDecode(unittest.TestCase):
    def setUp(self):
        self.id_url = "http://decoder.am.unittest/"
        self.rt_url = "http://rp.unittest/foobot/?qux=zam"
        self.tr_url = "http://rp.unittest/"
        self.assoc_handle = "{assoc}{handle}"
        self.decode = server.Decoder().decode

    def test_none(self):
        args = {}
        r = self.decode(args)
        self.failUnlessEqual(r, None)

    def test_irrelevant(self):
        args = {
            'pony': 'spotted',
            'sreg.mutant_power': 'decaffinator',
            }
        r = self.decode(args)
        self.failUnlessEqual(r, None)

    def test_bad(self):
        args = {
            'openid.mode': 'twos-compliment',
            'openid.pants': 'zippered',
            }
        self.failUnlessRaises(server.ProtocolError, self.decode, args)

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
        r = self.decode(args)
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
        r = self.decode(args)
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
        self.failUnlessRaises(server.ProtocolError, self.decode, args)

    def test_checkidSetupNoReturn(self):
        args = {
            'openid.mode': 'checkid_setup',
            'openid.identity': self.id_url,
            'openid.assoc_handle': self.assoc_handle,
            'openid.trust_root': self.tr_url,
            }
        self.failUnlessRaises(server.ProtocolError, self.decode, args)

    def test_checkAuth(self):
        args = {
            'openid.mode': 'check_authentication',
            'openid.assoc_handle': '{dumb}{handle}',
            'openid.sig': 'sigblob',
            'openid.signed': 'foo,bar,mode',
            'openid.foo': 'signedval1',
            'openid.bar': 'signedval2',
            'openid.baz': 'unsigned',
            }
        r = self.decode(args)
        self.failUnless(isinstance(r, server.CheckAuthRequest))
        self.failUnlessEqual(r.mode, 'check_authentication')
        self.failUnlessEqual(r.sig, 'sigblob')
        self.failUnlessEqual(r.signed, [
            ('foo', 'signedval1'),
            ('bar', 'signedval2'),
            ('mode', 'id_res'),
            ])
        # XXX: and invalidate_handle, which is optional
        # XXX: test error cases (missing required fields,
        # missing fields that are in the signed list).

    def test_associateDH(self):
        args = {
            'openid.mode': 'associate',
            'openid.session_type': 'DH-SHA1',
            'openid.dh_consumer_public': "Rzup9265tw==",
            }
        r = self.decode(args)
        self.failUnless(isinstance(r, server.AssociateRequest))
        self.failUnlessEqual(r.mode, "associate")
        self.failUnlessEqual(r.session_type, "DH-SHA1")
        self.failUnlessEqual(r.assoc_type, "HMAC-SHA1")
        self.failUnless(r.pubkey)

    def test_associateDHMissingKey(self):
        """Trying DH assoc w/o public key"""
        args = {
            'openid.mode': 'associate',
            'openid.session_type': 'DH-SHA1',
            }
        # Using DH-SHA1 without supplying dh_consumer_public is an error.
        self.failUnlessRaises(server.ProtocolError, self.decode, args)

    def test_associatePlain(self):
        args = {
            'openid.mode': 'associate',
            }
        r = self.decode(args)
        self.failUnless(isinstance(r, server.AssociateRequest))
        self.failUnlessEqual(r.mode, "associate")
        self.failUnlessEqual(r.session_type, "plaintext")
        self.failUnlessEqual(r.assoc_type, "HMAC-SHA1")

    def test_nomode(self):
        args = {
            'openid.session_type': 'DH-SHA1',
            'openid.dh_consumer_public': "my public keeey",
            }
        self.failUnlessRaises(server.ProtocolError, self.decode, args)

class TestEncode(unittest.TestCase):
    def setUp(self):
        self.encoder = server.Encoder()
        self.encode = self.encoder.encode

    def test_id_res(self):
        request = server.CheckIDRequest(
            identity = 'http://bombom.unittest/',
            trust_root = 'http://burr.unittest/',
            return_to = 'http://burr.unittest/999',
            immediate = False,
            )
        response = server.CheckIDResponse(request)
        response.fields = {
            'openid.mode': 'id_res',
            'openid.identity': request.identity,
            'openid.return_to': request.return_to,
            }
        webresponse = self.encode(response)
        self.failUnlessEqual(webresponse.code, server.HTTP_REDIRECT)
        self.failUnless(webresponse.headers.has_key('location'))

        location = webresponse.headers['location']
        self.failUnless(location.startswith(request.return_to),
                        "%s does not start with %s" % (location,
                                                       request.return_to))
        query = cgi.parse_qs(urlparse(location)[4])
        # argh.
        q2 = dict([(k, v[0]) for k, v in query.iteritems()])
        self.failUnlessEqual(q2, response.fields)

    def test_cancel(self):
        request = server.CheckIDRequest(
            identity = 'http://bombom.unittest/',
            trust_root = 'http://burr.unittest/',
            return_to = 'http://burr.unittest/999',
            immediate = False,
            )
        response = server.CheckIDResponse(request)
        response.fields = {
            'openid.mode': 'cancel',
            }
        webresponse = self.encode(response)
        self.failUnlessEqual(webresponse.code, server.HTTP_REDIRECT)
        self.failUnless(webresponse.headers.has_key('location'))

    def test_assocReply(self):
        request = server.AssociateRequest()
        response = server.OpenIDResponse(request)
        response.fields = {'assoc_handle': "every-zig"}
        webresponse = self.encode(response)
        body = """assoc_handle:every-zig
"""
        self.failUnlessEqual(webresponse.code, server.HTTP_OK)
        self.failUnlessEqual(webresponse.headers, {})
        self.failUnlessEqual(webresponse.body, body)

    def test_checkauthReply(self):
        request = server.CheckAuthRequest('a_sock_monkey',
                                          'siggggg',
                                          [])
        response = server.OpenIDResponse(request)
        response.fields = {
            'is_valid': 'true',
            'invalidate_handle': 'xXxX:xXXx'
            }
        body = """invalidate_handle:xXxX:xXXx
is_valid:true
"""
        webresponse = self.encode(response)
        self.failUnlessEqual(webresponse.code, server.HTTP_OK)
        self.failUnlessEqual(webresponse.headers, {})
        self.failUnlessEqual(webresponse.body, body)

class TestSigningEncode(unittest.TestCase):
    def setUp(self):
        self.dumb_key = server.Signatory.dumb_key
        self.normal_key = server.Signatory.normal_key
        self.store = _memstore.MemoryStore()
        self.request = server.CheckIDRequest(
            identity = 'http://bombom.unittest/',
            trust_root = 'http://burr.unittest/',
            return_to = 'http://burr.unittest/999',
            immediate = False,
            )
        self.response = server.CheckIDResponse(self.request)
        self.response.fields = {
            'openid.mode': 'id_res',
            'openid.identity': self.request.identity,
            'openid.return_to': self.request.return_to,
            }
        self.signatory = server.Signatory(self.store)
        self.encoder = server.SigningEncoder(self.signatory)
        self.encode = self.encoder.encode

    def test_idres(self):
        assoc_handle = '{bicycle}{shed}'
        self.store.storeAssociation(
            self.normal_key,
            association.Association.fromExpiresIn(60, assoc_handle,
                                                  'sekrit', 'HMAC-SHA1'))
        self.request.assoc_handle = assoc_handle
        webresponse = self.encode(self.response)
        self.failUnlessEqual(webresponse.code, server.HTTP_REDIRECT)
        self.failUnless(webresponse.headers.has_key('location'))

        location = webresponse.headers['location']
        query = cgi.parse_qs(urlparse(location)[4])
        self.failUnless('openid.sig' in query)
        self.failUnless('openid.assoc_handle' in query)
        self.failUnless('openid.signed' in query)

    def test_idresDumb(self):
        webresponse = self.encode(self.response)
        self.failUnlessEqual(webresponse.code, server.HTTP_REDIRECT)
        self.failUnless(webresponse.headers.has_key('location'))

        location = webresponse.headers['location']
        query = cgi.parse_qs(urlparse(location)[4])
        self.failUnless('openid.sig' in query)
        self.failUnless('openid.assoc_handle' in query)
        self.failUnless('openid.signed' in query)

    def test_forgotStore(self):
        self.encoder.signatory = None
        self.failUnlessRaises(ValueError, self.encode, self.response)

    def test_cancel(self):
        request = server.CheckIDRequest(
            identity = 'http://bombom.unittest/',
            trust_root = 'http://burr.unittest/',
            return_to = 'http://burr.unittest/999',
            immediate = False,
            )
        response = server.CheckIDResponse(request, 'cancel')
        webresponse = self.encode(response)
        self.failUnlessEqual(webresponse.code, server.HTTP_REDIRECT)
        self.failUnless(webresponse.headers.has_key('location'))
        location = webresponse.headers['location']
        query = cgi.parse_qs(urlparse(location)[4])
        self.failIf('openid.sig' in query, query.get('openid.sig'))

    def test_assocReply(self):
        request = server.AssociateRequest()
        response = server.OpenIDResponse(request)
        response.fields = {'assoc_handle': "every-zig"}
        webresponse = self.encode(response)
        body = """assoc_handle:every-zig
"""
        self.failUnlessEqual(webresponse.code, server.HTTP_OK)
        self.failUnlessEqual(webresponse.headers, {})
        self.failUnlessEqual(webresponse.body, body)

    def test_alreadySigned(self):
        self.response.fields['openid.sig'] = 'priorSig=='
        self.failUnlessRaises(server.AlreadySigned, self.encode, self.response)


class TestCheckID(unittest.TestCase):
    def setUp(self):
        self.request = server.CheckIDRequest(
            identity = 'http://bambam.unittest/',
            trust_root = 'http://bar.unittest/',
            return_to = 'http://bar.unittest/999',
            immediate = False,
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
        self.request.immediate = True
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
        self.failUnlessEqual(answer.signed, [])

class MockSignatory(object):
    isValid = True

    def __init__(self, assoc):
        self.assocs = [assoc]

    def verify(self, assoc_handle, sig, signed_pairs):
        assert sig
        signed_pairs[:]
        if (True, assoc_handle) in self.assocs:
            return self.isValid
        else:
            return False

    def getAssociation(self, assoc_handle, dumb):
        if (dumb, assoc_handle) in self.assocs:
            # This isn't a valid implementation for many uses of this
            # function, mind you.
            return True
        else:
            return None

    def invalidate(self, assoc_handle, dumb):
        if (dumb, assoc_handle) in self.assocs:
            self.assocs.remove((dumb, assoc_handle))

class TestCheckAuth(unittest.TestCase):
    def setUp(self):
        self.assoc_handle = 'mooooooooo'
        self.request = server.CheckAuthRequest(
            self.assoc_handle, 'signarture',
            [('one', 'alpha'), ('two', 'beta')])

        self.signatory = MockSignatory((True, self.assoc_handle))

    def test_valid(self):
        r = self.request.answer(self.signatory)
        self.failUnlessEqual(r.fields, {'is_valid': 'true'})
        self.failUnlessEqual(r.request, self.request)

    def test_invalid(self):
        self.signatory.isValid = False
        r = self.request.answer(self.signatory)
        self.failUnlessEqual(r.fields, {'is_valid': 'false'})

    def test_replay(self):
        r = self.request.answer(self.signatory)
        r = self.request.answer(self.signatory)
        self.failUnlessEqual(r.fields, {'is_valid': 'false'})

    def test_invalidatehandle(self):
        self.request.invalidate_handle = "bogusHandle"
        r = self.request.answer(self.signatory)
        self.failUnlessEqual(r.fields, {'is_valid': 'true',
                                        'invalidate_handle': "bogusHandle"})
        self.failUnlessEqual(r.request, self.request)

    def test_invalidatehandleNo(self):
        assoc_handle = 'goodhandle'
        self.signatory.assocs.append((False, 'goodhandle'))
        self.request.invalidate_handle = assoc_handle
        r = self.request.answer(self.signatory)
        self.failUnlessEqual(r.fields, {'is_valid': 'true'})


class TestAssociate(unittest.TestCase):
    def setUp(self):
        self.request = server.AssociateRequest()
        self.store = _memstore.MemoryStore()
        self.signatory = server.Signatory(self.store)
        self.assoc = self.signatory.createAssociation(dumb=False)

    def test_dh(self):
        self.request.session_type = 'DH-SHA1'
        self.request.pubkey = 42 # 'FIXME-99'
        response = self.request.answer(self.assoc)
        rfg = response.fields.get
        self.failUnlessEqual(rfg("assoc_type"), "HMAC-SHA1")
        self.failUnlessEqual(rfg("assoc_handle"), self.assoc.handle)
        self.failIf(rfg("mac_key"))
        self.failUnlessEqual(rfg("session_type"), "DH-SHA1")
        self.failUnless(rfg("enc_mac_key")) # , "FIXME-abc")
        self.failUnless(rfg("dh_server_public")) #, "FIXME-def")

    def test_plaintext(self):
        response = self.request.answer(self.assoc)
        rfg = response.fields.get

        self.failUnlessEqual(rfg("assoc_type"), "HMAC-SHA1")
        self.failUnlessEqual(rfg("assoc_handle"), self.assoc.handle)

        self.failUnlessEqual(
            rfg("expires_in"), "%d" % (self.signatory.SECRET_LIFETIME,))
        self.failUnlessEqual(
            rfg("mac_key"), oidutil.toBase64(self.assoc.secret))
        self.failIf(rfg("session_type"))
        self.failIf(rfg("enc_mac_key"))
        self.failIf(rfg("dh_server_public"))

class Counter(object):
    def __init__(self):
        self.count = 0

    def inc(self):
        self.count += 1

class TestServer(unittest.TestCase, CatchLogs):
    def setUp(self):
        self.store = _memstore.MemoryStore()
        self.server = server.OpenIDServer2(self.store)
        CatchLogs.setUp(self)

    def test_dispatch(self):
        monkeycalled = Counter()
        def monkeyDo(request):
            monkeycalled.inc()
            r = server.OpenIDResponse(request)
            return r
        self.server.openid_monkeymode = monkeyDo
        request = server.OpenIDRequest()
        request.mode = "monkeymode"
        webresult = self.server.handleRequest(request)
        self.failUnlessEqual(monkeycalled.count, 1)

    def test_associate(self):
        request = server.AssociateRequest()
        response = self.server.openid_associate(request)
        self.failUnless(response.fields.has_key("assoc_handle"))

    def test_checkAuth(self):
        request = server.CheckAuthRequest('arrrrrf', '0x3999', [])
        response = self.server.openid_check_authentication(request)
        self.failUnless(response.fields.has_key("is_valid"))

class TestSignatory(unittest.TestCase, CatchLogs):
    def setUp(self):
        self.store = _memstore.MemoryStore()
        self.signatory = server.Signatory(self.store)
        self.dumb_key = self.signatory.dumb_key
        self.normal_key = self.signatory.normal_key
        CatchLogs.setUp(self)

    def test_sign(self):
        request = server.OpenIDRequest()
        assoc_handle = '{assoc}{lookatme}'
        self.store.storeAssociation(
            self.normal_key,
            association.Association.fromExpiresIn(60, assoc_handle,
                                                  'sekrit', 'HMAC-SHA1'))
        request.assoc_handle = assoc_handle
        response = server.CheckIDResponse(request)
        response.fields = {
            'openid.foo': 'amsigned',
            'openid.bar': 'notsigned',
            'openid.azu': 'alsosigned',
            }
        response.signed = ['foo', 'azu']
        sresponse = self.signatory.sign(response)
        self.failUnlessEqual(sresponse.fields.get('openid.assoc_handle'),
                             assoc_handle)
        self.failUnlessEqual(sresponse.fields.get('openid.signed'),
                             'foo,azu')
        self.failUnless(sresponse.fields.get('openid.sig'))
        self.failIf(self.messages, self.messages)

    def test_signDumb(self):
        request = server.OpenIDRequest()
        request.assoc_handle = assoc_handle
        response = server.CheckIDResponse(request)
        response.fields = {
            'openid.foo': 'amsigned',
            'openid.bar': 'notsigned',
            'openid.azu': 'alsosigned',
            }
        response.signed = ['foo', 'azu']
        sresponse = self.signatory.sign(response)
        assoc_handle = sresponse.fields.get('openid.assoc_handle')
        self.failUnless(assoc_handle)
        assoc = self.signatory.getAssociation(assoc_handle, dumb=True)
        self.failUnless(assoc)
        self.failUnlessEqual(sresponse.fields.get('openid.signed'),
                             'foo,azu')
        self.failUnless(sresponse.fields.get('openid.sig'))
        self.failIf(self.messages, self.messages)

    def test_signExpired(self):
        request = server.OpenIDRequest()
        assoc_handle = '{assoc}{lookatme}'
        self.store.storeAssociation(
            self.normal_key,
            association.Association.fromExpiresIn(-10, assoc_handle,
                                                  'sekrit', 'HMAC-SHA1'))
        self.failUnless(self.store.getAssociation(self.normal_key, assoc_handle))

        request.assoc_handle = assoc_handle
        response = server.CheckIDResponse(request)
        response.fields = {
            'openid.foo': 'amsigned',
            'openid.bar': 'notsigned',
            'openid.azu': 'alsosigned',
            }
        response.signed = ['foo', 'azu']
        sresponse = self.signatory.sign(response)

        new_assoc_handle = sresponse.fields.get('openid.assoc_handle')
        self.failUnless(new_assoc_handle)
        self.failIfEqual(new_assoc_handle, assoc_handle)

        self.failUnlessEqual(sresponse.fields.get('openid.invalidate_handle'),
                             assoc_handle)

        self.failUnlessEqual(sresponse.fields.get('openid.signed'),
                             'foo,azu')
        self.failUnless(sresponse.fields.get('openid.sig'))

        # make sure the expired association is gone
        self.failIf(self.store.getAssociation(self.normal_key, assoc_handle))

        # make sure the new key is a dumb mode association
        self.failUnless(self.store.getAssociation(self.dumb_key, new_assoc_handle))
        self.failIf(self.store.getAssociation(self.normal_key, new_assoc_handle))
        self.failUnless(self.messages)

    def test_signInvalidHandle(self):
        request = server.OpenIDRequest()
        assoc_handle = '{bogus-assoc}{notvalid}'

        request.assoc_handle = assoc_handle
        response = server.CheckIDResponse(request)
        response.fields = {
            'openid.foo': 'amsigned',
            'openid.bar': 'notsigned',
            'openid.azu': 'alsosigned',
            }
        response.signed = ['foo', 'azu']
        sresponse = self.signatory.sign(response)

        new_assoc_handle = sresponse.fields.get('openid.assoc_handle')
        self.failUnless(new_assoc_handle)
        self.failIfEqual(new_assoc_handle, assoc_handle)

        self.failUnlessEqual(sresponse.fields.get('openid.invalidate_handle'),
                             assoc_handle)

        self.failUnlessEqual(sresponse.fields.get('openid.signed'),
                             'foo,azu')
        self.failUnless(sresponse.fields.get('openid.sig'))

        # make sure the new key is a dumb mode association
        self.failUnless(self.store.getAssociation(self.dumb_key, new_assoc_handle))
        self.failIf(self.store.getAssociation(self.normal_key, new_assoc_handle))
        self.failIf(self.messages, self.messages)

    def test_signDumb(self):
        request = server.OpenIDRequest()
        request.assoc_handle = None
        response = server.CheckIDResponse(request)
        response.fields = {
            'openid.foo': 'amsigned',
            'openid.bar': 'notsigned',
            'openid.azu': 'alsosigned',
            }
        response.signed = ['foo', 'azu']
        sresponse = self.signatory.sign(response)
        self.failUnlessEqual(sresponse.fields.get('openid.signed'),
                             'foo,azu')
        self.failUnless(sresponse.fields.get('openid.assoc_handle'))
        self.failUnless(sresponse.fields.get('openid.sig'))
        # Not actually testing the signature integrity on the assumption
        # that Association.signDict has its own tests.
        # XXX: BAD ASSUMPTION!
        self.failIf(self.messages, self.messages)

    def test_verify(self):
        assoc_handle = '{vroom}{zoom}'
        assoc = association.Association.fromExpiresIn(60, assoc_handle,
                                                      'sekrit', 'HMAC-SHA1')

        self.store.storeAssociation(self.dumb_key, assoc)

        signed_pairs = [('foo', 'bar'),
                        ('apple', 'orange')]

        sig = "Ylu0KcIR7PvNegB/K41KpnRgJl0="
        verified = self.signatory.verify(assoc_handle, sig, signed_pairs)
        self.failUnless(verified)
        self.failIf(self.messages, self.messages)

    def test_verifyBadSig(self):
        assoc_handle = '{vroom}{zoom}'
        assoc = association.Association.fromExpiresIn(60, assoc_handle,
                                                      'sekrit', 'HMAC-SHA1')

        self.store.storeAssociation(self.dumb_key, assoc)

        signed_pairs = [('foo', 'bar'),
                        ('apple', 'orange')]

        sig = "Ylu0KcIR7PvNegB/K41KpnRgJl0=".encode('rot13')
        verified = self.signatory.verify(assoc_handle, sig, signed_pairs)
        self.failIf(verified)
        self.failIf(self.messages, self.messages)

    def test_verifyBadHandle(self):
        assoc_handle = '{vroom}{zoom}'
        signed_pairs = [('foo', 'bar'),
                        ('apple', 'orange')]

        sig = "Ylu0KcIR7PvNegB/K41KpnRgJl0="
        verified = self.signatory.verify(assoc_handle, sig, signed_pairs)
        self.failIf(verified)
        self.failUnless(self.messages)

    def test_getAssoc(self):
        assoc_handle = self.makeAssoc(dumb=True)
        assoc = self.signatory.getAssociation(assoc_handle, True)
        self.failUnless(assoc)
        self.failUnlessEqual(assoc.handle, assoc_handle)
        self.failIf(self.messages, self.messages)

    def test_getAssocExpired(self):
        assoc_handle = self.makeAssoc(dumb=True, lifetime=-10)
        assoc = self.signatory.getAssociation(assoc_handle, True)
        self.failIf(assoc, assoc)
        self.failUnless(self.messages)

    def test_getAssocInvalid(self):
        ah = 'no-such-handle'
        self.failUnlessEqual(
            self.signatory.getAssociation(ah, dumb=False), None)
        self.failIf(self.messages, self.messages)

    def test_getAssocDumbVsNormal(self):
        assoc_handle = self.makeAssoc(dumb=True)
        self.failUnlessEqual(
            self.signatory.getAssociation(assoc_handle, dumb=False), None)
        self.failIf(self.messages, self.messages)

    def test_createAssociation(self):
        assoc = self.signatory.createAssociation(dumb=False)
        self.failUnless(self.signatory.getAssociation(assoc.handle, dumb=False))
        self.failIf(self.messages, self.messages)

    def makeAssoc(self, dumb, lifetime=60):
        assoc_handle = '{bling}'
        assoc = association.Association.fromExpiresIn(lifetime, assoc_handle,
                                                      'sekrit', 'HMAC-SHA1')

        self.store.storeAssociation((dumb and self.dumb_key) or self.normal_key, assoc)
        return assoc_handle

    def test_invalidate(self):
        assoc_handle = '-squash-'
        assoc = association.Association.fromExpiresIn(60, assoc_handle,
                                                      'sekrit', 'HMAC-SHA1')

        self.store.storeAssociation(self.dumb_key, assoc)
        assoc = self.signatory.getAssociation(assoc_handle, dumb=True)
        self.failUnless(assoc)
        assoc = self.signatory.getAssociation(assoc_handle, dumb=True)
        self.failUnless(assoc)
        self.signatory.invalidate(assoc_handle, dumb=True)
        assoc = self.signatory.getAssociation(assoc_handle, dumb=True)
        self.failIf(assoc)
        self.failIf(self.messages, self.messages)


if __name__ == '__main__':
    unittest.main()
