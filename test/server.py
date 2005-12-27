from openid.server import server
from openid import cryptutil, kvform
import _memstore
import cgi
import urlparse
import urllib

import unittest

class TestServer(unittest.TestCase):
    def setUp(self):
        self.sv_url = 'http://id.server.url/'
        self.id_url = 'http://foo.com/'
        self.rt_url = 'http://return.to/'

        self.store = _memstore.MemoryStore()
        self.server = server.OpenIDServer(self.sv_url, self.store)

    def test_dumbCheckidImmediateFailure(self):
        args = {
            'openid.mode': 'checkid_immediate',
            'openid.identity': self.id_url,
            'openid.return_to': self.rt_url,
            }

        fail = lambda i, r: 0
        status, info = self.server.getOpenIDResponse('GET', args, fail)

        self.failUnlessEqual(status, server.REDIRECT)

        expected = self.rt_url + '?openid.mode=id_res&openid.user_setup_url='
        eargs = [
            ('openid.identity', self.id_url),
            ('openid.mode', 'checkid_setup'),
            ('openid.return_to', self.rt_url),
            ]
        expected += urllib.quote_plus(self.sv_url + '?' +
                                      urllib.urlencode(eargs))
        self.failUnlessEqual(info, expected)


class TestLowLevel(unittest.TestCase):
    def setUp(self):
        self.sv_url = 'http://id.server.url/'
        self.id_url = 'http://foo.com/'
        self.rt_url = 'http://return.to/'

        self.store = _memstore.MemoryStore()
        self.server = server.LowLevelServer(self.sv_url, self.store)

    def test_dumbCheckidImmediateFailure(self):
        args = {
            'openid.mode': 'checkid_immediate',
            'openid.identity': self.id_url,
            'openid.return_to': self.rt_url,
            }


        status, info = self.server.getAuthResponse(False, args)

        self.failUnlessEqual(status, server.REDIRECT)

        expected = self.rt_url + '?openid.mode=id_res&openid.user_setup_url='
        eargs = [
            ('openid.identity', self.id_url),
            ('openid.mode', 'checkid_setup'),
            ('openid.return_to', self.rt_url),
            ]
        expected += urllib.quote_plus(self.sv_url + '?' +
                                      urllib.urlencode(eargs))
        self.failUnlessEqual(info, expected)


    def test_dumbCheckidImmediate(self):
        args = {
            'openid.mode': 'checkid_immediate',
            'openid.identity': self.id_url,
            'openid.return_to': self.rt_url,
            }


        status, info = self.server.getAuthResponse(True, args)

        self.failUnlessEqual(status, server.REDIRECT)

        rt_base, resultArgs = info.split('?', 1)
        resultArgs = cgi.parse_qs(resultArgs)
        ra = resultArgs
        self.failUnlessEqual(rt_base, self.rt_url)
        self.failUnlessEqual(ra['openid.mode'], ['id_res'])
        self.failUnlessEqual(ra['openid.identity'], [self.id_url])
        self.failUnlessEqual(ra['openid.return_to'], [self.rt_url])
        self.failUnlessEqual(ra['openid.signed'], ['mode,identity,return_to'])

        assoc = self.store.getAssociation(self.server.dumb_key,
                                          ra['openid.assoc_handle'][0])
        self.failUnless(assoc)
        expectSig = assoc.sign([('mode', 'id_res'),
                                ('identity', self.id_url),
                                ('return_to', self.rt_url)])
        sig = ra['openid.sig'][0]
        sig = sig.decode('base64')
        self.failUnlessEqual(sig, expectSig)

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

    def test_associateDHnoKey(self):
        args = {'openid.session_type': 'DH-SHA1',
                # Oops, no key.
                }
        status, info = self.server.associate(args)
        self.failUnlessEqual(status, server.REMOTE_ERROR)

        resultArgs = kvform.kvToDict(info)
        ra = resultArgs
        self.failUnless(ra['error'])


if __name__ == '__main__':
    unittest.main()
