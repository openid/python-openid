from openid.server import server
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


if __name__ == '__main__':
    unittest.main()
