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


if __name__ == '__main__':
    unittest.main()
