
from unittest import TestCase

from openid.yadis import xrires


class ProxyQueryTestCase(TestCase):
    def setUp(self):
        self.proxy_url = 'http://xri.example.com/'
        self.proxy = xrires.ProxyResolver(self.proxy_url)
        self.servicetype = 'xri://+i-service*(+forwarding)*($v*1.0)'
        self.servicetype_enc = 'xri%3A%2F%2F%2Bi-service%2A%28%2Bforwarding%29%2A%28%24v%2A1.0%29'

    def test_proxy_url(self):
        st = self.servicetype
        ste = self.servicetype_enc
        args_esc = "_xrd_r=application%2Fxrds%2Bxml&_xrd_t=" + ste
        pqu = self.proxy.queryURL
        h = self.proxy_url
        self.assertEqual(pqu('=foo', st), h + '=foo?' + args_esc)
        self.assertEqual(pqu('=foo/bar?baz', st), h + '=foo/bar?baz&' + args_esc)
        self.assertEqual(pqu('=foo/bar?baz=quux', st), h + '=foo/bar?baz=quux&' + args_esc)
        self.assertEqual(pqu('=foo/bar?mi=fa&so=la', st), h + '=foo/bar?mi=fa&so=la&' + args_esc)

        # With no service endpoint selection.
        args_esc = "_xrd_r=application%2Fxrds%2Bxml%3Bsep%3Dfalse"
        self.assertEqual(pqu('=foo', None), h + '=foo?' + args_esc)

    def test_proxy_url_qmarks(self):
        st = self.servicetype
        ste = self.servicetype_enc
        args_esc = "_xrd_r=application%2Fxrds%2Bxml&_xrd_t=" + ste
        pqu = self.proxy.queryURL
        h = self.proxy_url
        self.assertEqual(pqu('=foo/bar?', st), h + '=foo/bar??' + args_esc)
        self.assertEqual(pqu('=foo/bar???', st), h + '=foo/bar????' + args_esc)
