"""Unit tests for verification of return_to URLs for a realm
"""

__all__ = ['TestBuildDiscoveryURL']

from openid.yadis.etxrd import XRDSError
from openid.server import trustroot
import unittest

# Too many methods does not apply to unit test objects
#pylint:disable-msg=R0904
class TestBuildDiscoveryURL(unittest.TestCase):
    """Tests for building the discovery URL from a realm and a
    return_to URL
    """

    def failUnlessDiscoURL(self, realm, return_to,
                                  expected_discovery_url):
        """Build a discovery URL out of the realm and a return_to and
        make sure that it matches the expected discovery URL
        """
        realm_obj = trustroot.TrustRoot.parse(realm)
        actual_discovery_url = realm_obj.buildDiscoveryURL(return_to)
        self.failUnlessEqual(expected_discovery_url, actual_discovery_url)

    def test_trivial(self):
        """There is no wildcard and the realm is the same as the return_to URL
        """
        self.failUnlessDiscoURL('http://example.com/foo',
                                'http://example.com/foo',
                                'http://example.com/foo')

    def test_wildcard(self):
        """There is a wildcard, but there is no difference in the path"""
        self.failUnlessDiscoURL('http://*.example.com/foo',
                                'http://example.com/foo',
                                'http://example.com/foo')

    def test_wildcardSibling(self):
        """There is a wildcard, there is no difference in the path,
        and the domain name on the return_to URL has more subdomains
        in it than segments in the realm"""
        self.failUnlessDiscoURL('http://*.example.com/foo',
                                'http://strong.types.example.com/foo',
                                'http://strong.types.example.com/foo')

    def test_pathDifference(self):
        """There is no wildcard and the return_to URL's path is not
        the same as the realm
        """
        self.failUnlessDiscoURL('http://example.com/foo',
                                'http://example.com/foo/bar',
                                'http://example.com/foo')

    def test_queryAdded(self):
        """There is no a wildcard and the return_to URL has a query is not
        the same as the realm
        """
        self.failUnlessDiscoURL('http://example.com/foo',
                                'http://example.com/foo?x=y',
                                'http://example.com/foo')

    def test_pathDifference_wild(self):
        """There is a wildcard and the return_to URL's path is not
        the same as the realm
        """
        self.failUnlessDiscoURL('http://*.example.com/foo',
                                'http://example.com/foo/bar',
                                'http://example.com/foo')

    def test_queryAdded_wild(self):
        """There is a wildcard and the return_to URL has a query is not
        the same as the realm
        """
        self.failUnlessDiscoURL('http://*.example.com/foo',
                                'http://example.com/foo?x=y',
                                'http://example.com/foo')



class TestExtractReturnToURLs(unittest.TestCase):
    disco_url = 'http://example.com/'

    def failUnlessFileHasReturnURLs(self, filename, expected_return_urls):
        self.failUnlessXRDSHasReturnURLs(file(filename).read(),
                                         expected_return_urls)

    def failUnlessXRDSHasReturnURLs(self, data, expected_return_urls):
        actual_return_urls = list(trustroot.extractReturnToURLs(
            self.disco_url, data))
        self.failUnlessEqual(expected_return_urls, actual_return_urls)

    def failUnlessXRDSError(self, text):
        self.failUnlessRaises(XRDSError, trustroot.extractReturnToURLs, self.disco_url, text)

    def test_empty(self):
        self.failUnlessXRDSError('')

    def test_badXML(self):
        self.failUnlessXRDSError('>')

    def test_noEntries(self):
        self.failUnlessXRDSHasReturnURLs('''\
<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS xmlns:xrds="xri://$xrds"
           xmlns="xri://$xrd*($v*2.0)"
           >
  <XRD>
  </XRD>
</xrds:XRDS>
''', [])

    def test_noReturnToEntries(self):
        self.failUnlessXRDSHasReturnURLs('''\
<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS xmlns:xrds="xri://$xrds"
           xmlns="xri://$xrd*($v*2.0)"
           >
  <XRD>
    <Service priority="10">
      <Type>http://specs.openid.net/auth/2.0/server</Type>
      <URI>http://www.myopenid.com/server</URI>
    </Service>
  </XRD>
</xrds:XRDS>
''', [])

    def test_oneEntry(self):
        self.failUnlessXRDSHasReturnURLs('''\
<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS xmlns:xrds="xri://$xrds"
           xmlns="xri://$xrd*($v*2.0)"
           >
  <XRD>
    <Service>
      <Type>http://specs.openid.net/auth/2.0/return_to</Type>
      <URI>http://rp.example.com/return</URI>
    </Service>
  </XRD>
</xrds:XRDS>
''', ['http://rp.example.com/return'])

    def test_twoEntries(self):
        self.failUnlessXRDSHasReturnURLs('''\
<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS xmlns:xrds="xri://$xrds"
           xmlns="xri://$xrd*($v*2.0)"
           >
  <XRD>
    <Service priority="0">
      <Type>http://specs.openid.net/auth/2.0/return_to</Type>
      <URI>http://rp.example.com/return</URI>
    </Service>
    <Service priority="1">
      <Type>http://specs.openid.net/auth/2.0/return_to</Type>
      <URI>http://other.rp.example.com/return</URI>
    </Service>
  </XRD>
</xrds:XRDS>
''', ['http://rp.example.com/return',
      'http://other.rp.example.com/return'])

    def test_twoEntries_withOther(self):
        self.failUnlessXRDSHasReturnURLs('''\
<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS xmlns:xrds="xri://$xrds"
           xmlns="xri://$xrd*($v*2.0)"
           >
  <XRD>
    <Service priority="0">
      <Type>http://specs.openid.net/auth/2.0/return_to</Type>
      <URI>http://rp.example.com/return</URI>
    </Service>
    <Service priority="1">
      <Type>http://specs.openid.net/auth/2.0/return_to</Type>
      <URI>http://other.rp.example.com/return</URI>
    </Service>
    <Service priority="0">
      <Type>http://example.com/LOLCATS</Type>
      <URI>http://example.com/invisible+uri</URI>
    </Service>
  </XRD>
</xrds:XRDS>
''', ['http://rp.example.com/return',
      'http://other.rp.example.com/return'])



class TestReturnToMatches(unittest.TestCase):
    def test_noEntries(self):
        self.failIf(trustroot.returnToMatches([], 'anything'))

    def test_exactMatch(self):
        r = 'http://example.com/return.to'
        self.failUnless(trustroot.returnToMatches([r], r))

    def test_garbageMatch(self):
        r = 'http://example.com/return.to'
        self.failUnless(trustroot.returnToMatches(
            ['This is not a URL at all. In fact, it has characters, like "<" that are not allowed in URLs',
             r],
            r))

    def test_descendant(self):
        r = 'http://example.com/return.to'
        self.failUnless(trustroot.returnToMatches(
            [r],
            'http://example.com/return.to/user:joe'))

    def test_wildcard(self):
        self.failIf(trustroot.returnToMatches(
            ['http://*.example.com/return.to'],
            'http://example.com/return.to'))

    def test_noMatch(self):
        r = 'http://example.com/return.to'
        self.failIf(trustroot.returnToMatches(
            [r],
            'http://example.com/xss_exploit'))

class TestVerifyReturnTo(unittest.TestCase):
    def test_bogusRealm(self):
        self.failIf(trustroot.verifyReturnTo('', None))

    def test_verifyWithDiscoveryCalled(self):
        sentinel = object()
        realm = 'http://*.example.com/'
        return_to = 'http://www.example.com/foo'
        def vrfy(disco_url, passed_return_to):
            self.failUnlessEqual('http://www.example.com/', disco_url)
            self.failUnlessEqual(return_to, passed_return_to)
            return sentinel

        self.failUnless(
            trustroot.verifyReturnTo(realm, return_to, _vrfy=vrfy) is sentinel)

if __name__ == '__main__':
    unittest.main()