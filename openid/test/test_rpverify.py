"""Unit tests for verification of return_to URLs for a realm
"""

__all__ = ['TestBuildDiscoveryURL']

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

if __name__ == '__main__':
    unittest.main()
