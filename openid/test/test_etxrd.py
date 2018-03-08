import os.path
import tempfile
import unittest

from lxml import etree

from openid.yadis import etxrd, services, xri


def datapath(filename):
    module_directory = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(module_directory, 'data', 'test_etxrd', filename)


XRD_FILE = datapath('valid-populated-xrds.xml')
NOXRDS_FILE = datapath('not-xrds.xml')
NOXRD_FILE = datapath('no-xrd.xml')

# None of the namespaces or service URIs below are official (or even
# sanctioned by the owners of that piece of URL-space)

LID_2_0 = "http://lid.netmesh.org/sso/2.0b5"
TYPEKEY_1_0 = "http://typekey.com/services/1.0"


def simpleOpenIDTransformer(endpoint):
    """Function to extract information from an OpenID service element"""
    if 'http://openid.net/signon/1.0' not in endpoint.type_uris:
        return None

    delegates = list(endpoint.service_element.findall(
        '{http://openid.net/xmlns/1.0}Delegate'))
    assert len(delegates) == 1
    delegate = delegates[0].text
    return (endpoint.uri, delegate)


class TestParseXRDS(unittest.TestCase):
    """Test `parseXRDS` function."""

    def assertXmlEqual(self, result, expected):
        self.assertEqual(result.tag, expected.tag)
        self.assertEqual(result.text, expected.text)
        self.assertEqual(result.tail, expected.tail)
        self.assertEqual(result.attrib, expected.attrib)
        self.assertEqual(len(result), len(expected))
        for child_r, child_e in zip(result, expected):
            self.assertXmlEqual(child_r, child_e)

    def test_minimal_xrds(self):
        xml = '<xrds:XRDS xmlns:xrds="xri://$xrds" xmlns="xri://$xrd*($v*2.0)"></xrds:XRDS>'
        tree = etxrd.parseXRDS(xml)
        self.assertIsInstance(tree, type(etree.ElementTree()))
        self.assertXmlEqual(tree.getroot(), etree.XML(xml))

    def test_not_xrds(self):
        xml = '<not_xrds />'
        with self.assertRaisesRegexp(etxrd.XRDSError, 'Not an XRDS document'):
            etxrd.parseXRDS(xml)

    def test_invalid_xml(self):
        xml = '<'
        with self.assertRaisesRegexp(etxrd.XRDSError, 'Error parsing document as XML'):
            etxrd.parseXRDS(xml)

    def test_xxe(self):
        xxe_content = 'XXE CONTENT'
        _, tmp_file = tempfile.mkstemp()
        try:
            with open(tmp_file, 'w') as xxe_file:
                xxe_file.write(xxe_content)
            # XXE example from Testing for XML Injection (OTG-INPVAL-008)
            # https://www.owasp.org/index.php/Testing_for_XML_Injection_(OTG-INPVAL-008)
            xml = ('<?xml version="1.0" encoding="ISO-8859-1"?>'
                   '<!DOCTYPE foo ['
                   '<!ELEMENT foo ANY >'
                   '<!ENTITY xxe SYSTEM "file://%s" >]>'
                   '<xrds:XRDS xmlns:xrds="xri://$xrds" xmlns="xri://$xrd*($v*2.0)">&xxe;</xrds:XRDS>')
            tree = etxrd.parseXRDS(xml % tmp_file)
            self.assertNotIn(xxe_content, etree.tostring(tree))
        finally:
            os.remove(tmp_file)


class TestServiceParser(unittest.TestCase):
    def setUp(self):
        self.xmldoc = file(XRD_FILE).read()
        self.yadis_url = 'http://unittest.url/'

    def _getServices(self, flt=None):
        return list(services.applyFilter(self.yadis_url, self.xmldoc, flt))

    def testParse(self):
        """Make sure that parsing succeeds at all"""
        self._getServices()

    def testParseOpenID(self):
        """Parse for OpenID services with a transformer function"""
        services = self._getServices(simpleOpenIDTransformer)

        expectedServices = [
            ("http://www.myopenid.com/server", "http://josh.myopenid.com/"),
            ("http://www.schtuff.com/openid", "http://users.schtuff.com/josh"),
            ("http://www.livejournal.com/openid/server.bml",
             "http://www.livejournal.com/users/nedthealpaca/"),
        ]

        it = iter(services)
        for (server_url, delegate) in expectedServices:
            for (actual_url, actual_delegate) in it:
                self.assertEqual(actual_url, server_url)
                self.assertEqual(actual_delegate, delegate)
                break
            else:
                self.fail('Not enough services found')

    def _checkServices(self, expectedServices):
        """Check to make sure that the expected services are found in
        that order in the parsed document."""
        it = iter(self._getServices())
        for (type_uri, uri) in expectedServices:
            for service in it:
                if type_uri in service.type_uris:
                    self.assertEqual(service.uri, uri)
                    break
            else:
                self.fail('Did not find %r service' % (type_uri,))

    def testGetSeveral(self):
        """Get some services in order"""
        expectedServices = [
            # type, URL
            (TYPEKEY_1_0, None),
            (LID_2_0, "http://mylid.net/josh"),
        ]

        self._checkServices(expectedServices)

    def testGetSeveralForOne(self):
        """Getting services for one Service with several Type elements."""
        types = ['http://lid.netmesh.org/sso/2.0b5', 'http://lid.netmesh.org/2.0b5']
        uri = "http://mylid.net/josh"

        for service in self._getServices():
            if service.uri == uri:
                found_types = service.matchTypes(types)
                if found_types == types:
                    break
        else:
            self.fail('Did not find service with expected types and uris')

    def testNoXRDS(self):
        """Make sure that we get an exception when an XRDS element is
        not present"""
        self.xmldoc = file(NOXRDS_FILE).read()
        self.assertRaises(etxrd.XRDSError, services.applyFilter, self.yadis_url, self.xmldoc, None)

    def testEmpty(self):
        """Make sure that we get an exception when an XRDS element is
        not present"""
        self.xmldoc = ''
        self.assertRaises(etxrd.XRDSError, services.applyFilter, self.yadis_url, self.xmldoc, None)

    def testNoXRD(self):
        """Make sure that we get an exception when there is no XRD
        element present."""
        self.xmldoc = file(NOXRD_FILE).read()
        self.assertRaises(etxrd.XRDSError, services.applyFilter, self.yadis_url, self.xmldoc, None)


class TestCanonicalID(unittest.TestCase):

    def mkTest(iname, filename, expectedID):
        """This function builds a method that runs the CanonicalID
        test for the given set of inputs"""

        filename = datapath(filename)

        def test(self):
            xrds = etxrd.parseXRDS(file(filename).read())
            self._getCanonicalID(iname, xrds, expectedID)
        return test

    test_delegated = mkTest(
        "@ootao*test1", "delegated-20060809.xrds",
        "@!5BAD.2AA.3C72.AF46!0000.0000.3B9A.CA01")

    test_delegated_r1 = mkTest(
        "@ootao*test1", "delegated-20060809-r1.xrds",
        "@!5BAD.2AA.3C72.AF46!0000.0000.3B9A.CA01")

    test_delegated_r2 = mkTest(
        "@ootao*test1", "delegated-20060809-r2.xrds",
        "@!5BAD.2AA.3C72.AF46!0000.0000.3B9A.CA01")

    test_sometimesprefix = mkTest(
        "@ootao*test1", "sometimesprefix.xrds",
        "@!5BAD.2AA.3C72.AF46!0000.0000.3B9A.CA01")

    test_prefixsometimes = mkTest(
        "@ootao*test1", "prefixsometimes.xrds",
        "@!5BAD.2AA.3C72.AF46!0000.0000.3B9A.CA01")

    test_spoof1 = mkTest("=keturn*isDrummond", "spoof1.xrds", etxrd.XRDSFraud)

    test_spoof2 = mkTest("=keturn*isDrummond", "spoof2.xrds", etxrd.XRDSFraud)

    test_spoof3 = mkTest("@keturn*is*drummond", "spoof3.xrds", etxrd.XRDSFraud)

    test_status222 = mkTest("=x", "status222.xrds", None)

    test_multisegment_xri = mkTest('xri://=nishitani*masaki',
                                   'subsegments.xrds',
                                   '=!E117.EF2F.454B.C707!0000.0000.3B9A.CA01')

    test_iri_auth_not_allowed = mkTest(
        "phreak.example.com", "delegated-20060809-r2.xrds", etxrd.XRDSFraud)
    test_iri_auth_not_allowed.__doc__ = \
        "Don't let IRI authorities be canonical for the GCS."

    # TODO: Refs
    # test_ref = mkTest("@ootao*test.ref", "ref.xrds", "@!BAE.A650.823B.2475")

    # TODO: Add a IRI authority with an IRI canonicalID.
    # TODO: Add test cases with real examples of multiple CanonicalIDs
    #   somewhere in the resolution chain.

    def _getCanonicalID(self, iname, xrds, expectedID):
        if isinstance(expectedID, (str, unicode, type(None))):
            cid = etxrd.getCanonicalID(iname, xrds)
            self.assertEqual(cid, expectedID and xri.XRI(expectedID))
        elif issubclass(expectedID, etxrd.XRDSError):
            self.assertRaises(expectedID, etxrd.getCanonicalID, iname, xrds)
        else:
            self.fail("Don't know how to test for expected value %r"
                      % (expectedID,))


if __name__ == '__main__':
    unittest.main()
