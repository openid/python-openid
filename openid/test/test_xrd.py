import unittest
from openid.yadis import xrd
from openid.yadis.servicetypes import openid
import os.path

def sibpath(one, other, make_absolute=True):
    if os.path.isabs(other):
        return other
    p = os.path.join(os.path.dirname(one), other)
    if make_absolute:
        p = os.path.abspath(p)
    return p


XRD_FILE = sibpath(__file__, os.path.join("data", "test1-xrd.xml"))
NOXRDS_FILE = sibpath(__file__, os.path.join("data", "not-xrds.xml"))
NOXRD_FILE = sibpath(__file__, os.path.join("data", "no-xrd.xml"))

# None of the namespaces or service URIs below are official (or even
# sanctioned by the owners of that piece of URL-space)

LID_2_0 = "http://lid.netmesh.org/sso/2.0b5"
TYPEKEY_1_0 = "http://typekey.com/services/1.0"

class TestServiceParser(unittest.TestCase):
    def setUp(self):
        self.xmldoc = file(XRD_FILE).read()
        self.sp = xrd.ServiceParser()

    def testParse(self):
        services = self.sp.parse(self.xmldoc)

    def testParseOpenID(self):
        self.sp = xrd.ServiceParser([openid.OpenIDParser()])
        services = self.sp.parse(self.xmldoc)
        oidservices = services.getServices(openid.OPENID_1_0)

        expectedServices = [
            ("http://www.myopenid.com/server", "http://josh.myopenid.com/"),
            ("http://www.schtuff.com/openid", "http://users.schtuff.com/josh"),
            ("http://www.livejournal.com/openid/server.bml",
             "http://www.livejournal.com/users/nedthealpaca/"),
            ]

        count = 0
        for expected, service in zip(expectedServices, oidservices):
            self.failUnlessEqual(service.uri, expected[0])
            self.failUnlessEqual(service.delegate, expected[1])
            # Fine test, but zip truncates to the length of the shortest
            # sequence.
            count = count + 1
        self.failUnlessEqual(count, len(expectedServices))

    def testGetSeveral(self):
        services = self.sp.parse(self.xmldoc)
        oidservices = services.getServices(LID_2_0, TYPEKEY_1_0)
        expectedServices = [
            # type, URL
            (TYPEKEY_1_0, None),
            (LID_2_0, "http://mylid.net/josh"),
            ]

        count = 0
        for expected, service in zip(expectedServices, oidservices):
            self.failUnlessEqual(service.type, expected[0])
            self.failUnlessEqual(service.uri, expected[1])
            count = count + 1
        self.failUnlessEqual(count, len(expectedServices))

    def testGetSeveralForOne(self):
        """Getting services for one Service with several Type elements."""
        services = self.sp.parse(self.xmldoc)
        oidservices = services.getServices(
            'http://lid.netmesh.org/sso/2.0b5',
            'http://lid.netmesh.org/2.0b5')

        expectedServices = [
            ('http://lid.netmesh.org/sso/2.0b5', "http://mylid.net/josh"),
            ('http://lid.netmesh.org/2.0b5', "http://mylid.net/josh"),
            ]

        count = 0
        for expected, service in zip(expectedServices, oidservices):
            self.failUnlessEqual(service.type, expected[0])
            self.failUnlessEqual(service.uri, expected[1])
            count = count + 1
        self.failUnlessEqual(count, len(expectedServices))

    def testNoXRDS(self):
        self.xmldoc = file(NOXRDS_FILE).read()
        self.failUnlessRaises(xrd.XrdsError, self.sp.parse, self.xmldoc)

    def testNoXRD(self):
        self.xmldoc = file(NOXRD_FILE).read()
        self.failUnlessRaises(xrd.XrdsError, self.sp.parse, self.xmldoc)

if __name__ == '__main__':
    unittest.main()
