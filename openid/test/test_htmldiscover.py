from openid.consumer.discover import OpenIDServiceEndpoint
from openid.consumer.parse import openIDDiscover as parseOpenIDLinkRel
from openid.consumer.parse import ParseError
import datadriven

class BadLinksTestCase(datadriven.DataDrivenTestCase):
    cases = [
        '',
        "http://not.in.a.link.tag/",
        '<link rel="openid.server" href="not.in.html.or.head" />',
        ]

    def __init__(self, data):
        datadriven.DataDrivenTestCase.__init__(self, data)
        self.data = data

    def callFunc(self):
        return parseOpenIDLinkRel(self.data)

    def runOneTest(self):
        self.failUnlessRaises(ParseError, self.callFunc)

class BadLinksThroughEndpoint(BadLinksTestCase):
    def callFunc(self):
        return OpenIDServiceEndpoint.fromHTML('http://unused.url/', self.data)

def pyUnitTests():
    return datadriven.loadTests(__name__)
