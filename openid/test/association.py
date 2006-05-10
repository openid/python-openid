from openid.test import datadriven

import unittest

from openid import association
import time

class AssociationSerializationTest(unittest.TestCase):
    def test_roundTrip(self):
        issued = int(time.time())
        lifetime = 600
        assoc = association.Association(
            'handle', 'secret', issued, lifetime, 'HMAC-SHA1')
        s = assoc.serialize()
        assoc2 = association.Association.deserialize(s)
        self.failUnlessEqual(assoc.handle, assoc2.handle)
        self.failUnlessEqual(assoc.issued, assoc2.issued)
        self.failUnlessEqual(assoc.secret, assoc2.secret)
        self.failUnlessEqual(assoc.lifetime, assoc2.lifetime)
        self.failUnlessEqual(assoc.assoc_type, assoc2.assoc_type)

from openid.server.server import \
     DiffieHellmanServerSession, \
     PlainTextServerSession

from openid.consumer.consumer import \
     DiffieHellmanConsumerSession, \
     PlainTextConsumerSession

from openid.dh import DiffieHellman

def createNonstandardConsumerDH():
    nonstandard_dh = DiffieHellman(1315291, 2)
    return DiffieHellmanConsumerSession(nonstandard_dh)

class DiffieHellmanSessionTest(datadriven.DataDrivenTestCase):
    secrets = [
        '\x00' * 20,
        '\xff' * 20,
        ' ' * 20,
        'This is a secret....',
        ]

    session_factories = [
        (DiffieHellmanConsumerSession, DiffieHellmanServerSession),
        (createNonstandardConsumerDH, DiffieHellmanServerSession),
        (PlainTextConsumerSession, PlainTextServerSession),
        ]

    def generateCases(cls):
        return [(c, s, sec)
                for c, s in cls.session_factories
                for sec in cls.secrets]

    generateCases = classmethod(generateCases)

    def __init__(self, csess_fact, ssess_fact, secret):
        datadriven.DataDrivenTestCase.__init__(self, csess_fact.__name__)
        self.secret = secret
        self.csess_fact = csess_fact
        self.ssess_fact = ssess_fact

    def runOneTest(self):
        csess = self.csess_fact()
        ssess = self.ssess_fact.fromQuery(csess.getRequest())
        check_secret = csess.extractSecret(ssess.answer(self.secret))
        self.failUnlessEqual(self.secret, check_secret)

def pyUnitTests():
    return datadriven.loadTests(__name__)

if __name__ == '__main__':
    suite = pyUnitTests()
    runner = unittest.TextTestRunner()
    runner.run(suite)
