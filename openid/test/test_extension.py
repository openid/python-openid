import unittest

from openid import extension, message


class DummyExtension(extension.Extension):
    ns_uri = 'http://an.extension/'
    ns_alias = 'dummy'

    def getExtensionArgs(self):
        return {}


class ToMessageTest(unittest.TestCase):
    def test_OpenID1(self):
        oid1_msg = message.Message(message.OPENID1_NS)
        ext = DummyExtension()
        ext.toMessage(oid1_msg)
        namespaces = oid1_msg.namespaces
        self.assertTrue(namespaces.isImplicit(DummyExtension.ns_uri))
        self.assertEqual(DummyExtension.ns_uri, namespaces.getNamespaceURI(DummyExtension.ns_alias))
        self.assertEqual(DummyExtension.ns_alias, namespaces.getAlias(DummyExtension.ns_uri))

    def test_OpenID2(self):
        oid2_msg = message.Message(message.OPENID2_NS)
        ext = DummyExtension()
        ext.toMessage(oid2_msg)
        namespaces = oid2_msg.namespaces
        self.assertFalse(namespaces.isImplicit(DummyExtension.ns_uri))
        self.assertEqual(DummyExtension.ns_uri, namespaces.getNamespaceURI(DummyExtension.ns_alias))
        self.assertEqual(DummyExtension.ns_alias, namespaces.getAlias(DummyExtension.ns_uri))
