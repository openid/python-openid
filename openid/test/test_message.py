from openid import message

import urllib
import cgi
import unittest
import datadriven

class EmptyMessageTest(unittest.TestCase):
    def setUp(self):
        self.msg = message.Message()

    def test_toPostArgs(self):
        self.failUnlessEqual(self.msg.toPostArgs(), {})

    def test_toArgs(self):
        self.failUnlessEqual(self.msg.toArgs(), {})

    def test_toKVForm(self):
        self.failUnlessEqual(self.msg.toKVForm(), '')

    def test_toURLEncoded(self):
        self.failUnlessEqual(self.msg.toURLEncoded(), '')

    def test_toURL(self):
        base_url = 'http://base.url/'
        self.failUnlessEqual(self.msg.toURL(base_url), base_url)

    def test_getOpenID(self):
        self.failUnlessEqual(self.msg.getOpenIDNamespace(), None)

    def test_getKeyOpenID(self):
        # Could reasonably return None instead of raising an
        # exception. I'm not sure which one is more right, since this
        # case should only happen when you're building a message from
        # scratch and so have no default namespace.
        self.failUnlessRaises(message.UndefinedOpenIDNamespace,
                              self.msg.getKey, message.OPENID_NS, 'foo')

    def test_getKeyBARE(self):
        self.failUnlessEqual(self.msg.getKey(message.BARE_NS, 'foo'), 'foo')

    def test_getKeyNS1(self):
        self.failUnlessEqual(self.msg.getKey(message.OPENID1_NS, 'foo'), None)

    def test_getKeyNS2(self):
        self.failUnlessEqual(self.msg.getKey(message.OPENID2_NS, 'foo'), None)

    def test_getKeyNS3(self):
        self.failUnlessEqual(self.msg.getKey('urn:nothing-significant', 'foo'),
                             None)

    def test_hasKey(self):
        # Could reasonably return False instead of raising an
        # exception. I'm not sure which one is more right, since this
        # case should only happen when you're building a message from
        # scratch and so have no default namespace.
        self.failUnlessRaises(message.UndefinedOpenIDNamespace,
                              self.msg.hasKey, message.OPENID_NS, 'foo')

    def test_hasKeyBARE(self):
        self.failUnlessEqual(self.msg.hasKey(message.BARE_NS, 'foo'), False)

    def test_hasKeyNS1(self):
        self.failUnlessEqual(self.msg.hasKey(message.OPENID1_NS, 'foo'), False)

    def test_hasKeyNS2(self):
        self.failUnlessEqual(self.msg.hasKey(message.OPENID2_NS, 'foo'), False)

    def test_hasKeyNS3(self):
        self.failUnlessEqual(self.msg.hasKey('urn:nothing-significant', 'foo'),
                             False)

    def test_getArg(self):
        # Could reasonably return None instead of raising an
        # exception. I'm not sure which one is more right, since this
        # case should only happen when you're building a message from
        # scratch and so have no default namespace.
        self.failUnlessRaises(message.UndefinedOpenIDNamespace,
                              self.msg.getArg, message.OPENID_NS, 'foo')

    def test_getArgBARE(self):
        self.failUnlessEqual(self.msg.getArg(message.BARE_NS, 'foo'), None)

    def test_getArgNS1(self):
        self.failUnlessEqual(self.msg.getArg(message.OPENID1_NS, 'foo'), None)

    def test_getArgNS2(self):
        self.failUnlessEqual(self.msg.getArg(message.OPENID2_NS, 'foo'), None)

    def test_getArgNS3(self):
        self.failUnlessEqual(self.msg.getArg('urn:nothing-significant', 'foo'),
                             None)

    def test_getArgs(self):
        # Could reasonably return {} instead of raising an
        # exception. I'm not sure which one is more right, since this
        # case should only happen when you're building a message from
        # scratch and so have no default namespace.
        self.failUnlessRaises(message.UndefinedOpenIDNamespace,
                              self.msg.getArgs, message.OPENID_NS)

    def test_getArgsBARE(self):
        self.failUnlessEqual(self.msg.getArgs(message.BARE_NS), {})

    def test_getArgsNS1(self):
        self.failUnlessEqual(self.msg.getArgs(message.OPENID1_NS), {})

    def test_getArgsNS2(self):
        self.failUnlessEqual(self.msg.getArgs(message.OPENID2_NS), {})

    def test_getArgsNS3(self):
        self.failUnlessEqual(self.msg.getArgs('urn:nothing-significant'), {})

    def test_updateArgs(self):
        self.failUnlessRaises(message.UndefinedOpenIDNamespace,
                              self.msg.updateArgs, message.OPENID_NS,
                              {'does not':'matter'})

    def _test_updateArgsNS(self, ns):
        update_args = {
            'Camper van Beethoven':'David Lowery',
            'Magnolia Electric Co.':'Jason Molina',
            }

        self.failUnlessEqual(self.msg.getArgs(ns), {})
        self.msg.updateArgs(ns, update_args)
        self.failUnlessEqual(self.msg.getArgs(ns), update_args)

    def test_updateArgsBARE(self):
        self._test_updateArgsNS(message.BARE_NS)

    def test_updateArgsNS1(self):
        self._test_updateArgsNS(message.OPENID1_NS)

    def test_updateArgsNS2(self):
        self._test_updateArgsNS(message.OPENID2_NS)

    def test_updateArgsNS3(self):
        self._test_updateArgsNS('urn:nothing-significant')

    def test_setArg(self):
        self.failUnlessRaises(message.UndefinedOpenIDNamespace,
                              self.msg.setArg, message.OPENID_NS,
                              'does not', 'matter')

    def _test_setArgNS(self, ns):
        key = 'Camper van Beethoven'
        value = 'David Lowery'
        self.failUnlessEqual(self.msg.getArg(ns, key), None)
        self.msg.setArg(ns, key, value)
        self.failUnlessEqual(self.msg.getArg(ns, key), value)

    def test_setArgBARE(self):
        self._test_setArgNS(message.BARE_NS)

    def test_setArgNS1(self):
        self._test_setArgNS(message.OPENID1_NS)

    def test_setArgNS2(self):
        self._test_setArgNS(message.OPENID2_NS)

    def test_setArgNS3(self):
        self._test_setArgNS('urn:nothing-significant')

    def test_delArg(self):
        # Could reasonably raise KeyError instead of raising
        # UndefinedOpenIDNamespace. I'm not sure which one is more
        # right, since this case should only happen when you're
        # building a message from scratch and so have no default
        # namespace.
        self.failUnlessRaises(message.UndefinedOpenIDNamespace,
                              self.msg.setArg, message.OPENID_NS,
                              'does not', 'matter')

    def _test_delArgNS(self, ns):
        key = 'Camper van Beethoven'
        self.failUnlessRaises(KeyError, self.msg.delArg, ns, key)

    def test_delArgBARE(self):
        self._test_delArgNS(message.BARE_NS)

    def test_delArgNS1(self):
        self._test_delArgNS(message.OPENID1_NS)

    def test_delArgNS2(self):
        self._test_delArgNS(message.OPENID2_NS)

    def test_delArgNS3(self):
        self._test_delArgNS('urn:nothing-significant')


class OpenID1MessageTest(unittest.TestCase):
    def setUp(self):
        self.msg = message.Message.fromPostArgs({'openid.mode':'error',
                                                 'openid.error':'unit test'})

    def test_toPostArgs(self):
        self.failUnlessEqual(self.msg.toPostArgs(),
                             {'openid.mode':'error',
                              'openid.error':'unit test'})

    def test_toArgs(self):
        self.failUnlessEqual(self.msg.toArgs(), {'mode':'error',
                                                 'error':'unit test'})

    def test_toKVForm(self):
        self.failUnlessEqual(self.msg.toKVForm(),
                             'error:unit test\nmode:error\n')

    def test_toURLEncoded(self):
        self.failUnlessEqual(self.msg.toURLEncoded(),
                             'openid.error=unit+test&openid.mode=error')

    def test_toURL(self):
        base_url = 'http://base.url/'
        actual = self.msg.toURL(base_url)
        actual_base = actual[:len(base_url)]
        self.failUnlessEqual(actual_base, base_url)
        self.failUnlessEqual(actual[len(base_url)], '?')
        query = actual[len(base_url) + 1:]
        parsed = cgi.parse_qs(query)
        self.failUnlessEqual(parsed, {'openid.mode':['error'],
                                      'openid.error':['unit test']})

    def test_getOpenID(self):
        self.failUnlessEqual(self.msg.getOpenIDNamespace(), message.OPENID1_NS)

    def test_getKeyOpenID(self):
        self.failUnlessEqual(self.msg.getKey(message.OPENID_NS, 'mode'),
                             'openid.mode')

    def test_getKeyBARE(self):
        self.failUnlessEqual(self.msg.getKey(message.BARE_NS, 'mode'), 'mode')

    def test_getKeyNS1(self):
        self.failUnlessEqual(
            self.msg.getKey(message.OPENID1_NS, 'mode'), 'openid.mode')

    def test_getKeyNS2(self):
        self.failUnlessEqual(self.msg.getKey(message.OPENID2_NS, 'mode'), None)

    def test_getKeyNS3(self):
        self.failUnlessEqual(
            self.msg.getKey('urn:nothing-significant', 'mode'), None)

    def test_hasKey(self):
        self.failUnlessEqual(self.msg.hasKey(message.OPENID_NS, 'mode'), True)

    def test_hasKeyBARE(self):
        self.failUnlessEqual(self.msg.hasKey(message.BARE_NS, 'mode'), False)

    def test_hasKeyNS1(self):
        self.failUnlessEqual(self.msg.hasKey(message.OPENID1_NS, 'mode'), True)

    def test_hasKeyNS2(self):
        self.failUnlessEqual(
            self.msg.hasKey(message.OPENID2_NS, 'mode'), False)

    def test_hasKeyNS3(self):
        self.failUnlessEqual(
            self.msg.hasKey('urn:nothing-significant', 'mode'), False)

    def test_getArg(self):
        self.failUnlessEqual(self.msg.getArg(message.OPENID_NS, 'mode'),
                             'error')

    def test_getArgBARE(self):
        self.failUnlessEqual(self.msg.getArg(message.BARE_NS, 'mode'), None)

    def test_getArgNS1(self):
        self.failUnlessEqual(self.msg.getArg(message.OPENID1_NS, 'mode'),
                             'error')

    def test_getArgNS2(self):
        self.failUnlessEqual(self.msg.getArg(message.OPENID2_NS, 'mode'), None)

    def test_getArgNS3(self):
        self.failUnlessEqual(
            self.msg.getArg('urn:nothing-significant', 'mode'), None)

    def test_getArgs(self):
        self.failUnlessEqual(self.msg.getArgs(message.OPENID_NS),
                             {'mode':'error',
                              'error':'unit test',
                              })

    def test_getArgsBARE(self):
        self.failUnlessEqual(self.msg.getArgs(message.BARE_NS), {})

    def test_getArgsNS1(self):
        self.failUnlessEqual(self.msg.getArgs(message.OPENID1_NS),
                             {'mode':'error',
                              'error':'unit test',
                              })

    def test_getArgsNS2(self):
        self.failUnlessEqual(self.msg.getArgs(message.OPENID2_NS), {})

    def test_getArgsNS3(self):
        self.failUnlessEqual(self.msg.getArgs('urn:nothing-significant'), {})

    def _test_updateArgsNS(self, ns, before=None):
        if before is None:
            before = {}
        update_args = {
            'Camper van Beethoven':'David Lowery',
            'Magnolia Electric Co.':'Jason Molina',
            }

        self.failUnlessEqual(self.msg.getArgs(ns), before)
        self.msg.updateArgs(ns, update_args)
        after = dict(before)
        after.update(update_args)
        self.failUnlessEqual(self.msg.getArgs(ns), after)

    def test_updateArgs(self):
        self._test_updateArgsNS(message.OPENID_NS,
                                before={'mode':'error', 'error':'unit test'})

    def test_updateArgsBARE(self):
        self._test_updateArgsNS(message.BARE_NS)

    def test_updateArgsNS1(self):
        self._test_updateArgsNS(message.OPENID1_NS,
                                before={'mode':'error', 'error':'unit test'})

    def test_updateArgsNS2(self):
        self._test_updateArgsNS(message.OPENID2_NS)

    def test_updateArgsNS3(self):
        self._test_updateArgsNS('urn:nothing-significant')

    def _test_setArgNS(self, ns):
        key = 'Camper van Beethoven'
        value = 'David Lowery'
        self.failUnlessEqual(self.msg.getArg(ns, key), None)
        self.msg.setArg(ns, key, value)
        self.failUnlessEqual(self.msg.getArg(ns, key), value)

    def test_setArg(self):
        self._test_setArgNS(message.OPENID_NS)

    def test_setArgBARE(self):
        self._test_setArgNS(message.BARE_NS)

    def test_setArgNS1(self):
        self._test_setArgNS(message.OPENID1_NS)

    def test_setArgNS2(self):
        self._test_setArgNS(message.OPENID2_NS)

    def test_setArgNS3(self):
        self._test_setArgNS('urn:nothing-significant')

    def _test_delArgNS(self, ns):
        key = 'Camper van Beethoven'
        value = 'David Lowery'

        self.failUnlessRaises(KeyError, self.msg.delArg, ns, key)
        self.msg.setArg(ns, key, value)
        self.failUnlessEqual(self.msg.getArg(ns, key), value)
        self.msg.delArg(ns, key)
        self.failUnlessEqual(self.msg.getArg(ns, key), None)

    def test_delArg(self):
        self._test_delArgNS(message.OPENID1_NS)

    def test_delArgBARE(self):
        self._test_delArgNS(message.BARE_NS)

    def test_delArgNS1(self):
        self._test_delArgNS(message.OPENID1_NS)

    def test_delArgNS2(self):
        self._test_delArgNS(message.OPENID2_NS)

    def test_delArgNS3(self):
        self._test_delArgNS('urn:nothing-significant')


class OpenID1ExplicitMessageTest(OpenID1MessageTest):
    def setUp(self):
        self.msg = message.Message.fromPostArgs({'openid.mode':'error',
                                                 'openid.error':'unit test',
                                                 'openid.ns':message.OPENID1_NS
                                                 })


class OpenID2MessageTest(unittest.TestCase):
    def setUp(self):
        self.msg = message.Message.fromPostArgs({'openid.mode':'error',
                                                 'openid.error':'unit test',
                                                 'openid.ns':message.OPENID2_NS
                                                 })

    def test_toPostArgs(self):
        self.failUnlessEqual(self.msg.toPostArgs(),
                             {'openid.mode':'error',
                              'openid.error':'unit test',
                              'openid.ns':message.OPENID2_NS,
                              })

    def test_toArgs(self):
        self.failUnlessEqual(self.msg.toArgs(), {'mode':'error',
                                                 'error':'unit test',
                                                 'ns':message.OPENID2_NS,
                                                 })

    def test_toKVForm(self):
        self.failUnlessEqual(self.msg.toKVForm(),
                             'error:unit test\nmode:error\nns:%s\n' %
                             (message.OPENID2_NS,))

    def _test_urlencoded(self, s):
        expected = 'openid.error=unit+test&openid.mode=error&openid.ns=%s' % (
            urllib.quote(message.OPENID2_NS, ''),)
        self.failUnlessEqual(s, expected)
        

    def test_toURLEncoded(self):
        self._test_urlencoded(self.msg.toURLEncoded())

    def test_toURL(self):
        base_url = 'http://base.url/'
        actual = self.msg.toURL(base_url)
        actual_base = actual[:len(base_url)]
        self.failUnlessEqual(actual_base, base_url)
        self.failUnlessEqual(actual[len(base_url)], '?')
        query = actual[len(base_url) + 1:]
        self._test_urlencoded(query)

    def test_getOpenID(self):
        self.failUnlessEqual(self.msg.getOpenIDNamespace(), message.OPENID2_NS)

    def test_getKeyOpenID(self):
        self.failUnlessEqual(self.msg.getKey(message.OPENID_NS, 'mode'),
                             'openid.mode')

    def test_getKeyBARE(self):
        self.failUnlessEqual(self.msg.getKey(message.BARE_NS, 'mode'), 'mode')

    def test_getKeyNS1(self):
        self.failUnlessEqual(
            self.msg.getKey(message.OPENID1_NS, 'mode'), None)

    def test_getKeyNS2(self):
        self.failUnlessEqual(
            self.msg.getKey(message.OPENID2_NS, 'mode'), 'openid.mode')

    def test_getKeyNS3(self):
        self.failUnlessEqual(
            self.msg.getKey('urn:nothing-significant', 'mode'), None)

    def test_hasKeyOpenID(self):
        self.failUnlessEqual(self.msg.hasKey(message.OPENID_NS, 'mode'), True)

    def test_hasKeyBARE(self):
        self.failUnlessEqual(self.msg.hasKey(message.BARE_NS, 'mode'), False)

    def test_hasKeyNS1(self):
        self.failUnlessEqual(
            self.msg.hasKey(message.OPENID1_NS, 'mode'), False)

    def test_hasKeyNS2(self):
        self.failUnlessEqual(
            self.msg.hasKey(message.OPENID2_NS, 'mode'), True)

    def test_hasKeyNS3(self):
        self.failUnlessEqual(
            self.msg.hasKey('urn:nothing-significant', 'mode'), False)

    def test_getArgOpenID(self):
        self.failUnlessEqual(self.msg.getArg(message.OPENID_NS, 'mode'),
                             'error')

    def test_getArgBARE(self):
        self.failUnlessEqual(self.msg.getArg(message.BARE_NS, 'mode'), None)

    def test_getArgNS1(self):
        self.failUnlessEqual(self.msg.getArg(message.OPENID1_NS, 'mode'), None)

    def test_getArgNS2(self):
        self.failUnlessEqual(self.msg.getArg(message.OPENID2_NS, 'mode'),
                             'error')

    def test_getArgNS3(self):
        self.failUnlessEqual(
            self.msg.getArg('urn:nothing-significant', 'mode'), None)

    def test_getArgsOpenID(self):
        self.failUnlessEqual(self.msg.getArgs(message.OPENID_NS),
                             {'mode':'error',
                              'error':'unit test',
                              })

    def test_getArgsBARE(self):
        self.failUnlessEqual(self.msg.getArgs(message.BARE_NS), {})

    def test_getArgsNS1(self):
        self.failUnlessEqual(self.msg.getArgs(message.OPENID2_NS),
                             {'mode':'error',
                              'error':'unit test',
                              })

    def test_getArgsNS2(self):
        self.failUnlessEqual(self.msg.getArgs(message.OPENID1_NS), {})

    def test_getArgsNS3(self):
        self.failUnlessEqual(self.msg.getArgs('urn:nothing-significant'), {})

    def _test_updateArgsNS(self, ns, before=None):
        if before is None:
            before = {}
        update_args = {
            'Camper van Beethoven':'David Lowery',
            'Magnolia Electric Co.':'Jason Molina',
            }

        self.failUnlessEqual(self.msg.getArgs(ns), before)
        self.msg.updateArgs(ns, update_args)
        after = dict(before)
        after.update(update_args)
        self.failUnlessEqual(self.msg.getArgs(ns), after)

    def test_updateArgsOpenID(self):
        self._test_updateArgsNS(message.OPENID_NS,
                                before={'mode':'error', 'error':'unit test'})

    def test_updateArgsBARE(self):
        self._test_updateArgsNS(message.BARE_NS)

    def test_updateArgsNS1(self):
        self._test_updateArgsNS(message.OPENID2_NS,
                                before={'mode':'error', 'error':'unit test'})

    def test_updateArgsNS2(self):
        self._test_updateArgsNS(message.OPENID1_NS)

    def test_updateArgsNS3(self):
        self._test_updateArgsNS('urn:nothing-significant')

    def _test_setArgNS(self, ns):
        key = 'Camper van Beethoven'
        value = 'David Lowery'
        self.failUnlessEqual(self.msg.getArg(ns, key), None)
        self.msg.setArg(ns, key, value)
        self.failUnlessEqual(self.msg.getArg(ns, key), value)

    def test_setArgOpenID(self):
        self._test_setArgNS(message.OPENID_NS)

    def test_setArgBARE(self):
        self._test_setArgNS(message.BARE_NS)

    def test_setArgNS1(self):
        self._test_setArgNS(message.OPENID1_NS)

    def test_setArgNS2(self):
        self._test_setArgNS(message.OPENID2_NS)

    def test_setArgNS3(self):
        self._test_setArgNS('urn:nothing-significant')

    def _test_delArgNS(self, ns):
        key = 'Camper van Beethoven'
        value = 'David Lowery'

        self.failUnlessRaises(KeyError, self.msg.delArg, ns, key)
        self.msg.setArg(ns, key, value)
        self.failUnlessEqual(self.msg.getArg(ns, key), value)
        self.msg.delArg(ns, key)
        self.failUnlessEqual(self.msg.getArg(ns, key), None)

    def test_delArgOpenID(self):
        self._test_delArgNS(message.OPENID1_NS)

    def test_delArgBARE(self):
        self._test_delArgNS(message.BARE_NS)

    def test_delArgNS1(self):
        self._test_delArgNS(message.OPENID1_NS)

    def test_delArgNS2(self):
        self._test_delArgNS(message.OPENID2_NS)

    def test_delArgNS3(self):
        self._test_delArgNS('urn:nothing-significant')

class NamespaceMapTest(unittest.TestCase):
    def test_onealias(self):
        nsm = message.NamespaceMap()
        uri = 'http://example.com/foo'
        alias = "foo"
        nsm.addAlias(uri, alias)
        self.failUnless(nsm.getNamespaceURI(alias) == uri)
        self.failUnless(nsm.getAlias(uri) == alias)

    def test_iteration(self):
        nsm = message.NamespaceMap()
        uripat = 'http://example.com/foo%r'
        
        nsm.add(uripat%0)
        for n in range(1,23):
            self.failUnless(uripat%(n-1) in nsm)
            self.failUnless(nsm.isDefined(uripat%(n-1)))
            nsm.add(uripat%n)

        for (uri, alias) in nsm.iteritems():
            self.failUnless(uri[22:]==alias)

        i=0
        it = nsm.iterAliases() 
        try:
            while True:
                it.next()
                i += 1
        except StopIteration:
            self.failUnless(i == 23)

        i=0
        it = nsm.iterNamespaceURIs() 
        try:
            while True:
                it.next()
                i += 1
        except StopIteration:
            self.failUnless(i == 23)

            
if __name__ == '__main__':
    unittest.main()
