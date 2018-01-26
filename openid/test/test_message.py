# -*- coding: utf-8 -*-
import unittest
import urllib
import warnings
from urlparse import parse_qs

from lxml import etree as ElementTree
from testfixtures import ShouldWarn

from openid.extensions import sreg
from openid.message import (BARE_NS, NULL_NAMESPACE, OPENID1_NS, OPENID2_NS, OPENID_NS, OPENID_PROTOCOL_FIELDS,
                            THE_OTHER_OPENID1_NS, InvalidNamespace, InvalidOpenIDNamespace, Message, NamespaceMap,
                            UndefinedOpenIDNamespace, no_default)


def mkGetArgTest(ns, key, expected=None):
    def test(self):
        a_default = object()
        self.assertEqual(self.msg.getArg(ns, key), expected)
        if expected is None:
            self.assertEqual(self.msg.getArg(ns, key, a_default), a_default)
            self.assertRaises(KeyError, self.msg.getArg, ns, key, no_default)
        else:
            self.assertEqual(self.msg.getArg(ns, key, a_default), expected)
            self.assertEqual(self.msg.getArg(ns, key, no_default), expected)

    return test


class EmptyMessageTest(unittest.TestCase):
    def setUp(self):
        self.msg = Message()

    def test_toPostArgs(self):
        self.assertEqual(self.msg.toPostArgs(), {})

    def test_toArgs(self):
        self.assertEqual(self.msg.toArgs(), {})

    def test_toKVForm(self):
        self.assertEqual(self.msg.toKVForm(), '')

    def test_toURLEncoded(self):
        self.assertEqual(self.msg.toURLEncoded(), '')

    def test_toURL(self):
        base_url = 'http://base.url/'
        self.assertEqual(self.msg.toURL(base_url), base_url)

    def test_getOpenID(self):
        self.assertIsNone(self.msg.getOpenIDNamespace())

    def test_getKeyOpenID(self):
        # Could reasonably return None instead of raising an
        # exception. I'm not sure which one is more right, since this
        # case should only happen when you're building a message from
        # scratch and so have no default namespace.
        self.assertRaises(UndefinedOpenIDNamespace, self.msg.getKey, OPENID_NS, 'foo')

    def test_getKeyBARE(self):
        self.assertEqual(self.msg.getKey(BARE_NS, 'foo'), 'foo')

    def test_getKeyNS1(self):
        self.assertIsNone(self.msg.getKey(OPENID1_NS, 'foo'))

    def test_getKeyNS2(self):
        self.assertIsNone(self.msg.getKey(OPENID2_NS, 'foo'))

    def test_getKeyNS3(self):
        self.assertIsNone(self.msg.getKey('urn:nothing-significant', 'foo'))

    def test_hasKey(self):
        # Could reasonably return False instead of raising an
        # exception. I'm not sure which one is more right, since this
        # case should only happen when you're building a message from
        # scratch and so have no default namespace.
        self.assertRaises(UndefinedOpenIDNamespace, self.msg.hasKey, OPENID_NS, 'foo')

    def test_hasKeyBARE(self):
        self.assertFalse(self.msg.hasKey(BARE_NS, 'foo'))

    def test_hasKeyNS1(self):
        self.assertFalse(self.msg.hasKey(OPENID1_NS, 'foo'))

    def test_hasKeyNS2(self):
        self.assertFalse(self.msg.hasKey(OPENID2_NS, 'foo'))

    def test_hasKeyNS3(self):
        self.assertFalse(self.msg.hasKey('urn:nothing-significant', 'foo'))

    def test_getAliasedArgSuccess(self):
        msg = Message.fromPostArgs({'openid.ns.test': 'urn://foo', 'openid.test.flub': 'bogus'})
        actual_uri = msg.getAliasedArg('ns.test', no_default)
        self.assertEquals("urn://foo", actual_uri)

    def test_getAliasedArgFailure(self):
        msg = Message.fromPostArgs({'openid.test.flub': 'bogus'})
        self.assertRaises(KeyError, msg.getAliasedArg, 'ns.test', no_default)

    def test_getArg(self):
        # Could reasonably return None instead of raising an
        # exception. I'm not sure which one is more right, since this
        # case should only happen when you're building a message from
        # scratch and so have no default namespace.
        self.assertRaises(UndefinedOpenIDNamespace, self.msg.getArg, OPENID_NS, 'foo')

    test_getArgBARE = mkGetArgTest(BARE_NS, 'foo')
    test_getArgNS1 = mkGetArgTest(OPENID1_NS, 'foo')
    test_getArgNS2 = mkGetArgTest(OPENID2_NS, 'foo')
    test_getArgNS3 = mkGetArgTest('urn:nothing-significant', 'foo')

    def test_getArgs(self):
        # Could reasonably return {} instead of raising an
        # exception. I'm not sure which one is more right, since this
        # case should only happen when you're building a message from
        # scratch and so have no default namespace.
        self.assertRaises(UndefinedOpenIDNamespace, self.msg.getArgs, OPENID_NS)

    def test_getArgsBARE(self):
        self.assertEqual(self.msg.getArgs(BARE_NS), {})

    def test_getArgsNS1(self):
        self.assertEqual(self.msg.getArgs(OPENID1_NS), {})

    def test_getArgsNS2(self):
        self.assertEqual(self.msg.getArgs(OPENID2_NS), {})

    def test_getArgsNS3(self):
        self.assertEqual(self.msg.getArgs('urn:nothing-significant'), {})

    def test_updateArgs(self):
        self.assertRaises(UndefinedOpenIDNamespace, self.msg.updateArgs, OPENID_NS, {'does not': 'matter'})

    def _test_updateArgsNS(self, ns):
        update_args = {
            'Camper van Beethoven': 'David Lowery',
            'Magnolia Electric Co.': 'Jason Molina',
        }

        self.assertEqual(self.msg.getArgs(ns), {})
        self.msg.updateArgs(ns, update_args)
        self.assertEqual(self.msg.getArgs(ns), update_args)

    def test_updateArgsBARE(self):
        self._test_updateArgsNS(BARE_NS)

    def test_updateArgsNS1(self):
        self._test_updateArgsNS(OPENID1_NS)

    def test_updateArgsNS2(self):
        self._test_updateArgsNS(OPENID2_NS)

    def test_updateArgsNS3(self):
        self._test_updateArgsNS('urn:nothing-significant')

    def test_setArg(self):
        self.assertRaises(UndefinedOpenIDNamespace, self.msg.setArg, OPENID_NS, 'does not', 'matter')

    def _test_setArgNS(self, ns):
        key = 'Camper van Beethoven'
        value = 'David Lowery'
        self.assertIsNone(self.msg.getArg(ns, key))
        self.msg.setArg(ns, key, value)
        self.assertEqual(self.msg.getArg(ns, key), value)

    def test_setArgBARE(self):
        self._test_setArgNS(BARE_NS)

    def test_setArgNS1(self):
        self._test_setArgNS(OPENID1_NS)

    def test_setArgNS2(self):
        self._test_setArgNS(OPENID2_NS)

    def test_setArgNS3(self):
        self._test_setArgNS('urn:nothing-significant')

    def test_setArgToNone(self):
        self.assertRaises(AssertionError, self.msg.setArg, OPENID1_NS, 'op_endpoint', None)

    def test_delArg(self):
        # Could reasonably raise KeyError instead of raising
        # UndefinedOpenIDNamespace. I'm not sure which one is more
        # right, since this case should only happen when you're
        # building a message from scratch and so have no default
        # namespace.
        self.assertRaises(UndefinedOpenIDNamespace, self.msg.delArg, OPENID_NS, 'key')

    def _test_delArgNS(self, ns):
        key = 'Camper van Beethoven'
        self.assertRaises(KeyError, self.msg.delArg, ns, key)

    def test_delArgBARE(self):
        self._test_delArgNS(BARE_NS)

    def test_delArgNS1(self):
        self._test_delArgNS(OPENID1_NS)

    def test_delArgNS2(self):
        self._test_delArgNS(OPENID2_NS)

    def test_delArgNS3(self):
        self._test_delArgNS('urn:nothing-significant')

    def test_isOpenID1(self):
        self.assertFalse(self.msg.isOpenID1())

    def test_isOpenID2(self):
        self.assertFalse(self.msg.isOpenID2())


class OpenID1MessageTest(unittest.TestCase):
    def setUp(self):
        self.msg = Message.fromPostArgs({'openid.mode': 'error', 'openid.error': 'unit test'})

    def test_toPostArgs(self):
        self.assertEqual(self.msg.toPostArgs(), {'openid.mode': 'error', 'openid.error': 'unit test'})

    def test_toArgs(self):
        self.assertEqual(self.msg.toArgs(), {'mode': 'error', 'error': 'unit test'})

    def test_toKVForm(self):
        self.assertEqual(self.msg.toKVForm(), 'error:unit test\nmode:error\n')

    def test_toURLEncoded(self):
        self.assertEqual(self.msg.toURLEncoded(), 'openid.error=unit+test&openid.mode=error')

    def test_toURL(self):
        base_url = 'http://base.url/'
        actual = self.msg.toURL(base_url)
        actual_base = actual[:len(base_url)]
        self.assertEqual(actual_base, base_url)
        self.assertEqual(actual[len(base_url)], '?')
        query = actual[len(base_url) + 1:]
        parsed = parse_qs(query)
        self.assertEqual(parsed, {'openid.mode': ['error'], 'openid.error': ['unit test']})

    def test_getOpenID(self):
        self.assertEqual(self.msg.getOpenIDNamespace(), OPENID1_NS)

    def test_getKeyOpenID(self):
        self.assertEqual(self.msg.getKey(OPENID_NS, 'mode'), 'openid.mode')

    def test_getKeyBARE(self):
        self.assertEqual(self.msg.getKey(BARE_NS, 'mode'), 'mode')

    def test_getKeyNS1(self):
        self.assertEqual(self.msg.getKey(OPENID1_NS, 'mode'), 'openid.mode')

    def test_getKeyNS2(self):
        self.assertIsNone(self.msg.getKey(OPENID2_NS, 'mode'))

    def test_getKeyNS3(self):
        self.assertIsNone(self.msg.getKey('urn:nothing-significant', 'mode'))

    def test_hasKey(self):
        self.assertTrue(self.msg.hasKey(OPENID_NS, 'mode'))

    def test_hasKeyBARE(self):
        self.assertFalse(self.msg.hasKey(BARE_NS, 'mode'))

    def test_hasKeyNS1(self):
        self.assertTrue(self.msg.hasKey(OPENID1_NS, 'mode'))

    def test_hasKeyNS2(self):
        self.assertFalse(self.msg.hasKey(OPENID2_NS, 'mode'))

    def test_hasKeyNS3(self):
        self.assertFalse(self.msg.hasKey('urn:nothing-significant', 'mode'))

    test_getArgBARE = mkGetArgTest(BARE_NS, 'mode')
    test_getArgNS = mkGetArgTest(OPENID_NS, 'mode', 'error')
    test_getArgNS1 = mkGetArgTest(OPENID1_NS, 'mode', 'error')
    test_getArgNS2 = mkGetArgTest(OPENID2_NS, 'mode')
    test_getArgNS3 = mkGetArgTest('urn:nothing-significant', 'mode')

    def test_getArgs(self):
        self.assertEqual(self.msg.getArgs(OPENID_NS), {'mode': 'error', 'error': 'unit test'})

    def test_getArgsBARE(self):
        self.assertEqual(self.msg.getArgs(BARE_NS), {})

    def test_getArgsNS1(self):
        self.assertEqual(self.msg.getArgs(OPENID1_NS), {'mode': 'error', 'error': 'unit test'})

    def test_getArgsNS2(self):
        self.assertEqual(self.msg.getArgs(OPENID2_NS), {})

    def test_getArgsNS3(self):
        self.assertEqual(self.msg.getArgs('urn:nothing-significant'), {})

    def _test_updateArgsNS(self, ns, before=None):
        if before is None:
            before = {}
        update_args = {
            'Camper van Beethoven': 'David Lowery',
            'Magnolia Electric Co.': 'Jason Molina',
        }

        self.assertEqual(self.msg.getArgs(ns), before)
        self.msg.updateArgs(ns, update_args)
        after = dict(before)
        after.update(update_args)
        self.assertEqual(self.msg.getArgs(ns), after)

    def test_updateArgs(self):
        self._test_updateArgsNS(OPENID_NS, before={'mode': 'error', 'error': 'unit test'})

    def test_updateArgsBARE(self):
        self._test_updateArgsNS(BARE_NS)

    def test_updateArgsNS1(self):
        self._test_updateArgsNS(OPENID1_NS, before={'mode': 'error', 'error': 'unit test'})

    def test_updateArgsNS2(self):
        self._test_updateArgsNS(OPENID2_NS)

    def test_updateArgsNS3(self):
        self._test_updateArgsNS('urn:nothing-significant')

    def _test_setArgNS(self, ns):
        key = 'Camper van Beethoven'
        value = 'David Lowery'
        self.assertIsNone(self.msg.getArg(ns, key))
        self.msg.setArg(ns, key, value)
        self.assertEqual(self.msg.getArg(ns, key), value)

    def test_setArg(self):
        self._test_setArgNS(OPENID_NS)

    def test_setArgBARE(self):
        self._test_setArgNS(BARE_NS)

    def test_setArgNS1(self):
        self._test_setArgNS(OPENID1_NS)

    def test_setArgNS2(self):
        self._test_setArgNS(OPENID2_NS)

    def test_setArgNS3(self):
        self._test_setArgNS('urn:nothing-significant')

    def _test_delArgNS(self, ns):
        key = 'Camper van Beethoven'
        value = 'David Lowery'

        self.assertRaises(KeyError, self.msg.delArg, ns, key)
        self.msg.setArg(ns, key, value)
        self.assertEqual(self.msg.getArg(ns, key), value)
        self.msg.delArg(ns, key)
        self.assertIsNone(self.msg.getArg(ns, key))

    def test_delArg(self):
        self._test_delArgNS(OPENID_NS)

    def test_delArgBARE(self):
        self._test_delArgNS(BARE_NS)

    def test_delArgNS1(self):
        self._test_delArgNS(OPENID1_NS)

    def test_delArgNS2(self):
        self._test_delArgNS(OPENID2_NS)

    def test_delArgNS3(self):
        self._test_delArgNS('urn:nothing-significant')

    def test_isOpenID1(self):
        self.assertTrue(self.msg.isOpenID1())

    def test_isOpenID2(self):
        self.assertFalse(self.msg.isOpenID2())


class OpenID1ExplicitMessageTest(unittest.TestCase):
    def setUp(self):
        self.msg = Message.fromPostArgs({'openid.mode': 'error', 'openid.error': 'unit test', 'openid.ns': OPENID1_NS})

    def test_toPostArgs(self):
        self.assertEqual(self.msg.toPostArgs(),
                         {'openid.mode': 'error', 'openid.error': 'unit test', 'openid.ns': OPENID1_NS})

    def test_toArgs(self):
        self.assertEqual(self.msg.toArgs(), {'mode': 'error', 'error': 'unit test', 'ns': OPENID1_NS})

    def test_toKVForm(self):
        self.assertEqual(self.msg.toKVForm(), 'error:unit test\nmode:error\nns:%s\n' % OPENID1_NS)

    def test_toURLEncoded(self):
        self.assertEqual(self.msg.toURLEncoded(),
                         'openid.error=unit+test&openid.mode=error&openid.ns=http%3A%2F%2Fopenid.net%2Fsignon%2F1.0')

    def test_toURL(self):
        base_url = 'http://base.url/'
        actual = self.msg.toURL(base_url)
        actual_base = actual[:len(base_url)]
        self.assertEqual(actual_base, base_url)
        self.assertEqual(actual[len(base_url)], '?')
        query = actual[len(base_url) + 1:]
        parsed = parse_qs(query)
        self.assertEqual(parsed,
                         {'openid.mode': ['error'], 'openid.error': ['unit test'], 'openid.ns': [OPENID1_NS]})

    def test_isOpenID1(self):
        self.assertTrue(self.msg.isOpenID1())


class OpenID2MessageTest(unittest.TestCase):
    def setUp(self):
        self.msg = Message.fromPostArgs({'openid.mode': 'error', 'openid.error': 'unit test', 'openid.ns': OPENID2_NS})
        self.msg.setArg(BARE_NS, "xey", "value")

    def test_toPostArgs(self):
        self.assertEqual(
            self.msg.toPostArgs(),
            {'openid.mode': 'error', 'openid.error': 'unit test', 'openid.ns': OPENID2_NS, 'xey': 'value'})

    def test_toPostArgs_bug_with_utf8_encoded_values(self):
        msg = Message.fromPostArgs({'openid.mode': 'error', 'openid.error': 'unit test', 'openid.ns': OPENID2_NS})
        msg.setArg(BARE_NS, 'ünicöde_key', 'ünicöde_välüe')
        post_args = {'openid.mode': 'error', 'openid.error': 'unit test', 'openid.ns': OPENID2_NS,
                     'ünicöde_key': 'ünicöde_välüe'}
        self.assertEqual(msg.toPostArgs(), post_args)

    def test_toArgs(self):
        # This method can't tolerate BARE_NS.
        self.msg.delArg(BARE_NS, "xey")
        self.assertEqual(self.msg.toArgs(), {'mode': 'error', 'error': 'unit test', 'ns': OPENID2_NS})

    def test_toKVForm(self):
        # Can't tolerate BARE_NS in kvform
        self.msg.delArg(BARE_NS, "xey")
        self.assertEqual(self.msg.toKVForm(), 'error:unit test\nmode:error\nns:%s\n' % OPENID2_NS)

    def _test_urlencoded(self, s):
        expected = ('openid.error=unit+test&openid.mode=error&openid.ns=%s&xey=value' %
                    urllib.quote(OPENID2_NS, ''))
        self.assertEqual(s, expected)

    def test_toURLEncoded(self):
        self._test_urlencoded(self.msg.toURLEncoded())

    def test_toURL(self):
        base_url = 'http://base.url/'
        actual = self.msg.toURL(base_url)
        actual_base = actual[:len(base_url)]
        self.assertEqual(actual_base, base_url)
        self.assertEqual(actual[len(base_url)], '?')
        query = actual[len(base_url) + 1:]
        self._test_urlencoded(query)

    def test_getOpenID(self):
        self.assertEqual(self.msg.getOpenIDNamespace(), OPENID2_NS)

    def test_getKeyOpenID(self):
        self.assertEqual(self.msg.getKey(OPENID_NS, 'mode'), 'openid.mode')

    def test_getKeyBARE(self):
        self.assertEqual(self.msg.getKey(BARE_NS, 'mode'), 'mode')

    def test_getKeyNS1(self):
        self.assertIsNone(self.msg.getKey(OPENID1_NS, 'mode'))

    def test_getKeyNS2(self):
        self.assertEqual(self.msg.getKey(OPENID2_NS, 'mode'), 'openid.mode')

    def test_getKeyNS3(self):
        self.assertIsNone(self.msg.getKey('urn:nothing-significant', 'mode'))

    def test_hasKeyOpenID(self):
        self.assertTrue(self.msg.hasKey(OPENID_NS, 'mode'))

    def test_hasKeyBARE(self):
        self.assertFalse(self.msg.hasKey(BARE_NS, 'mode'))

    def test_hasKeyNS1(self):
        self.assertFalse(self.msg.hasKey(OPENID1_NS, 'mode'))

    def test_hasKeyNS2(self):
        self.assertTrue(self.msg.hasKey(OPENID2_NS, 'mode'))

    def test_hasKeyNS3(self):
        self.assertFalse(self.msg.hasKey('urn:nothing-significant', 'mode'))

    test_getArgBARE = mkGetArgTest(BARE_NS, 'mode')
    test_getArgNS = mkGetArgTest(OPENID_NS, 'mode', 'error')
    test_getArgNS1 = mkGetArgTest(OPENID1_NS, 'mode')
    test_getArgNS2 = mkGetArgTest(OPENID2_NS, 'mode', 'error')
    test_getArgNS3 = mkGetArgTest('urn:nothing-significant', 'mode')

    def test_getArgsOpenID(self):
        self.assertEqual(self.msg.getArgs(OPENID_NS), {'mode': 'error', 'error': 'unit test'})

    def test_getArgsBARE(self):
        self.assertEqual(self.msg.getArgs(BARE_NS), {'xey': 'value'})

    def test_getArgsNS1(self):
        self.assertEqual(self.msg.getArgs(OPENID1_NS), {})

    def test_getArgsNS2(self):
        self.assertEqual(self.msg.getArgs(OPENID2_NS), {'mode': 'error', 'error': 'unit test'})

    def test_getArgsNS3(self):
        self.assertEqual(self.msg.getArgs('urn:nothing-significant'), {})

    def _test_updateArgsNS(self, ns, before=None):
        if before is None:
            before = {}
        update_args = {
            'Camper van Beethoven': 'David Lowery',
            'Magnolia Electric Co.': 'Jason Molina',
        }

        self.assertEqual(self.msg.getArgs(ns), before)
        self.msg.updateArgs(ns, update_args)
        after = dict(before)
        after.update(update_args)
        self.assertEqual(self.msg.getArgs(ns), after)

    def test_updateArgsOpenID(self):
        self._test_updateArgsNS(OPENID_NS, before={'mode': 'error', 'error': 'unit test'})

    def test_updateArgsBARE(self):
        self._test_updateArgsNS(BARE_NS, before={'xey': 'value'})

    def test_updateArgsNS1(self):
        self._test_updateArgsNS(OPENID1_NS)

    def test_updateArgsNS2(self):
        self._test_updateArgsNS(OPENID2_NS, before={'mode': 'error', 'error': 'unit test'})

    def test_updateArgsNS3(self):
        self._test_updateArgsNS('urn:nothing-significant')

    def _test_setArgNS(self, ns):
        key = 'Camper van Beethoven'
        value = 'David Lowery'
        self.assertIsNone(self.msg.getArg(ns, key))
        self.msg.setArg(ns, key, value)
        self.assertEqual(self.msg.getArg(ns, key), value)

    def test_setArgOpenID(self):
        self._test_setArgNS(OPENID_NS)

    def test_setArgBARE(self):
        self._test_setArgNS(BARE_NS)

    def test_setArgNS1(self):
        self._test_setArgNS(OPENID1_NS)

    def test_setArgNS2(self):
        self._test_setArgNS(OPENID2_NS)

    def test_setArgNS3(self):
        self._test_setArgNS('urn:nothing-significant')

    def test_badAlias(self):
        """Make sure dotted aliases and OpenID protocol fields are not
        allowed as namespace aliases."""

        for f in OPENID_PROTOCOL_FIELDS + ['dotted.alias']:
            args = {'openid.ns.%s' % f: 'blah',
                    'openid.%s.foo' % f: 'test'}

            # .fromPostArgs covers .fromPostArgs, .fromOpenIDArgs,
            # ._fromOpenIDArgs, and .fromOpenIDArgs (since it calls
            # .fromPostArgs).
            self.assertRaises(AssertionError, self.msg.fromPostArgs, args)

    def test_mysterious_missing_namespace_bug(self):
        """A failing test for bug #112"""
        openid_args = {
            'assoc_handle': '{{HMAC-SHA256}{1211477242.29743}{v5cadg==}',
            'claimed_id': 'http://nerdbank.org/OPAffirmative/AffirmativeIdentityWithSregNoAssoc.aspx',
            'ns.sreg': 'http://openid.net/extensions/sreg/1.1',
            'response_nonce': '2008-05-22T17:27:22ZUoW5.\\NV',
            'signed': 'return_to,identity,claimed_id,op_endpoint,response_nonce,ns.sreg,sreg.email,sreg.nickname,'
                      'assoc_handle',
            'sig': 'e3eGZ10+TNRZitgq5kQlk5KmTKzFaCRI8OrRoXyoFa4=',
            'mode': 'check_authentication',
            'op_endpoint': 'http://nerdbank.org/OPAffirmative/ProviderNoAssoc.aspx',
            'sreg.nickname': 'Andy',
            'return_to': 'http://localhost.localdomain:8001/process?janrain_nonce=2008-05-22T17%3A27%3A21ZnxHULd',
            'invalidate_handle': '{{HMAC-SHA1}{1211477241.92242}{H0akXw==}',
            'identity': 'http://nerdbank.org/OPAffirmative/AffirmativeIdentityWithSregNoAssoc.aspx',
            'sreg.email': 'a@b.com'}
        m = Message.fromOpenIDArgs(openid_args)

        self.assertEqual(m.namespaces.getAlias('http://openid.net/extensions/sreg/1.1'), 'sreg')
        missing = []
        for k in openid_args['signed'].split(','):
            if not ("openid." + k) in m.toPostArgs().keys():
                missing.append(k)
        self.assertEqual(missing, [])
        self.assertEqual(m.toArgs(), openid_args)
        self.assertTrue(m.isOpenID1())

    def test_112B(self):
        args = {
            'openid.assoc_handle': 'fa1f5ff0-cde4-11dc-a183-3714bfd55ca8',
            'openid.claimed_id': 'http://binkley.lan/user/test01',
            'openid.identity': 'http://test01.binkley.lan/',
            'openid.mode': 'id_res',
            'openid.ns': 'http://specs.openid.net/auth/2.0',
            'openid.ns.pape': 'http://specs.openid.net/extensions/pape/1.0',
            'openid.op_endpoint': 'http://binkley.lan/server',
            'openid.pape.auth_policies': 'none',
            'openid.pape.auth_time': '2008-01-28T20:42:36Z',
            'openid.pape.nist_auth_level': '0',
            'openid.response_nonce': '2008-01-28T21:07:04Z99Q=',
            'openid.return_to': 'http://binkley.lan:8001/process?janrain_nonce=2008-01-28T21%3A07%3A02Z0tMIKx',
            'openid.sig': 'YJlWH4U6SroB1HoPkmEKx9AyGGg=',
            'openid.signed': 'assoc_handle,identity,response_nonce,return_to,claimed_id,op_endpoint,pape.auth_time,'
                             'ns.pape,pape.nist_auth_level,pape.auth_policies'}
        m = Message.fromPostArgs(args)
        missing = []
        for k in args['openid.signed'].split(','):
            if not ("openid." + k) in m.toPostArgs().keys():
                missing.append(k)
        self.assertEqual(missing, [], missing)
        self.assertEqual(m.toPostArgs(), args)
        self.assertTrue(m.isOpenID2())

    def test_repetitive_namespaces(self):
        """
        Message that raises KeyError during encoding, because openid namespace is used in attributes
        """
        args = {
            'openid.assoc_handle': 'fa1f5ff0-cde4-11dc-a183-3714bfd55ca8',
            'openid.claimed_id': 'http://binkley.lan/user/test01',
            'openid.identity': 'http://test01.binkley.lan/',
            'openid.mode': 'id_res',
            'openid.ns': 'http://specs.openid.net/auth/2.0',
            'openid.op_endpoint': 'http://binkley.lan/server',
            'openid.response_nonce': '2008-01-28T21:07:04Z99Q=',
            'openid.return_to': 'http://binkley.lan:8001/process?janrain_nonce=2008-01-28T21%3A07%3A02Z0tMIKx',
            'openid.sig': 'YJlWH4U6SroB1HoPkmEKx9AyGGg=',
            'openid.signed': 'assoc_handle,identity,response_nonce,return_to,claimed_id,op_endpoint,pape.auth_time,'
                             'ns.pape,pape.nist_auth_level,pape.auth_policies',
            'openid.ns.pape': 'http://specs.openid.net/auth/2.0',
            'openid.pape.auth_policies': 'none',
            'openid.pape.auth_time': '2008-01-28T20:42:36Z',
            'openid.pape.nist_auth_level': '0',
        }
        self.assertRaises(InvalidNamespace, Message.fromPostArgs, args)

    def test_implicit_sreg_ns(self):
        openid_args = {'sreg.email': 'a@b.com'}
        m = Message.fromOpenIDArgs(openid_args)
        self.assertEqual(m.namespaces.getAlias(sreg.ns_uri), 'sreg')
        self.assertEqual(m.getArg(sreg.ns_uri, 'email'), 'a@b.com')
        self.assertEqual(m.toArgs(), openid_args)
        self.assertTrue(m.isOpenID1())

    def _test_delArgNS(self, ns):
        key = 'Camper van Beethoven'
        value = 'David Lowery'

        self.assertRaises(KeyError, self.msg.delArg, ns, key)
        self.msg.setArg(ns, key, value)
        self.assertEqual(self.msg.getArg(ns, key), value)
        self.msg.delArg(ns, key)
        self.assertIsNone(self.msg.getArg(ns, key))

    def test_delArgOpenID(self):
        self._test_delArgNS(OPENID_NS)

    def test_delArgBARE(self):
        self._test_delArgNS(BARE_NS)

    def test_delArgNS1(self):
        self._test_delArgNS(OPENID1_NS)

    def test_delArgNS2(self):
        self._test_delArgNS(OPENID2_NS)

    def test_delArgNS3(self):
        self._test_delArgNS('urn:nothing-significant')

    def test_overwriteExtensionArg(self):
        ns = 'urn:unittest_extension'
        key = 'mykey'
        value_1 = 'value_1'
        value_2 = 'value_2'

        self.msg.setArg(ns, key, value_1)
        self.assertEqual(self.msg.getArg(ns, key), value_1)
        self.msg.setArg(ns, key, value_2)
        self.assertEqual(self.msg.getArg(ns, key), value_2)

    def test_argList(self):
        self.assertRaises(TypeError, self.msg.fromPostArgs, {'arg': [1, 2, 3]})

    def test_isOpenID1(self):
        self.assertFalse(self.msg.isOpenID1())

    def test_isOpenID2(self):
        self.assertTrue(self.msg.isOpenID2())


class MessageTest(unittest.TestCase):
    def setUp(self):
        self.postargs = {
            'openid.ns': OPENID2_NS,
            'openid.mode': 'checkid_setup',
            'openid.identity': 'http://bogus.example.invalid:port/',
            'openid.assoc_handle': 'FLUB',
            'openid.return_to': 'Neverland',
        }

        self.action_url = 'scheme://host:port/path?query'

        self.form_tag_attrs = {
            'company': 'janrain',
            'class': 'fancyCSS',
        }

        self.submit_text = 'GO!'

        # Expected data regardless of input

        self.required_form_attrs = {
            'accept-charset': 'UTF-8',
            'enctype': 'application/x-www-form-urlencoded',
            'method': 'post',
        }

    def _checkForm(self, html, message_, action_url,
                   form_tag_attrs, submit_text):
        # Build element tree from HTML source
        input_tree = ElementTree.ElementTree(ElementTree.fromstring(html))

        # Get root element
        form = input_tree.getroot()

        # Check required form attributes
        for k, v in self.required_form_attrs.iteritems():
            assert form.attrib[k] == v, \
                "Expected '%s' for required form attribute '%s', got '%s'" % (v, k, form.attrib[k])

        # Check extra form attributes
        for k, v in form_tag_attrs.iteritems():

            # Skip attributes that already passed the required
            # attribute check, since they should be ignored by the
            # form generation code.
            if k in self.required_form_attrs:
                continue

            assert form.attrib[k] == v, \
                "Form attribute '%s' should be '%s', found '%s'" % (k, v, form.attrib[k])

        # Check hidden fields against post args
        hiddens = [e for e in form
                   if e.tag.upper() == 'INPUT' and e.attrib['type'].upper() == 'HIDDEN']

        # For each post arg, make sure there is a hidden with that
        # value.  Make sure there are no other hiddens.
        for name, value in message_.toPostArgs().iteritems():
            for e in hiddens:
                if e.attrib['name'] == name:
                    assert e.attrib['value'] == value, \
                        "Expected value of hidden input '%s' to be '%s', got '%s'" % \
                        (e.attrib['name'], value, e.attrib['value'])
                    break
            else:
                self.fail("Post arg '%s' not found in form" % (name,))

        for e in hiddens:
            assert e.attrib['name'] in message_.toPostArgs().keys(), \
                "Form element for '%s' not in original message" % (e.attrib['name'])

        # Check action URL
        assert form.attrib['action'] == action_url, \
            "Expected form 'action' to be '%s', got '%s'" % (action_url, form.attrib['action'])

        # Check submit text
        submits = [e for e in form
                   if e.tag.upper() == 'INPUT' and e.attrib['type'].upper() == 'SUBMIT']

        assert len(submits) == 1, \
            "Expected only one 'input' with type = 'submit', got %d" % (len(submits),)

        assert submits[0].attrib['value'] == submit_text, \
            "Expected submit value to be '%s', got '%s'" % (submit_text, submits[0].attrib['value'])

    def test_toFormMarkup(self):
        m = Message.fromPostArgs(self.postargs)
        html = m.toFormMarkup(self.action_url, self.form_tag_attrs,
                              self.submit_text)
        self._checkForm(html, m, self.action_url,
                        self.form_tag_attrs, self.submit_text)

    def test_toFormMarkup_bug_with_utf8_values(self):
        postargs = {
            'openid.ns': OPENID2_NS,
            'openid.mode': 'checkid_setup',
            'openid.identity': 'http://bogus.example.invalid:port/',
            'openid.assoc_handle': 'FLUB',
            'openid.return_to': 'Neverland',
            'ünicöde_key': 'ünicöde_välüe',
        }
        m = Message.fromPostArgs(postargs)
        html = m.toFormMarkup(self.action_url, self.form_tag_attrs,
                              self.submit_text)
        self.assertIn('ünicöde_key', html)
        self.assertIn('ünicöde_välüe', html)
        self.assertNotIn('&#195;&#188;nic&#195;&#182;de_key', html,
                         'UTF-8 bytes should not convert to XML character references')
        self.assertNotIn('&#195;&#188;nic&#195;&#182;de_v&#195;&#164;l&#195;&#188;e', html,
                         'UTF-8 bytes should not convert to XML character references')

    def test_overrideMethod(self):
        """Be sure that caller cannot change form method to GET."""
        m = Message.fromPostArgs(self.postargs)

        tag_attrs = dict(self.form_tag_attrs)
        tag_attrs['method'] = 'GET'

        html = m.toFormMarkup(self.action_url, self.form_tag_attrs,
                              self.submit_text)
        self._checkForm(html, m, self.action_url,
                        self.form_tag_attrs, self.submit_text)

    def test_overrideRequired(self):
        """Be sure that caller CANNOT change the form charset for
        encoding type."""
        m = Message.fromPostArgs(self.postargs)

        tag_attrs = dict(self.form_tag_attrs)
        tag_attrs['accept-charset'] = 'UCS4'
        tag_attrs['enctype'] = 'invalid/x-broken'

        html = m.toFormMarkup(self.action_url, tag_attrs,
                              self.submit_text)
        self._checkForm(html, m, self.action_url,
                        tag_attrs, self.submit_text)

    def test_setOpenIDNamespace_deprecated(self):
        message = Message()
        warning_msg = "Method 'setOpenIDNamespace' is deprecated. Pass namespace to Message constructor instead."
        with ShouldWarn(DeprecationWarning(warning_msg)):
            warnings.simplefilter('always')
            message.setOpenIDNamespace(OPENID2_NS, False)
        self.assertEqual(message.getOpenIDNamespace(), OPENID2_NS)

    def test_openid_namespace_invalid(self):
        invalid_things = [
            # Empty string is not okay here.
            '',
            # Good guess!  But wrong.
            'http://openid.net/signon/2.0',
            # What?
            u'http://specs%\\\r2Eopenid.net/auth/2.0',
            # Too much escapings!
            'http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0',
            # This is a Type URI, not a openid.ns value.
            'http://specs.openid.net/auth/2.0/signon',
        ]
        warning_msg = "Method 'setOpenIDNamespace' is deprecated. Pass namespace to Message constructor instead."

        for x in invalid_things:
            self.assertRaises(InvalidOpenIDNamespace, Message, x, False)
            # Test also deprecated setOpenIDNamespace
            message = Message()
            with ShouldWarn(DeprecationWarning(warning_msg)):
                warnings.simplefilter('always')
                self.assertRaises(InvalidOpenIDNamespace, message.setOpenIDNamespace, x, False)

    def test_isOpenID1(self):
        v1_namespaces = [
            # Yes, there are two of them.
            'http://openid.net/signon/1.1',
            'http://openid.net/signon/1.0',
        ]

        for ns in v1_namespaces:
            m = Message(ns)
            self.assertTrue(m.isOpenID1(), "%r not recognized as OpenID 1" % ns)
            self.assertEqual(m.getOpenIDNamespace(), ns)
            self.assertTrue(m.namespaces.isImplicit(ns))

    def test_isOpenID2(self):
        ns = 'http://specs.openid.net/auth/2.0'
        m = Message(ns)
        self.assertTrue(m.isOpenID2())
        self.assertFalse(m.namespaces.isImplicit(NULL_NAMESPACE))
        self.assertEqual(m.getOpenIDNamespace(), ns)

    def test_openid1_namespace_explicit(self):
        m = Message(THE_OTHER_OPENID1_NS, False)
        self.assertFalse(m.namespaces.isImplicit(THE_OTHER_OPENID1_NS))

    def test_openid1_namespace_implicit(self):
        m = Message(THE_OTHER_OPENID1_NS, True)
        self.assertTrue(m.namespaces.isImplicit(THE_OTHER_OPENID1_NS))

    def test_explicitOpenID11NSSerialzation(self):
        m = Message(THE_OTHER_OPENID1_NS, False)

        post_args = m.toPostArgs()
        self.assertEqual(post_args, {'openid.ns': THE_OTHER_OPENID1_NS})

    def test_fromPostArgs_ns11(self):
        # An example of the stuff that some Drupal installations send us,
        # which includes openid.ns but is 1.1.
        query = {
            u'openid.assoc_handle': u'',
            u'openid.claimed_id': u'http://foobar.invalid/',
            u'openid.identity': u'http://foobar.myopenid.com',
            u'openid.mode': u'checkid_setup',
            u'openid.ns': u'http://openid.net/signon/1.1',
            u'openid.ns.sreg': u'http://openid.net/extensions/sreg/1.1',
            u'openid.return_to': u'http://drupal.invalid/return_to',
            u'openid.sreg.required': u'nickname,email',
            u'openid.trust_root': u'http://drupal.invalid',
        }
        m = Message.fromPostArgs(query)
        self.assertTrue(m.isOpenID1())


class NamespaceMapTest(unittest.TestCase):
    def test_onealias(self):
        nsm = NamespaceMap()
        uri = 'http://example.com/foo'
        alias = "foo"
        nsm.addAlias(uri, alias)
        self.assertEqual(nsm.getNamespaceURI(alias), uri)
        self.assertEqual(nsm.getAlias(uri), alias)

    def test_iteration(self):
        nsm = NamespaceMap()
        uripat = 'http://example.com/foo%r'

        nsm.add(uripat % 0)
        for n in range(1, 23):
            self.assertIn(uripat % (n - 1), nsm)
            self.assertTrue(nsm.isDefined(uripat % (n - 1)))
            nsm.add(uripat % n)

        for (uri, alias) in nsm.iteritems():
            self.assertEqual(uri[22:], alias[3:])

        i = 0
        it = nsm.iterAliases()
        try:
            while True:
                it.next()
                i += 1
        except StopIteration:
            self.assertEqual(i, 23)

        i = 0
        it = nsm.iterNamespaceURIs()
        try:
            while True:
                it.next()
                i += 1
        except StopIteration:
            self.assertEqual(i, 23)


if __name__ == '__main__':
    unittest.main()
