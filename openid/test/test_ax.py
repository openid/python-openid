"""Tests for the attribute exchange extension module
"""

import unittest
from openid import ax
from openid.message import NamespaceMap

class BogusAXMessage(ax.AXMessage):
    mode = 'bogus'

    getExtensionArgs = ax.AXMessage._newArgs


class AXMessageTest(unittest.TestCase):
    def setUp(self):
        self.bax = BogusAXMessage()

    def test_checkMode(self):
        check = self.bax._checkMode
        self.failUnlessRaises(ax.AXError, check, {})
        self.failUnlessRaises(ax.AXError, check, {'mode':'fetch_request'})

        # does not raise an exception when the mode is right
        check({'mode':self.bax.mode})

    def test_checkMode_newArgs(self):
        """_newArgs generates something that has the correct mode"""
        self.bax._checkMode(self.bax._newArgs())


class AttrInfoTest(unittest.TestCase):
    def test_construct(self):
        self.failUnlessRaises(TypeError, ax.AttrInfo)
        type_uri = 'a uri'
        ainfo = ax.AttrInfo(type_uri)

        self.failUnlessEqual(type_uri, ainfo.type_uri)
        self.failUnless(ainfo.count is None)
        self.failIf(ainfo.required)
        self.failUnless(ainfo.alias is None)


class ToTypeURIsTest(unittest.TestCase):
    def setUp(self):
        self.aliases = NamespaceMap()

    def test_empty(self):
        for empty in [None, '']:
            uris = ax.toTypeURIs(self.aliases, empty)
            self.failUnlessEqual([], uris)

    def test_undefined(self):
        self.failUnlessRaises(
            KeyError,
            ax.toTypeURIs, self.aliases, 'http://janrain.com/')

    def test_one(self):
        uri = 'http://janrain.com/'
        alias = 'openid_hackers'
        self.aliases.addAlias(uri, alias)
        uris = ax.toTypeURIs(self.aliases, alias)
        self.failUnlessEqual([uri], uris)

    def test_two(self):
        uri1 = 'http://janrain.com/'
        alias1 = 'openid_hackers'
        self.aliases.addAlias(uri1, alias1)

        uri2 = 'http://jyte.com/'
        alias2 = 'openid_hack'
        self.aliases.addAlias(uri2, alias2)

        uris = ax.toTypeURIs(self.aliases, ','.join([alias1, alias2]))
        self.failUnlessEqual([uri1, uri2], uris)

class ParseAXValuesTest(unittest.TestCase):
    def failUnlessAXKeyError(self, ax_args):
        self.failUnlessRaises(KeyError, ax.parseAXValues, ax_args)

    def failUnlessAXValues(self, ax_args, expected_singletons, expected_args):
        singletons, data = ax.parseAXValues(ax_args)
        singletons.sort()
        expected_singletons = list(expected_singletons)
        expected_singletons.sort()
        self.failUnlessEqual(expected_singletons, singletons)
        self.failUnlessEqual(expected_args, data)

    def test_emptyIsValid(self):
        self.failUnlessAXValues({}, [], {})

    def test_missingValueForAliasExplodes(self):
        self.failUnlessAXKeyError({'type.foo':'urn:foo'})

    def test_countPresentButNotValue(self):
        self.failUnlessAXKeyError({'type.foo':'urn:foo',
                                   'count.foo':'1'})

    def test_countPresentAndIsZero(self):
        self.failUnlessAXValues(
            {'type.foo':'urn:foo',
             'count.foo':'0',
             }, [], {'urn:foo':[]})

    def test_singletonEmpty(self):
        self.failUnlessAXValues(
            {'type.foo':'urn:foo',
             'value.foo':'',
             }, ['urn:foo'], {'urn:foo':[]})

    def test_doubleAlias(self):
        self.failUnlessAXKeyError(
            {'type.foo':'urn:foo',
             'value.foo':'',
             'type.bar':'urn:foo',
             'value.bar':'',
             })

    def test_doubleSingleton(self):
        self.failUnlessAXValues(
            {'type.foo':'urn:foo',
             'value.foo':'',
             'type.bar':'urn:bar',
             'value.bar':'',
             }, ['urn:foo', 'urn:bar'], {'urn:foo':[], 'urn:bar':[]})

    def test_singletonValue(self):
        self.failUnlessAXValues(
            {'type.foo':'urn:foo',
             'value.foo':'Westfall',
             }, ['urn:foo'], {'urn:foo':['Westfall']})
