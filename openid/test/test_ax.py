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
        self.failUnlessEqual(1, ainfo.count)
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
        msg = ax.AXKeyValueMessage()
        self.failUnlessRaises(KeyError, msg.parseExtensionArgs, ax_args)

    def failUnlessAXValues(self, ax_args, expected_args):
        msg = ax.AXKeyValueMessage()
        msg.parseExtensionArgs(ax_args)
        self.failUnlessEqual(expected_args, msg.data)

    def test_emptyIsValid(self):
        self.failUnlessAXValues({}, {})

    def test_missingValueForAliasExplodes(self):
        self.failUnlessAXKeyError({'type.foo':'urn:foo'})

    def test_countPresentButNotValue(self):
        self.failUnlessAXKeyError({'type.foo':'urn:foo',
                                   'count.foo':'1'})

    def test_invalidCountValue(self):
        msg = ax.FetchRequest()
        self.failUnlessRaises(ax.AXError,
                              msg.parseExtensionArgs,
                              {'type.foo':'urn:foo',
                               'count.foo':'bogus'})

    def test_requestUnlimitedValues(self):
        msg = ax.FetchRequest()

        msg.parseExtensionArgs(
            {'mode':'fetch_request',
             'required':'foo',
             'type.foo':'urn:foo',
             'count.foo':ax.UNLIMITED_VALUES})

        attrs = list(msg.iterAttrs())
        foo = attrs[0]

        self.failUnless(foo.count == ax.UNLIMITED_VALUES)
        self.failUnless(foo.wantsUnlimitedValues())

    def test_invalidAlias(self):
        types = [
            ax.AXKeyValueMessage,
            ax.FetchRequest
            ]

        inputs = [
            {'type.a.b':'urn:foo',
             'count.a.b':'1'},
            {'type.a,b':'urn:foo',
             'count.a,b':'1'},
            ]

        for typ in types:
            for input in inputs:
                msg = typ()
                self.failUnlessRaises(ax.AXError, msg.parseExtensionArgs,
                                      input)

    def test_countPresentAndIsZero(self):
        self.failUnlessAXValues(
            {'type.foo':'urn:foo',
             'count.foo':'0',
             }, {'urn:foo':[]})

    def test_singletonEmpty(self):
        self.failUnlessAXValues(
            {'type.foo':'urn:foo',
             'value.foo':'',
             }, {'urn:foo':[]})

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
             }, {'urn:foo':[], 'urn:bar':[]})

    def test_singletonValue(self):
        self.failUnlessAXValues(
            {'type.foo':'urn:foo',
             'value.foo':'Westfall',
             }, {'urn:foo':['Westfall']})


class FetchRequestTest(unittest.TestCase):
    def setUp(self):
        self.msg = ax.FetchRequest()
        self.type_a = 'http://janrain.example.com/a'
        self.alias_a = 'a'


    def test_mode(self):
        self.failUnlessEqual(self.msg.mode, 'fetch_request')

    def test_construct(self):
        self.failUnlessEqual({}, self.msg.requested_attributes)
        self.failUnlessEqual(None, self.msg.update_url)

        msg = ax.FetchRequest('hailstorm')
        self.failUnlessEqual({}, msg.requested_attributes)
        self.failUnlessEqual('hailstorm', msg.update_url)

    def test_add(self):
        uri = 'mud://puddle'

        # Not yet added:
        self.failIf(uri in self.msg)

        attr = ax.AttrInfo(uri)
        self.msg.add(attr)

        # Present after adding
        self.failUnless(uri in self.msg)

    def test_addTwice(self):
        uri = 'lightning://storm'

        attr = ax.AttrInfo(uri)
        self.msg.add(attr)
        self.failUnlessRaises(KeyError, self.msg.add, attr)

    def test_getExtensionArgs_empty(self):
        expected_args = {
            'mode':'fetch_request',
            }
        self.failUnlessEqual(expected_args, self.msg.getExtensionArgs())

    def test_getExtensionArgs_noAlias(self):
        attr = ax.AttrInfo(
            type_uri = 'type://of.transportation',
            )
        self.msg.add(attr)
        ax_args = self.msg.getExtensionArgs()
        for k, v in ax_args.iteritems():
            if v == attr.type_uri and k.startswith('type.'):
                alias = k[5:]
                break
        else:
            self.fail("Didn't find the type definition")

        self.failUnlessExtensionArgs({
            'type.' + alias:attr.type_uri,
            'if_available':alias,
            })

    def test_getExtensionArgs_alias_if_available(self):
        attr = ax.AttrInfo(
            type_uri = 'type://of.transportation',
            alias = 'transport',
            )
        self.msg.add(attr)
        self.failUnlessExtensionArgs({
            'type.' + attr.alias:attr.type_uri,
            'if_available':attr.alias,
            })

    def test_getExtensionArgs_alias_req(self):
        attr = ax.AttrInfo(
            type_uri = 'type://of.transportation',
            alias = 'transport',
            required = True,
            )
        self.msg.add(attr)
        self.failUnlessExtensionArgs({
            'type.' + attr.alias:attr.type_uri,
            'required':attr.alias,
            })

    def failUnlessExtensionArgs(self, expected_args):
        """Make sure that getExtensionArgs has the expected result

        This method will fill in the mode.
        """
        expected_args = dict(expected_args)
        expected_args['mode'] = self.msg.mode
        self.failUnlessEqual(expected_args, self.msg.getExtensionArgs())

    def test_isIterable(self):
        self.failUnlessEqual([], list(self.msg))
        self.failUnlessEqual([], list(self.msg.iterAttrs()))

    def test_getRequiredAttrs_empty(self):
        self.failUnlessEqual([], self.msg.getRequiredAttrs())

    def test_parseExtensionArgs_extraType(self):
        extension_args = {
            'mode':'fetch_request',
            'type.' + self.alias_a:self.type_a,
            }
        self.failUnlessRaises(ValueError,
                              self.msg.parseExtensionArgs, extension_args)

    def test_parseExtensionArgs(self):
        extension_args = {
            'mode':'fetch_request',
            'type.' + self.alias_a:self.type_a,
            'if_available':self.alias_a
            }
        self.msg.parseExtensionArgs(extension_args)
        self.failUnless(self.type_a in self.msg)
        self.failUnlessEqual([self.type_a], list(self.msg))
        attr_info = self.msg.requested_attributes.get(self.type_a)
        self.failUnless(attr_info)
        self.failIf(attr_info.required)
        self.failUnlessEqual(self.type_a, attr_info.type_uri)
        self.failUnlessEqual(self.alias_a, attr_info.alias)
        self.failUnlessEqual([attr_info], list(self.msg.iterAttrs()))

    def test_extensionArgs_idempotent(self):
        extension_args = {
            'mode':'fetch_request',
            'type.' + self.alias_a:self.type_a,
            'if_available':self.alias_a
            }
        self.msg.parseExtensionArgs(extension_args)
        self.failUnlessEqual(extension_args, self.msg.getExtensionArgs())
        self.failIf(self.msg.requested_attributes[self.type_a].required)

    def test_extensionArgs_idempotent_count_required(self):
        extension_args = {
            'mode':'fetch_request',
            'type.' + self.alias_a:self.type_a,
            'count.' + self.alias_a:'2',
            'required':self.alias_a
            }
        self.msg.parseExtensionArgs(extension_args)
        self.failUnlessEqual(extension_args, self.msg.getExtensionArgs())
        self.failUnless(self.msg.requested_attributes[self.type_a].required)

    def test_extensionArgs_count1(self):
        extension_args = {
            'mode':'fetch_request',
            'type.' + self.alias_a:self.type_a,
            'count.' + self.alias_a:'1',
            'if_available':self.alias_a,
            }
        extension_args_norm = {
            'mode':'fetch_request',
            'type.' + self.alias_a:self.type_a,
            'if_available':self.alias_a,
            }
        self.msg.parseExtensionArgs(extension_args)
        self.failUnlessEqual(extension_args_norm, self.msg.getExtensionArgs())


class FetchResponseTest(unittest.TestCase):
    def setUp(self):
        self.msg = ax.FetchResponse()
        self.value_a = 'monkeys'
        self.type_a = 'http://phone.home/'
        self.alias_a = 'robocop'

    def test_construct(self):
        self.failUnless(self.msg.update_url is None)
        self.failUnlessEqual({}, self.msg.data)

    def test_getExtensionArgs_empty(self):
        expected_args = {
            'mode':'fetch_response',
            }
        self.failUnlessEqual(expected_args, self.msg.getExtensionArgs())

    def test_getExtensionArgs_empty_request(self):
        expected_args = {
            'mode':'fetch_response',
            }
        req = ax.FetchRequest()
        self.failUnlessEqual(expected_args, self.msg.getExtensionArgs(req))

    def test_getExtensionArgs_empty_request_some(self):
        expected_args = {
            'mode':'fetch_response',
            }
        req = ax.FetchRequest()
        req.add(ax.AttrInfo('http://not.found/'))
        self.failUnlessEqual(expected_args, self.msg.getExtensionArgs(req))

    def test_getExtensionArgs_some_request(self):
        expected_args = {
            'mode':'fetch_response',
            'type.' + self.alias_a:self.type_a,
            'value.' + self.alias_a:self.value_a,
            }
        req = ax.FetchRequest()
        req.add(ax.AttrInfo(self.type_a, alias=self.alias_a))
        self.msg.addValue(self.type_a, self.value_a)
        self.failUnlessEqual(expected_args, self.msg.getExtensionArgs(req))

    def test_getExtensionArgs_some_not_request(self):
        req = ax.FetchRequest()
        self.msg.addValue(self.type_a, self.value_a)
        self.failUnlessRaises(KeyError, self.msg.getExtensionArgs, req)

    def test_getSingle_success(self):
        req = ax.FetchRequest()
        self.msg.addValue(self.type_a, self.value_a)
        self.failUnlessEqual(self.value_a, self.msg.getSingle(self.type_a))

    def test_getSingle_none(self):
        self.failUnlessEqual(None, self.msg.getSingle(self.type_a))

    def test_getSingle_extra(self):
        self.msg.setValues(self.type_a, ['x', 'y'])
        self.failUnlessRaises(ax.AXError, self.msg.getSingle, self.type_a)

    def test_get(self):
        self.failUnlessRaises(KeyError, self.msg.get, self.type_a)


class StoreRequestTest(unittest.TestCase):
    def setUp(self):
        self.msg = ax.StoreRequest()
        self.type_a = 'http://three.count/'
        self.alias_a = 'juggling'

    def test_construct(self):
        self.failUnlessEqual({}, self.msg.data)

    def test_getExtensionArgs_empty(self):
        args = self.msg.getExtensionArgs()
        expected_args = {
            'mode':'store_request',
            }
        self.failUnlessEqual(expected_args, args)

    def test_getExtensionArgs_nonempty(self):
        self.msg.setValues(self.type_a, ['foo', 'bar'])
        aliases = NamespaceMap()
        aliases.addAlias(self.type_a, self.alias_a)
        args = self.msg.getExtensionArgs(aliases)
        expected_args = {
            'mode':'store_request',
            'type.' + self.alias_a: self.type_a,
            'count.' + self.alias_a: '2',
            'value.%s.1' % (self.alias_a,):'foo',
            'value.%s.2' % (self.alias_a,):'bar',
            }
        self.failUnlessEqual(expected_args, args)

class StoreResponseTest(unittest.TestCase):
    def test_success(self):
        msg = ax.StoreResponse()
        self.failUnless(msg.succeeded())
        self.failIf(msg.error_message)
        self.failUnlessEqual({'mode':'store_response_success'},
                             msg.getExtensionArgs())

    def test_fail_nomsg(self):
        msg = ax.StoreResponse(False)
        self.failIf(msg.succeeded())
        self.failIf(msg.error_message)
        self.failUnlessEqual({'mode':'store_response_failure'},
                             msg.getExtensionArgs())

    def test_fail_msg(self):
        reason = 'no reason, really'
        msg = ax.StoreResponse(False, reason)
        self.failIf(msg.succeeded())
        self.failUnlessEqual(reason, msg.error_message)
        self.failUnlessEqual({'mode':'store_response_failure',
                              'error':reason}, msg.getExtensionArgs())
