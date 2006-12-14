import urlparse
import cgi
import time

from openid.message import Message, OPENID_NS, OPENID2_NS, IDENTIFIER_SELECT
from openid import cryptutil, dh, oidutil, kvform
from openid.store.nonce import mkNonce, split as splitNonce
from openid.consumer.discover import OpenIDServiceEndpoint
from openid.consumer.consumer import \
     AuthRequest, GenericConsumer, SUCCESS, FAILURE, CANCEL, SETUP_NEEDED, \
     SuccessResponse, FailureResponse, SetupNeededResponse, CancelResponse, \
     DiffieHellmanSHA1ConsumerSession, Consumer
from openid import association
from openid.server.server import \
     PlainTextServerSession, DiffieHellmanSHA1ServerSession
from openid.yadis.manager import Discovery
from openid.yadis.discover import DiscoveryFailure


from openid.consumer import parse

from openid.fetchers import HTTPResponse, HTTPFetchingError
from openid import fetchers

import _memstore

assocs = [
    ('another 20-byte key.', 'Snarky'),
    ('\x00' * 20, 'Zeros'),
    ]

def mkSuccess(endpoint, q):
    """Convenience function to create a SuccessResponse with the given
    arguments, all signed."""
    signed_list = q.keys()
    return SuccessResponse(endpoint, Message.fromPostArgs(q), signed_list)

def parseQuery(qs):
    q = {}
    for (k, v) in cgi.parse_qsl(qs):
        assert not q.has_key(k)
        q[k] = v
    return q

def associate(qs, assoc_secret, assoc_handle):
    """Do the server's half of the associate call, using the given
    secret and handle."""
    q = parseQuery(qs)
    assert q['openid.mode'] == 'associate'
    assert q['openid.assoc_type'] == 'HMAC-SHA1'
    reply_dict = {
        'assoc_type':'HMAC-SHA1',
        'assoc_handle':assoc_handle,
        'expires_in':'600',
        }

    if q.get('openid.session_type') == 'DH-SHA1':
        assert len(q) == 6 or len(q) == 4
        message = Message.fromPostArgs(q)
        session = DiffieHellmanSHA1ServerSession.fromMessage(message)
        reply_dict['session_type'] = 'DH-SHA1'
    else:
        assert len(q) == 2
        session = PlainTextServerSession.fromQuery(q)

    reply_dict.update(session.answer(assoc_secret))
    return kvform.dictToKV(reply_dict)


GOODSIG = "[A Good Signature]"


class GoodAssociation:
    expiresIn = 3600
    handle = "-blah-"

    def getExpiresIn(self):
        return self.expiresIn

    def checkMessageSignature(self, message):
        return message.getArg(OPENID_NS, 'sig') == GOODSIG


class GoodAssocStore(_memstore.MemoryStore):
    def getAssociation(self, server_url, handle=None):
        return GoodAssociation()



class CatchLogs(object):

    def setUp(self):
        self.old_logger = oidutil.log
        oidutil.log = self.gotLogMessage
        self.messages = []


    def gotLogMessage(self, message):
        self.messages.append(message)


    def tearDown(self):
        oidutil.log = self.old_logger



class TestFetcher(object):
    def __init__(self, user_url, user_page, (assoc_secret, assoc_handle)):
        self.get_responses = {user_url:self.response(user_url, 200, user_page)}
        self.assoc_secret = assoc_secret
        self.assoc_handle = assoc_handle
        self.num_assocs = 0

    def response(self, url, status, body):
        return HTTPResponse(
            final_url=url, status=status, headers={}, body=body)

    def fetch(self, url, body=None, headers=None):
        if body is None:
            if url in self.get_responses:
                return self.get_responses[url]
        else:
            try:
                body.index('openid.mode=associate')
            except ValueError:
                pass # fall through
            else:
                assert body.find('DH-SHA1') != -1
                response = associate(
                    body, self.assoc_secret, self.assoc_handle)
                self.num_assocs += 1
                return self.response(url, 200, response)

        return self.response(url, 404, 'Not found')

def _test_success(server_url, user_url, delegate_url, links, immediate=False):
    store = _memstore.MemoryStore()
    if immediate:
        mode = 'checkid_immediate'
    else:
        mode = 'checkid_setup'

    endpoint = OpenIDServiceEndpoint()
    endpoint.identity_url = user_url
    endpoint.server_url = server_url
    endpoint.delegate = delegate_url

    fetcher = TestFetcher(None, None, assocs[0])
    fetchers.setDefaultFetcher(fetcher, wrap_exceptions=False)

    def run():
        trust_root = consumer_url

        consumer = GenericConsumer(store)
        request = consumer.begin(endpoint)
        return_to = consumer_url

        m = request.getMessage(trust_root, return_to, immediate)
        
        redirect_url = request.redirectURL(trust_root, return_to, immediate)

        parsed = urlparse.urlparse(redirect_url)
        qs = parsed[4]
        q = parseQuery(qs)
        new_return_to = q['openid.return_to']
        del q['openid.return_to']
        assert q == {
            'openid.mode':mode,
            'openid.identity':delegate_url,
            'openid.trust_root':trust_root,
            'openid.assoc_handle':fetcher.assoc_handle,
            }, (q, user_url, delegate_url, mode)

        assert new_return_to.startswith(return_to)
        assert redirect_url.startswith(server_url)

        query = {
            'nonce':request.return_to_args['nonce'],
            'openid.mode':'id_res',
            'openid.return_to':new_return_to,
            'openid.identity':delegate_url,
            'openid.assoc_handle':fetcher.assoc_handle,
            }

        assoc = store.getAssociation(server_url, fetcher.assoc_handle)

        message = Message.fromPostArgs(query)
        message = assoc.signMessage(message)
        info = consumer.complete(message, request.endpoint)
        assert info.status == SUCCESS, info.message
        assert info.identity_url == user_url

    assert fetcher.num_assocs == 0
    run()
    assert fetcher.num_assocs == 1

    # Test that doing it again uses the existing association
    run()
    assert fetcher.num_assocs == 1

    # Another association is created if we remove the existing one
    store.removeAssociation(server_url, fetcher.assoc_handle)
    run()
    assert fetcher.num_assocs == 2

    # Test that doing it again uses the existing association
    run()
    assert fetcher.num_assocs == 2

import unittest

http_server_url = 'http://server.example.com/'
consumer_url = 'http://consumer.example.com/'
https_server_url = 'https://server.example.com/'

class TestSuccess(unittest.TestCase):
    server_url = http_server_url
    user_url = 'http://www.example.com/user.html'
    delegate_url = 'http://consumer.example.com/user'

    def setUp(self):
        self.links = '<link rel="openid.server" href="%s" />' % (
            self.server_url,)

        self.delegate_links = ('<link rel="openid.server" href="%s" />'
                               '<link rel="openid.delegate" href="%s" />') % (
            self.server_url, self.delegate_url)

    def test_nodelegate(self):
        _test_success(self.server_url, self.user_url,
                      self.user_url, self.links)

    def test_nodelegateImmediate(self):
        _test_success(self.server_url, self.user_url,
                      self.user_url, self.links, True)

    def test_delegate(self):
        _test_success(self.server_url, self.user_url,
                      self.delegate_url, self.delegate_links)

    def test_delegateImmediate(self):
        _test_success(self.server_url, self.user_url,
                      self.delegate_url, self.delegate_links, True)


class TestSuccessHTTPS(TestSuccess):
    server_url = https_server_url


class TestConstruct(unittest.TestCase):
    def setUp(self):
        self.store_sentinel = object()

    def test_construct(self):
        oidc = GenericConsumer(self.store_sentinel)
        self.failUnless(oidc.store is self.store_sentinel)

    def test_nostore(self):
        self.failUnlessRaises(TypeError, GenericConsumer)


class TestIdRes(unittest.TestCase):
    consumer_class = GenericConsumer

    def setUp(self):
        self.store = _memstore.MemoryStore()
        self.consumer = self.consumer_class(self.store)
        self.return_to = "nonny"
        self.endpoint = OpenIDServiceEndpoint()
        self.endpoint.identity_url = self.consumer_id = "consu"
        self.endpoint.server_url = self.server_url = "serlie"
        self.endpoint.delegate = self.server_id = "sirod"



class TestIdResCheckSignature(TestIdRes):
    def setUp(self):
        TestIdRes.setUp(self)
        self.assoc = GoodAssociation()
        self.assoc.handle = "{not_dumb}"
        self.store.storeAssociation(self.endpoint.server_url, self.assoc)

        self.message = Message.fromPostArgs({
            'openid.mode': 'id_res',
            'openid.identity': '=example',
            'openid.sig': GOODSIG,
            'openid.assoc_handle': self.assoc.handle,
            'openid.signed': 'mode,identity,assoc_handle,signed',
            'frobboz': 'banzit',
            })
        self.expected_signed = ['mode',
                                'signed',
                                'identity',
                                'assoc_handle']
        self.expected_signed.sort()


    def test_sign(self):
        # assoc_handle to assoc with good sig
        signed = self.consumer._idResCheckSignature(self.message,
                                                    self.endpoint.server_url)
        signed.sort()
        self.failUnlessEqual(self.expected_signed, signed)


    def test_stateless(self):
        # assoc_handle missing assoc, consumer._checkAuth returns goodthings
        self.message.setArg(OPENID_NS, "assoc_handle", "dumbHandle")
        self.consumer._processCheckAuthResponse = (
            lambda response, server_url: True)
        self.consumer._makeKVPost = lambda args, server_url: {}
        signed = self.consumer._idResCheckSignature(self.message,
                                                    self.endpoint.server_url)
        signed.sort()
        self.failUnlessEqual(self.expected_signed, signed)



class TestQueryFormat(TestIdRes):
    def test_notAList(self):
        # XXX: should be a Message object test, not a consumer test

        # Value should be a single string.  If it's a list, it should generate
        # an exception.
        query = {'openid.mode': ['cancel']}
        try:
            r = Message.fromPostArgs(query)
        except TypeError, err:
            self.failUnless(str(err).find('values') != -1, err)
        else:
            self.fail("expected TypeError, got this instead: %s" % (r,))

class TestComplete(TestIdRes):
    def test_cancel(self):
        message = Message.fromPostArgs({'openid.mode': 'cancel'})
        r = self.consumer.complete(message, self.endpoint)
        self.failUnlessEqual(r.status, CANCEL)
        self.failUnless(r.identity_url == self.endpoint.identity_url)

    def test_error(self):
        msg = 'an error message'
        message = Message.fromPostArgs({'openid.mode': 'error',
                 'openid.error': msg,
                 })
        r = self.consumer.complete(message, self.endpoint)
        self.failUnlessEqual(r.status, FAILURE)
        self.failUnless(r.identity_url == self.endpoint.identity_url)
        self.failUnlessEqual(r.message, msg)

    def test_errorWithNoOptionalKeys(self):
        msg = 'an error message'
        message = Message.fromPostArgs({'openid.mode': 'error',
                 'openid.error': msg, 'openid.reference': 'a ref',
                 'openid.contact': 'some contact info here',
                 })
        r = self.consumer.complete(message, self.endpoint)
        self.failUnlessEqual(r.status, FAILURE)
        self.failUnless(r.identity_url == self.endpoint.identity_url)
        self.failUnless(r.contact is None)
        self.failUnless(r.reference is None)
        self.failUnlessEqual(r.message, msg)

    def test_errorWithOptionalKeys(self):
        msg = 'an error message'
        contact = 'me'
        reference = 'support ticket'
        message = Message.fromPostArgs({'openid.mode': 'error',
                 'openid.error': msg, 'openid.reference': reference,
                 'openid.contact': contact, 'openid.ns': OPENID2_NS,
                 })
        r = self.consumer.complete(message, self.endpoint)
        self.failUnlessEqual(r.status, FAILURE)
        self.failUnless(r.identity_url == self.endpoint.identity_url)
        self.failUnless(r.contact == contact)
        self.failUnless(r.reference == reference)
        self.failUnlessEqual(r.message, msg)

    def test_noMode(self):
        message = Message.fromPostArgs({})
        r = self.consumer.complete(message, self.endpoint)
        self.failUnlessEqual(r.status, FAILURE)
        self.failUnless(r.identity_url == self.endpoint.identity_url)

    def test_idResMissingField(self):
        # XXX - this test is passing, but not necessarily by what it
        # is supposed to test for.  status in FAILURE, but it's because
        # *check_auth* failed, not because it's missing an arg, exactly.
        message = Message.fromPostArgs({'openid.mode': 'id_res'})
        r = self.consumer.complete(message, self.endpoint)
        self.failUnlessEqual(r.status, FAILURE)
        self.failUnlessEqual(r.identity_url, self.consumer_id)

    def test_idResURLMismatch(self):
        message = Message.fromPostArgs(
            {'openid.mode': 'id_res',
             'openid.return_to': 'return_to (just anything)',
             'openid.identity': 'something wrong (not self.consumer_id)',
             'openid.assoc_handle': 'does not matter',
             'openid.sig': GOODSIG,
             'openid.signed': 'identity,return_to',
             })
        self.consumer.store = GoodAssocStore()
        r = self.consumer.complete(message, self.endpoint)
        self.failUnlessEqual(r.status, FAILURE)
        self.failUnlessEqual(r.identity_url, self.consumer_id)
        self.failUnless(r.message.find('delegate') != -1,
                        r.message)



class TestCompleteMissingSig(unittest.TestCase, CatchLogs):

    def setUp(self):
        self.store = GoodAssocStore()
        self.consumer = GenericConsumer(self.store)
        self.server_url = "http://idp.unittest/"
        CatchLogs.setUp(self)

        self.message = Message.fromPostArgs(
            {'openid.mode': 'id_res',
             'openid.return_to': 'return_to (just anything)',
             'openid.identity': 'something something',
             'openid.assoc_handle': 'does not matter',
             'openid.sig': GOODSIG,
             'openid.nonce': mkNonce(),
             'openid.signed': 'identity,return_to,nonce',
             'openid.ns':OPENID2_NS,
             })
        self.endpoint = OpenIDServiceEndpoint()
        self.endpoint.server_url = self.server_url

    def tearDown(self):
        CatchLogs.tearDown(self)


    def test_idResMissingNoSigs(self):
        def _vrfy(vid, surl):
            endpoint = OpenIDServiceEndpoint()
            endpoint.identity_url = vid
            endpoint.server_url = surl
            endpoint.delegate = vid
            return endpoint

        self.consumer._verifyDiscoveryResults = _vrfy
        r = self.consumer.complete(self.message, self.endpoint)
        self.failUnlessSuccess(r)


    def test_idResNoIdentity(self):
        self.message.delArg(OPENID_NS, 'identity')
        self.message.setArg(OPENID_NS, 'signed', 'return_to,nonce')
        r = self.consumer.complete(self.message, self.endpoint)
        self.failUnlessSuccess(r)


    def test_idResMissingIdentitySig(self):
        self.message.setArg(OPENID_NS, 'signed', 'return_to,nonce')
        r = self.consumer.complete(self.message, self.endpoint)
        self.failUnlessEqual(r.status, FAILURE)


    def test_idResMissingReturnToSig(self):
        self.message.setArg(OPENID_NS, 'signed', 'identity,nonce')
        r = self.consumer.complete(self.message, self.endpoint)
        self.failUnlessEqual(r.status, FAILURE)


    def failUnlessSuccess(self, response):
        if response.status != SUCCESS:
            self.fail("Non-successful response: %s" % (response,))



class TestCheckAuthResponse(TestIdRes):
    def _createAssoc(self):
        issued = time.time()
        lifetime = 1000
        assoc = association.Association(
            'handle', 'secret', issued, lifetime, 'HMAC-SHA1')
        store = self.consumer.store
        store.storeAssociation(self.server_url, assoc)
        assoc2 = store.getAssociation(self.server_url)
        self.failUnlessEqual(assoc, assoc2)

    def test_goodResponse(self):
        """successful response to check_authentication"""
        response = {
            'is_valid':'true',
            }
        r = self.consumer._processCheckAuthResponse(response, self.server_url)
        self.failUnless(r)

    def test_missingAnswer(self):
        """check_authentication returns false when the server sends no answer"""
        response = {
            }
        r = self.consumer._processCheckAuthResponse(response, self.server_url)
        self.failIf(r)

    def test_badResponse(self):
        """check_authentication returns false when is_valid is false"""
        response = {
            'is_valid':'false',
            }
        r = self.consumer._processCheckAuthResponse(response, self.server_url)
        self.failIf(r)

    def test_badResponseInvalidate(self):
        """Make sure that the handle is invalidated when is_valid is false"""
        self._createAssoc()
        response = {
            'is_valid':'false',
            'invalidate_handle':'handle',
            }
        r = self.consumer._processCheckAuthResponse(response, self.server_url)
        self.failIf(r)
        self.failUnless(
            self.consumer.store.getAssociation(self.server_url) is None)

    def test_invalidateMissing(self):
        """invalidate_handle with a handle that is not present"""
        response = {
            'is_valid':'true',
            'invalidate_handle':'missing',
            }
        r = self.consumer._processCheckAuthResponse(response, self.server_url)
        self.failUnless(r)

    def test_invalidatePresent(self):
        """invalidate_handle with a handle that exists"""
        self._createAssoc()
        response = {
            'is_valid':'true',
            'invalidate_handle':'handle',
            }
        r = self.consumer._processCheckAuthResponse(response, self.server_url)
        self.failUnless(r)
        self.failUnless(
            self.consumer.store.getAssociation(self.server_url) is None)

class IdResFetchFailingConsumer(GenericConsumer):
    message = 'fetch failed'

    def _doIdRes(self, *args, **kwargs):
        raise HTTPFetchingError(self.message)

class TestFetchErrorInIdRes(TestIdRes):
    consumer_class = IdResFetchFailingConsumer

    def test_idResFailure(self):
        message = Message.fromPostArgs({'openid.mode': 'id_res'})
        r = self.consumer.complete(message, self.endpoint)
        self.failUnlessEqual(r.status, FAILURE)
        self.failUnlessEqual(r.identity_url, self.consumer_id)
        r.message.index(IdResFetchFailingConsumer.message)

class TestSetupNeeded(TestIdRes):
    def test_setupNeeded(self):
        setup_url = 'http://unittest/setup-here'
        message = Message.fromPostArgs({
            'openid.mode': 'id_res',
            'openid.user_setup_url': setup_url,
            })
        ret = self.consumer._doIdRes(message, self.endpoint,)
        self.failUnlessEqual(ret.status, SETUP_NEEDED)
        self.failUnlessEqual(ret.setup_url, setup_url)

class CheckAuthHappened(Exception): pass

class CheckAuthDetectingConsumer(GenericConsumer):
    def _checkAuth(self, *args):
        raise CheckAuthHappened(args)


class CheckNonceTest(TestIdRes, CatchLogs):
    def setUp(self):
        CatchLogs.setUp(self)
        TestIdRes.setUp(self)

    def tearDown(self):
        CatchLogs.tearDown(self)

    def test_consumerNonce(self):
        """use consumer-generated nonce"""
        self.return_to = 'http://rt.unittest/?nonce=%s' % (mkNonce(),)
        self.response = mkSuccess(self.endpoint,
                                  {'openid.return_to': self.return_to})
        ret = self.consumer._checkNonce(None, self.response)
        self.failUnlessEqual(ret.status, SUCCESS)
        self.failUnlessEqual(ret.identity_url, self.consumer_id)

    def test_serverNonce(self):
        """use server-generated nonce"""
        self.response = mkSuccess(self.endpoint,
                                  {'openid.ns':OPENID2_NS,
                                   'openid.nonce': mkNonce(),})
        ret = self.consumer._checkNonce(self.server_url, self.response)
        self.failUnlessEqual(ret.status, SUCCESS)
        self.failUnlessEqual(ret.identity_url, self.consumer_id)


    def test_badNonce(self):
        """remove the nonce from the store"""
        nonce = mkNonce()
        stamp, salt = splitNonce(nonce)
        self.store.useNonce(self.server_url, stamp, salt)
        self.response = mkSuccess(self.endpoint,
                                  {'openid.nonce': nonce,
                                   'openid.ns':OPENID2_NS,
                                   })
        ret = self.consumer._checkNonce(self.server_url, self.response)
        self.failUnlessEqual(ret.status, FAILURE)
        self.failUnlessEqual(ret.identity_url, self.consumer_id)
        self.failUnless(ret.message.startswith('Nonce missing from store'),
                        ret.message)


    def test_tamperedNonce(self):
        """Malformed nonce"""
        self.response = mkSuccess(self.endpoint, {'openid.ns':OPENID2_NS,
                                                  'openid.nonce':'malformed'})
        ret = self.consumer._checkNonce(self.server_url, self.response)
        self.failUnlessEqual(ret.status, FAILURE)
        self.failUnlessEqual(ret.identity_url, self.consumer_id)
        self.failUnless(ret.message.startswith('Malformed nonce'), ret.message)

    def test_missingNonce(self):
        """no nonce parameter on the return_to"""
        self.response = mkSuccess(self.endpoint,
                                  {'openid.return_to': self.return_to})
        ret = self.consumer._checkNonce(self.server_url, self.response)
        self.failUnlessEqual(ret.status, FAILURE)
        self.failUnlessEqual(ret.identity_url, self.consumer_id)
        self.failUnless(ret.message.startswith('Nonce missing from return_to'))



class TestCheckAuthTriggered(TestIdRes, CatchLogs):
    consumer_class = CheckAuthDetectingConsumer

    def setUp(self):
        TestIdRes.setUp(self)
        CatchLogs.setUp(self)

    def test_checkAuthTriggered(self):
        message = Message.fromPostArgs({
            'openid.return_to':self.return_to,
            'openid.identity':self.server_id,
            'openid.assoc_handle':'not_found',
            'openid.sig': GOODSIG,
            'openid.signed': 'identity,return_to',
            })
        try:
            result = self.consumer._doIdRes(message, self.endpoint)
        except CheckAuthHappened:
            pass
        else:
            self.fail('_checkAuth did not happen. Result was: %r %s' %
                      (result, self.messages))

    def test_checkAuthTriggeredWithAssoc(self):
        # Store an association for this server that does not match the
        # handle that is in the message
        issued = time.time()
        lifetime = 1000
        assoc = association.Association(
            'handle', 'secret', issued, lifetime, 'HMAC-SHA1')
        self.store.storeAssociation(self.server_url, assoc)

        message = Message.fromPostArgs({
            'openid.return_to':self.return_to,
            'openid.identity':self.server_id,
            'openid.assoc_handle':'not_found',
            'openid.sig': GOODSIG,
            'openid.signed': 'identity,return_to',
            })
        try:
            result = self.consumer._doIdRes(message, self.endpoint)
        except CheckAuthHappened:
            pass
        else:
            self.fail('_checkAuth did not happen. Result was: %r' % (result,))

    def test_expiredAssoc(self):
        # Store an expired association for the server with the handle
        # that is in the message
        issued = time.time() - 10
        lifetime = 0
        handle = 'handle'
        assoc = association.Association(
            handle, 'secret', issued, lifetime, 'HMAC-SHA1')
        self.failUnless(assoc.expiresIn <= 0)
        self.store.storeAssociation(self.server_url, assoc)

        message = Message.fromPostArgs({
            'openid.return_to':self.return_to,
            'openid.identity':self.server_id,
            'openid.assoc_handle':handle,
            'openid.sig': GOODSIG,
            'openid.signed': 'identity,return_to',
            })
        info = self.consumer._doIdRes(message, self.endpoint)
        self.failUnlessEqual(FAILURE, info.status)
        self.failUnlessEqual(self.consumer_id, info.identity_url)
        self.failUnless(info.message.find('expired') != -1,
                        info.message)

    def test_newerAssoc(self):
        lifetime = 1000

        good_issued = time.time() - 10
        good_handle = 'handle'
        good_assoc = association.Association(
            good_handle, 'secret', good_issued, lifetime, 'HMAC-SHA1')
        self.store.storeAssociation(self.server_url, good_assoc)

        bad_issued = time.time() - 5
        bad_handle = 'handle2'
        bad_assoc = association.Association(
            bad_handle, 'secret', bad_issued, lifetime, 'HMAC-SHA1')
        self.store.storeAssociation(self.server_url, bad_assoc)

        query = {
            'openid.return_to':self.return_to,
            'openid.identity':self.server_id,
            'openid.assoc_handle':good_handle,
            }

        message = Message.fromPostArgs(query)
        message = good_assoc.signMessage(message)
        info = self.consumer._doIdRes(message, self.endpoint)
        self.failUnlessEqual(info.status, SUCCESS, info.message)
        self.failUnlessEqual(self.consumer_id, info.identity_url)


class MockFetcher(object):
    def __init__(self, response=None):
        self.response = response or HTTPResponse()
        self.fetches = []

    def fetch(self, url, body=None, headers=None):
        self.fetches.append((url, body, headers))
        return self.response

class ExceptionRaisingMockFetcher(object):
    def fetch(self, url, body=None, headers=None):
        raise HTTPFetchingError('mock fetcher exception')

class BadArgCheckingConsumer(GenericConsumer):
    def _makeKVPost(self, args, _):
        assert args == {
            'openid.mode':'check_authentication',
            'openid.signed':'foo',
            }, args
        return None

class TestCheckAuth(unittest.TestCase, CatchLogs):
    consumer_class = GenericConsumer

    def setUp(self):
        CatchLogs.setUp(self)
        self.store = _memstore.MemoryStore()

        self.consumer = self.consumer_class(self.store)

        self._orig_fetcher = fetchers.getDefaultFetcher()
        self.fetcher = MockFetcher()
        fetchers.setDefaultFetcher(self.fetcher)

    def tearDown(self):
        CatchLogs.tearDown(self)
        fetchers.setDefaultFetcher(self._orig_fetcher)

    def test_error(self):
        self.fetcher.response = HTTPResponse(
            "http://some_url", 404, {'Hea': 'der'}, 'blah:blah\n')
        query = {'openid.signed': 'stuff',
                 'openid.stuff':'a value'}
        r = self.consumer._checkAuth(Message.fromPostArgs(query),
                                     http_server_url)
        self.failIf(r)
        self.failUnless(self.messages)

    def test_bad_args(self):
        query = {
            'openid.signed':'foo',
            'closid.foo':'something',
            }
        consumer = BadArgCheckingConsumer(self.store)
        consumer._checkAuth(Message.fromPostArgs(query), 'does://not.matter')


    def test_signedList(self):
        query = {
            'openid.mode': 'id_res',
            'openid.sig': 'rabbits',
            'openid.identity': '=example',
            'openid.assoc_handle': 'munchkins',
            'openid.signed': 'identity,mode',
            'foo': 'bar',
            }
        expected = {
            'openid.mode': 'check_authentication',
            'openid.sig': 'rabbits',
            'openid.assoc_handle': 'munchkins',
            'openid.identity': '=example',
            'openid.signed': 'identity,mode'
            }
        args = self.consumer._createCheckAuthRequest(
            Message.fromPostArgs(query))
        self.failUnlessEqual(args, expected)



class TestFetchAssoc(unittest.TestCase, CatchLogs):
    consumer_class = GenericConsumer

    def setUp(self):
        CatchLogs.setUp(self)
        self.store = _memstore.MemoryStore()
        self.fetcher = MockFetcher()
        fetchers.setDefaultFetcher(self.fetcher)
        self.consumer = self.consumer_class(self.store)

    def test_error(self):
        self.fetcher.response = HTTPResponse(
            "http://some_url", 404, {'Hea': 'der'}, 'blah:blah\n')
        r = self.consumer._makeKVPost({'openid.mode':'associate'},
                                      "http://server_url")
        self.failUnlessEqual(r, None)
        self.failUnless(self.messages)

    def test_error_exception(self):
        self.fetcher = ExceptionRaisingMockFetcher()
        fetchers.setDefaultFetcher(self.fetcher)
        self.failUnlessRaises(fetchers.HTTPFetchingError,
                              self.consumer._makeKVPost,
                              {'openid.mode':'associate'},
                              "http://server_url")

        # exception fetching returns no association
        self.failUnless(self.consumer._getAssociation('some://url') is None)

        self.failUnlessRaises(fetchers.HTTPFetchingError,
                              self.consumer._checkAuth,
                              Message.fromPostArgs({'openid.signed':''}),
                              'some://url')


class TestAuthRequest(unittest.TestCase):
    def setUp(self):
        self.endpoint = OpenIDServiceEndpoint()
        self.endpoint.delegate = 'http://server.unittest/joe'
        self.endpoint.server_url = 'http://server.unittest/'
        self.assoc = self
        self.assoc.handle = 'assoc@handle'
        self.authreq = AuthRequest(self.endpoint, self.assoc)

    def test_addExtensionArg(self):
        self.authreq.addExtensionArg('bag:', 'color', 'brown')
        self.authreq.addExtensionArg('bag:', 'material', 'paper')
        self.failUnless('bag:' in self.authreq.message.namespaces)
        self.failUnlessEqual(self.authreq.message.getArgs('bag:'),
                             {'color': 'brown',
                              'material': 'paper'})
        url = self.authreq.redirectURL('http://7.utest/', 'http://7.utest/r')
        self.failUnless(url.find('openid.ns.0=bag%3A') != -1,
                        'extension bag namespace not found in %s' % (url,))
        self.failUnless(url.find('openid.0.color=brown') != -1,
                        'extension arg not found in %s' % (url,))
        self.failUnless(url.find('openid.0.material=paper') != -1,
                        'extension arg not found in %s' % (url,))

    def test_idpEndpoint(self):
        self.endpoint.delegate = None
        self.endpoint.identity_url = None
        url = self.authreq.redirectURL('http://7.utest/', 'http://7.utest/r')
        _, qstring = url.split('?')
        params = dict(cgi.parse_qsl(qstring))
        self.failUnlessEqual(params['openid.identity'], IDENTIFIER_SELECT)

    def test_idpAnonymous(self):
        self.endpoint.delegate = None
        self.endpoint.identity_url = None
        self.authreq.anonymous = True
        url = self.authreq.redirectURL('http://7.utest/', 'http://7.utest/r')
        self.failUnless(url.find('openid.identity') == -1,
                        'unwanted openid.identity arg appeared in %s' % (url,))

    def test_userAnonymous(self):
        self.authreq.anonymous = True
        url = self.authreq.redirectURL('http://7.utest/', 'http://7.utest/r')
        self.failUnless(url.find('openid.identity') == -1,
                        'unwanted openid.identity arg appeared in %s' % (url,))

class TestSuccessResponse(unittest.TestCase):
    def setUp(self):
        self.endpoint = OpenIDServiceEndpoint()
        self.endpoint.identity_url = 'identity_url'

    def test_extensionResponse(self):
        resp = mkSuccess(self.endpoint, {
            'openid.ns.sreg':'urn:sreg',
            'openid.ns.unittest':'urn:unittest',
            'openid.unittest.one':'1',
            'openid.unittest.two':'2',
            'openid.sreg.nickname':'j3h',
            'openid.return_to':'return_to',
            })
        utargs = resp.message.getArgs('urn:unittest')
        self.failUnlessEqual(utargs, {'one':'1', 'two':'2'})
        sregargs = resp.message.getArgs('urn:sreg')
        self.failUnlessEqual(sregargs, {'nickname':'j3h'})

    def test_noReturnTo(self):
        resp = mkSuccess(self.endpoint, {})
        self.failUnless(resp.getReturnTo() is None)

    def test_returnTo(self):
        resp = mkSuccess(self.endpoint, {'openid.return_to':'return_to'})
        self.failUnlessEqual(resp.getReturnTo(), 'return_to')

class TestParseAssociation(TestIdRes):
    secret = 'x' * 20

    def test_missing(self):
        # Missing required arguments
        result = self.consumer._parseAssociation({}, None, 'server_url')
        self.failUnless(result is None)

    def _setUpDH(self):
        sess, args = \
                    self.consumer._createAssociateRequest(self.server_url,
                                                          'HMAC-SHA1',
                                                          'DH-SHA1')
        message = Message.fromPostArgs(args)
        server_sess = DiffieHellmanSHA1ServerSession.fromMessage(message)
        server_resp = server_sess.answer(self.secret)
        server_resp['assoc_type'] = 'HMAC-SHA1'
        server_resp['assoc_handle'] = 'handle'
        server_resp['expires_in'] = '1000'
        server_resp['session_type'] = 'DH-SHA1'
        return sess, server_resp

    def test_success(self):
        sess, server_resp = self._setUpDH()
        ret = self.consumer._parseAssociation(server_resp, sess, 'server_url')
        self.failIf(ret is None)
        self.failUnlessEqual(ret.assoc_type, 'HMAC-SHA1')
        self.failUnlessEqual(ret.secret, self.secret)
        self.failUnlessEqual(ret.handle, 'handle')
        self.failUnlessEqual(ret.lifetime, 1000)

    def test_badAssocType(self):
        sess, server_resp = self._setUpDH()
        server_resp['assoc_type'] = 'Crazy Low Prices!!!'
        ret = self.consumer._parseAssociation(server_resp, sess, 'server_url')
        self.failUnless(ret is None)

    def test_badExpiresIn(self):
        sess, server_resp = self._setUpDH()
        server_resp['expires_in'] = 'Crazy Low Prices!!!'
        ret = self.consumer._parseAssociation(server_resp, sess, 'server_url')
        self.failUnless(ret is None)

    def test_badSessionType(self):
        sess, server_resp = self._setUpDH()
        server_resp['session_type'] = '|/iA6rA'
        ret = self.consumer._parseAssociation(server_resp, sess, 'server_url')
        self.failUnless(ret is None)

    def test_plainFallback(self):
        sess = DiffieHellmanSHA1ConsumerSession()
        server_resp = {
            'assoc_type': 'HMAC-SHA1',
            'assoc_handle': 'handle',
            'expires_in': '1000',
            'mac_key': oidutil.toBase64(self.secret),
            }
        ret = self.consumer._parseAssociation(server_resp, sess, 'server_url')
        self.failIf(ret is None)
        self.failUnlessEqual(ret.assoc_type, 'HMAC-SHA1')
        self.failUnlessEqual(ret.secret, self.secret)
        self.failUnlessEqual(ret.handle, 'handle')
        self.failUnlessEqual(ret.lifetime, 1000)

    def test_plainFallbackFailure(self):
        sess = DiffieHellmanSHA1ConsumerSession()
        # missing mac_key
        server_resp = {
            'assoc_type': 'HMAC-SHA1',
            'assoc_handle': 'handle',
            'expires_in': '1000',
            }
        ret = self.consumer._parseAssociation(server_resp, sess, 'server_url')
        self.failUnless(ret is None)

    def test_badDHValues(self):
        sess, server_resp = self._setUpDH()
        server_resp['enc_mac_key'] = '\x00\x00\x00'
        ret = self.consumer._parseAssociation(server_resp, sess, 'server_url')
        self.failUnless(ret is None)

class StubConsumer(object):
    def __init__(self):
        self.assoc = object()
        self.response = None
        self.endpoint = None

    def begin(self, service):
        auth_req = AuthRequest(service, self.assoc)
        self.endpoint = service
        return auth_req

    def complete(self, message, endpoint):
        assert endpoint is self.endpoint
        return self.response

class ConsumerTest(unittest.TestCase):
    def setUp(self):
        self.endpoint = OpenIDServiceEndpoint()
        self.endpoint.identity_url = self.identity_url = 'http://identity.url/'
        self.store = None
        self.session = {}
        self.consumer = Consumer(self.session, self.store)
        self.consumer.consumer = StubConsumer()
        self.discovery = Discovery(self.session,
                                   self.identity_url,
                                   self.consumer.session_key_prefix)

    def test_beginWithoutDiscovery(self):
        # Does this really test anything non-trivial?
        result = self.consumer.beginWithoutDiscovery(self.endpoint)

        # The result is an auth request
        self.failUnless(isinstance(result, AuthRequest))

        # Side-effect of calling beginWithoutDiscovery is setting the
        # session value to the endpoint attribute of the result
        self.failUnless(self.session[self.consumer._token_key] is result.endpoint)

        # The endpoint that we passed in is the endpoint on the auth_request
        self.failUnless(result.endpoint is self.endpoint)

    def test_completeEmptySession(self):
        response = self.consumer.complete({})
        self.failUnlessEqual(response.status, FAILURE)
        self.failUnless(response.identity_url is None)

    def _doResp(self, auth_req, exp_resp):
        """complete a transaction, using the expected response from
        the generic consumer."""
        self.consumer.consumer.response = exp_resp

        # endpoint is stored in the session
        self.failUnless(self.session)
        resp = self.consumer.complete({})

        # All responses should have the same identity URL, and the
        # session should be cleaned out
        self.failUnless(resp.identity_url is self.identity_url)
        self.failIf(self.consumer._token_key in self.session)

        # Expected status response
        self.failUnlessEqual(resp.status, exp_resp.status)

        return resp

    def _doRespNoDisco(self, exp_resp):
        """Set up a transaction without discovery"""
        auth_req = self.consumer.beginWithoutDiscovery(self.endpoint)
        resp = self._doResp(auth_req, exp_resp)
        # There should be nothing left in the session once we have completed.
        self.failIf(self.session)
        return resp

    def test_noDiscoCompleteSuccessWithToken(self):
        self._doRespNoDisco(mkSuccess(self.endpoint, {}))

    def test_noDiscoCompleteCancelWithToken(self):
        self._doRespNoDisco(CancelResponse(self.endpoint))

    def test_noDiscoCompleteFailure(self):
        msg = 'failed!'
        resp = self._doRespNoDisco(FailureResponse(self.endpoint, msg))
        self.failUnless(resp.message is msg)

    def test_noDiscoCompleteSetupNeeded(self):
        setup_url = 'http://setup.url/'
        resp = self._doRespNoDisco(
            SetupNeededResponse(self.endpoint, setup_url))
        self.failUnless(resp.setup_url is setup_url)

    # To test that discovery is cleaned up, we need to initialize a
    # Yadis manager, and have it put its values in the session.
    def _doRespDisco(self, is_clean, exp_resp):
        """Set up and execute a transaction, with discovery"""
        self.discovery.createManager([self.endpoint], self.identity_url)
        auth_req = self.consumer.begin(self.identity_url)
        resp = self._doResp(auth_req, exp_resp)

        manager = self.discovery.getManager()
        if is_clean:
            self.failUnless(self.discovery.getManager() is None, manager)
        else:
            self.failIf(self.discovery.getManager() is None, manager)

        return resp

    # Cancel and success DO clean up the discovery process
    def test_completeSuccess(self):
        self._doRespDisco(True, mkSuccess(self.endpoint, {}))

    def test_completeCancel(self):
        self._doRespDisco(True, CancelResponse(self.endpoint))

    # Failure and setup_needed don't clean up the discovery process
    def test_completeFailure(self):
        msg = 'failed!'
        resp = self._doRespDisco(False, FailureResponse(self.endpoint, msg))
        self.failUnless(resp.message is msg)

    def test_completeSetupNeeded(self):
        setup_url = 'http://setup.url/'
        resp = self._doRespDisco(
            False,
            SetupNeededResponse(self.endpoint, setup_url))
        self.failUnless(resp.setup_url is setup_url)

    def test_begin(self):
        self.discovery.createManager([self.endpoint], self.identity_url)
        # Should not raise an exception
        auth_req = self.consumer.begin(self.identity_url)
        self.failUnless(isinstance(auth_req, AuthRequest))
        self.failUnless(auth_req.endpoint is self.endpoint)
        self.failUnless(auth_req.endpoint is self.consumer.consumer.endpoint)
        self.failUnless(auth_req.assoc is self.consumer.consumer.assoc)



class IDPDrivenTest(unittest.TestCase):

    def setUp(self):
        self.store = GoodAssocStore()
        self.consumer = GenericConsumer(self.store)
        self.endpoint = OpenIDServiceEndpoint()
        self.endpoint.server_url = "http://idp.unittest/"
        self.endpoint.type_uris = ['http://openid.net/server/2.0']


    def test_idpDrivenBegin(self):
        # Testing here that the token-handling doesn't explode...
        self.consumer.begin(self.endpoint)


    def test_idpDrivenComplete(self):
        identifier = '=directed_identifier'
        message = Message.fromPostArgs({
            'openid.identity': '=directed_identifier',
            'openid.return_to': 'x',
            'openid.assoc_handle': 'z',
            'openid.signed': 'identity,return_to',
            'openid.sig': GOODSIG,
            })

        endpoint = OpenIDServiceEndpoint()
        endpoint.identity_url = identifier
        endpoint.server_url = self.endpoint.server_url
        endpoint.delegate = identifier
        iverified = []
        def verifyDiscoveryResults(identifier, server_url):
            iverified.append(endpoint)
            return endpoint
        self.consumer._verifyDiscoveryResults = verifyDiscoveryResults
        response = self.consumer._doIdRes(message, self.endpoint)

        self.failUnlessSuccess(response)
        self.failUnlessEqual(response.identity_url, "=directed_identifier")

        # assert that discovery attempt happens and returns good
        self.failUnlessEqual(iverified, [endpoint])


    def test_idpDrivenCompleteFraud(self):
        # crap with an identifier that doesn't match discovery info
        message = Message.fromPostArgs({
            'openid.identity': '=directed_identifier',
            'openid.return_to': 'x',
            'openid.assoc_handle': 'z',
            'openid.signed': 'identity,return_to',
            'openid.sig': GOODSIG,
            })
        def verifyDiscoveryResults(identifier, server_url):
            raise DiscoveryFailure("PHREAK!", None)
        self.consumer._verifyDiscoveryResults = verifyDiscoveryResults
        response = self.consumer._doIdRes(message, self.endpoint)

        self.failIfEqual(response.status, SUCCESS)


    def failUnlessSuccess(self, response):
        if response.status != SUCCESS:
            self.fail("Non-successful response: %s" % (response,))



class TestDiscoveryVerification(unittest.TestCase):
    services = []

    def setUp(self):
        from openid.consumer import consumer
        self._orig_discoverURL = consumer.discoverURL
        consumer.discoverURL = self.discoveryFunc
        self.store = GoodAssocStore()
        self.consumer = GenericConsumer(self.store)

        self.identifier = "http://idp.unittest/1337"
        self.server_url = "http://endpoint.unittest/"


    def tearDown(self):
        from openid.consumer import consumer
        consumer.discoverURL = self._orig_discoverURL


    def test_theGoodStuff(self):
        endpoint = OpenIDServiceEndpoint()
        endpoint.identity_url = self.identifier
        endpoint.server_url = self.server_url
        endpoint.delegate = self.identifier
        self.services = [endpoint]
        r = self.consumer._verifyDiscoveryResults(self.identifier,
                                                  self.server_url)
        self.failUnlessEqual(r, endpoint)


    def test_otherServer(self):
        # a set of things without the stuff
        endpoint = OpenIDServiceEndpoint()
        endpoint.identity_url = self.identifier
        endpoint.server_url = "http://the-MOON.unittest/"
        endpoint.delegate = self.identifier
        self.services = [endpoint]
        self.failUnlessRaises(DiscoveryFailure,
                              self.consumer._verifyDiscoveryResults,
                              self.identifier, self.server_url)


    def test_foreignDelegate(self):
        # a set of things with the server stuff but other delegate
        endpoint = OpenIDServiceEndpoint()
        endpoint.identity_url = self.identifier
        endpoint.server_url = self.server_url
        endpoint.delegate = "http://unittest/juan-carlos"
        self.failUnlessRaises(DiscoveryFailure,
                              self.consumer._verifyDiscoveryResults,
                              self.identifier, self.server_url)


    def test_nothingDiscovered(self):
        # a set of no things.
        self.failUnlessRaises(DiscoveryFailure,
                              self.consumer._verifyDiscoveryResults,
                              self.identifier, self.server_url)


    def discoveryFunc(self, identifier):
        return identifier, self.services



if __name__ == '__main__':
    unittest.main()
