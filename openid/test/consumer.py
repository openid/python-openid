import urlparse
import cgi
import time

from openid import cryptutil, dh, oidutil, kvform
from openid.consumer.discover import OpenIDServiceEndpoint
from openid.consumer.consumer import \
     AuthRequest, GenericConsumer, SUCCESS, FAILURE, CANCEL, SETUP_NEEDED
from openid import association
from openid.server.server import \
     PlainTextServerSession, DiffieHellmanServerSession

from openid.consumer import parse

from urljr.fetchers import HTTPResponse, HTTPFetchingError
from urljr import fetchers

import _memstore

assocs = [
    ('another 20-byte key.', 'Snarky'),
    ('\x00' * 20, 'Zeros'),
    ]

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
        session = DiffieHellmanServerSession.fromQuery(q)
        reply_dict['session_type'] = 'DH-SHA1'
    else:
        assert len(q) == 2
        session = PlainTextServerSession.fromQuery(q)

    reply_dict.update(session.answer(assoc_secret))
    return kvform.dictToKV(reply_dict)

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
                if urlparse.urlparse(url)[0] == 'https':
                    # Should not be doing DH-SHA1 when using HTTPS.
                    assert body.find('DH-SHA1') == -1
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
        assoc.addSignature(['mode', 'return_to', 'identity'], query)

        info = consumer.complete(query, request.token)
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
        self.server_id = "sirod"
        self.server_url = "serlie"
        self.consumer_id = "consu"
        self.token = self.consumer._genToken(
            self.consumer_id,
            self.server_id,
            self.server_url,
            )



class TestQueryFormat(TestIdRes):
    def test_notAList(self):
        # Value should be a single string.  If it's a list, it should generate
        # an exception.
        query = {'openid.mode': ['cancel']}
        try:
            r = self.consumer.complete(query, 'badtoken')
        except TypeError, err:
            self.failUnless(str(err).find('values') != -1, err)
        else:
            self.fail("expected TypeError, got this instead: %s" % (r,))

class TestComplete(TestIdRes):
    def test_badTokenLength(self):
        query = {'openid.mode': 'id_res'}
        r = self.consumer.complete(query, 'badtoken')
        self.failUnlessEqual(r.status, FAILURE)
        self.failUnless(r.identity_url is None)

    def test_badTokenSig(self):
        query = {'openid.mode': 'id_res'}
        r = self.consumer.complete(query, 'badtoken' + self.token)
        self.failUnlessEqual(r.status, FAILURE)
        self.failUnless(r.identity_url is None)

    def test_expiredToken(self):
        self.consumer.TOKEN_LIFETIME = -1 # in the past
        query = {'openid.mode': 'id_res'}
        r = self.consumer.complete(query, self.token)
        self.failUnlessEqual(r.status, FAILURE)
        self.failUnless(r.identity_url is None)

    def test_cancel(self):
        query = {'openid.mode': 'cancel'}
        r = self.consumer.complete(query, 'badtoken')
        self.failUnlessEqual(r.status, CANCEL)
        self.failUnless(r.identity_url is None)

    def test_error(self):
        msg = 'an error message'
        query = {'openid.mode': 'error',
                 'openid.error': msg,
                 }
        r = self.consumer.complete(query, 'badtoken')
        self.failUnlessEqual(r.status, FAILURE)
        self.failUnless(r.identity_url is None)
        self.failUnlessEqual(r.message, msg)

    def test_noMode(self):
        query = {}
        r = self.consumer.complete(query, 'badtoken')
        self.failUnlessEqual(r.status, FAILURE)
        self.failUnless(r.identity_url is None)

    def test_idResMissingField(self):
        query = {'openid.mode': 'id_res'}
        r = self.consumer.complete(query, self.token)
        self.failUnlessEqual(r.status, FAILURE)
        self.failUnlessEqual(r.identity_url, self.consumer_id)

    def test_idResURLMismatch(self):
        query = {'openid.mode': 'id_res',
                 'openid.return_to': 'return_to (just anything)',
                 'openid.identity': 'something wrong (not self.consumer_id)',
                 'openid.assoc_handle': 'does not matter',
                 }
        r = self.consumer.complete(query, self.token)
        self.failUnlessEqual(r.status, FAILURE)
        self.failUnlessEqual(r.identity_url, self.consumer_id)
        r.message.index('delegate')

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
        query = {'openid.mode': 'id_res'}
        r = self.consumer.complete(query, self.token)
        self.failUnlessEqual(r.status, FAILURE)
        self.failUnlessEqual(r.identity_url, self.consumer_id)
        r.message.index(IdResFetchFailingConsumer.message)

class TestSetupNeeded(TestIdRes):
    def test_setupNeeded(self):
        setup_url = 'http://unittest/setup-here'
        query = {
            'openid.mode': 'id_res',
            'openid.user_setup_url': setup_url,
            }
        ret = self.consumer._doIdRes(query,
                                     self.consumer_id,
                                     self.server_id,
                                     self.server_url,
                                     )
        self.failUnlessEqual(ret.status, SETUP_NEEDED)
        self.failUnlessEqual(ret.setup_url, setup_url)

class CheckAuthHappened(Exception): pass

class CheckAuthDetectingConsumer(GenericConsumer):
    def _checkAuth(self, *args):
        raise CheckAuthHappened(args)

class CatchLogs(object):
    def setUp(self):
        self.old_logger = oidutil.log
        oidutil.log = self.gotLogMessage
        self.messages = []

    def gotLogMessage(self, message):
        self.messages.append(message)

    def tearDown(self):
        oidutil.log = self.old_logger

class NonceIdResTest(TestIdRes):
    def setUp(self):
        self.old_logger = oidutil.log
        oidutil.log = lambda *args: None
        TestIdRes.setUp(self)

    def tearDown(self):
        oidutil.log = self.old_logger

    def test_missingNonce(self):
        setup_url = 'http://unittest/setup-here'
        query = {
            'openid.mode': 'id_res',
            'openid.return_to': 'return_to', # No nonce parameter on return_to
            'openid.identity': self.server_id,
            'openid.assoc_handle': 'not_found',
            }
        ret = self.consumer._doIdRes(query,
                                     self.consumer_id,
                                     self.server_id,
                                     self.server_url,
                                     )
        self.failUnlessEqual(ret.status, FAILURE)
        self.failUnlessEqual(ret.identity_url, self.consumer_id)

    def test_badNonce(self):
        setup_url = 'http://unittest/setup-here'
        query = {
            'openid.mode': 'id_res',
            'openid.return_to': 'return_to?nonce=xxx',
            'openid.identity': self.server_id,
            'openid.assoc_handle': 'not_found',
            }
        ret = self.consumer._doIdRes(query,
                                     self.consumer_id,
                                     self.server_id,
                                     self.server_url,
                                     )
        self.failUnlessEqual(ret.status, FAILURE)
        self.failUnlessEqual(ret.identity_url, self.consumer_id)

    def test_twoNonce(self):
        setup_url = 'http://unittest/setup-here'
        query = {
            'openid.mode': 'id_res',
            'openid.return_to': 'return_to?nonce=nonny&nonce=xxx',
            'openid.identity': self.server_id,
            'openid.assoc_handle': 'not_found',
            }
        ret = self.consumer._doIdRes(query,
                                     self.consumer_id,
                                     self.server_id,
                                     self.server_url,
                                     )
        self.failUnlessEqual(ret.status, FAILURE)
        self.failUnlessEqual(ret.identity_url, self.consumer_id)

class TestCheckAuthTriggered(TestIdRes, CatchLogs):
    consumer_class = CheckAuthDetectingConsumer

    def setUp(self):
        TestIdRes.setUp(self)
        CatchLogs.setUp(self)

    def _doIdRes(self, query):
        return self.consumer._doIdRes(
            query,
            self.consumer_id,
            self.server_id,
            self.server_url)

    def test_checkAuthTriggered(self):
        query = {
            'openid.return_to':self.return_to,
            'openid.identity':self.server_id,
            'openid.assoc_handle':'not_found',
            }
        try:
            result = self._doIdRes(query)
        except CheckAuthHappened:
            pass
        else:
            self.fail('_checkAuth did not happen. Result was: %r %s' %
                      (result, self.messages))

    def test_checkAuthTriggeredWithAssoc(self):
        # Store an association for this server that does not match the
        # handle that is in the query
        issued = time.time()
        lifetime = 1000
        assoc = association.Association(
            'handle', 'secret', issued, lifetime, 'HMAC-SHA1')
        self.store.storeAssociation(self.server_url, assoc)

        query = {
            'openid.return_to':self.return_to,
            'openid.identity':self.server_id,
            'openid.assoc_handle':'not_found',
            }
        try:
            result = self._doIdRes(query)
        except CheckAuthHappened:
            pass
        else:
            self.fail('_checkAuth did not happen. Result was: %r' % (result,))

    def test_expiredAssoc(self):
        # Store an expired association for the server with the handle
        # that is in the query
        issued = time.time() - 10
        lifetime = 0
        handle = 'handle'
        assoc = association.Association(
            handle, 'secret', issued, lifetime, 'HMAC-SHA1')
        self.failUnless(assoc.expiresIn <= 0)
        self.store.storeAssociation(self.server_url, assoc)

        query = {
            'openid.return_to':self.return_to,
            'openid.identity':self.server_id,
            'openid.assoc_handle':handle,
            }
        info = self._doIdRes(query)
        self.failUnlessEqual(FAILURE, info.status)
        self.failUnlessEqual(self.consumer_id, info.identity_url)
        info.message.index('expired') # raises an exception if it's not there

    def test_newerAssoc(self):
        # Store an expired association for the server with the handle
        # that is in the query
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

        good_assoc.addSignature(['return_to', 'identity'], query)
        info = self._doIdRes(query)
        self.failUnlessEqual(info.status, SUCCESS)
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

        self.fetcher = MockFetcher()
        fetchers.setDefaultFetcher(self.fetcher)

    def test_error(self):
        self.fetcher.response = HTTPResponse(
            "http://some_url", 404, {'Hea': 'der'}, 'blah:blah\n')
        query = {'openid.signed': 'stuff, things'}
        r = self.consumer._checkAuth(query, http_server_url)
        self.failIf(r)
        self.failUnless(self.messages)

    def test_bad_args(self):
        query = {
            'openid.signed':'foo',
            'closid.foo':'something',
            }
        consumer = BadArgCheckingConsumer(self.store)
        consumer._checkAuth(query, 'does://not.matter')

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
                              {'openid.signed':''},
                              'some://url')


class TestAuthRequest(unittest.TestCase):
    def setUp(self):
        self.endpoint = OpenIDServiceEndpoint()
        self.endpoint.delegate = 'http://server.unittest/joe'
        self.endpoint.server_url = 'http://server.unittest/'
        self.assoc = self
        self.assoc.handle = 'assoc@handle'
        self.authreq = AuthRequest('toooken', self.assoc, self.endpoint)

    def test_addExtensionArg(self):
        self.authreq.addExtensionArg('bag', 'color', 'brown')
        self.authreq.addExtensionArg('bag', 'material', 'paper')
        self.failUnlessEqual(self.authreq.extra_args,
                             {'openid.bag.color': 'brown',
                              'openid.bag.material': 'paper'})
        url = self.authreq.redirectURL('http://7.utest/', 'http://7.utest/r')
        self.failUnless(url.find('openid.bag.color=brown') != -1,
                        'extension arg not found in %s' % (url,))
        self.failUnless(url.find('openid.bag.material=paper') != -1,
                        'extension arg not found in %s' % (url,))


if __name__ == '__main__':
    unittest.main()
