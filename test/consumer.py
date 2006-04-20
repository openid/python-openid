import urlparse
import cgi
import time

from openid import cryptutil, dh, oidutil, kvform
from openid.consumer.discover import OpenIDServiceEndpoint
from openid.consumer.consumer import OpenIDConsumer
from openid import association

from openid.consumer import parse

from urljr.fetchers import HTTPResponse
from urljr import fetchers

from yadis.discover import DiscoveryFailure

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
    if q.get('openid.session_type') == 'DH-SHA1':
        assert len(q) == 6 or len(q) == 4
        d = dh.DiffieHellman.fromBase64(
            q.get('openid.dh_modulus'), q.get('openid.dh_gen'))

        composite = cryptutil.base64ToLong(q['openid.dh_consumer_public'])
        enc_mac_key = oidutil.toBase64(d.xorSecret(composite, assoc_secret))
        reply_dict = {
            'assoc_type':'HMAC-SHA1',
            'assoc_handle':assoc_handle,
            'expires_in':'600',
            'session_type':'DH-SHA1',
            'dh_server_public':cryptutil.longToBase64(d.public),
            'enc_mac_key':enc_mac_key,
            }
    else:
        assert len(q) == 2
        mac_key = oidutil.toBase64(assoc_secret)
        reply_dict = {
            'assoc_type':'HMAC-SHA1',
            'assoc_handle':assoc_handle,
            'expires_in':'600',
            'mac_key':mac_key,
            }

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
        session = {}

        consumer = OpenIDConsumer(store)
        request = consumer.begin(endpoint, session)

        return_to = consumer_url
        redirect_url = request.redirectURL(trust_root, return_to, immediate)

        parsed = urlparse.urlparse(redirect_url)
        qs = parsed[4]
        q = parseQuery(qs)
        assert q == {
            'openid.mode':mode,
            'openid.identity':delegate_url,
            'openid.trust_root':trust_root,
            'openid.assoc_handle':fetcher.assoc_handle,
            'openid.return_to':return_to,
            }, (q, user_url, delegate_url, mode)

        assert redirect_url.startswith(server_url)

        query = {
            'openid.mode':'id_res',
            'openid.return_to':return_to,
            'openid.identity':delegate_url,
            'openid.assoc_handle':fetcher.assoc_handle,
            }

        assoc = store.getAssociation(server_url, fetcher.assoc_handle)
        assoc.addSignature(['mode', 'return_to', 'identity'], query)

        info = consumer.complete(query, session)
        assert info.status == 'success'
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
        oidc = OpenIDConsumer(self.store_sentinel)
        self.failUnless(oidc.store is self.store_sentinel)

    def test_nostore(self):
        self.failUnlessRaises(TypeError, OpenIDConsumer)


class TestIdRes(unittest.TestCase):
    consumer_class = OpenIDConsumer

    def setUp(self):
        self.store = _memstore.MemoryStore()
        self.consumer = self.consumer_class(self.store)
        self.return_to = "nonny"
        self.server_id = "sirod"
        self.server_url = "serlie"
        self.consumer_id = "consu"
        self.nonce = 'nonce'

class TestSetupNeeded(TestIdRes):
    def test_setupNeeded(self):
        setup_url = 'http://unittest/setup-here'
        query = {
            'openid.mode': 'id_res',
            'openid.user_setup_url': setup_url,
            }
        ret = self.consumer._doIdRes(query,
                                     self.nonce,
                                     self.consumer_id,
                                     self.server_id,
                                     self.server_url,
                                     )
        self.failUnlessEqual(ret.status, 'setup_needed')
        self.failUnlessEqual(ret.setup_url, setup_url)

class CheckAuthHappened(Exception): pass

class CheckAuthDetectingConsumer(OpenIDConsumer):
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

class TestCheckAuthTriggered(TestIdRes, CatchLogs):
    consumer_class = CheckAuthDetectingConsumer

    def setUp(self):
        TestIdRes.setUp(self)
        CatchLogs.setUp(self)

    def _doIdRes(self, query):
        return self.consumer._doIdRes(
            query,
            self.nonce,
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
        self.failUnlessEqual('failure', info.status)
        self.failUnlessEqual(self.consumer_id, info.identity_url)
        self.failUnlessEqual(1, len(self.messages), self.messages)
        message = self.messages[0].lower()
        message.index('expired') # raises an exception if it's not there

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

        self.store.storeNonce(self.nonce)

        query = {
            'openid.return_to':self.return_to,
            'openid.identity':self.server_id,
            'openid.assoc_handle':good_handle,
            }

        good_assoc.addSignature(['return_to', 'identity'], query)
        info = self._doIdRes(query)
        self.failUnlessEqual(info.status, 'success')
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
        raise Exception('mock fetcher exception')

class BadArgCheckingConsumer(OpenIDConsumer):
    def _makeKVPost(self, args, _):
        assert args == {
            'openid.mode':'check_authentication',
            'openid.signed':'foo',
            }, args
        return None

class TestCheckAuth(unittest.TestCase, CatchLogs):
    consumer_class = OpenIDConsumer

    def setUp(self):
        CatchLogs.setUp(self)
        self.store = _memstore.MemoryStore()

        self.consumer = self.consumer_class(self.store)

        self.fetcher = MockFetcher()
        fetchers.setDefaultFetcher(self.fetcher)

    def test_error(self):
        self.fetcher.response = HTTPResponse(
            "http://some_url", 404, {'Hea': 'der'}, 'blah:blah\n')
        nonce = "nonce"
        query = {'openid.signed': 'stuff, things'}
        r = self.consumer._checkAuth(nonce, query, http_server_url)
        self.failIf(r)
        self.failUnless(self.messages)

    def test_bad_args(self):
        query = {
            'openid.signed':'foo',
            'closid.foo':'something',
            }
        consumer = BadArgCheckingConsumer(self.store)
        consumer._checkAuth('nonce', query, 'does://not.matter')

class TestFetchAssoc(unittest.TestCase, CatchLogs):
    consumer_class = OpenIDConsumer

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
                              'nonce',
                              {'openid.signed':''},
                              'some://url')

if __name__ == '__main__':
    unittest.main()
