import urlparse
import urllib
import cgi
import time

from openid import cryptutil, dh, oidutil, kvform
from openid.consumer.consumer import OpenIDConsumer, SUCCESS, \
     HTTP_FAILURE, PARSE_ERROR, SETUP_NEEDED, FAILURE
from openid import association

import _memstore

assocs = [
    ('another 20-byte key.', 'Snarky'),
    ('\x00' * 20, 'Zeros'),
    ]

def parse(qs):
    q = {}
    for (k, v) in cgi.parse_qsl(qs):
        assert not q.has_key(k)
        q[k] = v
    return q

def associate(qs, assoc_secret, assoc_handle):
    """Do the server's half of the associate call, using the given
    secret and handle."""
    q = parse(qs)
    assert len(q) == 6 or len(q) == 4
    assert q['openid.mode'] == 'associate'
    assert q['openid.assoc_type'] == 'HMAC-SHA1'
    assert q['openid.session_type'] == 'DH-SHA1'
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
    return kvform.dictToKV(reply_dict)

class TestFetcher(object):
    def __init__(self, user_url, user_page, (assoc_secret, assoc_handle)):
        self.get_responses = {user_url:(200, user_url, user_page)}
        self.assoc_secret = assoc_secret
        self.assoc_handle = assoc_handle
        self.num_assocs = 0

    def response(self, url, body):
        if body is None:
            return (404, url, 'Not found')
        else:
            return (200, url, body)

    def get(self, url):
        try:
            return self.get_responses[url]
        except KeyError:
            return self.response(url, None)

    def post(self, url, body):
        try:
            body.index('openid.mode=associate')
        except ValueError:
            return self.response(url, None)
        else:
            response = associate(body, self.assoc_secret, self.assoc_handle)
            self.num_assocs += 1
            return self.response(url, response)

user_page_pat = '''\
<html>
  <head>
    <title>A user page</title>
    %s
  </head>
  <body>
    blah blah
  </body>
</html>
'''
server_url = 'http://server.example.com/'
consumer_url = 'http://consumer.example.com/'

def _test_success(user_url, delegate_url, links, immediate=False):
    store = _memstore.MemoryStore()
    if immediate:
        mode = 'checkid_immediate'
    else:
        mode = 'checkid_setup'

    user_page = user_page_pat % (links,)
    fetcher = TestFetcher(user_url, user_page, assocs[0])

    consumer = OpenIDConsumer(store, fetcher, immediate)
    def run():
        (status, info) = consumer.beginAuth(user_url)
        assert status == SUCCESS, status

        return_to = consumer_url
        trust_root = consumer_url
        redirect_url = consumer.constructRedirect(info, return_to, trust_root)

        parsed = urlparse.urlparse(redirect_url)
        qs = parsed[4]
        q = parse(qs)
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

        (status, info) = consumer.completeAuth(info.token, query)
        assert status == 'success'
        assert info == user_url

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

def test_success():
    user_url = 'http://www.example.com/user.html'
    links = '<link rel="openid.server" href="%s" />' % (server_url,)

    delegate_url = 'http://consumer.example.com/user'
    delegate_links = ('<link rel="openid.server" href="%s" />'
             '<link rel="openid.delegate" href="%s" />') % (
        server_url, delegate_url)

    _test_success(user_url, user_url, links)
    _test_success(user_url, user_url, links, True)
    _test_success(user_url, delegate_url, delegate_links)
    _test_success(user_url, delegate_url, delegate_links, True)

def test_bad_fetch():
    store = _memstore.MemoryStore()
    fetcher = TestFetcher(None, None, (None, None))
    consumer = OpenIDConsumer(store, fetcher)
    cases = [
        (None, 'http://network.error/'),
        (404, 'http://not.found/'),
        (400, 'http://bad.request/'),
        (500, 'http://server.error/'),
        ]
    for error_code, url in cases:
        fetcher.get_responses[url] = (error_code, url, None)
        (status, info) = consumer.beginAuth(url)
        assert status == HTTP_FAILURE, status
        assert info == error_code, (url, info)

def test_bad_parse():
    store = _memstore.MemoryStore()
    user_url = 'http://user.example.com/'
    cases = [
        '',
        "http://not.in.a.link.tag/",
        '<link rel="openid.server" href="not.in.html.or.head" />',
        ]
    for user_page in cases:
        fetcher = TestFetcher(user_url, user_page, (None, None))
        consumer = OpenIDConsumer(store, fetcher)
        status, info = consumer.beginAuth(user_url)
        assert status == PARSE_ERROR
        assert info is None

def test_construct():
    store_sentinel = object()
    fetcher_sentinel = object()
    oidc = OpenIDConsumer(store_sentinel, fetcher_sentinel)
    assert oidc.store is store_sentinel
    assert oidc.fetcher is fetcher_sentinel
    assert not oidc.immediate

    oidc = OpenIDConsumer(store_sentinel, fetcher_sentinel, immediate=1)
    assert oidc.store is store_sentinel
    assert oidc.fetcher is fetcher_sentinel
    assert oidc.immediate

    oidc = OpenIDConsumer(store_sentinel, fetcher=None)
    f = oidc.fetcher
    assert hasattr(f, 'get')
    assert hasattr(f, 'post')

    try:
        oidc = OpenIDConsumer(fetcher=fetcher_sentinel)
    except TypeError:
        pass
    else:
        raise AssertionError('Instantiated a consumer without a store')

def test():
    test_success()
    test_bad_fetch()
    test_bad_parse()
    test_construct()




import unittest

class TestIdRes(unittest.TestCase):
    consumer_class = OpenIDConsumer

    def setUp(self):
        self.store = _memstore.MemoryStore()
        self.consumer = self.consumer_class(self.store)
        self.return_to = "nonny"
        self.server_id = "sirod"
        self.server_url = "serlie"
        self.consumer_id = "consu"
        self.token = self.consumer._genToken(self.return_to,
                                             self.consumer_id,
                                             self.server_id,
                                             self.server_url)

class TestSetupNeeded(TestIdRes):
    def test_setupNeeded(self):
        setup_url = 'http://unittest/setup-here'
        query = {
            'openid.mode': 'id_res',
            'openid.user_setup_url': setup_url,
            }
        ret = self.consumer._doIdRes(self.token, query)
        self.failUnlessEqual(ret[0], SETUP_NEEDED)
        self.failUnlessEqual(ret[1], setup_url)

class CheckAuthHappened(Exception): pass

class CheckAuthDetectingConsumer(OpenIDConsumer):
    def _checkAuth(self, *args):
        raise CheckAuthHappened(args)

class TestCheckAuthTriggered(TestIdRes):
    consumer_class = CheckAuthDetectingConsumer

    def setUp(self):
        TestIdRes.setUp(self)
        self.old_logger = oidutil.log
        oidutil.log = self.gotLogMessage
        self.messages = []

    def tearDown(self):
        oidutil.log = self.old_logger

    def gotLogMessage(self, message):
        self.messages.append(message)

    def test_checkAuthTriggered(self):
        query = {
            'openid.return_to':self.return_to,
            'openid.identity':self.server_id,
            'openid.assoc_handle':'not_found',
            }
        try:
            result = self.consumer._doIdRes(self.token, query)
        except CheckAuthHappened:
            pass
        else:
            self.fail('_checkAuth did not happen. Result was: %r' % result)

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
            result = self.consumer._doIdRes(self.token, query)
        except CheckAuthHappened:
            pass
        else:
            self.fail('_checkAuth did not happen. Result was: %r' % result)

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
        status, info = self.consumer._doIdRes(self.token, query)
        self.failUnlessEqual(FAILURE, status)
        self.failUnlessEqual(self.consumer_id, info)
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

        nonce = self.consumer._splitToken(self.token)[0]
        self.store.storeNonce(nonce)

        query = {
            'openid.return_to':self.return_to,
            'openid.identity':self.server_id,
            'openid.assoc_handle':good_handle,
            }

        good_assoc.addSignature(['return_to', 'identity'], query)
        status, info = self.consumer._doIdRes(self.token, query)

        self.failUnlessEqual(SUCCESS, status)
        self.failUnlessEqual(self.consumer_id, info)

if __name__ == '__main__':
    test()
    unittest.main()
