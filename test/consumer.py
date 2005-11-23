import urlparse
import urllib
import cgi

from openid import cryptutil, dh, oidutil, kvform
from openid.consumer.consumer import OpenIDConsumer, SUCCESS, \
     HTTP_FAILURE, PARSE_ERROR

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
    assert len(q) == 6
    assert q['openid.mode'] == 'associate'
    assert q['openid.assoc_type'] == 'HMAC-SHA1'
    assert q['openid.session_type'] == 'DH-SHA1'
    d = dh.DiffieHellman.fromBase64(q['openid.dh_modulus'], q['openid.dh_gen'])

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

if __name__ == '__main__':
    test()
