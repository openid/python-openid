import urlparse
import urllib
import cgi

from openid import cryptutil, dh, oidutil, kvform
from openid.consumer import interface

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
    d = dh.DiffieHellman.fromBase64(
        q['openid.dh_modulus'], q['openid.dh_gen'])

    composite = cryptutil.base64ToLong(q['openid.dh_consumer_public'])
    enc_mac_key = oidutil.toBase64(d.xorSecret(composite, assoc_secret))
    reply_dict = {
        'assoc_type':'HMAC-SHA1',
        'assoc_handle':assoc_handle,
        'expires_in':'600',
        'session_type':'DH-SHA1',
        'dh_server_public':cryptutil.longToBase64(d.createKeyExchange()),
        'enc_mac_key':enc_mac_key,
        }
    return kvform.dictToKV(reply_dict)

class TestFetcher(object):
    def __init__(self, user_url, user_page, (assoc_secret, assoc_handle)):
        self.get_responses = {user_url:(200, user_url, user_page)}
        self.assoc_secret = assoc_secret
        self.assoc_handle = assoc_handle

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
        if 'openid.mode=associate' in body:
            response = associate(body, self.assoc_secret, self.assoc_handle)
            return self.response(url, response)
        else:
            return self.response(url, None)

        
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

def test_success():
    store = _memstore.MemoryStore()

    user_url = 'http://www.example.com/user.html'
    consumer_url = 'http://consumer.example.com/'
    server_url = 'http://server.example.com/'
    links = '<link rel="openid.server" href="%s" />' % (server_url,)
    user_page = user_page_pat % links

    fetcher = TestFetcher(user_url, user_page, assocs[0])

    consumer = interface.OpenIDConsumer(store, fetcher)
    (status, info) = consumer.beginAuth(user_url)
    assert status == interface.SUCCESS, status

    return_to = consumer_url
    trust_root = consumer_url
    redirect_url = consumer.constructRedirect(info, return_to, trust_root)

    parsed = urlparse.urlparse(redirect_url)
    qs = parsed[4]
    q = parse(qs)
    assert q == {
        'openid.mode':'checkid_setup',
        'openid.identity':user_url,
        'openid.trust_root':trust_root,
        'openid.assoc_handle':fetcher.assoc_handle,
        'openid.return_to':return_to,
        }, q

    assert redirect_url.startswith(server_url)

    query = {
        'openid.mode':'id_res',
        'openid.return_to':return_to,
        'openid.identity':user_url,
        'openid.assoc_handle':fetcher.assoc_handle,
        }

    assoc = store.getAssociation(server_url, fetcher.assoc_handle)
    assoc.addSignature(['mode', 'return_to', 'identity'], query)

    (status, info) = consumer.completeAuth(info.token, query)
    assert status == 'success'
    assert info == user_url

def test_bad_fetch():
    store = _memstore.MemoryStore()
    fetcher = TestFetcher(None, None, (None, None))
    consumer = interface.OpenIDConsumer(store, fetcher)
    cases = [
        (None, 'http://network.error/'),
        (404, 'http://not.found/'),
        (400, 'http://bad.request/'),
        (500, 'http://server.error/'),
        ]
    for error_code, url in cases:
        fetcher.get_responses[url] = (error_code, url, None)
        (status, info) = consumer.beginAuth(url)
        assert status == interface.HTTP_FAILURE, status
        assert info == error_code, (url, info)

def test_bad_parse():
    store = _memstore.MemoryStore()
    user_url = 'http://user.example.com/'
    user_page = ''
    fetcher = TestFetcher(user_url, user_page, (None, None))
    consumer = interface.OpenIDConsumer(store, fetcher)
    status, info = consumer.beginAuth(user_url)
    assert status == interface.PARSE_ERROR
    assert info is None

def test():
    test_success()
    test_bad_fetch()
    test_bad_parse()

if __name__ == '__main__':
    test()
