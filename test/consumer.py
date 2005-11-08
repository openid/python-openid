import cgi
from openid import cryptutil, dh, oidutil, kvform
from openid.consumer import interface

assoc_secret = 'another 20-byte key.'
assoc_handle = 'Moustache'

class TestFetcher(object):
    def __init__(self):
        self.get_responses = {}
        self.post_responses = {}

    def response(self, url, data):
        if data is None:
            return (404, url, 'Not found')
        else:
            return (200, url, data)

    def get(self, url):
        return self.response(url, self.get_responses.get(url))

    def post(self, url, body):
        if 'openid.mode=associate' in body:
            return self._associate(url, body)
        elif 'openid.mode=check_authentication':
            return self._checkAuth(url, body)
        else:
            return self.response(url, None)

    def _associate(self, url, body):
        q = {}
        for (k, v) in cgi.parse_qsl(body):
            assert not q.has_key(k)
            q[k] = v

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
        reply_body = kvform.dictToKV(reply_dict)
        return self.response(url, reply_body)
        
import _memstore

def test():
    print 'Testing consumer'
    fetcher = TestFetcher()
    store = _memstore.MemoryStore()

    store.auth_key = '20-byte long secret.'
    user_url = 'http://www.example.com/user.html'
    consumer_url = 'http://consumer.example.com/'
    server_url = 'http://server.example.com/'
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

    links = '<link rel="openid.server" href="%s" />' % (server_url,)
    user_page = user_page_pat % links
    fetcher.get_responses[user_url] = user_page

    consumer = interface.OpenIDConsumer(store, fetcher)
    (status, info) = consumer.beginAuth(user_url)
    assert status == interface.SUCCESS, status
    return_to = consumer_url
    trust_root = consumer_url
    redirect_url = consumer.constructRedirect(info, return_to, trust_root)
    assert redirect_url == (
        'http://server.example.com/?'
        'openid.mode=checkid_setup&'
        'openid.identity=http%3A%2F%2Fwww.example.com%2Fuser.html&'
        'openid.trust_root=http%3A%2F%2Fconsumer.example.com%2F&'
        'openid.assoc_handle=Moustache&'
        'openid.return_to=http%3A%2F%2Fconsumer.example.com%2F'
        )

    query = {
        'openid.mode':'id_res',
        'openid.return_to':return_to,
        'openid.identity':user_url,
        'openid.assoc_handle':assoc_handle,
        }
    assoc = consumer.impl.store.getAssociation(server_url, assoc_handle)
    fields = ['mode', 'return_to', 'identity']
    sig = assoc.signDict(fields, query)
    query['openid.signed'] = ','.join(fields)
    query['openid.sig'] = sig
    (status, info) = consumer.completeAuth(info.token, query)
    assert status == 'success'
    assert info == user_url

if __name__ == '__main__':
    test()
