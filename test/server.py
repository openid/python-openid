from openid.server import server
import _memstore
import cgi
import urlparse
import urllib

def test():
    sv_url = 'http://id.server.url/'
    id_url = 'http://foo.com/'
    rt_url = 'http://return.to/'

    store = _memstore.MemoryStore()
    s = server.OpenIDServer(sv_url, store)

    # The only thing tested so far is the failure case of
    # checkid_immediate in dumb mode.
    args = {
        'openid.mode': 'checkid_immediate',
        'openid.identity': id_url,
        'openid.return_to': rt_url,
        }

    fail = lambda i, r: 0
    status, info = s.getOpenIDResponse('GET', args, fail)

    assert status == server.REDIRECT, status

    expected = rt_url + '?openid.mode=id_res&openid.user_setup_url='
    eargs = [
        ('openid.identity', id_url),
        ('openid.mode', 'checkid_setup'),
        ('openid.return_to', rt_url),
        ]
    expected += urllib.quote_plus(sv_url + '?' + urllib.urlencode(eargs))

    assert info == expected, (info, expected)


if __name__ == '__main__':
    test()
