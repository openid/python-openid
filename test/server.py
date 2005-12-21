from openid.server import server
import _memstore
import cgi
import urlparse
import urllib

def test():
    store = _memstore.MemoryStore()
    s = server.OpenIDServer('http://id.server.url/', store)

    args = {
        'openid.mode': 'checkid_immediate',
        'openid.identity': 'http://foo.com/',
        'openid.return_to': 'http://return.to/',
        }

    fail = lambda i, r: 0
    status, info = s.getOpenIDResponse('GET', args, fail)

    assert status == server.REDIRECT, status

    expected = 'http://return.to/?openid.mode=id_res&openid.user_setup_url='
    eargs = [
        ('openid.identity', 'http://foo.com/'),
        ('openid.mode', 'checkid_setup'),
        ('openid.return_to', 'http://return.to/'),
        ]
    expected += urllib.quote_plus('http://id.server.url/?' + urllib.urlencode(eargs))
    
    assert info == expected, (info, expected)

    

if __name__ == '__main__':
    test()
