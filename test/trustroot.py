from openid.trustroot import TrustRoot

def test():
    print 'Testing...'

    # test invalid trust root strings
    def assertBad(s):
        tr = TrustRoot.parse(s)
        assert tr is None, repr(tr)

    assertBad('baz.org')
    assertBad('*.foo.com')
    assertBad('http://*.schtuff.*/')
    assertBad('ftp://foo.com')
    assertBad('ftp://*.foo.com')
    assertBad('http://*.foo.com:80:90/')
    assertBad('foo.*.com')
    assertBad('http://foo.*.com')
    assertBad('http://www.*')
    assertBad('')
    assertBad(' ')
    assertBad(' \t\n ')
    assertBad(None)
    assertBad(5)

    # test valid trust root string
    def assertGood(s):
        tr = TrustRoot.parse(s)
        assert tr is not None

    assertGood('http://*/')
    assertGood('http://*.schtuff.com/')
    assertGood('http://*.schtuff.com')
    assertGood('http://www.schtuff.com/')
    assertGood('http://www.schtuff.com')
    assertGood('http://*.this.that.schtuff.com/')
    assertGood('http://*.com/')
    assertGood('http://*.com')
    assertGood('http://*.foo.com/path')
    assertGood('http://x.foo.com/path?action=foo2')
    assertGood('http://*.foo.com/path?action=foo2')
    assertGood('http://localhost:8081/')

    # test trust root sanity
    def assertSane(s, truth):
        tr = TrustRoot.parse(s)
        assert tr.isSane() == truth, (tr.isSane(), truth)

    assertSane('http://*.schtuff.com/', True)
    assertSane('http://*.foo.schtuff.com/', True)
    assertSane('http://*.com/', False)
    assertSane('http://*.com.au/', False)
    assertSane('http://*.co.uk/', False)
    assertSane('http://localhost:8082/?action=openid', True)
    assertSane('http://*.foo.notatld', False)
    assertSane('http://*.museum/', False)

    # XXX: what exactly is a sane trust root?
    #assertSane('http://*.k12.va.us/', False)

    # validate a url against a trust root
    def assertValid(trust_root, url, truth):
        tr = TrustRoot.parse(trust_root)
        assert tr.isSane()
        assert tr.validateURL(url) == truth, (tr.validateURL(url), truth)

    assertValid('http://*.foo.com', 'http://b.foo.com', True)
    assertValid('http://*.foo.com', 'http://b.foo.com/', True)
    assertValid('http://*.foo.com', 'http://b.foo.com/', True)
    assertValid('http://*.foo.com', 'http://b.foo.com', True)
    assertValid('http://*.b.foo.com', 'http://b.foo.com', True)
    assertValid('http://*.b.foo.com', 'http://x.b.foo.com', True)
    assertValid('http://*.bar.co.uk', 'http://www.bar.co.uk', True)
    assertValid('http://*.uoregon.edu', 'http://x.cs.uoregon.edu', True)

    assertValid('http://*.cs.uoregon.edu', 'http://x.uoregon.edu', False)
    assertValid('http://*.foo.com', 'http://bar.com', False)
    assertValid('http://*.foo.com', 'http://www.bar.com', False)
    assertValid('http://*.bar.co.uk', 'http://xxx.co.uk', False)

    # path validity
    assertValid('http://x.com/abc', 'http://x.com/', False)
    assertValid('http://x.com/abc', 'http://x.com/a', False)
    assertValid('http://*.x.com/abc', 'http://foo.x.com/abc', True)
    assertValid('http://*.x.com/abc', 'http://foo.x.com', False)
    assertValid('http://*.x.com', 'http://foo.x.com/gallery', True)
    assertValid('http://foo.x.com', 'http://foo.x.com/gallery', True)
    assertValid('http://foo.x.com/gallery', 'http://foo.x.com/gallery/xxx', True)
    assertValid('http://localhost:8081/x?action=openid',
                'http://localhost:8081/x?action=openid', True)
    assertValid('http://*.x.com/gallery', 'http://foo.x.com/gallery', True)

    assertValid('http://localhost:8082/?action=openid',
                'http://localhost:8082/?action=openid', True)
    assertValid('http://goathack.livejournal.org:8020/',
                'http://goathack.livejournal.org:8020/openid/login.bml', True)

    print 'All tests passed!'

if __name__ == '__main__':
    test()
