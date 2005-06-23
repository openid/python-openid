from urlparse import urlparse, urlunparse

def validateURL(trust_root, url):
    """quick func for validating a url against a trust root.  See the
    TrustRoot class if you need more control."""
    tr = TrustRoot.parse(trust_root, check_sanity=True)
    if tr is not None:
        return tr.validateURL(url)

    return False

############################################
_protocols = ['http', 'https']
_top_level_domains = (
    'com|edu|gov|int|mil|net|org|biz|info|name|museum|coop|aero|ac|ad|ae|'
    'af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|az|ba|bb|bd|be|bf|bg|bh|bi|bj|'
    'bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|'
    'cu|cv|cx|cy|cz|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|fi|fj|fk|fm|fo|'
    'fr|ga|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|'
    'ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|'
    'kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|mg|mh|mk|ml|mm|'
    'mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|'
    'nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|ru|rw|sa|'
    'sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|st|sv|sy|sz|tc|td|tf|tg|th|'
    'tj|tk|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|um|us|uy|uz|va|vc|ve|vg|vi|'
    'vn|vu|wf|ws|ye|yt|yu|za|zm|zw|localhost'
    ).split('|')


def parseURL(url):
    proto, netloc, path, params, query, frag = urlparse(url)
    path = urlunparse(('', '', path, params, query, frag))

    if ':' in netloc:
        try:
            host, port = netloc.split(':')
        except ValueError:
            return None
    else:
        host = netloc
        port = ''

    return proto, host, port, path



class TrustRoot(object):
    """Represents a valid openid trust root.  The parse classmethod
    accepts a trust root string, producing a TrustRoot object.
    """
    
    def __init__(self, unparsed, proto, wildcard, host, port, path):
        self.unparsed = unparsed
        self.proto = proto
        self.wildcard = wildcard
        self.host = host
        self.port = port
        self.path = path

        self._is_sane = None

    def isSane(self):
        """Checks the sanity of this trust root.
        http://*.com/ for example is not sane.  Returns a bool."""        
        if self._is_sane is not None:
            return self._is_sane

        if self.host == 'localhost':
            return True

        host_parts = self.host.split('.')

        # extract sane "top-level-domain"
        host = []
        if len(host_parts[-1]) == 2:
            if len(host_parts[-2]) <= 3:
                host = host_parts[:-2]
        elif len(host_parts[-1]) == 3:
            host = host_parts[:-1]

        self._is_sane = bool(len(host))
        return self._is_sane

    def validateURL(self, url):
        """Validates a URL against this trust root.  Returns a bool"""

        if not self.isSane():
            return False

        url_parts = parseURL(url)
        if url_parts is None:
            return False
        
        proto, host, port, path = url_parts

        if proto != self.proto:
            return False

        if port != self.port:
            return False

        if path.split('?', 1)[0] != self.path.split('?', 1)[0]:
            return False
            
        if not path.startswith(self.path):
            return False
        
        if not self.wildcard:
            return host == self.host
        else:
            return host.endswith(self.host)

    @classmethod
    def parse(klass, trust_root, check_sanity=False):
        if not isinstance(trust_root, basestring):
            return None

        url_parts = parseURL(trust_root)
        if url_parts is None:
            return None
        
        proto, host, port, path = url_parts

        # check for valid prototype
        if proto not in _protocols:
            return None        

        # extract wildcard if it is there
        if '*' in host:
            # wildcard must be at start of domain:  *.foo.com, not foo.*.com
            if not host.startswith('*'):
                return None

            # there should also be a '.' ala *.schtuff.com
            if host[1] != '.':
                return None
            
            host = host[2:]
            wilcard = True
        else:
            wilcard = False
        
        # at least needs to end in a top-level-domain
        ends_in_tld = False
        for tld in _top_level_domains:
            if host.endswith(tld):
                ends_in_tld = True
                break

        if not ends_in_tld:
            return None

        # we have a valid trust root
        tr = TrustRoot(trust_root, proto, wilcard, host, port, path)
        if check_sanity:
            if not tr.isSane():
                return None

        return tr

    def __repr__(self):
        return "TrustRoot('%s', '%s', '%s', '%s', '%s', '%s')" % (
            self.unparsed, self.proto, self.wildcard, self.host, self.port,
            self.path)

    def __str__(self):
        return repr(self)


def _test():
    print 'Testing...'

    # test invalid trust root strings
    def assertBad(s):
        tr = TrustRoot.parse(s)
        assert tr is None, repr(tr)

    assertBad('baz.org')
    assertBad('*.foo.com')
    assertBad('ftp://foo.com')
    assertBad('ftp://*.foo.com')
    assertBad('http://*.foo.notatld')
    assertBad('http://*.foo.com:80:90/')
    assertBad('')
    assertBad(' ')
    assertBad(' \t\n ')
    assertBad(None)
    assertBad(5)

    # test valid trust root string
    def assertGood(s):
        tr = TrustRoot.parse(s)
        assert tr is not None

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

    # XXX: what exactly is a sane trust root?
    #assertSane('http://*.k12.va.us/', False)

    # validate a url against a trust root
    def assertValid(trust_root, url, truth):
        tr = TrustRoot.parse(trust_root)
        assert tr.validateURL(url) == truth, (tr.validateURL(url), truth)

    assertValid('http://*.foo.com', 'http://b.foo.com', True)
    assertValid('http://*.foo.com', 'http://hat.baz.foo.com', True)
    assertValid('http://*.foo.com', 'http://b.foo.com', True)
    assertValid('http://*.b.foo.com', 'http://b.foo.com', True)
    assertValid('http://*.b.foo.com', 'http://x.b.foo.com', True)
    assertValid('http://*.bar.co.uk', 'http://www.bar.co.uk', True)
    assertValid('http://*.uoregon.edu', 'http://*.cs.uoregon.edu', True)

    assertValid('http://*.cs.uoregon.edu', 'http://*.uoregon.edu', False)
    assertValid('http://*.com', 'http://foo.com', False)
    assertValid('http://*.foo.com', 'http://bar.com', False)
    assertValid('http://*.foo.com', 'http://www.bar.com', False)
    assertValid('http://*.co.uk', 'http://www.bar.com', False)
    assertValid('http://*.co.uk', 'http://www.bar.co.uk', False)
    assertValid('http://*.bar.co.uk', 'http://xxx.co.uk', False)

    # path validity
    assertValid('http://x.com/abc', 'http://x.com/', False)
    assertValid('http://x.com/abc', 'http://x.com/a', False)
    assertValid('http://*.x.com/abc', 'http://foo.x.com/abc', True)
    assertValid('http://*.x.com/abc', 'http://foo.x.com', False)
    assertValid('http://*.x.com', 'http://foo.x.com/gallery', False)
    assertValid('http://foo.x.com', 'http://foo.x.com/gallery', False)
    assertValid('http://foo.x.com/gallery', 'http://foo.x.com/gallery/xxx', False)
    assertValid('http://localhost:8081/x?action=openid',
                'http://localhost:8081/x?action=openid', True)
    assertValid('http://*.x.com/gallery', 'http://foo.x.com/gallery', True)
    assertValid('http://*.x.com/gallery?foo=bar', 'http://foo.x.com/gallery', False)
    assertValid('http://*.x.com/gallery?foo=bar', 'http://foo.x.com/gallery?foo=bar', True)
    assertValid('http://*.x.com/gallery?foo=bar', 'http://foo.x.com/gallery?foo=bar&x=y', True)

    assertValid('http://localhost:8082/?action=openid',
                'http://localhost:8082/?action=openid', True)

    print 'All tests passed!'

if __name__ == '__main__':
    _test()
