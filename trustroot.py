from urlparse import urlparse

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

class TrustRoot(object):
    """Represents a valid openid trust root.  The parse classmethod
    accepts a trust root string, producing a TrustRoot object.
    """
    
    def __init__(self, unparsed, proto, wildcard, host, port):
        self.unparsed = unparsed
        self.proto = proto
        self.wildcard = wildcard
        self.host = host
        self.port = port

        self._is_sane = None

    def isSane(self):
        """Checks the sanity of this trust root.
        http://*.com/ for example is not sane.  Returns a bool."""        
        if self._is_sane is not None:
            return self._is_sane
        
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

        proto, netloc, path, params, query, frag = urlparse(url)

        if ':' in netloc:
            try:
                host, port = netloc.split(':')
            except ValueError:
                return False
        else:
            host = netloc
            port = ''

        if proto != self.proto:
            return False

        if port != self.port:
            return False

        if not self.wildcard:
            return host == self.host
        else:
            return host.endswith(self.host)

    @classmethod
    def parse(klass, trust_root, check_sanity=False):
        if not isinstance(trust_root, basestring):
            return None
        
        proto, netloc, path, params, query, frag = urlparse(trust_root)

        # check for valid prototype
        if proto not in _protocols:
            return None        

        # if the input has anything other than a domain, it is invalid
        if path not in ('', '/') or params or query or frag:
            return None

        # extract wildcard if it is there
        if '*' in netloc:
            # wildcard must be at start of domain:  *.foo.com, not foo.*.com
            if not netloc.startswith('*'):
                return None

            # there should also be a '.' ala *.schtuff.com
            if netloc[1] != '.':
                return None
            
            netloc = netloc[2:]
            wilcard = True
        else:
            wilcard = False
        
        # extract host and port
        if ':' in netloc:
            try:
                host, port = netloc.split(':')
            except ValueError:
                return None
        else:
            host = netloc
            port = ''

        # at least needs to end in a top-level-domain
        ends_in_tld = False
        for tld in _top_level_domains:
            if host.endswith(tld):
                ends_in_tld = True
                break

        if not ends_in_tld:
            return None

        # we have a valid trust root
        tr = TrustRoot(trust_root, proto, wilcard, host, port)
        if check_sanity:
            if not tr.isSane():
                return None

        return tr

    def __repr__(self):
        return "TrustRoot('%s', '%s', '%s', '%s', '%s')" % (
            self.unparsed, self.proto, self.wildcard, self.host, self.port)

    def __str__(self):
        return repr(self)


def _test():
    print 'Testing...'

    # test invalid trust root strings
    def assertBad(s):
        tr = TrustRoot.parse(s)
        assert tr is None, repr(tr)

    assertBad('baz.org')
    assertBad('http://*.foo.com/path')
    assertBad('http://x.foo.com/path?action=foo2')
    assertBad('http://*.foo.com/path?action=foo2')
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

    # test trust root sanity
    def assertSane(s, truth):
        tr = TrustRoot.parse(s)
        assert tr.isSane() == truth, (tr.isSane(), truth)

    assertSane('http://*.schtuff.com/', True)
    assertSane('http://*.foo.schtuff.com/', True)
    assertSane('http://*.com/', False)
    assertSane('http://*.com.au/', False)
    assertSane('http://*.co.uk/', False)

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

    assertValid('http://*.com', 'http://foo.com', False)
    assertValid('http://*.foo.com', 'http://bar.com', False)
    assertValid('http://*.foo.com', 'http://www.bar.com', False)
    assertValid('http://*.co.uk', 'http://www.bar.com', False)
    assertValid('http://*.co.uk', 'http://www.bar.co.uk', False)
    assertValid('http://*.bar.co.uk', 'http://xxx.co.uk', False)
        

    print 'All tests passed!'

if __name__ == '__main__':
    _test()
