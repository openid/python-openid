"""
This module contains the C{L{TrustRoot}} class, which helps handle
trust root checking.  This module is used by the
C{L{openid.server.server}} module, but it is also available to server
implementers who wish to use it for additional trust root checking.
"""

from urlparse import urlparse, urlunparse

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
    'vn|vu|wf|ws|ye|yt|yu|za|zm|zw'
    ).split('|')


def _parseURL(url):
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
    """
    This class represents an OpenID trust root.  The C{L{parse}}
    classmethod accepts a trust root string, producing a
    C{L{TrustRoot}} object.  The method OpenID server implementers
    would be most likely to use is the C{L{isSane}} method, which
    checks the trust root for given patterns that indicate that the
    trust root is too broad or points to a local network resource.

    @sort: parse, isSane
    """
    
    def __init__(self, unparsed, proto, wildcard, host, port, path):
        self.unparsed = unparsed
        self.proto = proto
        self.wildcard = wildcard
        self.host = host
        self.port = port
        self.path = path

    def isSane(self):
        """
        This method checks the to see if a trust root represents a
        reasonable (sane) set of URLs.  'http://*.com/', for example
        is not a reasonable pattern, as it cannot meaningfully specify
        the site claiming it.  This function attempts to find many
        related examples, but it can only work via heuristics.
        Negative responses from this method should be treated as
        advisory, used only to alert the user to examine the trust
        root carefully.


        @return: Whether the trust root is sane

        @rtype: C{bool}
        """

        if self.host == 'localhost':
            return True

        host_parts = self.host.split('.')

        ends_in_tld = False
        for tld in _top_level_domains:
            if host_parts[-1].endswith(tld):
                ends_in_tld = True
                break

        if not ends_in_tld:
            return False

        # extract sane "top-level-domain"
        host = []
        if len(host_parts[-1]) == 2:
            if len(host_parts[-2]) <= 3:
                host = host_parts[:-2]
        elif len(host_parts[-1]) == 3:
            host = host_parts[:-1]

        return bool(len(host))

    def validateURL(self, url):
        """
        Validates a URL against this trust root.


        @param url: The URL to check

        @type url: C{str}


        @return: Whether the given URL is within this trust root.

        @rtype: C{bool}
        """

        url_parts = _parseURL(url)
        if url_parts is None:
            return False

        proto, host, port, path = url_parts

        if proto != self.proto:
            return False

        if port != self.port:
            return False

        if not path.split('?', 1)[0].startswith(self.path.split('?', 1)[0]):
            return False

        if not self.wildcard:
            return host == self.host
        else:
            return host.endswith(self.host)

    def parse(cls, trust_root):
        """
        This method creates a C{L{TrustRoot}} instance from the given
        input, if possible.


        @param trust_root: This is the trust root to parse into a
        C{L{TrustRoot}} object.

        @type trust_root: C{str}


        @return: A C{L{TrustRoot}} instance if trust_root parses as a
        trust root, C{None} otherwise.

        @rtype: C{NoneType} or C{L{TrustRoot}}
        """
        if not isinstance(trust_root, (str, unicode)):
            return None

        url_parts = _parseURL(trust_root)
        if url_parts is None:
            return None
        
        proto, host, port, path = url_parts

        # check for valid prototype
        if proto not in _protocols:
            return None        

        # extract wildcard if it is there
        if host.find('*', 1) != -1:
            # wildcard must be at start of domain:  *.foo.com, not foo.*.com
            return None

        if host.startswith('*'):
            # Starts with star, so must have a dot after it (if a
            # domain is specified)
            if len(host) > 1 and host[1] != '.':
                return None

            host = host[2:]
            wilcard = True
        else:
            wilcard = False
        

        # we have a valid trust root
        tr = cls(trust_root, proto, wilcard, host, port, path)

        return tr

    parse = classmethod(parse)

    def checkSanity(cls, trust_root_string):
        """str -> bool

        is this a sane trust root?
        """
        return cls.parse(trust_root_string).isSane()

    checkSanity = classmethod(checkSanity)

    def checkURL(cls, trust_root, url):
        """quick func for validating a url against a trust root.  See the
        TrustRoot class if you need more control."""
        tr = cls.parse(trust_root)
        return tr is not None and tr.validateURL(url)

    checkURL = classmethod(checkURL)

    def __repr__(self):
        return "TrustRoot('%s', '%s', '%s', '%s', '%s', '%s')" % (
            self.unparsed, self.proto, self.wildcard, self.host, self.port,
            self.path)

    def __str__(self):
        return repr(self)
