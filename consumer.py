import datetime
import re
import time
import urllib
import urllib2

from openid.constants import *
from openid.util import *
from openid.errors import *
from openid.association import *
from openid.parse import parseLinkAttrs

def normalize_url(url):
    assert isinstance(url, basestring), type(url)
    url = url.strip()
    if not (url.startswith('http://') or url.startswith('https://')):
        url = 'http://' + url
    return url


class SimpleHTTPClient(object):
    def get(self, url):
        f = urllib2.urlopen(url)
        try:
            data = f.read()
        finally:
            f.close()
        
        return (f.geturl(), data)

    def post(self, url, body):
        req = urllib2.Request(url, body)
        try:
            f = urllib2.urlopen(req)
            try:
                data = f.read()
            finally:
                f.close()
        except urllib2.HTTPError, why:
            if why.code == 400:
                try:
                    data = why.read()
                finally:
                    why.close()
                args = parsekv(data)
                error = args.get('error')
                if error is None:
                    raise ProtocolError("Unspecified Server Error: %r" %
                                        (args,))
                else:
                    raise ProtocolError("Server Response: %r" % (error,))
            else:
                raise 
            
        return (f.geturl(), data)


class OpenIDConsumer(object):
    # regexes for parsing out server url
    link_re = re.compile(r'<link(?P<linkinner>.*?)>', re.M|re.U|re.I)
    href_re = re.compile(r'.*?href\s*=\s*[\'"](?P<href>.*?)[\'"].*?',
                         re.M|re.U|re.I)
    
    def __init__(self, http_client=None, assoc_mngr=None):
        if http_client is None:
            http_client = SimpleHTTPClient()
        self.http_client = http_client
        
        if assoc_mngr is None:
            assoc_mngr = BaseAssociationManager(
                DiffieHelmanAssociator(http_client))
        self.assoc_mngr = assoc_mngr

    def handle_request(self, url, return_to, trust_root=None, immediate=False):
        """Returns the url to redirect to or None if no identity was found."""
        url = normalize_url(url)
        
        server_info = self.find_server(url)
        if server_info is None:
            return None
        
        identity, server_url = server_info
        
        redir_args = {"openid.identity" : identity,
                      "openid.return_to" : return_to,}

        if trust_root is not None:
            redir_args["openid.trust_root"] = trust_root

        if immediate:
            mode = "checkid_immediate"
        else:
            mode = "checkid_setup"

        redir_args['openid.mode'] = mode

        assoc_handle = self.assoc_mngr.associate(server_url)
        if assoc_handle is not None:
            redir_args["openid.assoc_handle"] = assoc_handle

        return str(append_args(server_url, redir_args))

    def handle_response(self, req):
        """Handles an OpenID GET request with openid.mode in the
        arguments. req should be a Request instance, properly
        initialized with the http arguments given, and the http method
        used to make the request.  Returns a """
        if not req.hasOpenIDParams():
            raise NoArgumentsError
        
        if req.http_method != 'GET':
            raise ProtocolError("Expected HTTP Method 'GET', got %r" %
                                (req.http_method,))

        func = getattr(self, 'do_' + req.mode, None)
        if func is None:
            raise ProtocolError("Unknown Mode: %r" % (req.mode,))

        return func(req)

    def determine_server_url(self, req):
        """Subclasses might extract the server_url from a cache or
        from a signed parameter specified in the return_to url passed
        to initialRequest. Returns the unix timestamp when the session
        will expire.  0 if invalid."""
        # Grab the server_url from the identity in args
        identity, server_url = self.find_server(req.identity)
        if req.identity != identity:
            raise ValueMismatchError("ID URL %r seems to have moved: %r"
                                     % (req.identity, identity))
        
        return server_url

    def find_server(self, url):
        """<--(identity_url, server_url) or None if no server found.
        Parse url and follow delegates to find ther openid.server url.
        """
        def _(url, depth=0, max_depth=5):
            if depth == max_depth:
                return None

            identity, data = self.http_client.get(url)

            link_attrs = parseLinkAttrs(data)
            for attrs in link_attrs:
                rel = attrs.get('rel')
                if rel == 'openid.server':
                    href = attrs.get('href')
                    if href is not None:
                        return identity, href
                if rel == 'openid.delegate':
                    href = attrs.get('href')
                    if href is not None:
                        return _(href, depth=depth+1)

            return None

        return _(url)

    def _dumb_auth(self, server_url, now, req):
        check_args = {}
        for k, v in req.args.iteritems():
            if k.startswith('openid.'):
                check_args[k] = v

        check_args['openid.mode'] = 'check_authentication'

        body = urllib.urlencode(check_args)
        _, data = self.http_client.post(server_url, body)
        results = parsekv(data)
        lifetime = int(results['lifetime'])
        if lifetime:
            return time.mktime(now.utctimetuple()) + lifetime
        else:
            return 0
        
    def do_id_res(self, req):
        now = utc_now()

        server_url = self.determine_server_url(req)
        secret = self.assoc_mngr.get_secret(server_url, req.assoc_handle)
        if secret is None:
            # No matching association found. I guess we're in dumb mode...
            return self._dumb_auth(server_url, now, req)

        # Check the signature
        sig = req.sig
        signed_fields = req.signed.strip().split(',')

        v_sig = sign_reply(req.args, secret, signed_fields)
        if v_sig != sig:
            raise ValueMismatchError("Signatures did not Match: %r" %
                                     ((req.args, v_sig, secret),))

        issued = w3c2datetime(req.issued)
        valid_to = w3c2datetime(req.valid_to)

        return time.mktime((now + (valid_to - issued)).utctimetuple())

    def do_error(self, req):
        error = req.get('error')
        if error is None:
            raise ProtocolError("Unspecified Server Error: %r" % (req.args,))
        else:
            raise ProtocolError("Server Response: %r" % (error,))

