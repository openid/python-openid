import urllib
import urllib2
import urlparse

from openid.util import parsekv, append_args, sign_reply

from openid.errors import (ProtocolError, ValueMismatchError,
                           UserSetupNeeded, UserCancelled)

from openid.association import DumbAssociationManager

from openid.parse import parseLinkAttrs

# Do not escape anything that is already 7-bit safe, so we do the
# minimal transform on the identity URL
def quote_minimal(s):
    res = []
    for c in s:
        if c >= u'\x80':
            for b in c.encode('utf8'):
                res.append('%%%02X' % ord(b))
        else:
            res.append(c)
    return str(''.join(res))

def normalize_url(url):
    assert isinstance(url, basestring), type(url)
    url = url.strip()
    if not (url.startswith('http://') or url.startswith('https://')):
        url = 'http://' + url

    if isinstance(url, unicode):
        parsed = urlparse.urlparse(url)
        authority = parsed[1].encode('idna')
        tail = map(quote_minimal, parsed[2:])
        encoded = (str(parsed[0]), authority) + tuple(tail)
        url = urlparse.urlunparse(encoded)
        assert type(url) is str

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
    def handle_request(self, server_id, server_url, return_to,
                       trust_root=None, immediate=False):
        """Returns the url to redirect to, where server_id is the
        identity url the server is checking and server_url is the url
        of the openid server."""
        redir_args = {'openid.identity': server_id,
                      'openid.return_to': return_to,}

        if trust_root is not None:
            redir_args['openid.trust_root'] = trust_root

        if immediate:
            mode = 'checkid_immediate'
        else:
            mode = 'checkid_setup'

        redir_args['openid.mode'] = mode

        assoc_handle = self.assoc_mngr.associate(server_url)
        if assoc_handle is not None:
            redir_args['openid.assoc_handle'] = assoc_handle

        return str(append_args(server_url, redir_args))

    def handle_response(self, req):
        """Handles an OpenID GET request with openid.mode in the
        arguments. req should be a Request instance, properly
        initialized with the http arguments given, and the http method
        used to make the request.

        This method returns True if the identity was authenticated,
        False if the authentication was canceled or (in dumb mode
        only) failed, and raises openid.errors.UserSetupNeeded with
        the appropriate url if more work is needed in immediate mode."""
        if req.http_method != 'GET':
            raise ProtocolError("Expected HTTP Method 'GET', got %r" %
                                (req.http_method,))

        func = getattr(self, 'do_' + req.mode, None)
        if func is None:
            raise ProtocolError("Unknown Mode: %r" % (req.mode,))

        return func(req)

    def find_identity_info(self, identity_url):
        """Returns (consumer_id, server_id, server_url) or None if no
        server found. Fetch url and parse openid.server and
        potentially openid.delegate urls.  consumer_id is the identity
        url the consumer should use.  It is the url after following
        any redirects the url passed in might use.  server_id is the
        url actually sent to the server to verify, and may be the
        result of finding a delegate link."""
        url = normalize_url(identity_url)
        consumer_id, data = self.http_client.get(url)

        server = None
        delegate = None
        link_attrs = parseLinkAttrs(data)
        for attrs in link_attrs:
            rel = attrs.get('rel')
            if rel == 'openid.server' and server is None:
                href = attrs.get('href')
                if href is not None:
                    server = href

            if rel == 'openid.delegate' and delegate is None:
                href = attrs.get('href')
                if href is not None:
                    delegate = href

        if server is None:
            return None

        if delegate is not None:
            server_id = delegate
        else:
            server_id = consumer_id

        return tuple(map(normalize_url, (consumer_id, server_id, server)))

    def _dumb_auth(self, server_url, req):
        if not self.verify_return_to(req):
            return False

        check_args = {}
        for k, v in req.args.iteritems():
            if k.startswith('openid.'):
                check_args[k] = v

        check_args['openid.mode'] = 'check_authentication'

        body = urllib.urlencode(check_args)
        _, data = self.http_client.post(server_url, body)

        results = parsekv(data)
        is_valid = results.get('is_valid', 'false')
        if is_valid == 'true':
            invalidate_handle = results.get('invalidate_handle')
            if invalidate_handle is not None:
                self.assoc_mngr.invalidate(server_url, invalidate_handle)

            return True
        else:
            return False

    def do_id_res(self, req):
        user_setup_url = req.get('user_setup_url')
        if user_setup_url is not None:
            raise UserSetupNeeded(user_setup_url)

        server_url = self.determine_server_url(req)

        assoc = self.assoc_mngr.get_association(server_url, req.assoc_handle)
        if assoc is None:
            # No matching association found. I guess we're in dumb mode...
            return self._dumb_auth(server_url, req)

        # Check the signature
        sig = req.sig
        signed_fields = req.signed.strip().split(',')

        _signed, v_sig = sign_reply(req.args, assoc.secret, signed_fields)
        if v_sig != sig:
            return False

        return True

    def do_error(self, req):
        error = req.get('error')
        if error is None:
            raise ProtocolError("Unspecified Server Error: %r" % (req.args,))
        else:
            raise ProtocolError("Server Response: %r" % (error,))

    def do_cancel(self, unused_req):
        raise UserCancelled()


    # Callbacks
    def determine_server_url(self, req):
        """Returns the url of the identity server for the identity in
        the request.

        Subclasses might extract the server_url from a cache or from a
        signed parameter specified in the return_to url passed to
        initialRequest.

        The default implementation fetches the identity page again,
        and parses the server url out of it."""
        # Grab the server_url from the identity in args
        ret = self.find_identity_info(req.identity)
        if ret is None:
            raise ValueMismatchError(
                'ID URL %r seems not to be an OpenID identity.' % req.identity)

        _, server_id, server_url = ret
        if req.identity != server_id:
            raise ValueMismatchError('ID URL %r seems to have moved: %r'
                                     % (req.identity, server_id))

        return server_url

    def get_http_client(self):
        """This method returns an http client that the consumer will
        use to fetch the identity url page and make posts to the
        identity server.  The client should provide get and post
        methods.  See the SimpleHTTPClient class definition above for
        more on the expected interface.  The default implementation of
        this method returns an instance of SimpleHTTPClient, which is
        functional but doesn't try to prevent any kind of bad behavior
        like tarpitting the http requests.

        This method will be called repeatedly, so care should be taken
        to return the same instance each time if the returned instance
        will maintain internal state."""
        return SimpleHTTPClient()

    def get_assoc_mngr(self):
        """This method returns an AssociationManager (see
        openid.association) instance that will manage associations
        between this consumer and openid servers that it connects to.
        The default implemention of this method returns an
        AssociationManager that doesn't keep track of anything,
        putting the consumer into dumb mode perpetually.

        This method will be called repeatedly, so care should be taken
        to return the same instance each time if the returned instance
        will maintain internal state."""
        return DumbAssociationManager()

    def verify_return_to(self, req):
        """This method is called before the consumer makes a
        check_authentication call to the server.  It helps verify that
        the request being authenticated is valid by confirming that
        the openid.return_to value signed by the server corresponds to
        this consumer.  The full Request object (see openid.interface)
        is passed in, though most implementations will only use its
        return_to field.  The return value should be True if the
        return_to field corresponds to this consumer, or False
        otherwise.  This method must be overridden, as it has no
        default implementation."""
        raise NotImplementedError

    # properties for accessing some of the callbacks
    http_client = property(get_http_client)
    assoc_mngr = property(get_assoc_mngr)
