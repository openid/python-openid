import urllib
import urllib2
import urlparse
import cgi

from openid.util import parsekv, append_args, sign_reply
from openid.errors import ProtocolError, ValueMismatchError
from openid.association import DumbAssociationManager
from openid.parse import parseLinkAttrs
from openid.interface import (ValidLogin, InvalidLogin, ErrorFromServer,
                              UserCancelled, UserSetupNeeded,
                              CheckAuthRequired)

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
    def __init__(self, http_client=None, assoc_mngr=None):
        self.http_client = http_client or SimpleHTTPClient()
        self.assoc_mngr = assoc_mngr or DumbAssociationManager()

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

        This method returns a subclass of
        openid.interface.ConsumerResponse.  See the openid.interface
        module for the list of subclasses possible."""
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

    def check_auth(self, server_url, return_to, post_data):
        """This method is called to perform the openid.mode =
        check_authentication call.  The identity argument should be
        the identity url you are confirming (from the consumer's
        viewpoint, ie. not a delegated identity).  The return_to and
        post_data arguments should be as contained in the
        CheckAuthRequired object returned by a previous call to
        handle_response."""
        if not self.verify_return_to(return_to):
            return InvalidLogin()

        _, data = self.http_client.post(server_url, post_data)

        results = parsekv(data)
        is_valid = results.get('is_valid', 'false')
        if is_valid == 'true':
            invalidate_handle = results.get('invalidate_handle')
            if invalidate_handle is not None:
                self.assoc_mngr.invalidate(server_url, invalidate_handle)

            identity = cgi.parse_qs(post_data)['openid.identity'][0]
            return ValidLogin(self, identity)
        else:
            return InvalidLogin()

    def do_id_res(self, req):
        if not self.verify_return_to(req.return_to):
            return InvalidLogin()

        user_setup_url = req.get('user_setup_url')
        if user_setup_url is not None:
            return UserSetupNeeded(user_setup_url)

        server_url = self.determine_server_url(req)

        assoc = self.assoc_mngr.get_association(server_url, req.assoc_handle)

        if assoc is None:
            # No matching association found. I guess we're in dumb mode...
            check_args = {}
            for k, v in req.args.iteritems():
                if k.startswith('openid.'):
                    check_args[k] = v

            check_args['openid.mode'] = 'check_authentication'

            post_data = urllib.urlencode(check_args)
            return CheckAuthRequired(server_url, req.return_to, post_data)

        # Check the signature
        sig = req.sig
        signed_fields = req.signed.strip().split(',')

        _signed, v_sig = sign_reply(req.args, assoc.secret, signed_fields)
        if v_sig != sig:
            return InvalidLogin()

        return ValidLogin(self, req.identity)

    def do_error(self, req):
        error = req.get('error')
        if error is None:
            return ErrorFromServer("Unspecified Server Error: %r" % (req.args,))
        else:
            return ErrorFromServer("Server Response: %r" % (error,))

    def do_cancel(self, unused_req):
        return UserCancelled()


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

    def verify_return_to(self, return_to):
        """This method is called before the consumer makes a
        check_authentication call to the server.  It helps verify that
        the request being authenticated is valid by confirming that
        the openid.return_to value signed by the server corresponds to
        this consumer.  The return value should be True if the
        return_to field corresponds to this consumer, or False
        otherwise.  This method must be overridden, as it has no
        default implementation."""
        raise NotImplementedError
