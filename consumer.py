import datetime
import random
import re
import time
import urllib
import urllib2

from constants import *
from util import *

class ProtocolError(Exception): pass
class ValueMismatchError(Exception): pass

def _getArg(name, args):
    arg = args.get("openid." + name)
    if arg is None:
        raise ProtocolError("Missing Argument: %r" % (name,))
    return arg

def _fullURL(url):
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

    def post(self, url, body, headers):
        req = urllib2.Request(url, body, headers)
        f = urllib2.urlopen(req)
        try:
            data = f.read()
        finally:
            f.close()
            
        return (f.geturl(), data)


class DumbAssociationStore(object):
    """This class provides the API for an association store to be used
    with am OpenIDConsumer instance. The current implementation is
    sufficient for an consumer instance to behave in dumb mode. To
    create a smart consumer, subclass this and implement each of the
    methods as described."""
    
    def getMostRecent(self, server_url):
        """Subclasses should return the handle associated with
        server_url that expires furthest in the future if one exists
        and None otherwise."""
        return None

    def getAll(self, server_url):
        """Subclasses should return a list of (assoc_handle, secret)
        pairs associated with the server_url and that have not yet
        expired."""
        return []

    def put(self, server_url, handle, key, expiry, replace_after):
        """Subclasses should add the association information to
        server_url."""
        pass


class OpenIDConsumer(object):
    # regexes for parsing out server url
    link_re = re.compile(r'<link(?P<linkinner>.*?)>', re.M|re.U|re.I)
    href_re = re.compile(r'.*?href\s*=\s*[\'"](?P<href>.*?)[\'"].*?',
                         re.M|re.U|re.I)
    
    def __init__(self, assoc_store=None, http_client=None):
        if assoc_store is None:
            assoc_store = DumbAssociationStore()
        self.assoc_store = assoc_store
        if http_client is None:
            http_client = SimpleHTTPClient()
        self.http_client = http_client

    def _get(self, url):
        return self.http_client.get(url)

    def _post(self, url, args):
        """args here is a dict, which we encode as:
        application/x-www-form-urlencoded """
        body = urllib.urlencode(args)
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        return self.http_client.post(url, body, headers)

    def _findServer(self, url):
        """<--(identity_url, server_url) or None if no server found.

        Parse url and follow delegates to find ther openid.server url.
        """
        def _(url, depth=0, max_depth=5):
            if depth == max_depth:
                return None

            id_url, data = self._get(url)

            for match in self.link_re.finditer(data):
                linkinner = match.group('linkinner')
                href_match = self.href_re.match(linkinner)

                if href_match:
                    href = href_match.group('href')

                    if 'openid.server' in linkinner:
                        return id_url, href
                    elif 'openid.delegate' in linkinner:
                        return _(href, depth=depth+1)

            return None

        return _(url)

    def _associate(self, server_url):
        """Returns assoc_handle associated with server_url"""
        handle = self.assoc_store.getMostRecent(server_url)
        if handle is not None:
            return handle
        
        p = default_dh_modulus
        g = default_dh_gen
        x = random.randrange(1, p-1) # 1 <= x < p-1; x is the private key

        args = {
            'openid.mode': 'associate',
            'openid.assoc_type':'HMAC-SHA1',
            'openid.session_type':'DH-SHA1',
            'openid.dh_modulus': to_b64(long2a(p)),
            'openid.dh_gen': to_b64(long2a(g)),
            'openid.dh_consumer_public': to_b64(long2a(pow(g, x, p))),
            }

        url, data = self._post(server_url, args)
        # data is key, value pairs of result from server

        # XXX: We need to handle the case where the server isn't up for
        #      DH and just returns mac_key in the clear.


        # XXX: handle malformed data exceptions, call to parsekv could fail
        results = parsekv(data)
        # XXX: check results?
        
        dh_server_pub = from_b64(a2long(
            _getArg('dh_server_public', results)))
        enc_mac_key = _getArg('enc_mac_key', results)
        expiry = w3c2datetime(_getArg('expiry', results))
        assoc_handle = _getArg('assoc_handle', results)

        dh_shared = pow(dh_server_pub, x, p)
        secret = strxor(from_b64(enc_mac_key), sha1(long2a(dh_shared)))

        self.assoc_store.put(server_url, assoc_handle, secret, expiry)
        
        return assoc_handle

    def initialRequest(self, url, return_to, trust_root=None):
        """Returns the url to redirect to or None if no identity was found."""
        url = _fullURL(url.strip())
        
        server_info = self._findServer(url)
        if server_info is None:
            return None
        
        id_url, server_url = server_info
        
        redir_args = {"openid.mode" : "checkid_immediate",
                      "openid.identity" : id_url,
                      "openid.return_to" : return_to,}

        if trust_root is not None:
            redir_args["openid.trust_root"] = trust_root

        assoc_handle = self._associate(server_url)
        if assoc_handle is not None:
            redir_args["openid.assoc_handle"] = assoc_handle

        return append_args(server_url, redir_args)

    def idResponse(self, args):
        """Returns the unix timestampe when the session will expire.
        0 if invalid."""
        ################################################################
        #  Expected Args
        #
        # 'openid.mode=id_res'
        # 'openid.identity=' + OpenID URL
        # 'openid.assoc_handle=' + HMAC secret handle
        # 'openid.issued=' + UTC date
        # 'openid.valid_to=' + UTC date
        # 'openid.return_to=' + return URL
        # 'openid.signed=' + 'mode,issued,valid_to,identity,return_to'
        # 'openid.sig=' + base64(HMAC(secret(assoc_handle), token_contents))
        now = datetime.datetime.utcnow()

        mode = _getArg('mode', args)
        if mode != "id_res":
            raise ProtocolError("Unexpected Mode: %r" % (mode,))

        # XXX: What kind of response do we get if the user didn't auth?
        # XXX: What about trust_root acceptance?

        assoc_handle = _getArg('assoc_handle', args)
        id_url = _getArg('identity', args)

        # Grab the server_url from the id_url in args
        new_id_url, server_url = self._findServer(id_url)
        if id_url != new_id_url:
            raise ValueMismatchError("ID URL %r seems to have moved: %r"
                                     % (id_url, new_id_url))

        # Find the secret matching server_url and assoc_handle
        associations = self.assoc_store.getAll(server_url)
        for _assoc_handle, secret in associations:
            if _assoc_handle == assoc_handle:
                break
        else:
            # No matching association found. I guess we're in dumb mode...
            # POST openid.mode=check_authentication
            check_args = dict(args)
            check_args['openid.mode'] = 'check_authentication'
            _, data = self._post(server_url, check_args)
            results = parsekv(data)
            lifetime = float(results['lifetime'])
            if lifetime:
                return time.mktime(now.utctimetuple()) + lifetime
            else:
                return 0

        # Check the signature
        sig = _getArg('sig', args)
        signed_fields = _getArg('signed', args).strip().split(',')

        check_sig = sign_reply(args, secret, signed_fields)
        if check_sig != sig:
            raise ValueMismatchError("Signatures did not Match: %r" %
                                     ((args, assoc_handle, secret),))

        issued = w3c2datetime(_getArg('issued', args))
        valid_to = w3c2datetime(_getArg('valid_to', args))

        return time.mktime((now + (valid_to - issued)).utctimetuple())
        
        
