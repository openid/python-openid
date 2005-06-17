import datetime
import random
import re
import time
import urllib
import urllib2

from openid.constants import *
from openid.util import *
from openid.errors import *

def _getArg(name, args):
    arg = args.get("openid." + name)
    if arg is None:
        raise ProtocolError("Missing Argument: %r" % (name,))
    return arg

def normalizeURL(url):
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
        f = urllib2.urlopen(req)
        try:
            data = f.read()
        finally:
            f.close()
            
        return (f.geturl(), data)



class DumbAssociationManager(object):
    """This class provides the API for an association store to be used
    with an OpenIDConsumer instance. An instance of this class will
    cause the consumer to run in dumb mode."""
    def put(self, *unused):
        pass

    def associate(self, *unused):
        return None

    def getSecret(self, *unused):
        return None

def DHAssociate(assoc_mngr, server_url, http_client):
    """Returns assoc_handle associated with server_url"""
    handle = assoc_mngr.getMostRecent(server_url)
    if handle is not None:
        return handle

    p = default_dh_modulus
    g = default_dh_gen
    priv_key = random.randrange(1, p-1)

    args = {
        'openid.mode': 'associate',
        'openid.assoc_type':'HMAC-SHA1',
        'openid.session_type':'DH-SHA1',
        'openid.dh_modulus': to_b64(long2a(p)),
        'openid.dh_gen': to_b64(long2a(g)),
        'openid.dh_consumer_public': to_b64(long2a(pow(p, priv_key, p))),
        }

    body = urllib.urlencode(args)

    url, data = http_client.post(server_url, body)
    results = parsekv(data)
    # XXX: check results?
    # XXX: We need to handle the case where the server isn't up for
    #      DH and just returns mac_key in the clear.

    dh_server_pub = from_b64(a2long(
        results.get('dh_server_public')))
    enc_mac_key = results.get('enc_mac_key')
    expiry = w3c2datetime(results.get('expiry'))
    assoc_handle = results.get('assoc_handle')

    dh_shared = pow(dh_server_pub, priv_key, p)
    secret = strxor(from_b64(enc_mac_key), sha1(long2a(dh_shared)))

    assoc_mngr.put(server_url, assoc_handle, secret, expiry)

    return assoc_handle
    

class BaseAssociationManager(DumbAssociationManager):
    """Abstract base class for association manager implementations."""
    
    associate = DHAssociate

    def getSecret(self, server_url, assoc_handle):
        # Find the secret matching server_url and assoc_handle
        associations = self.getAll(server_url)
        for _assoc_handle, secret in associations:
            if _assoc_handle == assoc_handle:
                return secret

        return None

    # Subclass should implement the rest of this classes methods.
    def put(self, server_url, handle, key, expiry, replace_after):
        """Subclasses should add the association information to
        server_url."""
        raise NotImplementedError
    
    def getMostRecent(server_url):
        """Subclasses should return the handle associated with
        server_url that expires furthest in the future if one exists
        and None otherwise."""
        raise NotImplementedError
    
    def getAll(self, server_url):
        """Subclasses should return a list of (assoc_handle, secret)
        pairs associated with the server_url and that have not yet
        expired."""
        raise NotImplementedError
    


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
            assoc_mngr = DumbAssociationManager()
        self.assoc_mngr = assoc_mngr

    def handleRequest(self, url, return_to, trust_root=None):
        """Returns the url to redirect to or None if no identity was found."""
        url = normalizeURL(url)
        
        server_info = self.findServer(url)
        if server_info is None:
            return None
        
        id_url, server_url = server_info
        
        redir_args = {"openid.mode" : "checkid_immediate",
                      "openid.identity" : id_url,
                      "openid.return_to" : return_to,}

        if trust_root is not None:
            redir_args["openid.trust_root"] = trust_root

        assoc_handle = self.assoc_mngr.associate(server_url, self.http_client)
        if assoc_handle is not None:
            redir_args["openid.assoc_handle"] = assoc_handle

        return append_args(server_url, redir_args)

    def handleResponse(self, args):
        mode = _getArg('mode', args)
        func = getattr(self, 'do_' + mode, None)
        if func is None:
            raise ProtocolError("Unknown Mode: %r" % (mode,))

        return func(args)

    def determineServerURL(self, args):
        """Subclasses might extract the server_url from a cache or
        from a signed parameter specified in the return_to url passed
        to initialRequest."""
        id_url = _getArg('identity', args)

        # Grab the server_url from the id_url in args
        new_id_url, server_url = self.findServer(id_url)
        if id_url != new_id_url:
            raise ValueMismatchError("ID URL %r seems to have moved: %r"
                                     % (id_url, new_id_url))
        
        return server_url

    def findServer(self, url):
        """<--(identity_url, server_url) or None if no server found.
        Parse url and follow delegates to find ther openid.server url.
        """
        def _(url, depth=0, max_depth=5):
            if depth == max_depth:
                return None

            id_url, data = self.http_client.get(url)

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

    def do_id_res(self, args):
        """Returns the unix timestamp when the session will expire.
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

        # XXX: What about trust_root acceptance?

        server_url = self.determineServerURL(args)
        assoc_handle = _getArg('assoc_handle', args)
        
        secret = self.assoc_mngr.getSecret(server_url, assoc_handle)
        if secret is None:
            # No matching association found. I guess we're in dumb mode...
            # POST openid.mode=check_authentication
            check_args = {}
            for k, v in args.iteritems():
                if k.startswith('openid.'):
                    check_args[k] = v

            check_args['openid.mode'] = 'check_authentication'

            body = urllib.urlencode(check_args)
            _, data = self.http_client.post(server_url, body)
            results = parsekv(data)
            lifetime = float(results['lifetime'])
            if lifetime:
                return time.mktime(now.utctimetuple()) + lifetime
            else:
                return 0

        # Check the signature
        sig = _getArg('sig', args)
        signed_fields = _getArg('signed', args).strip().split(',')

        v_sig = sign_reply(args, secret, signed_fields)
        if v_sig != sig:
            raise ValueMismatchError("Signatures did not Match: %r" %
                                     ((args, assoc_handle, secret),))

        issued = w3c2datetime(_getArg('issued', args))
        valid_to = w3c2datetime(_getArg('valid_to', args))

        return time.mktime((now + (valid_to - issued)).utctimetuple())
        
    def do_error(self, args):
        raise NotImplementedError #XXX: handle errors

