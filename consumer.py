from constants import *
from util import *


class SimpleHTTPClient(object):
    def get(self, url):
        f = urllib2.urlopen(url)
        try:
            data = f.read()
        finally:
            f.close()
        
        return (f.geturl(), data)

    def post(self, url, body, headers):
        f = urllib2.urlopen(url, body, headers)
        try:
            data = f.read()
        finally:
            f.close()
            
        return (f.geturl(), data)

class AssociationStore(object):
    def get(self, server_url):
        raise NotImplementedError

    def put(self, server_url, handle, key, expiry):
        raise NotImplementedError

class MissingArgumentError(Exception): pass


def _getArg(name, args):
    arg = args.get("openid." + name)
    if arg is None:
        raise MissingArgumentError(name)
    return arg

def fullURL(url):
    assert isinstance(url, basestring), type(url)
    url = url.strip()
    if not (url.startswith('http://') or url.startswith('https://')):
        url = 'http://' + url
    return url


class OpenIDConsumer(class):
    # regexes for parsing out server url
    link_re = re.compile(r'<link(?P<linkinner>.*?)>', re.M|re.U|re.I)
    href_re = re.compile(r'.*?href\s*=\s*[\'"](?P<href>.*?)[\'"].*?',
                         re.M|re.U|re.I)
    
    def __init__(self, assoc_store, http_client=None):
        self.assoc_store = assoc_store
        if http_client is None:
            http_client = SimpleHTTPClient()
        self.http_client = http_client

    def get(self, url):
        return self.http_client.get(url)

    def post(self, url, args):
        """args here is a dict, which we encode as:
        application/x-www-form-urlencoded """
        body = urllib.urlencode(args)
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        return self.http_client.post(url, body, headers)

    def findServer(self, url):
        """<--(identity_url, server_url) or None if no server found.

        Parse url and follow delegates to find ther openid.server url.
        """
        def _(url, depth=0, max_depth=5)
            if depth == max_depth:
                return None

            f = urllib2.urlopen(url)
            data = f.read()

            for match in self.link_re.finditer(data):
                linkinner = match.group('linkinner')
                href_match = self.href_re.match(linkinner)

                if href_match:
                    href = href_match.group('href')

                    if 'openid.server' in linkinner:
                        return href
                    elif 'openid.delegate' in linkinner:
                        return _(href, depth=depth+1)

            return None

        return _(url)

    def associate(self, server_url):
        """Returns (assoc_handle, mac_key, expiry) for server_url"""
        p = DEFAULT_MOD
        g = DEFAULT_GEN
        x = random.randrange(1, p-1) # 1 <= x < p-1; x is the private key

        args = {
            'openid.mode': 'associate',
            'openid.assoc_type':'HMAC-SHA1',
            'openid.session_type':'DH-SHA1',
            'openid.dh_modulus': to_b64(long2a(p)),
            'openid.dh_gen': to_b64(long2a(g)),
            'openid.dh_consumer_public': b64(long2a(pow(g, x, p))),
            }

        url, data = self.post(server_url, args)
        # data is key, value pairs of result from server

        results = parsekv(data)
        #XXX: check results?
        enc_dh_server_pub = _getArg('dh_server_public', results)
        dh_server_pub = from_b64(a2long(enc_dh_server_pub))
        enc_mac_key = _getArg('enc_mac_key', results))

        dh_shared = pow(dh_server_pub, x, p)
        secret = strxor(from_b64(enc_mac_key), sha1(long2a(dh_shared)))

        expiry = _getArg('expiry', results)
        return (_getArg('assoc_handle', results), secret, w3c2datetime(expiry))











## class ClaimedIdentity(object):

##     def __init__(self, identity_url, server_url, consumer):
##         self.identity_url = identity_url
##         self.server_url = server_url
##         self.consumer = consumer

##     def claimedURL(self):
##         return self.identity_url

##     def identityServer(self):
##         if self.server_url:
##             return self.server_url
##         return None

##     def checkURL(self, return_to, trust_root=None, assoc_handle=None):

##         args = {
##             'openid.mode':'checkid_immediate',
##             'openid.return_to': return_to,
##             'openid.identity': self.identity_url,
##             'openid.trust_root':trust_root,
##             }

##         # XXX: if assoc_handle is None, we are operating in dumb mode
##         if assoc_handle is not None:
##             args['openid.assoc_handle'] = assoc_handle

##         if trust_root is not None:
##             args['openid.trust_root'] = trust_root
        
##         req_url = addparams(self.identityServer(), args)

##         info = self.consumer.requester.get(req_url)
##         if info:
##             response_url, page = info
##             return response_url

##         return None

##     def associate(self):
##         # XXX: check for cached handle and skip if we already have one
        
##         p = dh.DEFAULT_MOD
##         g = dh.DEFAULT_GEN
##         x = random.randrange(1, p-1) # 1 <= x < p-1; x is the private key
        
##         args = {
##             'openid.mode': 'associate',
##             'openid.assoc_type':'HMAC-SHA1',
##             'openid.session_type':'DH-SHA1',
##             'openid.dh_modulus': b64(binint(p)),
##             'openid.dh_gen': b64(binint(g)),
##             'openid.dh_consumer_public': b64(binint(pow(g, x, p)),
##             }

##         url, data = self.consumer.requester.post(self.server_url, args)
##         # data is key, value pairs of result from server

##         results = dict([[(k.strip(), v.strip()) for k,v in line.split(':')]
##                         for line in data.split('\n') if line])

##         handle = results['dh_server_public']
##         handle = base64(btwoc(g ** y % p))
        
   

## class Consumer(object):

##     # regexes for parsing out server url
##     link_re = re.compile(r'<link(?P<linkinner>.*?)>', re.M|re.U|re.I)
##     href_re = re.compile(r'.*?href\s*=\s*[\'"](?P<href>.*?)[\'"].*?', re.M|re.U|re.I)

##     def __init__(self, args=None):
##         self.args = args
##         self.requester = HTTPRequester()


##     def _findServer(self, url, depth=0, max_depth=5):
##         """<--(identity_url, server_url) or None if no server found.

##         Parse url and follow delegates to find ther openid.server url.
##         """
##         if depth == max_depth:
##             return None
        
##         f = urllib2.urlopen(url)
##         data = f.read()

##         for match in self.link_re.finditer(data):            
##             linkinner = match.group('linkinner')
##             href_match = self.href_re.match(linkinner)
            
##             if href_match:
##                 href = href_match.group('href')
            
##                 if 'openid.server' in linkinner:
##                     return f.geturl(), href
##                 elif 'openid.delegate' in linkinner:
##                     return self._findServer(href, depth=depth+1)
                    
##         return None

##     def getClaimedIdentity(self, url):
##         """<-- ClaimedIdentity instance or None
##         if server info cannot be found"""        
##         url = fullURL(url.strip())

##         server_info = self._findServer(url)
##         if server_info is None:
##             return None

##         id_url, server_url = server_info

##         return ClaimedIdentity(id_url, server_url, self)



## if __name__ == '__main__':
##     c = Consumer()
##     ci = c.claimedIdentity('livejournal.com/~serotta')

##     print ci.identityServer()

##     resp_url = ci.checkURL('http://www.schtuff.com/', 'http://*.schtuff.com/')
##     print 'Response URL', resp_url


##     print '\nDone'
