import base64
import binascii
import re
import urllib, urllib2
import os, os.path
import random
import pickle
import sys
import sha
import time
import datetime
import hmac

import dh

########################################################################
# Format conversions

def w3cdate(x):
    "Represent UNIX time x as a W3C UTC timestamp"
    dt = datetime.datetime.utcfromtimestamp(x)
    dt = dt.replace(microsecond=0)
    return dt.isoformat() + "Z"

def b64(b):
    "Represent string b as base64, omitting newlines"
    return base64.encodestring(b).replace("\n", "")

def binint(n):
    "Represent bigint n in big-endian two's complement, using the least bytes"
    if n < 128 and n >= -128:
        return chr(n % 256)
    return binint(n / 256) + chr(n % 256)

def kvform2(d):
    "Represent dict d as newline-terminated key:value pairs; return also order of keys"
    keys = d.keys()
    return keys, "".join(["%s:%s\n" % (k, d[k]) for k in keys])

def kvform(d):
    "Represent dict d as newline-terminated key:value pairs"
    return kvform2(d)[1]

def parseKVPairs

########################################################################
# HTTP

def addparams(s, params):
    if len(params) == 0:
        return s
    if "?" in s:
        return s + "&" +  urllib.urlencode(params)
    else:
        return s + "?" +  urllib.urlencode(params)

def http_getrequest(host, path):
    return "GET %s HTTP/1.0\r\nHost: %s\r\n\r\n" % (path, host)

def http_postrequest(host, path, params):
    "Return a string representing what might be sent to make a POST request"
    return ("POST %s HTTP/1.0\r\n" +
            "Host: %s\r\n" +
            "Content-Type: x-www-form-urlencoded\r\n" +
            "\r\n%s") % (path, host, urllib.urlencode(params))

def http_response(type, content):
    "Return a string showing a successful response to an HTTP request"
    return "HTTP/1.0 200 OK\r\nContent-Type: %s\r\n\r\n%s" % (type, content)

def http_redirectresponse(location):
    return ("HTTP/1.0 302 Found\r\n" + 
            "Location: %s\r\n" +
            "Content-Type: text/html\r\n" + 
            "\r\n" +
            "<html><a href=\"%s\">%s</a></html>\r\n") % (location, location, location)


def fullURL(url):
    assert isinstance(url, basestring), type(url)
    url = url.strip()
    if not (url.startswith('http://') or url.startswith('https://')):
        url = 'http://' + url
    return url

########################################################################
# Cryptography

def random_string(ll):
    "Produce a string of ll random bytes"
    return "".join([chr(random.randrange(256)) for i in xrange(ll)])

def sign_token(d, s):
    "Sign the token dict d with key s; return \"signed\" and \"sig\""
    k, t = kvform2(d)
    return ",".join(k), b64(hmac.new(s, t, sha).digest())

def strxor(a, b):
    return "".join([chr(ord(aa) ^ ord(bb)) for aa, bb in zip(a, b)])



#################################



class HTTPRequester(object):

    def get(self, url):
        f = urllib2.urlopen(url)
        data = f.read()
        f.close()
        return (f.geturl(), data)

    def post(self, url, args):
        """args here is a dict, which we encode as:
        application/x-www-form-urlencoded """
        args = urllib.urlencode(args)
        f = urllib2.urlopen(url, args)  # does a POST
        data = f.read()
        f.close()
        return (f.geturl(), data)
        

class ClaimedIdentity(object):

    def __init__(self, identity_url, server_url, consumer):
        self.identity_url = identity_url
        self.server_url = server_url
        self.consumer = consumer

    def claimedURL(self):
        return self.identity_url

    def identityServer(self):
        if self.server_url:
            return self.server_url
        return None

    def checkURL(self, return_to, trust_root=None, assoc_handle=None):

        args = {
            'openid.mode':'checkid_immediate',
            'openid.return_to': return_to,
            'openid.identity': self.identity_url,
            'openid.trust_root':trust_root,
            }

        # XXX: if assoc_handle is None, we are operating in dumb mode
        if assoc_handle is not None:
            args['openid.assoc_handle'] = assoc_handle

        if trust_root is not None:
            args['openid.trust_root'] = trust_root
        
        req_url = addparams(self.identityServer(), args)

        info = self.consumer.requester.get(req_url)
        if info:
            response_url, page = info
            return response_url

        return None

    def associate(self):
        # XXX: check for cached handle and skip if we already have one
        
        p = dh.DEFAULT_MOD
        g = dh.DEFAULT_GEN
        x = random.randrange(1, p-1) # 1 <= x < p-1; x is the private key
        
        args = {
            'openid.mode': 'associate',
            'openid.assoc_type':'HMAC-SHA1',
            'openid.session_type':'DH-SHA1',
            'openid.dh_modulus': b64(binint(p)),
            'openid.dh_gen': b64(binint(g)),
            'openid.dh_consumer_public': b64(binint(pow(g, x, p)),
            }

        url, data = self.consumer.requester.post(self.server_url, args)
        # data is key, value pairs of result from server

        results = dict([[(k.strip(), v.strip()) for k,v in line.split(':')]
                        for line in data.split('\n') if line])

        handle = results['dh_server_public']
        handle = base64(btwoc(g ** y % p))
        
   

class Consumer(object):

    # regexes for parsing out server url
    link_re = re.compile(r'<link(?P<linkinner>.*?)>', re.M|re.U|re.I)
    href_re = re.compile(r'.*?href\s*=\s*[\'"](?P<href>.*?)[\'"].*?', re.M|re.U|re.I)

    def __init__(self, args=None):
        self.args = args
        self.requester = HTTPRequester()


    def _findServer(self, url, depth=0, max_depth=5):
        """<--(identity_url, server_url) or None if no server found.

        Parse url and follow delegates to find ther openid.server url.
        """
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
                    return f.geturl(), href
                elif 'openid.delegate' in linkinner:
                    return self._findServer(href, depth=depth+1)
                    
        return None

    def getClaimedIdentity(self, url):
        """<-- ClaimedIdentity instance or None
        if server info cannot be found"""        
        url = fullURL(url.strip())

        server_info = self._findServer(url)
        if server_info is None:
            return None

        id_url, server_url = server_info

        return ClaimedIdentity(id_url, server_url, self)


        

if __name__ == '__main__':
    c = Consumer()
    ci = c.claimedIdentity('livejournal.com/~serotta')

    print ci.identityServer()

    resp_url = ci.checkURL('http://www.schtuff.com/', 'http://*.schtuff.com/')
    print 'Response URL', resp_url


    print '\nDone'
