import urlparse
import cgi
import time

from openid import cryptutil, dh, oidutil, kvform
from openid.consumer.consumer import OpenIDConsumer, SUCCESS, \
     HTTP_FAILURE, PARSE_ERROR, SETUP_NEEDED, FAILURE
from openid import association

from openid.consumer import parse

from urljr.fetchers import HTTPResponse

from yadis.discover import DiscoveryFailure

import _memstore

assocs = [
    ('another 20-byte key.', 'Snarky'),
    ('\x00' * 20, 'Zeros'),
    ]

def parseQuery(qs):
    q = {}
    for (k, v) in cgi.parse_qsl(qs):
        assert not q.has_key(k)
        q[k] = v
    return q

def associate(qs, assoc_secret, assoc_handle):
    """Do the server's half of the associate call, using the given
    secret and handle."""
    q = parseQuery(qs)
    assert q['openid.mode'] == 'associate'
    assert q['openid.assoc_type'] == 'HMAC-SHA1'
    if q.get('openid.session_type') == 'DH-SHA1':
        assert len(q) == 6 or len(q) == 4
        d = dh.DiffieHellman.fromBase64(
            q.get('openid.dh_modulus'), q.get('openid.dh_gen'))

        composite = cryptutil.base64ToLong(q['openid.dh_consumer_public'])
        enc_mac_key = oidutil.toBase64(d.xorSecret(composite, assoc_secret))
        reply_dict = {
            'assoc_type':'HMAC-SHA1',
            'assoc_handle':assoc_handle,
            'expires_in':'600',
            'session_type':'DH-SHA1',
            'dh_server_public':cryptutil.longToBase64(d.public),
            'enc_mac_key':enc_mac_key,
            }
    else:
        assert len(q) == 2
        mac_key = oidutil.toBase64(assoc_secret)
        reply_dict = {
            'assoc_type':'HMAC-SHA1',
            'assoc_handle':assoc_handle,
            'expires_in':'600',
            'mac_key':mac_key,
            }

    return kvform.dictToKV(reply_dict)

class TestFetcher(object):
    def __init__(self, user_url, user_page, (assoc_secret, assoc_handle)):
        self.get_responses = {user_url:self.response(user_url, 200, user_page)}
        self.assoc_secret = assoc_secret
        self.assoc_handle = assoc_handle
        self.num_assocs = 0

    def response(self, url, status, body):
        return HTTPResponse(
            final_url=url, status=status, headers={}, body=body)

    def fetch(self, url, body=None, headers=None):
        if body is None:
            if url in self.get_responses:
                return self.get_responses[url]
        else:
            try:
                body.index('openid.mode=associate')
            except ValueError:
                pass # fall through
            else:
                if urlparse.urlparse(url)[0] == 'https':
                    # Should not be doing DH-SHA1 when using HTTPS.
                    assert body.find('DH-SHA1') == -1
                else:
                    assert body.find('DH-SHA1') != -1
                response = associate(
                    body, self.assoc_secret, self.assoc_handle)
                self.num_assocs += 1
                return self.response(url, 200, response)

        return self.response(url, 404, 'Not found')

user_page_pat = '''\
<html>
  <head>
    <title>A user page</title>
    %s
  </head>
  <body>
    blah blah
  </body>
</html>
'''
http_server_url = 'http://server.example.com/'
consumer_url = 'http://consumer.example.com/'
https_server_url = 'https://server.example.com/'

def _test_success(server_url, user_url, delegate_url, links, immediate=False):
    store = _memstore.MemoryStore()
    if immediate:
        mode = 'checkid_immediate'
    else:
        mode = 'checkid_setup'

    user_page = user_page_pat % (links,)
    fetcher = TestFetcher(user_url, user_page, assocs[0])

    consumer = OpenIDConsumer(store, fetcher, immediate)
    def run():
        (status, info) = consumer.beginAuth(user_url)
        assert status == SUCCESS, status

        return_to = consumer_url
        trust_root = consumer_url
        redirect_url = consumer.constructRedirect(info, return_to, trust_root)

        parsed = urlparse.urlparse(redirect_url)
        qs = parsed[4]
        q = parseQuery(qs)
        assert q == {
            'openid.mode':mode,
            'openid.identity':delegate_url,
            'openid.trust_root':trust_root,
            'openid.assoc_handle':fetcher.assoc_handle,
            'openid.return_to':return_to,
            }, (q, user_url, delegate_url, mode)

        assert redirect_url.startswith(server_url)

        query = {
            'openid.mode':'id_res',
            'openid.return_to':return_to,
            'openid.identity':delegate_url,
            'openid.assoc_handle':fetcher.assoc_handle,
            }

        assoc = store.getAssociation(server_url, fetcher.assoc_handle)
        assoc.addSignature(['mode', 'return_to', 'identity'], query)

        (status, info) = consumer.completeAuth(info.token, query)
        assert status == 'success'
        assert info == user_url

    assert fetcher.num_assocs == 0
    run()
    assert fetcher.num_assocs == 1

    # Test that doing it again uses the existing association
    run()
    assert fetcher.num_assocs == 1

    # Another association is created if we remove the existing one
    store.removeAssociation(server_url, fetcher.assoc_handle)
    run()
    assert fetcher.num_assocs == 2

    # Test that doing it again uses the existing association
    run()
    assert fetcher.num_assocs == 2

import unittest

class TestSuccess(unittest.TestCase):
    server_url = http_server_url
    user_url = 'http://www.example.com/user.html'
    delegate_url = 'http://consumer.example.com/user'

    def setUp(self):
        self.links = '<link rel="openid.server" href="%s" />' % (
            self.server_url,)

        self.delegate_links = ('<link rel="openid.server" href="%s" />'
                               '<link rel="openid.delegate" href="%s" />') % (
            self.server_url, self.delegate_url)

    def test_nodelegate(self):
        _test_success(self.server_url, self.user_url,
                      self.user_url, self.links)
        
    def test_nodelegateImmediate(self):
        _test_success(self.server_url, self.user_url,
                      self.user_url, self.links, True)

    def test_delegate(self):
        _test_success(self.server_url, self.user_url,
                      self.delegate_url, self.delegate_links)

    def test_delegateImmediate(self):
        _test_success(self.server_url, self.user_url,
                      self.delegate_url, self.delegate_links, True)


class TestSuccessHTTPS(TestSuccess):
    server_url = https_server_url
    

class TestFetch(unittest.TestCase):
    def test_badFetch(self):
        store = _memstore.MemoryStore()
        fetcher = TestFetcher(None, None, (None, None))
        consumer = OpenIDConsumer(store, fetcher)
        cases = [
            (None, 'http://network.error/'),
            (404, 'http://not.found/'),
            (400, 'http://bad.request/'),
            (500, 'http://server.error/'),
            ]
        for error_code, url in cases:
            fetcher.get_responses[url] = fetcher.response(url, error_code, None)
            (status, info) = consumer.beginAuth(url)
            self.failUnlessEqual(status, HTTP_FAILURE)
            self.failUnlessEqual(info, error_code)


class TestParse(unittest.TestCase):
    def test_badParse(self):
        store = _memstore.MemoryStore()
        user_url = 'http://user.example.com/'
        cases = [
            '',
            "http://not.in.a.link.tag/",
            '<link rel="openid.server" href="not.in.html.or.head" />',
            ]
        for user_page in cases:
            fetcher = TestFetcher(user_url, user_page, (None, None))
            consumer = OpenIDConsumer(store, fetcher)
            status, info = consumer.beginAuth(user_url)
            self.failUnlessEqual(status, PARSE_ERROR)
            self.failUnlessEqual(info, None)


class TestConstruct(unittest.TestCase):
    def setUp(self):
        self.store_sentinel = object()
        self.fetcher_sentinel = object()

    def test_construct(self):
        oidc = OpenIDConsumer(self.store_sentinel, self.fetcher_sentinel)
        assert oidc.store is self.store_sentinel
        assert oidc.fetcher is self.fetcher_sentinel

    def test_defaultFetcher(self):
        oidc = OpenIDConsumer(self.store_sentinel, fetcher=None)
        f = oidc.fetcher
        self.failUnless(hasattr(f, 'fetch'), "oidc.fetcher is %r, which "
                        "does not match the fetcher interface.")

    def test_nostore(self):
        self.failUnlessRaises(TypeError,
                              OpenIDConsumer, fetcher=self.fetcher_sentinel)


class TestIdRes(unittest.TestCase):
    consumer_class = OpenIDConsumer

    def setUp(self):
        self.store = _memstore.MemoryStore()
        self.consumer = self.consumer_class(self.store)
        self.return_to = "nonny"
        self.server_id = "sirod"
        self.server_url = "serlie"
        self.consumer_id = "consu"
        self.token = self.consumer._genToken(self.return_to,
                                             self.consumer_id,
                                             self.server_id,
                                             self.server_url)

class TestSetupNeeded(TestIdRes):
    def test_setupNeeded(self):
        setup_url = 'http://unittest/setup-here'
        query = {
            'openid.mode': 'id_res',
            'openid.user_setup_url': setup_url,
            }
        ret = self.consumer._doIdRes(self.token, query)
        self.failUnlessEqual(ret[0], SETUP_NEEDED)
        self.failUnlessEqual(ret[1], setup_url)

class CheckAuthHappened(Exception): pass

class CheckAuthDetectingConsumer(OpenIDConsumer):
    def _checkAuth(self, *args):
        raise CheckAuthHappened(args)

class CatchLogs(object):
    def setUp(self):
        self.old_logger = oidutil.log
        oidutil.log = self.gotLogMessage
        self.messages = []

    def gotLogMessage(self, message):
        self.messages.append(message)

    def tearDown(self):
        oidutil.log = self.old_logger

class TestCheckAuthTriggered(TestIdRes, CatchLogs):
    consumer_class = CheckAuthDetectingConsumer

    def setUp(self):
        TestIdRes.setUp(self)
        CatchLogs.setUp(self)

    def test_checkAuthTriggered(self):
        query = {
            'openid.return_to':self.return_to,
            'openid.identity':self.server_id,
            'openid.assoc_handle':'not_found',
            }
        try:
            result = self.consumer._doIdRes(self.token, query)
        except CheckAuthHappened:
            pass
        else:
            self.fail('_checkAuth did not happen. Result was: %r' % result)

    def test_checkAuthTriggeredWithAssoc(self):
        # Store an association for this server that does not match the
        # handle that is in the query
        issued = time.time()
        lifetime = 1000
        assoc = association.Association(
            'handle', 'secret', issued, lifetime, 'HMAC-SHA1')
        self.store.storeAssociation(self.server_url, assoc)

        query = {
            'openid.return_to':self.return_to,
            'openid.identity':self.server_id,
            'openid.assoc_handle':'not_found',
            }
        try:
            result = self.consumer._doIdRes(self.token, query)
        except CheckAuthHappened:
            pass
        else:
            self.fail('_checkAuth did not happen. Result was: %r' % result)

    def test_expiredAssoc(self):
        # Store an expired association for the server with the handle
        # that is in the query
        issued = time.time() - 10
        lifetime = 0
        handle = 'handle'
        assoc = association.Association(
            handle, 'secret', issued, lifetime, 'HMAC-SHA1')
        self.failUnless(assoc.expiresIn <= 0)
        self.store.storeAssociation(self.server_url, assoc)

        query = {
            'openid.return_to':self.return_to,
            'openid.identity':self.server_id,
            'openid.assoc_handle':handle,
            }
        status, info = self.consumer._doIdRes(self.token, query)
        self.failUnlessEqual(FAILURE, status)
        self.failUnlessEqual(self.consumer_id, info)
        self.failUnlessEqual(1, len(self.messages), self.messages)
        message = self.messages[0].lower()
        message.index('expired') # raises an exception if it's not there

    def test_newerAssoc(self):
        # Store an expired association for the server with the handle
        # that is in the query
        lifetime = 1000

        good_issued = time.time() - 10
        good_handle = 'handle'
        good_assoc = association.Association(
            good_handle, 'secret', good_issued, lifetime, 'HMAC-SHA1')
        self.store.storeAssociation(self.server_url, good_assoc)

        bad_issued = time.time() - 5
        bad_handle = 'handle2'
        bad_assoc = association.Association(
            bad_handle, 'secret', bad_issued, lifetime, 'HMAC-SHA1')
        self.store.storeAssociation(self.server_url, bad_assoc)

        nonce = self.consumer._splitToken(self.token)[0]
        self.store.storeNonce(nonce)

        query = {
            'openid.return_to':self.return_to,
            'openid.identity':self.server_id,
            'openid.assoc_handle':good_handle,
            }

        good_assoc.addSignature(['return_to', 'identity'], query)
        status, info = self.consumer._doIdRes(self.token, query)

        self.failUnlessEqual(SUCCESS, status)
        self.failUnlessEqual(self.consumer_id, info)


class MockFetcher(object):
    def __init__(self, response=None):
        self.response = response or HTTPResponse()
        self.fetches = []

    def fetch(self, url, body=None, headers=None):
        self.fetches.append((url, body, headers))
        return self.response

class TestCheckAuth(unittest.TestCase, CatchLogs):
    consumer_class = OpenIDConsumer

    def setUp(self):
        CatchLogs.setUp(self)
        self.store = _memstore.MemoryStore()
        self.fetcher = MockFetcher()

        self.consumer = self.consumer_class(self.store, self.fetcher)

    def test_error(self):
        self.fetcher.response = HTTPResponse(
            "http://some_url", 404, {'Hea': 'der'}, 'blah:blah\n')
        nonce = "nonce"
        query = {'openid.signed': 'stuff, things'}
        r = self.consumer._checkAuth(nonce, query, http_server_url)
        self.failUnlessEqual(r, FAILURE)
        self.failUnless(self.messages)

class TestFetchAssoc(unittest.TestCase, CatchLogs):
    consumer_class = OpenIDConsumer

    def setUp(self):
        CatchLogs.setUp(self)
        self.store = _memstore.MemoryStore()
        self.fetcher = MockFetcher()
        self.consumer = self.consumer_class(self.store, self.fetcher)

    def test_error(self):
        self.fetcher.response = HTTPResponse(
            "http://some_url", 404, {'Hea': 'der'}, 'blah:blah\n')
        r = self.consumer._fetchAssociation("dh",
                                            "http://server_url", "postbody")
        self.failUnlessEqual(r, None)
        self.failUnless(self.messages)


from openid.consumer import factory

class TestOpenidRequest(unittest.TestCase):
    def setUp(self):
        self.store = _memstore.MemoryStore()
        self.trust_root = 'http://trustme.unittest/'
        self.consumer = factory.OpenIDConsumer(self.trust_root, self.store,
                                               {})

        self.oidrequest = factory.OpenIDRequest()
        self.oidrequest.delegate = 'http://delegate.unittest/'
        self.oidrequest.uri = 'http://some.unittest/server'
        self.oidrequest.consumer = self.consumer

    def test_fromToken(self):
        token = self.oidrequest.getToken()
        req2 = self.consumer.makeRequestFromToken(token)
        token2 = req2.getToken()
        self.failUnlessEqual(token2, token)
        self.failUnlessEqual(req2, self.oidrequest)

    def test_getToken(self):
        token1 = self.oidrequest.getToken()
        token2 = self.oidrequest.getToken()
        self.failUnlessEqual(token1, token2)


class DiscoveryMockFetcher(object):
    redirect = None

    def __init__(self, documents):
        self.documents = documents
        self.fetchlog = []

    def fetch(self, url, body=None, headers=None):
        self.fetchlog.append((url, body, headers))
        if self.redirect:
            final_url = self.redirect
        else:
            final_url = url
        try:
            ctype, body = self.documents[url]
            return HTTPResponse(final_url, 200, {'content-type': ctype},
                                         body)
        except KeyError:
            return HTTPResponse(final_url, 404, {}, '')


# from twisted.trial import unittest as trialtest

class BaseTestDiscovery(unittest.TestCase):
    id_url = "http://someuser.unittest/"

    documents = {}

    def setUp(self):
        self.documents = self.documents.copy()
        self.fetcher = DiscoveryMockFetcher(self.documents)
        self.store = _memstore.MemoryStore()
        self.trust_root = 'http://trustme.unittest/'
        self.session = {}
        self.consumer = factory.OpenIDConsumer(self.trust_root,
                                               self.store,
                                               self.session,
                                               fetcher=self.fetcher)


yadis_2entries = '''<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS xmlns:xrds="xri://$xrds"
           xmlns="xri://$xrd*($v*2.0)"
           xmlns:openid="http://openid.net/xmlns/1.0"
           >
  <XRD>

    <Service priority="10">
      <Type>http://openid.net/signon/1.0</Type>
      <URI>http://www.myopenid.com/server</URI>
      <openid:Delegate>http://smoker.myopenid.com/</openid:Delegate>
    </Service>

    <Service priority="20">
      <Type>http://openid.net/signon/1.0</Type>
      <URI>http://www.livejournal.com/openid/server.bml</URI>
      <openid:Delegate>http://frank.livejournal.com/</openid:Delegate>
    </Service>

  </XRD>
</xrds:XRDS>
'''

yadis_another = '''<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS xmlns:xrds="xri://$xrds"
           xmlns="xri://$xrd*($v*2.0)"
           xmlns:openid="http://openid.net/xmlns/1.0"
           >
  <XRD>

    <Service priority="10">
      <Type>http://openid.net/signon/1.0</Type>
      <URI>http://vroom.unittest/server</URI>
      <openid:Delegate>http://smoker.myopenid.com/</openid:Delegate>
    </Service>
  </XRD>
</xrds:XRDS>
'''


yadis_0entries = '''<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS xmlns:xrds="xri://$xrds"
           xmlns="xri://$xrd*($v*2.0)"
           xmlns:openid="http://openid.net/xmlns/1.0"
           >
  <XRD>
    <Service >
      <Type>http://is-not-openid.unittest/</Type>
      <URI>http://noffing.unittest./</URI>
    </Service>
  </XRD>
</xrds:XRDS>
'''

yadis_no_delegate = '''<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS xmlns:xrds="xri://$xrds"
           xmlns="xri://$xrd*($v*2.0)"
           >
  <XRD>
    <Service priority="10">
      <Type>http://openid.net/signon/1.0</Type>
      <URI>http://www.myopenid.com/server</URI>
    </Service>
  </XRD>
</xrds:XRDS>
'''

class TestYadisFallback(BaseTestDiscovery):

    documents = {
        BaseTestDiscovery.id_url: ('application/xrds+xml', yadis_2entries),
        }

    servers = [
        "http://www.myopenid.com/server",
        "http://www.livejournal.com/openid/server.bml",
        ]

    def test_yadis(self):
        """trying one Yadis service."""
        status, info = self.consumer.beginAuth(self.id_url)
        self.failUnlessEqual(status, SUCCESS)
        self.failUnlessEqual(info.server_url, self.servers[0])

    def test_yadisFallback(self):
        """fallback to second Yadis service."""
        status, info = self.consumer.beginAuth(self.id_url)
        status, info = self.consumer.beginAuth(self.id_url)
        self.failUnlessEqual(status, SUCCESS)
        self.failUnlessEqual(info.server_url, self.servers[1])

    def test_yadisRetryAfterCancel(self):
        """Re-try same service after receiving cancel."""
        status, info = self.consumer.beginAuth(self.id_url)
        status, info = self.consumer.beginAuth(self.id_url)
        self.failUnlessEqual(status, SUCCESS)
        self.consumer.completeAuth(info.token, {'openid.mode': 'cancel'})
        status, info = self.consumer.beginAuth(self.id_url)
        self.failUnlessEqual(info.server_url, self.servers[1])

    def test_yadisExhausted(self):
        """Trying all services plus one."""
        status, info = self.consumer.beginAuth(self.id_url)
        status, info = self.consumer.beginAuth(self.id_url)
        # there were only two services, they were both broken but the
        # yadis doc changed in the meantime.
        self.documents[self.id_url] = ('application/xrds+xml',
                                       yadis_another)
        status, info = self.consumer.beginAuth(self.id_url)
        self.failUnlessEqual(status, SUCCESS)
        self.failUnlessEqual(info.server_url, "http://vroom.unittest/server")

    def test_zerolength(self):
        self.documents[self.id_url] = ('application/xrds+xml',
                                       yadis_0entries)
        status, info = self.consumer.beginAuth(self.id_url)
        # XXX - this is a bit of a stretch.  The page parsed fine, it's just
        # that there isn't any OpenID stuff in it.
        self.failUnlessEqual(status, PARSE_ERROR)

    def test_cPickleability(self):
        import cPickle
        status, info = self.consumer.beginAuth(self.id_url)
        pickled = cPickle.dumps(self.consumer.session)
        self.consumer.session = cPickle.loads(pickled)
        status, info = self.consumer.beginAuth(self.id_url)
        self.failUnlessEqual(status, SUCCESS)
        self.failUnlessEqual(info.server_url, self.servers[1])

    def test_pickleability(self):
        import pickle
        status, info = self.consumer.beginAuth(self.id_url)
        pickled = pickle.dumps(self.consumer.session)
        self.consumer.session = pickle.loads(pickled)
        status, info = self.consumer.beginAuth(self.id_url)
        self.failUnlessEqual(status, SUCCESS)
        self.failUnlessEqual(info.server_url, self.servers[1])

    def test_yadisFallback(self):
        """user supplies new URL"""
        self.documents[self.id_url + 'other'] = ('application/xrds+xml',
                                                 yadis_another)
        status, info = self.consumer.beginAuth(self.id_url)
        status, info = self.consumer.beginAuth(self.id_url + 'other')
        self.failUnlessEqual(status, SUCCESS)
        self.failUnlessEqual(info.server_url, "http://vroom.unittest/server")


openid_html = """
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html>
  <head>
    <title>Identity Page for Smoker</title>
<link rel="openid.server" href="http://www.myopenid.com/server" />
<link rel="openid.delegate" href="http://smoker.myopenid.com/" />
  </head><body><p>foo</p></body></html>
"""

openid_html_no_delegate = """
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html>
  <head>
    <title>Identity Page for Smoker</title>
<link rel="openid.server" href="http://www.myopenid.com/server" />
  </head><body><p>foo</p></body></html>
"""

openid_and_yadis_html = """
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html>
  <head>
    <title>Identity Page for Smoker</title>
<meta http-equiv="X-XRDS-Location" content="http://someuser.unittest/xrds" />
<link rel="openid.server" href="http://www.myopenid.com/server" />
<link rel="openid.delegate" href="http://smoker.myopenid.com/" />
  </head><body><p>foo</p></body></html>
"""

class TestDiscovery(BaseTestDiscovery):
    def test_404(self):
        self.failUnlessRaises(DiscoveryFailure,
                              self.consumer.discover, self.id_url + '/404')


    def test_noYadis(self):
        self.fetcher.documents = {
            self.id_url: ('text/html', openid_html),
        }
        final_url, services = self.consumer.discover(self.id_url)
        self.failUnlessEqual(len(services), 1,
                             "More than one service in %r" % (services,))
        self.failUnlessEqual(services[0].uri,
                             "http://www.myopenid.com/server")
        self.failUnlessEqual(services[0].delegate,
                             "http://smoker.myopenid.com/")
        self.failUnlessEqual(final_url, self.id_url)

    def test_noOpenID(self):
        self.fetcher.documents = {
            self.id_url: ('text/plain', "junk"),
        }
        self.failUnlessRaises(parse.ParseError,
                              self.consumer.discover, self.id_url)

    def test_yadis(self):
        self.fetcher.documents = {
            BaseTestDiscovery.id_url: ('application/xrds+xml', yadis_2entries),
            }

        final_url, services = self.consumer.discover(self.id_url)
        self.failUnlessEqual(len(services), 2,
                             "Not 2 services in %r" % (services,))
        self.failUnlessEqual(services[0].uri,
                             "http://www.myopenid.com/server")
        self.failUnlessEqual(services[1].uri,
                             "http://www.livejournal.com/openid/server.bml")


    def test_redirect(self):
        self.fetcher.redirect = "http://elsewhere.unittest/"
        self.fetcher.documents = {
            self.id_url: ('text/html', openid_html),
        }
        final_url, services = self.consumer.discover(self.id_url)
        self.failUnlessEqual(final_url, "http://elsewhere.unittest/")

    def test_emptyList(self):
        self.fetcher.documents = {
            self.id_url: ('application/xrds+xml', yadis_0entries),
        }
        final_url, services = self.consumer.discover(self.id_url)
        self.failIf(services)

    def test_emptyListWithLegacy(self):
        self.fetcher.documents = {
            self.id_url: ('text/html', openid_and_yadis_html),
            self.id_url + 'xrds': ('application/xrds+xml', yadis_0entries),
        }
        final_url, services = self.consumer.discover(self.id_url)
        self.failUnlessEqual(len(services), 1,
                             "Not one service in %r" % (services,))
        self.failUnlessEqual(services[0].uri,
                             "http://www.myopenid.com/server")
        self.failUnlessEqual(final_url, self.id_url)

    def test_yadisNoDelegate(self):
        self.fetcher.documents = {
            self.id_url: ('application/xrds+xml', yadis_no_delegate),
        }
        final_url, services = self.consumer.discover(self.id_url)
        self.failUnlessEqual(len(services), 1,
                             "Not 1 service in %r" % (services,))
        self.failUnlessEqual(services[0].uri,
                             "http://www.myopenid.com/server")

    def test_openidNoDelegate(self):
        self.fetcher.documents = {
            self.id_url: ('text/html', openid_html_no_delegate),
        }
        final_url, services = self.consumer.discover(self.id_url)
        self.failUnlessEqual(services[0].uri,
                             "http://www.myopenid.com/server")
        self.failUnlessEqual(final_url, self.id_url)

if __name__ == '__main__':
    unittest.main()
