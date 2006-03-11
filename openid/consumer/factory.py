
"""OpenIDConsumer with de-coupled discovery.

For use with alternate discovery methods such as YADIS.
"""

from openid.consumer import consumer
from openid import oidutil

from yadis.discover import discover as yadisDiscover
from yadis.discover import DiscoveryFailure
from yadis import xrd
from yadis.servicetypes.openid import OPENID_1_0, OpenIDParser, OpenIDDescriptor
import parse

class OpenIDRequest(object):
    """I want log in to an OpenID Server.

    @type authreq: L{openid.consumer.consumer.OpenIDAuthRequest}

    @type delegate: str
    @param delegate: The string (typically a URL) the OpenID server knows me as.

    @type uri: str
    @param uri: The location of the OpenID server endpoint.
    """

    # A class in identity crisis:
    #  * This class is almost yadis.servicetypes.openid.OpenIDDescriptor,
    #    but with a few methods to make it do useful things with the consumer.
    #
    #  * It is *also* almost like openid.consumer.consumer.OpenIDAuthRequest,
    #    but OpenIDAuthRequest is created with a nonce.  (And creating a
    #    nonce changes the state of the store, so we probably shouldn't do
    #    that until we really want to.)
    #

    _authreq = None
    delegate = None
    uri = None
    consumer = None

    def constructRedirect(self, return_to):
        # Right now we're calling out to the implementation as it exists
        # in the Consumer object, but maybe that object should be split
        # up a bit and some of the implementation moved in to here?
        # (Discovery in one class, createRedirect and response verification
        # in this one, and association management in another?)
        #
        # The interface this class presents should be able to stay the same
        # in any case.
        return self.consumer._constructRedirect(self, return_to)

    def complete(self, args):
        return self.consumer._complete(self, args)

    def getToken(self):
        return self.getAuthRequest().token

    def getAuthRequest(self):
        if self._authreq is None:
            status, info = self.consumer._newAuthRequest('-unused-',
                                                         self.delegate,
                                                         self.uri)
            # heck, that method doesn't even have a path where it
            # returns anything but SUCCESS.
            assert status is consumer.SUCCESS
            self._authreq = info

        return self._authreq

    def __eq__(self, other):
        # XXX: Must the consumer attributes be equal?
        # That really means "must the store attributes be equal,"
        # which means defining equivalancy for stores, which is probably
        # hard.
        return ((self.uri == other.uri) and
                (self.delegate == other.delegate) and
                (self._authreq == other._authreq) and
                (self.consumer == other.consumer))

    def __ne__(self, other):
        return not (self == other)

    def __repr__(self):
        return '<%s.%s uri:%s delegate:%s consumer@0x%x>' % (
            __name__, self.__class__.__name__, self.uri, self.delegate,
            id(self.consumer))

class OpenIDConsumer(object):

    requestClass = OpenIDRequest

    sessionKeyPrefix = "_openid_consumer_"

    _server_list = 'servers'
    _visited_list = 'visited'
    _last_uri = 'last_uri'

    def __init__(self, trust_root, store, session, fetcher=None):
        self.orig = consumer.OpenIDConsumer(store, fetcher=fetcher)
        self.fetcher = fetcher
        self.session = session
        self.trust_root = trust_root

        # XXX: Will want multiple service parsers if we support more than one
        # value of XRDS/Service/Type
        service_parsers = [
            OpenIDParser(),
            ]
        self.xrd_parser = xrd.ServiceParser(service_parsers)

    def beginAuth(self, user_url):
        uri = oidutil.normalizeUrl(user_url)

        try:
            identity_url, next_server = self._popNextServer(uri)
        except DiscoveryFailure, e:
            return consumer.HTTP_FAILURE, e.http_response.status
        except parse.ParseError, e:
            return consumer.PARSE_ERROR, str(e)
        if not next_server:
            return consumer.PARSE_ERROR, "No supported OpenID services found."


        return self.orig._newAuthRequest(identity_url,
                                         next_server.delegate,
                                         next_server.uri)

    def _popNextServer(self, uri):
        identity_url, server_list, visited_list = self._getServerList(uri)
        if not server_list:
            return identity_url, None
        next_server = None
        for server in server_list:
            if server in visited_list:
                continue
            next_server = server
            visited_list.append(next_server)
            break
        else:
            # TODO: refersh server list
            next_server = server_list[0]
            visited_list[:] = [next_server]

        return identity_url, next_server

    def _getServerList(self, uri):
        previous_uri = self.session.get(
            self.sessionKeyPrefix + self._last_uri, None)
        if (not previous_uri) or (uri != previous_uri[0]):
            server_list = self._resetServerList()
            visited_list = self._resetVisitedList()
            identity_url = None
        else:
            identity_url = previous_uri[1]
            server_list = self.session.get(
                self.sessionKeyPrefix + self._server_list, None)
            if server_list is None:
                server_list = self._resetServerList()
                visited_list = self._resetVisitedList()
            else:
                visited_list = self.session.get(
                    self.sessionKeyPrefix + self._visited_list, None)
                if visited_list is None:
                    visited_list = self._resetVisitedList()

        if (not server_list) or (not identity_url):
            identity_url, openid_servers = self.discover(uri)
            visited_list = self._resetVisitedList()
            server_list[:] = openid_servers
            self.session[self.sessionKeyPrefix + self._last_uri] = (
                uri, identity_url)

        return identity_url, server_list, visited_list

    def _resetServerList(self):
        return self._resetSessionThing(self._server_list, [])

    def _resetVisitedList(self):
        return self._resetSessionThing(self._visited_list, [])

    def _resetSessionThing(self, key, value):
        self.session[self.sessionKeyPrefix + key] = value
        return self.session[self.sessionKeyPrefix + key]

    def discover(self, uri):
        # Might raise a yadis.discover.DiscoveryFailure if no document
        # came back for that URI at all.  I don't think falling back
        # to OpenID 1.0 discovery on the same URL will help, so don't bother
        # to catch it.
        final_uri, xrd_doc = yadisDiscover(self.fetcher, uri)

        try:
            yadis_services = self.xrd_parser.parse(xrd_doc)
        except xrd.XrdsError, xrd_err:
            # This next might raise parse.ParseError.
            openid_services = [
                discoveryVersion1FromString(final_uri, xrd_doc),
                ]
        else:
            openid_services = yadis_services.getServices(OPENID_1_0)

            if not openid_services:
                # If we're here, we found an XRD that didn't blow up,
                # but it didn't contain any recognized services
                # either.  We should re-start with old style discovery
                # (no following headers or content-negotiation tricks)
                # and see if we get HTML with some links.
                try:
                    openid_services = [discoveryVersion1(uri, self.fetcher)]
                except parse.ParseError:
                    # It *did* successfully parse for Yadis...
                    # (the logic here is questionable.)
                    pass

        return final_uri, openid_services

    def completeAuth(self, token, query):
        return self.orig.completeAuth(token, query)

    def makeRequest(self, consumer_id, server_id, server_url):
        descriptor = self.requestClass()
        if server_id:
            descriptor.delegate = server_id
        descriptor.uri = server_url
        return descriptor

    def makeRequestFromToken(self, token):
        fields = self.orig._splitToken(token)
        descriptor = self.requestClass()
        nonce, consumer_id, descriptor.delegate, descriptor.uri = fields
        descriptor._authreq = consumer.OpenIDAuthRequest(token,
                                                         descriptor.delegate,
                                                         descriptor.uri,
                                                         nonce)
        descriptor.consumer = self
        return descriptor

    def _constructRedirect(self, idreq, return_to):
        if not idreq.delegate:
            raise NotImplementedError # XXX FIXME
        authreq = idreq.getAuthRequest()
        return self.orig.constructRedirect(authreq, return_to, self.trust_root)

    def _completeAuth(self, idreq, args):
        return self.orig.completeAuth(idreq.getToken(), args)

    def _findIdentityInfo(self, url):
        return self.orig._findIdentityInfo(url)

    def _newAuthRequest(self, consumer_id, server_id, server_url):
        return self.orig._newAuthRequest(consumer_id, server_id, server_url)

    def __eq__(self, other):
        return ((self.orig == other.orig) and
                (self.trust_root == other.trust_root))

    def __ne__(self, other):
        return not (self == other)


def discoveryVersion1FromString(uri, doc):
    # XXX - parse.openIDDiscover probably doesn't need to take the URI
    # or return it.
    unused, delegate_url, server_url = \
            parse.openIDDiscover(uri, doc)
    service = OpenIDDescriptor()
    service.delegate = delegate_url
    service.uri = server_url
    service.type = OPENID_1_0
    return service

def discoveryVersion1(uri, fetcher):
    resp = fetcher.fetch(uri)
    if resp.status != 200:
        raise DiscoveryFailure(
            'HTTP Response status from identity URL host is not 200. '
            'Got status %r' % (resp.status,), resp)

    return discoveryVersion1FromString(resp.final_url, resp.body)

class DiscoveryVersion1(object):
    """OpenID v1.0 discovery.

    Uses the old 'link rel="openid.server"' parsing routine.
    """
    def __init__(self, oid_consumer):
        self.consumer = oid_consumer

    def discover(self, url):
        status, info = self.consumer._findIdentityInfo(url)
        if status is not consumer.SUCCESS:
            # No, really, can we have exceptions back, please?
            return status, info

        openidRequest = self.consumer.makeRequest(*info)
        openidRequest.consumer = self.consumer
        return consumer.SUCCESS, openidRequest


################################
#
# Adaptage for use with YADIS:
#

class OpenIDRequestDescriptor(OpenIDDescriptor, OpenIDRequest):
    """See the comments in the source for L{OpenIDRequest} about confusion.
    """
    pass

class OpenIDConsumerParser(OpenIDParser):
    """Adapter to the consumer-factory for use with our YADIS lib."""

    # implements(IParser)

    descriptorClass = OpenIDRequestDescriptor

    def __init__(self, oid_consumer):
        self.consumer = oid_consumer

    def parse(self, service):
        descriptor = super(OpenIDConsumerParser, self).parse(service)
        descriptor.consumer = self.consumer
        return descriptor

# registry.register([implementedBy(OpenIDConsumer)], IParser, '',
#                   OpenIDConsumerParser)
