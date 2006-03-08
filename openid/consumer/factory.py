
"""OpenIDConsumer with de-coupled discovery.

For use with alternate discovery methods such as YADIS.
"""

from openid.consumer import consumer


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


class OpenIDConsumer(object):

    requestClass = OpenIDRequest

    def __init__(self, store, trust_root):
        self.orig = consumer.OpenIDConsumer(store)
        self.trust_root = trust_root

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

from yadis.servicetypes.openid import OpenIDParser, OpenIDDescriptor
from yadis.servicetypes.base import IParser

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
