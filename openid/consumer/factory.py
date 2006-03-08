
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

    authreq = None
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

    def _constructRedirect(self, idreq, return_to):
        if not idreq.delegate:
            raise NotImplementedError # XXX FIXME
        authreq = self.orig._newAuthRequest("-unused-", idreq.delegate,
                                            idreq.uri)
        idreq.authreq = authreq
        return self.orig.constructRedirect(authreq, return_to, self.trust_root)

    def _completeAuth(self, idreq, args):
        return self.orig.completeAuth(idreq.authreq.token, args)


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

        return consumer.SUCCESS, self.consumer.makeRequest(*info)


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
