from yadis.etxrd import nsTag
from yadis.discover import discover as yadisDiscover
from yadis.discover import DiscoveryFailure
from openid.consumer.parse import openIDDiscover as parseOpenIDLinkRel

OPENID_1_0_NS = 'http://openid.net/xmlns/1.0'
OPENID_1_2_TYPE = 'http://openid.net/signon/1.2'
OPENID_1_1_TYPE = 'http://openid.net/signon/1.1'
OPENID_1_0_TYPE = 'http://openid.net/signon/1.0'

delegate_tag = nsTag(OPENID_1_0_NS, 'Delegate')

class OpenIDServiceEndpoint(object):
    """Object representing an OpenID service endpoint."""
    openid_type_uris = [
        OPENID_1_2_TYPE,
        OPENID_1_1_TYPE,
        OPENID_1_0_TYPE,
        ]

    def __init__(self):
        self.identity_url = None
        self.server_url = None
        self.type_uris = []
        self.delegate = None
        self.used_yadis = False # whether this came from an XRDS

    def parseService(self, yadis_url, uri, type_uris, service_element):
        """Set the state of this object based on the contents of the
        service element."""
        self.type_uris = type_uris
        self.identity_url = yadis_url
        self.server_url = uri
        self.delegate = findDelegate(service_element)
        self.used_yadis = True

    def getServerID(self):
        """Return the identifier that should be sent as the
        openid.identity_url parameter to the server."""
        if self.delegate is None:
            return self.identity_url
        else:
            return self.delegate

    def fromBasicServiceEndpoint(cls, endpoint):
        """Create a new instance of this class from the endpoint
        object passed in.

        @return: None or OpenIDServiceEndpoint for this endpoint object"""
        type_uris = endpoint.matchTypes(cls.openid_type_uris)

        # If any Type URIs match and there is an endpoint URI
        # specified, then this is an OpenID endpoint
        if type_uris and endpoint.uri is not None:
            openid_endpoint = cls()
            openid_endpoint.parseService(
                endpoint.yadis_url,
                endpoint.uri,
                endpoint.type_uris,
                endpoint.service_element)
        else:
            openid_endpoint = None

        return openid_endpoint

    fromBasicServiceEndpoint = classmethod(fromBasicServiceEndpoint)

    def fromHTML(cls, uri, html):
        """Parse the given document as HTML looking for an OpenID <link
        rel=...>

        @raises: openid.consumer.parse.ParseError
        """
        delegate_url, server_url = parseOpenIDLinkRel(html)
        service = cls()
        service.identity_url = identity_url
        service.delegate = delegate_url
        service.server_url = server_url
        service.type_uris = [OPENID_1_0_TYPE]
        service.extensions = []
        return service

    fromHTML = classmethod(fromHTML)

def findDelegate(service_element):
    """Extract a openid:Delegate value from a Yadis Service element
    represented as an ElementTree Element object. If no delegate is
    found, returns None."""
    # XXX: should this die if there is more than one delegate element?
    delegates = service_element.findall(delegate_tag)
    for delegate_element in delegates:
        delegate = delegate_element.text
        break
    else:
        delegate = None

    return delegate

def discover(uri, fetcher):
    """Discover OpenID services for a URI. Tries Yadis and falls back
    on old-style <link rel='...'> discovery if Yadis fails.

    @param uri: normalized identity URL
    @type uri: str

    @returns: services
    @returntype: list(OpenIDServiceEndpoint)

    @raises: DiscoveryFailure
    """
    # Might raise a yadis.discover.DiscoveryFailure if no document
    # came back for that URI at all.  I don't think falling back
    # to OpenID 1.0 discovery on the same URL will help, so don't bother
    # to catch it.
    response = yadisDiscover(fetcher, uri)

    try:
        openid_services = extractServices(
            response.normalized_uri, response.response_text,
            OpenIDServiceEndpoint)
    except XRDSError:
        # Does not parse as a Yadis XRDS file
        openid_services = []

    if not openid_services:
        # Either not an XRDS or there are no OpenID services.

        # if we got the Yadis content-type or followed the Yadis
        # header, re-fetch the document without following the Yadis
        # header, with no Accept header.
        if resp.isXRDS():
            http_resp = fetcher.fetch(uri)
            if http_resp.status != 200:
                raise DiscoveryFailure(
                    'HTTP Response status from identity URL host is not 200. '
                    'Got status %r' % (http_resp.status,), http_resp)
            body = http_resp.body
            identity_url = http_resp.final_url
        else:
            body = resp.response_text
            identity_url = resp.normalized_uri

        # Try to parse the response as HTML to get OpenID 1.0/1.1
        # <link rel="...">
        try:
            service = OpenIDServiceEndpoint.fromHTML(body, identity_url)
        except ParseError:
            pass # Parsing failed, so return an empty list
        else:
            openid_services = [service]

    return openid_services
