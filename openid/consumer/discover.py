# -*- test-case-name: openid.test.test_discover -*-

from urljr import fetchers

from openid import oidutil

# If the Yadis library is available, use it. Otherwise, only use
# old-style discovery.
try:
    import yadis
except ImportError:
    yadis_available = False

    oidutil.log('Consumer operating without Yadis support '
                '(failed to import Yadis library)')

    class DiscoveryFailure(RuntimeError):
        """A failure to discover an OpenID server.

        When the C{yadis} package is available, this is
        C{yadis.discover.DiscoveryFailure}."""
else:
    yadis_available = True
    from yadis.etxrd import nsTag, XRDSError
    from yadis.services import applyFilter as extractServices
    from yadis.discover import discover as yadisDiscover
    from yadis.discover import DiscoveryFailure
    from yadis import xrires, filters

from openid.consumer.parse import openIDDiscover as parseOpenIDLinkRel
from openid.consumer.parse import ParseError

OPENID_1_0_NS = 'http://openid.net/xmlns/1.0'
OPENID_1_2_TYPE = 'http://openid.net/signon/1.2'
OPENID_1_1_TYPE = 'http://openid.net/signon/1.1'
OPENID_1_0_TYPE = 'http://openid.net/signon/1.0'

class OpenIDServiceEndpoint(object):
    """Object representing an OpenID service endpoint.

    @ivar identity_url: the verified identifier.
    @ivar canonicalID: For XRI, the persistent identifier.
    """
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
        self.canonicalID = None
        self.used_yadis = False # whether this came from an XRDS

    def usesExtension(self, extension_uri):
        return extension_uri in self.type_uris

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
            return self.canonicalID or self.identity_url
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
        service.identity_url = uri
        service.delegate = delegate_url
        service.server_url = server_url
        service.type_uris = [OPENID_1_0_TYPE]
        return service

    fromHTML = classmethod(fromHTML)

def findDelegate(service_element):
    """Extract a openid:Delegate value from a Yadis Service element
    represented as an ElementTree Element object. If no delegate is
    found, returns None."""
    # XXX: should this die if there is more than one delegate element?
    delegate_tag = nsTag(OPENID_1_0_NS, 'Delegate')

    delegates = service_element.findall(delegate_tag)
    for delegate_element in delegates:
        delegate = delegate_element.text
        break
    else:
        delegate = None

    return delegate

def discoverYadis(uri):
    """Discover OpenID services for a URI. Tries Yadis and falls back
    on old-style <link rel='...'> discovery if Yadis fails.

    @param uri: normalized identity URL
    @type uri: str

    @return: (identity_url, services)
    @rtype: (str, list(OpenIDServiceEndpoint))

    @raises: DiscoveryFailure
    """
    # Might raise a yadis.discover.DiscoveryFailure if no document
    # came back for that URI at all.  I don't think falling back
    # to OpenID 1.0 discovery on the same URL will help, so don't
    # bother to catch it.
    response = yadisDiscover(uri)

    identity_url = response.normalized_uri
    try:
        openid_services = extractServices(
            response.normalized_uri, response.response_text,
            OpenIDServiceEndpoint)
    except XRDSError:
        # Does not parse as a Yadis XRDS file
        openid_services = []

    if not openid_services:
        # Either not an XRDS or there are no OpenID services.

        if response.isXRDS():
            # if we got the Yadis content-type or followed the Yadis
            # header, re-fetch the document without following the Yadis
            # header, with no Accept header.
            return discoverNoYadis(uri)
        else:
            body = response.response_text

        # Try to parse the response as HTML to get OpenID 1.0/1.1
        # <link rel="...">
        try:
            service = OpenIDServiceEndpoint.fromHTML(identity_url, body)
        except ParseError:
            pass # Parsing failed, so return an empty list
        else:
            openid_services = [service]

    return (identity_url, openid_services)


def discoverXRI(iname):
    endpoints = []
    try:
        canonicalID, services = xrires.ProxyResolver().query(
            iname, OpenIDServiceEndpoint.openid_type_uris)
        flt = filters.mkFilter(OpenIDServiceEndpoint)
        for service_element in services:
            endpoints.extend(flt.getServiceEndpoints(iname, service_element))
    except XRDSError:
        oidutil.log('xrds error on ' + iname)

    for endpoint in endpoints:
        # Is there a way to pass this through the filter to the endpoint
        # constructor instead of tacking it on after?
        endpoint.canonicalID = canonicalID

    # FIXME: returned xri should probably be in some normal form
    return iname, endpoints


def discoverNoYadis(uri):
    http_resp = fetchers.fetch(uri)
    if http_resp.status != 200:
        raise DiscoveryFailure(
            'HTTP Response status from identity URL host is not 200. '
            'Got status %r' % (http_resp.status,), http_resp)
    identity_url = http_resp.final_url

    # Try to parse the response as HTML to get OpenID 1.0/1.1
    # <link rel="...">
    try:
        service = OpenIDServiceEndpoint.fromHTML(identity_url, http_resp.body)
    except ParseError:
        openid_services = []
    else:
        openid_services = [service]

    return identity_url, openid_services

if yadis_available:
    discover = discoverYadis
else:
    discover = discoverNoYadis
