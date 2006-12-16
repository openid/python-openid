# -*- test-case-name: openid.test.test_discover -*-

import urlparse

from openid import oidutil, fetchers, urinorm

from openid import yadis
from openid.yadis.etxrd import nsTag, XRDSError
from openid.yadis.services import applyFilter as extractServices
from openid.yadis.discover import discover as yadisDiscover
from openid.yadis.discover import DiscoveryFailure
from openid.yadis import xrires, filters

from openid.consumer.parse import openIDDiscover as parseOpenIDLinkRel
from openid.consumer.parse import ParseError

OPENID_1_0_NS = 'http://openid.net/xmlns/1.0'
OPENID_IDP_2_0_TYPE = 'http://openid.net/server/2.0'
OPENID_2_0_TYPE = 'http://openid.net/signon/2.0'
OPENID_1_2_TYPE = 'http://openid.net/signon/1.2'
OPENID_1_1_TYPE = 'http://openid.net/signon/1.1'
OPENID_1_0_TYPE = 'http://openid.net/signon/1.0'

from openid.message import OPENID1_NS as OPENID_1_0_MESSAGE_NS
from openid.message import OPENID2_NS as OPENID_2_0_MESSAGE_NS

class OpenIDServiceEndpoint(object):
    """Object representing an OpenID service endpoint.

    @ivar identity_url: the verified identifier.
    @ivar canonicalID: For XRI, the persistent identifier.
    """
    openid_type_uris = [
        OPENID_IDP_2_0_TYPE,

        OPENID_2_0_TYPE,
        OPENID_1_2_TYPE,
        OPENID_1_1_TYPE,
        OPENID_1_0_TYPE,
        ]

    def preferredNamespace(self):
        if (OPENID_IDP_2_0_TYPE in self.type_uris or 
            OPENID_2_0_TYPE in self.type_uris):
            return OPENID_2_0_MESSAGE_NS
        else:
            return OPENID_1_0_MESSAGE_NS

    def __init__(self):
        self.claimed_id = None
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
        self.server_url = uri
        self.used_yadis = True

        if not (OPENID_IDP_2_0_TYPE in self.type_uris):            
            # XXX: This has crappy implications for Service elements
            # that contain both 'server' and 'signon' Types.  But
            # that's a pathological configuration anyway, so I don't
            # think I care.
            self.delegate = findDelegate(service_element)
            self.claimed_id = yadis_url

    def getServerID(self):
        """Return the identifier that should be sent as the
        openid.identity parameter to the server."""
        if (self.delegate is self.canonicalID is None):
            return self.claimed_id
        else:
            return self.canonicalID or self.delegate

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
        service.claimed_id = uri
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

def normalizeURL(url):
    """Normalize a URL, converting normalization failures to
    DiscoveryFailure"""
    try:
        return urinorm.urinorm(url)
    except ValueError, why:
        raise DiscoveryFailure('Normalizing identifier: %s' % (why[0],), None)

def discoverYadis(uri):
    """Discover OpenID services for a URI. Tries Yadis and falls back
    on old-style <link rel='...'> discovery if Yadis fails.

    @param uri: normalized identity URL
    @type uri: str

    @return: (claimed_id, services)
    @rtype: (str, list(OpenIDServiceEndpoint))

    @raises: DiscoveryFailure
    """
    # Might raise a yadis.discover.DiscoveryFailure if no document
    # came back for that URI at all.  I don't think falling back
    # to OpenID 1.0 discovery on the same URL will help, so don't
    # bother to catch it.
    response = yadisDiscover(uri)

    claimed_id = response.normalized_uri
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
            service = OpenIDServiceEndpoint.fromHTML(claimed_id, body)
        except ParseError:
            pass # Parsing failed, so return an empty list
        else:
            openid_services = [service]

    return (claimed_id, openid_services)

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
    claimed_id = http_resp.final_url

    # Try to parse the response as HTML to get OpenID 1.0/1.1
    # <link rel="...">
    try:
        service = OpenIDServiceEndpoint.fromHTML(claimed_id, http_resp.body)
    except ParseError:
        openid_services = []
    else:
        openid_services = [service]

    return claimed_id, openid_services

def discover(uri):
    parsed = urlparse.urlparse(uri)
    if parsed[0] and parsed[1]:
        if parsed[0] not in ['http', 'https']:
            raise DiscoveryFailure('URI scheme is not HTTP or HTTPS', None)
    else:
        uri = 'http://' + uri
    
    uri = normalizeURL(uri)
    claimed_id, openid_services = discoverYadis(uri)
    claimed_id = normalizeURL(claimed_id)
    return claimed_id, openid_services
