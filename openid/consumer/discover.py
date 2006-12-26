# -*- test-case-name: openid.test.test_discover -*-

import urlparse

from openid import oidutil, fetchers, urinorm

from openid import yadis
from openid.yadis.etxrd import nsTag, XRDSError, XRD_NS_2_0
from openid.yadis.services import applyFilter as extractServices
from openid.yadis.discover import discover as yadisDiscover
from openid.yadis.discover import DiscoveryFailure
from openid.yadis import xrires, filters

from openid.consumer import html_parse

OPENID_1_0_NS = 'http://openid.net/xmlns/1.0'
OPENID_IDP_2_0_TYPE = 'http://openid.net/server/2.0'
OPENID_2_0_TYPE = 'http://openid.net/signon/2.0'
OPENID_1_1_TYPE = 'http://openid.net/signon/1.1'
OPENID_1_0_TYPE = 'http://openid.net/signon/1.0'

from openid.message import OPENID1_NS as OPENID_1_0_MESSAGE_NS
from openid.message import OPENID2_NS as OPENID_2_0_MESSAGE_NS

class OpenIDServiceEndpoint(object):
    """Object representing an OpenID service endpoint.

    @ivar identity_url: the verified identifier.
    @ivar canonicalID: For XRI, the persistent identifier.
    """

    # OpenID service type URIs, listed in order of preference.  The
    # ordering of this list affects yadis and XRI service discovery.
    openid_type_uris = [
        OPENID_IDP_2_0_TYPE,

        OPENID_2_0_TYPE,
        OPENID_1_1_TYPE,
        OPENID_1_0_TYPE,
        ]

    def preferredNamespace(self):
        if (OPENID_IDP_2_0_TYPE in self.type_uris or
            OPENID_2_0_TYPE in self.type_uris):
            return OPENID_2_0_MESSAGE_NS
        else:
            return OPENID_1_0_MESSAGE_NS

    def compatibilityMode(self):
        return OPENID_2_0_MESSAGE_NS not in self.type_uris

    def isOPIdentifier(self):
        return OPENID_IDP_2_0_TYPE in self.type_uris

    def __init__(self):
        self.claimed_id = None
        self.server_url = None
        self.type_uris = []
        self.local_id = None
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

        if not self.isOPIdentifier():
            # XXX: This has crappy implications for Service elements
            # that contain both 'server' and 'signon' Types.  But
            # that's a pathological configuration anyway, so I don't
            # think I care.
            self.local_id = findOPLocalIdentifier(service_element,
                                                  self.type_uris)
            self.claimed_id = yadis_url



    def getLocalID(self):
        """Return the identifier that should be sent as the
        openid.identity parameter to the server."""
        if (self.local_id is self.canonicalID is None):
            return self.claimed_id
        else:
            return self.local_id or self.canonicalID

    def isIdentifierSelect(self):
        return self.claimed_id is None

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

        @rtype: [OpenIDServiceEndpoint]
        """
        discovery_types = [
            (OPENID_2_0_TYPE, 'openid2.provider', 'openid2.local_id'),
            (OPENID_1_1_TYPE, 'openid.server', 'openid.delegate'),
            ]

        link_attrs = html_parse.parseLinkAttrs(html)
        services = []
        for type_uri, op_endpoint_rel, local_id_rel in discovery_types:
            op_endpoint_url = html_parse.findFirstHref(
                link_attrs, op_endpoint_rel)
            if op_endpoint_url is None:
                continue

            service = cls()
            service.claimed_id = uri
            service.local_id = html_parse.findFirstHref(
                link_attrs, local_id_rel)
            service.server_url = op_endpoint_url
            service.type_uris = [type_uri]

            services.append(service)

        return services

    fromHTML = classmethod(fromHTML)

def findOPLocalIdentifier(service_element, type_uris):
    """Find the OP-Local Identifier for this xrd:Service element.

    This considers openid:Delegate to be a synonym for xrd:LocalID if
    both OpenID 1.X and OpenID 2.0 types are present. If only OpenID
    1.X is present, it returns the value of openid:Delegate. If only
    OpenID 2.0 is present, it returns the value of xrd:LocalID. If
    there is more than one LocalID tag and the values are different,
    it raises a DiscoveryFailure. This is also triggered when the
    xrd:LocalID and openid:Delegate tags are different.

    @param service_element: The xrd:Service element
    @type service_element: ElementTree.Node

    @param type_uris: The xrd:Type values present in this service
        element. This function could extract them, but higher level
        code needs to do that anyway.
    @type type_uris: [str]

    @raises: DiscoveryFailure

    @returns: The OP-Local Identifier for this service element, if one
        is present, or None otherwise.
    @rtype: str or unicode or NoneType
    """
    # XXX: Test this function on its own!

    # Build the list of tags that could contain the OP-Local Identifier
    local_id_tags = []
    if (OPENID_1_1_TYPE in type_uris or
        OPENID_1_0_TYPE in type_uris):
        local_id_tags.append(nsTag(OPENID_1_0_NS, 'Delegate'))

    if OPENID_2_0_TYPE in type_uris:
        local_id_tags.append(nsTag(XRD_NS_2_0, 'LocalID'))

    # Walk through all the matching tags and make sure that they all
    # have the same value
    local_id = None
    for local_id_tag in local_id_tags:
        for local_id_element in service_element.findall(local_id_tag):
            if local_id is None:
                local_id = local_id_element.text
            elif local_id != local_id_element.text:
                format = 'More than one %r tag found in one service element'
                message = format % (local_id_tag,)
                raise DiscoveryFailure(message, None)

    return local_id

def normalizeURL(url):
    """Normalize a URL, converting normalization failures to
    DiscoveryFailure"""
    try:
        return urinorm.urinorm(url)
    except ValueError, why:
        raise DiscoveryFailure('Normalizing identifier: %s' % (why[0],), None)

def arrangeByType(service_list, preferred_types):
    """Rearrange service_list in a new list so services are ordered by
    types listed in preferred_types.  Return the new list."""

    def enumerate(elts):
        """Return an iterable that pairs the index of an element with
        that element.

        For Python 2.2 compatibility"""
        return zip(range(len(elts)), elts)

    def bestMatchingService(service):
        """Return the index of the first matching type, or something
        higher if no type matches.

        This provides an ordering in which service elements that
        contain a type that comes earlier in the preferred types list
        come before service elements that come later. If a service
        element has more than one type, the most preferred one wins.
        """
        for i, t in enumerate(preferred_types):
            if preferred_types[i] in service.type_uris:
                return i

        return len(preferred_types)

    # Build a list with the service elements in tuples whose
    # comparison will prefer the one with the best matching service
    prio_services = [(bestMatchingService(s), orig_index, s)
                     for (orig_index, s) in enumerate(service_list)]
    prio_services.sort()

    # Now that the services are sorted by priority, remove the sort
    # keys from the list.
    for i in range(len(prio_services)):
        prio_services[i] = prio_services[i][2]

    return prio_services

def getOPOrUserServices(openid_services):
    """Extract OP Identifier services.  If none found, return the
    rest, sorted with most preferred first according to
    OpenIDServiceEndpoint.openid_type_uris.

    openid_services is a list of OpenIDServiceEndpoint objects.

    Returns a list of OpenIDServiceEndpoint objects."""

    op_services = arrangeByType(openid_services, [OPENID_IDP_2_0_TYPE])

    openid_services = arrangeByType(openid_services,
                                    OpenIDServiceEndpoint.openid_type_uris)

    return op_services or openid_services

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

    yadis_url = response.normalized_uri
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
        openid_services = OpenIDServiceEndpoint.fromHTML(yadis_url, body)

    return (yadis_url, getOPOrUserServices(openid_services))

def discoverXRI(iname):
    endpoints = []
    try:
        canonicalID, services = xrires.ProxyResolver().query(
            iname, OpenIDServiceEndpoint.openid_type_uris)

        if canonicalID is None:
            raise XRDSError('No CanonicalID found for XRI %r' % (iname,))

        flt = filters.mkFilter(OpenIDServiceEndpoint)
        for service_element in services:
            endpoints.extend(flt.getServiceEndpoints(iname, service_element))
    except XRDSError:
        oidutil.log('xrds error on ' + iname)

    for endpoint in endpoints:
        # Is there a way to pass this through the filter to the endpoint
        # constructor instead of tacking it on after?
        endpoint.canonicalID = canonicalID
        endpoint.claimed_id = canonicalID

    # FIXME: returned xri should probably be in some normal form
    return iname, getOPOrUserServices(endpoints)


def discoverNoYadis(uri):
    http_resp = fetchers.fetch(uri)
    if http_resp.status != 200:
        raise DiscoveryFailure(
            'HTTP Response status from identity URL host is not 200. '
            'Got status %r' % (http_resp.status,), http_resp)

    claimed_id = http_resp.final_url
    openid_services = OpenIDServiceEndpoint.fromHTML(
        claimed_id, http_resp.body)
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
