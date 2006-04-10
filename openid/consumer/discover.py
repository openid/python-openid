from yadis.etxrd import nsTag

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

    def parseService(self, yadis_url, uri, type_uris, service_element):
        """Set the state of this object based on the contents of the
        service element."""
        self.type_uris = type_uris
        self.identity_url = yadis_url
        self.server_url = uri
        self.delegate = findDelegate(service_element)

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

    def getServerID(self):
        """Return the identifier that should be sent as the
        openid.identity_url parameter to the server."""
        if self.delegate is None:
            return self.identity_url
        else:
            return self.delegate

def findDelegate(service_element):
    """Return the content of the Delegate tag from the OpenID
    namespace in this service element. If no delegate is specified,
    returns None."""
    # XXX: should this die if there is more than one delegate element?
    delegates = service_element.findall(delegate_tag)
    for delegate_element in delegates:
        delegate = delegate_element.text
        break
    else:
        delegate = None

    return delegate
