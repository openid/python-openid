from yadis.etxrd import nsTag

OPENID_1_0_NS = 'http://openid.net/xmlns/1.0'
OPENID_1_2_TYPE = 'http://openid.net/signon/1.2'
OPENID_1_1_TYPE = 'http://openid.net/signon/1.1'
OPENID_1_0_TYPE = 'http://openid.net/signon/1.0'

delegate_tag = nsTag(OPENID_1_0_NS, 'Delegate')
extension_tag = nsTag(OPENID_1_0_NS, 'Extension')

class OpenIDServiceEndpoint(object):
    openid_type_uris = [
        OPENID_1_2_TYPE,
        OPENID_1_1_TYPE,
        OPENID_1_0_TYPE,
        ]

    def __init__(self):
        self.identity_url = None
        self.server_url = None
        self.type_uris = []
        self.extensions = []
        self.delegate = None

    def parseService(self, yadis_url, uri, type_uris, service_element):
        self.type_uris = type_uris
        self.identity_url = yadis_url
        self.server_url = uri
        self.delegate = findDelegate(service_element)
        if self.delegate is None:
            self.delegate = self.identity_url

        if OPENID_1_2_TYPE in self.type_uris:
            self.extensions = findExtensions(service_element)
        else:
            self.extensions = []

    def fromBasicServiceEndpoint(cls, endpoint):
        type_uris = endpoint.matchTypes(cls.openid_type_uris)

        # If any Type URIs match and there is an endpoint URI
        # specified, then this is an OpenID endpoint
        if type_uris and endpoint.uri is not None:
            openid_endpoint = cls()
            openid_endpoint.parseService(
                endpoint.yadis_url,
                endpoint.uri,
                type_uris,
                endpoint.service_element)
        else:
            openid_endpoint = None

        return openid_endpoint

    fromBasicServiceEndpoint = classmethod(fromBasicServiceEndpoint)

def findDelegate(service_element):
    # XXX: should this die if there is more than one delegate element?
    delegates = service_element.findall(delegate_tag)
    for delegate_element in delegates:
        delegate = delegate_element.text
    else:
        delegate = None

    return delegate

def findExtensions(service_element):
    return [ext.text for ext in service_element.findall(extension_tag)]
