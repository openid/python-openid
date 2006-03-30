from yadis.etxrd import nsTag
from yadis.filters import getEndpoints

OPENID_1_0_NS = 'http://openid.net/xmlns/1.0'
OPENID_1_2_TYPE = 'http://openid.net/signon/1.2'
OPENID_1_1_TYPE = 'http://openid.net/signon/1.1'
OPENID_1_0_TYPE = 'http://openid.net/signon/1.0'

delegate_tag = nsTag(OPENID_1_0_NS, 'Delegate')
extension_tag = nsTag(OPENID_1_0_NS, 'Extension')

class OpenIDEndpoint(object):
    type_uris = [
        OPENID_1_2_TYPE,
        OPENID_1_1_TYPE,
        OPENID_1_0_TYPE,
        ]

    type = None
    identifier = None
    uri = None
    delegate = None
    extensions = None

    def fromBasicEndpoint(cls, basic_endpoint):
        if basic_endpoint.type not in cls.type_uris:
            return None

        endpoint = cls()
        endpoint.type = basic_endpoint.type
        endpoint.identifier = basic_endpoint.yadis_url
        endpoint.uri = basic_endpoint.uri

        # XXX: should this die if there is more than one delegate element?
        delegates = basic_endpoint.service_element.findall(delegate_tag)
        for delegate_element in delegates:
            endpoint.delegate = delegate_element.text
            break
        else:
            endpoint.delegate = None

        if endpoint.type == OPENID_1_2_TYPE:
            endpoint.extensions = []
            extensions = basic_endpoint.service_element.findall(extension_tag)
            for extension_element in extensions:
                endpoint.extensions.append(extension_element.text)

        return endpoint

    fromBasicEndpoint = classmethod(fromBasicEndpoint)
