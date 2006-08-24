from __future__ import generators

__all__ = ['Service', 'ServiceParser', 'ServiceList', 'XrdsError']

import xml.dom
from servicetypes.base import GenericParser
import warnings

xrds_namespace = "xri://$xrds"
xrd_namespace = "xri://$xrd*($v*2.0)"

class XrdsError(Exception):
    """An error with the XRDS document."""

class ParseError(XrdsError):
    def __init__(self, other):
        self.other = other

    def __str__(self):
        return str(self.other)

    def __repr__(self):
        return '%s(%s)' % (type(self).__name__, repr(self.other))

def _matchElement(node, namespace, localname):
    return (node.nodeType == node.ELEMENT_NODE and
            node.namespaceURI == namespace and
            node.localName == localname)

_DATA_NODE_TYPES = [xml.dom.Node.CDATA_SECTION_NODE,
                    xml.dom.Node.TEXT_NODE]

def _getContents(node):
    chunks = []
    for child in node.childNodes:
        if child.nodeType in _DATA_NODE_TYPES:
            chunks.append(child.data)

    return ''.join(chunks)

def _getServices(dom):
    services = []

    root = dom.documentElement
    if _matchElement(root, xrds_namespace, 'XRDS'):
        for node in root.childNodes:
            if _matchElement(node, xrd_namespace, 'XRD'):
                services.extend(_getXRDServices(node))

    return services

def _getXRDServices(xrd):
    services = []
    for node in xrd.childNodes:
        if _matchElement(node, xrd_namespace, 'Service'):
            services.append(Service(node))

    return services

def _getAttributeValue(node, namespace, attr_name):
    prio_s = node.getAttributeNS(namespace, attr_name)

    # I don't know if this is a microdom bug or we just disagree on the API,
    # but that has an annoying tendency to return None.
    if (not prio_s) and (not node.prefix) and (
        node.namespaceURI == xrd_namespace):
        prio_s = node.getAttribute(attr_name)

    return prio_s

def _getXRDPriority(node):
    prio_s = _getAttributeValue(node, xrd_namespace, 'priority')
    if prio_s:
        return int(prio_s)
    else:
        return None

class Service(object):
    """I extract information from an XRD Service element.

    @ivar node: A C{Service} element
    @type node: XML DOM Element
    """
    def __init__(self, service_node):
        """Adapt a node.

        @param service_node: A C{Service} element
        @type service_node: XML DOM Element
        """
        self.node = service_node

    def priority(self):
        """The priority defined on the Service element.

        @returntype: int or NoneType"""
        return _getXRDPriority(self.node)

    def serviceTypes(self):
        """My service types.

        @returns: Generator over the URI in the Type elements.
        @returntype: unicode
        """
        service_type = None
        for node in self.node.childNodes:
            if _matchElement(node, xrd_namespace, 'Type'):
                yield _getContents(node)

    def _serviceURIs(self):
        """() -> [_ServiceURI]"""
        uris = []
        for node in self.node.childNodes:
            if _matchElement(node, xrd_namespace, 'URI'):
                uris.append(_ServiceURI(node))

        return uris

    def getExtraElements(self):
        extras = []
        for child in self.node.childNodes:
            if (child.nodeType == child.ELEMENT_NODE and
                child.namespaceURI != xrd_namespace):
                extras.append(child)

        return extras

    def getElementContents(self, namespace):
        pairs = []
        for child in self.node.childNodes:
            if (child.nodeType == child.ELEMENT_NODE and
                child.namespaceURI == namespace):
                pairs.append((child.localName, _getContents(child)))
        return pairs

class _ServiceURI(object):
    def __init__(self, uri_node):
        """xml.dom.Node -> NoneType"""
        self.node = uri_node

    def priority(self):
        """() -> int or NoneType"""
        return _getXRDPriority(self.node)

    def uri(self):
        """() -> str"""
        return _getContents(self.node)

def _prioSort(objs):
    """Sort a list of objects all having a priority method.

    The priority method should return an integer or None."""

    # Find max priority
    max_prio = None
    for obj in objs:
        prio = obj.priority()
        if prio is not None and (max_prio is None or prio > max_prio):
            max_prio = prio

    if max_prio is None:
        # There are no nodes with a set priority, so return them in
        # the order they were given to us.
        return objs

    # Create a list of pairs of priority and obj, giving objs with
    # no specified priority a higher priority than any other obj.
    def getPriority(obj):
        prio = obj.priority()
        if prio is None:
            prio = max_prio + 1

        return (prio, obj)

    prio_objs = map(getPriority, objs)

    # Sort the objs and peel off the priorities. Python has a stable
    # sort function, so ties will be in the order that they appear in
    # the input.
    prio_objs.sort()
    sorted_objs = [obj for (_, obj) in prio_objs]

    return sorted_objs

def _getServiceURIs(doc):
    services = _prioSort(_getServices(doc))

    uris = []
    for service in services:
        service_uris = service._serviceURIs()
        if not service_uris:
            uris.append((None, service))

        sorted_service_uris = _prioSort(service_uris)
        for uri in sorted_service_uris:
            uris.append((uri.uri(), service))

    return uris


class ServiceParser(object):

    defaultParserClass = GenericParser

    def __init__(self, parsers=None):
        self.parsers = {}
        if parsers is not None:
            for p in parsers:
                self.register(p)

    def parse(self, xmldoc):
        """Parse a XRDS document.

        Parsing a document does not change my state, so you may use one
        instance of me to parse as many documents as you wish.

        @returns: A list of L{Service}s.
        @returntype: L{ServiceList}

        @raises XrdsError: When some required element of the document is
            not present, i.e. C{XRDS} and C{XRD}.

        @raises Exception: The underlying XML parser may raise other
            exceptions if the document is not well-formed XML.
            (FixMe: Should we catch these and re-cast them as XrdsErrors?)
        """
        from xml.dom import minidom
        # importing this to be able to catch its exceptions, but having
        # to know which parser its using violates the encapsulation and
        # will probably be wrong.
        from xml.parsers.expat import ExpatError
        from xml.sax import SAXException
        try:
            domtree = minidom.parseString(xmldoc)
        except ExpatError, e:
            raise ParseError(e)
        except SAXException, e:
            raise ParseError(e)

        return self.extractServices(domtree)

    def extractServices(self, domtree):
        """Extract the services in the given DOM tree that I know how
        to parse.

        XXX: document me"""
        self._validate(domtree)
        services = []
        for uri, service in _getServiceURIs(domtree):
            for stype in service.serviceTypes():
                parser = self.parsers.get(stype, None)
                if parser is None:
                    parser = self.defaultParserClass(stype)
                    self.parsers[stype] = parser

                sdescriptor = parser.parse(service)
                if uri is not None:
                    sdescriptor.uri = uri.encode('ascii')
                else:
                    sdescriptor.uri = uri
                services.append(sdescriptor)
        return ServiceList(services)

    def _validate(self, domtree):
        root = domtree.documentElement
        if not _matchElement(root, xrds_namespace, 'XRDS'):
            raise XrdsError("Root element is not XRDS.")
        for node in root.childNodes:
            if _matchElement(node, xrd_namespace, 'XRD'):
                break
        else:
            raise XrdsError("No XRD elements found.")

    def register(self, parser):
        if self.parsers.has_key(parser.type):
            fmt = ("%s: previously registered parser %r being replaced "
                   "for type %r by %r.")
            warnings.warn(fmt % (self, self.parsers[parser.type],
                                 parser.type, parser))
        self.parsers[parser.type] = parser


class ServiceList(object):
    def __init__(self, services):
        self.services = services

    def __iter__(self):
        return iter(self.services)

    def getServices(self, *types):
        return [s for s in self.services if ((not types) or (s.type in types))]
