"""Extension argument processing code
"""
__all__ = ['Message', 'NamespaceMap',
           'OPENID_NS', 'BARE_NS', 'OPENID1_NS', 'OPENID2_NS', 'SREG_URI']

import copy
import warnings
import urllib

from openid import oidutil
from openid import kvform
try:
    ElementTree = oidutil.importElementTree()
except ImportError:
    # No elementtree found, so give up, but don't fail to import,
    # since we have fallbacks.
    ElementTree = None

# URI for Simple Registration extension, the only commonly deployed
# OpenID 1.x extension, and so a special case
SREG_URI = 'http://openid.net/sreg/1.0'

# The OpenID 1.X namespace URI
OPENID1_NS = 'http://openid.net/sso/1.0'

# The OpenID 2.0 namespace URI
# XXX: not official (yet)
OPENID2_NS = 'http://openid.net/specs/2.0/base'

# The namespace consisting of pairs with keys that are prefixed with
# "openid."  but not in another namespace.
NULL_NAMESPACE = oidutil.Symbol('Null namespace')

# The null namespace, when it is an allowed OpenID namespace
OPENID_NS = oidutil.Symbol('OpenID namespace')

# The top-level namespace, excluding all pairs with keys that start
# with "openid."
BARE_NS = oidutil.Symbol('Bare namespace')

class UndefinedOpenIDNamespace(ValueError):
    """Raised if the generic OpenID namespace is accessed when there
    is no OpenID namespace set for this message."""

class Message(object):
    """
    In the implementation of this object, None represents the global
    namespace as well as a namespace with no key.

    @cvar namespaces: A dictionary specifying specific
        namespace-URI to alias mappings that should be used when
        generating namespace aliases.

    @ivar ns_args: two-level dictionary of the values in this message,
        grouped by namespace URI. The first level is the namespace
        URI.
    """

    allowed_openid_namespaces = [OPENID1_NS, OPENID2_NS]

    def __init__(self):
        """Create an empty Message"""
        self.args = {}
        self.namespaces = NamespaceMap()
        self._openid_ns_uri = None

    def fromPostArgs(cls, args):
        """Construct a Message containing a set of POST arguments"""
        self = cls()

        # Partition into "openid." args and bare args
        openid_args = {}
        for key, value in args.iteritems():
            if isinstance(value, list):
                raise TypeError("query dict must have one value for each key, "
                                "not lists of values.  Query is %r" % (args,))


            try:
                prefix, rest = key.split('.', 1)
            except ValueError:
                prefix = None

            if prefix != 'openid':
                self.args[(BARE_NS, key)] = value
            else:
                openid_args[rest] = value
                    
        self._fromOpenIDArgs(openid_args)

        return self

    fromPostArgs = classmethod(fromPostArgs)

    def fromOpenIDArgs(cls, openid_args):
        """Construct a Message from a parsed KVForm message"""
        self = cls()
        self._fromOpenIDArgs(openid_args)
        return self

    fromOpenIDArgs = classmethod(fromOpenIDArgs)

    def _fromOpenIDArgs(self, openid_args):
        ns_args = []

        # Resolve namespaces
        for rest, value in openid_args.iteritems():
            try:
                ns_alias, ns_key = rest.split('.', 1)
            except ValueError:
                ns_alias = NULL_NAMESPACE
                ns_key = rest

            if ns_alias == 'ns':
                self.namespaces.addAlias(value, ns_key)
            elif ns_alias == NULL_NAMESPACE and ns_key == 'ns':
                # null namespace
                self.namespaces.addAlias(value, NULL_NAMESPACE)
            else:
                ns_args.append((ns_alias, ns_key, value))

        # Ensure that there is an OpenID namespace definition
        openid_ns_uri = self.namespaces.getNamespaceURI(NULL_NAMESPACE)
        if openid_ns_uri is None:
            openid_ns_uri = OPENID1_NS

        self.setOpenIDNamespace(openid_ns_uri)

        # Actually put the pairs into the appropriate namespaces
        for (ns_alias, ns_key, value) in ns_args:
            ns_uri = self.namespaces.getNamespaceURI(ns_alias)
            if ns_uri is None:
                raise ValueError(
                    'Namespace alias %r not defined' % (ns_alias,))
            self.setArg(ns_uri, ns_key, value)

    def setOpenIDNamespace(self, openid_ns_uri):
        if openid_ns_uri not in self.allowed_openid_namespaces:
            raise ValueError('Invalid null namespace: %r' % (openid_ns_uri,))

        self.namespaces.addAlias(openid_ns_uri, NULL_NAMESPACE)
        self._openid_ns_uri = openid_ns_uri

    def getOpenIDNamespace(self):
        return self._openid_ns_uri

    def fromKVForm(cls, kvform_string):
        """Create a Message from a KVForm string"""
        return cls.fromOpenIDArgs(kvform.kvToDict(kvform_string))

    fromKVForm = classmethod(fromKVForm)

    def copy(self):
        return copy.deepcopy(self)

    def toPostArgs(self):
        """Return all arguments with openid. in front of namespaced arguments.
        """
        args = {}

        # Add namespace definitions to the output
        for ns_uri, alias in self.namespaces.iteritems():
            if alias == NULL_NAMESPACE:
                if ns_uri != OPENID1_NS:
                    args['openid.ns'] = ns_uri
                else:
                    # drop the default null namespace definition. This
                    # potentially changes a message since we have no
                    # way of knowing whether it was explicitly
                    # specified at the time the message was
                    # parsed. The vast majority of the time, this will
                    # be the right thing to do. Possibly this could
                    # look in the signed list.
                    pass
            else:
                ns_key = 'openid.ns.' + alias
                args[ns_key] = ns_uri

        for (ns_uri, ns_key), value in self.args.iteritems():
            key = self.getKey(ns_uri, ns_key)
            args[key] = value

        return args

    def toArgs(self):
        """Return all namespaced arguments, failing if any
        non-namespaced arguments exist."""
        post_args = self.toPostArgs()
        kvargs = {}
        for k, v in post_args.iteritems():
            if not k.startswith('openid.'):
                raise ValueError(
                    'This message can only be encoded as a POST, because it '
                    'contains arguments that are not prefixed with "openid."')
            else:
                kvargs[k[7:]] = v

        return kvargs

    def toFormMarkup(self, action_url, form_tag_attrs=None,
                     submit_text="Continue"):
        """Generate HTML form markup that contains the values in this
        message, to be HTTP POSTed as x-www-form-urlencoded UTF-8.

        @param action_url: The URL to which the form will be POSTed
        @type action_url: str

        @param form_tag_attrs: Dictionary of attributes to be added to
            the form tag. 'accept-charset' and 'enctype' have defaults
            that can be overridden. If a value is supplied for
            'action' or 'method', it will be replaced.
        @type form_tag_attrs: {unicode: unicode}

        @param submit_text: The text that will appear on the submit
            button for this form.
        @type submit_text: unicode

        @returns: A string containing (X)HTML markup for a form that
            encodes the values in this Message object.
        @rtype: str or unicode
        """
        if ElementTree is None:
            raise RuntimeError('This function requires ElementTree.')

        form = ElementTree.Element('form', {
            'accept-charset':'UTF-8',
            'enctype':'application/x-www-form-urlencoded',
            })

        if form_tag_attrs:
            for name, attr in form_tag_attrs.iteritems():
                form.attrib[name] = attr

        form.attrib['action'] = action_url
        form.attrib['method'] = 'post'

        for name, value in self.toPostArgs().iteritems():
            attrs = dict(type='hidden', name=name, value=value) 
            form.append(ElementTree.Element('input', attrs))

        submit = ElementTree.Element(
                'input', {'type':'submit', 'value':submit_text})
        form.append(submit)

        return ElementTree.tostring(form)

    def toURL(self, base_url):
        """Generate a GET URL with the parameters in this message
        attached as query parameters."""
        return oidutil.appendArgs(base_url, self.toPostArgs())

    def toKVForm(self):
        """Generate a KVForm string that contains the parameters in
        this message. This will fail if the message contains arguments
        outside of the 'openid.' prefix.
        """
        return kvform.dictToKV(self.toArgs())

    def toURLEncoded(self):
        """Generate an x-www-urlencoded string"""
        args = self.toPostArgs().items()
        args.sort()
        return urllib.urlencode(args)

    def _fixNS(self, namespace):
        """Convert an input value into the internally used values of
        this object

        @param namespace: The string or constant to convert
        @type namespace: str or unicode or BARE_NS or OPENID_NS
        """
        if namespace == OPENID_NS:
            if self._openid_ns_uri is None:
                raise UndefinedOpenIDNamespace('OpenID namespace not set')
            else:
                namespace = self._openid_ns_uri
        elif namespace == BARE_NS:
            pass
        elif type(namespace) not in [str, unicode]:
            raise TypeError("Namespace must be BARE_NS, OPENID_NS or a string. got %r" % (namespace,))

        if namespace != BARE_NS and ':' not in namespace:
            fmt = 'OpenID 2.0 namespace identifiers SHOULD be URIs. Got %r'
            warnings.warn(fmt % (namespace,), DeprecationWarning)

            if namespace == 'sreg':
                fmt = 'Using %r instead of "sreg" as namespace'
                warnings.warn(fmt % (SREG_URI,), DeprecationWarning,)
                return SREG_URI

        return namespace

    def hasKey(self, namespace, ns_key):
        namespace = self._fixNS(namespace)
        return (namespace, ns_key) in self.args

    def getKey(self, namespace, ns_key):
        """Get the key for a particular namespaced argument"""
        namespace = self._fixNS(namespace)
        if namespace == BARE_NS:
            return ns_key

        ns_alias = self.namespaces.getAlias(namespace)

        # No alias is defined, so no key can exist
        if ns_alias is None:
            return None

        if ns_alias == NULL_NAMESPACE:
            tail = ns_key
        else:
            tail = '%s.%s' % (ns_alias, ns_key)

        return 'openid.' + tail

    def getArg(self, namespace, key, default=None):
        """Get a value for a namespaced key.
        """
        namespace = self._fixNS(namespace)
        return self.args.get((namespace, key), default)

    def getArgs(self, namespace):
        """Get the arguments that are defined for this namespace URI

        @returns: mapping from namespaced keys to values
        @returntype: dict
        """
        namespace = self._fixNS(namespace)
        return dict([
            (ns_key, value)
            for ((pair_ns, ns_key), value)
            in self.args.iteritems()
            if pair_ns == namespace
            ])

    def updateArgs(self, namespace, updates):
        """Set multiple key/value pairs in one call

        @param updates: The values to set
        @type updates: {unicode:unicode}
        """
        namespace = self._fixNS(namespace)
        for k, v in updates.iteritems():
            self.setArg(namespace, k, v)

    def setArg(self, namespace, key, value):
        """Set a single argument in this namespace"""
        namespace = self._fixNS(namespace)
        self.args[(namespace, key)] = value
        self.namespaces.add(namespace)

    def delArg(self, namespace, key):
        namespace = self._fixNS(namespace)
        del self.args[(namespace, key)]

#XXX: testme!
class NamespaceMap(object):
    # namespaces that should use a certain alias (for
    # backwards-compatibility or beauty)
    default_aliases = {SREG_URI:'sreg'}

    def __init__(self):
        self.alias_to_namespace = {}
        self.namespace_to_alias = {}

    def getAlias(self, namespace_uri):
        return self.namespace_to_alias.get(namespace_uri)

    def getNamespaceURI(self, alias):
        return self.alias_to_namespace.get(alias)

    def iterNamespaceURIs(self):
        return iter(self.namespace_to_alias)

    def iterAliases(self):
        return iter(self.alias_to_namespace)

    def iteritems(self):
        """Iterate over the mapping

        @returns: iterator of (namespace_uri, alias)
        """
        return self.namespace_to_alias.iteritems()

    def addAlias(self, namespace_uri, desired_alias):
        """Add an alias from this namespace URI to the desired alias
        """
        self._addAlias(namespace_uri, desired_alias)

    def _addAlias(self, namespace_uri, desired_alias):
        # Check that there is not a namespace already defined for
        # the desired alias
        current_namespace_uri = self.alias_to_namespace.get(desired_alias)
        if (current_namespace_uri is not None
            and current_namespace_uri != namespace_uri):

            fmt = ('Cannot map %r to alias %r. '
                   '%r is already mapped to alias %r')

            msg = fmt % (
                namespace_uri,
                desired_alias,
                current_namespace_uri,
                desired_alias)
            raise KeyError(msg)

        # Check that there is not already a (different) alias for
        # this namespace URI
        alias = self.namespace_to_alias.get(namespace_uri)
        if alias is not None and alias != desired_alias:
            fmt = ('Cannot map %r to alias %r. '
                   'It is already mapped to alias %r')
            raise KeyError(fmt % (namespace_uri, desired_alias, alias))

        assert (desired_alias == NULL_NAMESPACE or
                type(desired_alias) in [str, unicode]), repr(desired_alias)
        self.alias_to_namespace[desired_alias] = namespace_uri
        self.namespace_to_alias[namespace_uri] = desired_alias
        return desired_alias

    def add(self, namespace_uri):
        """Add this namespace URI to the mapping, without caring what
        alias it ends up with"""
        # See if this namespace is already mapped to an alias
        alias = self.namespace_to_alias.get(namespace_uri)
        if alias is not None:
            return alias

        # See if there is a default alias for this namespace
        default_alias = self.default_aliases.get(namespace_uri)
        if default_alias is not None:
            try:
                self._addAlias(namespace_uri, default_alias)
            except KeyError:
                pass
            else:
                return default_alias

        # Fall back to generating a numerical alias
        i = 0
        while True:
            alias = str(i)
            try:
                self._addAlias(namespace_uri, str(i))
            except KeyError:
                i += 1
            else:
                return alias

        assert False, "Not reached"

    def isDefined(self, namespace_uri):
        return namespace_uri in self.namespace_to_alias

    def __contains__(self, namespace_uri):
        return self.isDefined(namespace_uri)
