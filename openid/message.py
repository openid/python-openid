"""Extension argument processing code
"""
import warnings

__all__ = ['Message']

SREG_URI = 'http://openid.net/sreg/1.0'

class Message(object):
    """
    In the implementation of this object, None represents the global
    namespace as well as a namespace with no key.

    @cvar namespace_alaises: A dictionary specifying specific
        namespace-URI to alias mappings that should be used when
        generating namespace aliases.

    @ivar ns_args: two-level dictionary of the values in this message,
        grouped by namespace URI. The first level is the namespace
        URI.

    @ivar signed: list of fields to sign. It contains pairs of
        namespace and key. The namespace alias declarations are
        automatically signed.
    """

    # namespaces that should use a certain alias (for
    # backwards-compatibility or beauty)
    namespace_aliases = {SREG_URI:'sreg'}

    def __init__(self):
        """Create an empty Message"""
        self.ns_args = {}
        self.signed = []
        self.namespace_aliases = dict(self.namespace_aliases)

    def toArgs(self):
        """Build a dictionary out of the arguments defined for this
        message (realize the namespace mappings)

        @returntype: {unicode:unicode}
        """
        aliases = {}
        i = 0
        for (ns_uri, ns) in self.ns_args.iteritems():
            if ns_uri is None:
                continue

            try:
                ns_alias = aliases[ns_uri]
            except KeyError:
                try:
                    ns_alias = self.namespace_aliases[ns_uri]
                except KeyError:
                    ns_alias = str(i)
                    i += 1

                aliases[ns_uri] = ns_alias

        signed_s = []
        for ns_uri, key in self.signed:
            if ns_uri is None:
                signed_s.append(key)
            else:
                alias = aliases[ns_uri]
                if key is None:
                    signed_s.append(alias)
                else:
                    signed_s.append('%s.%s' % (alias, key))

        args = {}
        for ns_uri, alias in aliases.iteritems():
            ns_key = 'ns.' + alias
            args[ns_key] = ns_uri
            signed_s.append(ns_key)

        if signed_s:
            args['signed'] = ','.join(signed_s)

        for ns_uri, values in self.ns_args.iteritems():
            if ns_uri is None:
                args.update(values)
            else:
                alias = aliases[ns_uri]
                for k, v in values.iteritems():
                    if k is None:
                        args[alias] = v
                    else:
                        args['%s.%s' % (alias, k)] = v


        return args

    def fromArgs(cls, query, preserve_namespaces=False):
        """Construct a Message from a dictionary (parse the namespace args)

        @param query: The parsed query string or form post parameters
        @type query: {unicode:unicode}

        @rtype: ExtensionCollection
        """
        query = dict(query)

        # Build alias table mapping from alias to extension URI
        args = {}
        aliases = {None:{}}
        for k, v in query.iteritems():
            if k.startswith('ns.'):
                args[v] = {}
                aliases[k[3:]] = v

                # Preserve namespace mapping for e.g. signing
                if preserve_namespaces:
                    self.namespace_aliases[v] = k[3:]

        # Resolve the signed fields' namespaces
        try:
            signed_arg = query['signed']
        except KeyError:
            signed_keys = []
        else:
            del query['signed']
            signed_keys = signed_arg.split(',')

        signed = []
        for arg in signed_keys:
            parts = arg.split('.', 1)
            namespace_uri = aliases.get(parts[0], None)
            if len(parts) == 1:
                if namespace_uri is None:
                    key = arg
                else:
                    key = None
            else:
                key = parts[1]

            signed.append((namespace_uri, key))

        # Put the parameters in the query under their respective
        # namespace URI, if one is defined. A parameter whose key is a
        # namespace alias gets put in the collection with a key of None
        for k, v in query.iteritems():
            # We normalize out all the alias defininitions
            if k.startswith('ns.'):
                continue

            parts = k.split('.', 1)
            alias = parts[0]
            try:
                namespace_uri = aliases[alias]
            except KeyError:
                # Does not match a defined

                # Backwards-compatibility hack for sreg
                if alias == 'sreg':
                    namespace_uri = 'http://openid.net/sreg/1.0'
                else:
                    namespace_uri = None

            # Get the namespace args dictionary
            try:
                namespace_args = args[namespace_uri]
            except KeyError:
                namespace_args = args[namespace_uri] = {}

            # Get the key within the namespace
            if namespace_uri is None:
                # This is not namespaced
                ns_key = k
            elif len(parts) == 1:
                # This does not have a qualified part, so use None as
                # the key. ('openid.ninja' if the alias is 'ninja')
                ns_key = None
            else:
                # Strip off the alias, and everything that's left is
                # the namespace key.
                ns_key = parts[1]

            namespace_args[ns_key] = v

        self = cls()
        self.ns_args = args
        self.signed = signed
        return self

    fromArgs = classmethod(fromArgs)

    def toQueryArgs(self):
        return dict([('openid.' + k, v)
                     for k, v in self.toArgs().iteritems()])

    def fromQueryArgs(cls, args):
        openid_args = {}
        for k, v in args.iteritems():
            if k.startswith('openid.'):
                openid_args[k[7:]] = v
        return cls.fromArgs(openid_args)

    fromQueryArgs = classmethod(fromQueryArgs)

    def _fixNamespaceURI(self, ns_uri):
        """Check for deprecated API usage and fix the namespace URI if
        it's 'sreg'

        @param ns_uri: The string to check as a namespace URI

        @returns: The namespace URI, possibly cleaned up
        """
        if ns_uri is not None and ':' not in ns_uri:
            fmt = 'OpenID 2.0 namespace identifiers SHOULD be URIs. Got %r'
            warnings.warn(fmt % (ns_uri,), DeprecationWarning, stacklevel=3)

            if ns_uri == 'sreg':
                fmt = 'Using %r instead of "sreg" as namespace'
                warnings.warn(fmt % (SREG_URI,), DeprecationWarning,
                              stacklevel=3)
                return SREG_URI

        return ns_uri

    def addNSArg(self, namespace_uri, key, value, signed=True):
        """Add a single argument to this namespace"""
        namespace_uri = self._fixNamespaceURI(namespace_uri)
        try:
            ns_args = self.ns_args[namespace_uri]
        except KeyError:
            ns_args = self.ns_args[namespace_uri] = {}

        if signed:
            k = (namespace_uri, key)
            if k not in self.signed:
                self.signed.append(k)
        ns_args[key] = value

    def addArg(self, key, value, signed=True):
        self.addNSArg(None, key, value, signed)

    def addNSArgs(self, namespace_uri, values, signed=True):
        """Add a set of values to this namespace. Takes the same
        type as a second parameter as dict.update."""
        namespace_uri = self._fixNamespaceURI(namespace_uri)

        try:
            ns_args = self.ns_args[namespace_uri]
        except KeyError:
            ns_args = self.ns_args[namespace_uri] = {}

        ns_args.update(values)

    def addArgs(self, values, signed=True):
        self.addNSArgs(None, values, signed)

    def getNS(self, ns_uri, key, default=None):
        try:
            args = self.ns_args[ns_uri]
        except KeyError:
            return default
        else:
            return args.get(key, default)

    def get(self, key, default=None):
        return self.getNS(None, key, default)

    def undefineNamespace(self, namespace_uri):
        """XXX: does this do what it should?
        """
        try:
            contents = self.ns_args[namespace_uri]
        except KeyError:
            pass # not currently defined
        else:
            if contents:
                raise ValueError('Cannot undefine non-empty namespace')
            else:
                del self.ns_args[namespace_uri]

    def defineNamespace(self, namespace_uri):
        """Add an empty namespace defn"""
        if namespace_uri not in self.ns_args:
            self.ns_args[namespace_uri] = {}

    def isNamespaceDefined(self, namespace_uri):
        """Does this namespace have any arguments defined for it?"""
        return namespace_uri in self.ns_args

    def getNamespaceArgs(self, namespace_uri):
        """Get the arguments that are defined for this namespace URI

        @returns: mapping from namespaced keys to values
        @returntype: dict
        """
        return self.ns_args.get(namespace_uri, {})

    def update(self, other):
        for p in other.signed:
            if p not in self.signed:
                self.signed.append(p)

        for ns, other_values in other.ns_args.iteritems():
            try:
                my_values = self.ns_args[ns]
            except KeyError:
                my_values = self.ns_args[ns] = {}

            my_values.update(other_values)
