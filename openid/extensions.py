"""Extension argument processing code
"""

__all__ = ['ExtensionCollection']

SREG_URI = 'http://openid.net/sreg/1.0'

class ExtensionCollection(object):
    """A container for the extension arguments for an OpenID message.

    @cvar namespace_alaises: A dictionary specifying specific
        namespace-URI to alias mappings that should be used when
        generating namespace aliases.
    """
    # namespaces that should use a certain alias (for
    # backwards-compatibility or beauty)
    namespace_aliases = {SREG_URI:'sreg'}

    def __init__(self):
        """Create an empty ExtensionCollection"""
        # two-level dictionary. The first level is the namespace URI.
        self.args = {}

    def toQueryArgs(self):
        """Build a dictionary of parameters to add to an OpenID query
        or form for the extensions that are defined in this extension
        collection.

        @returntype: {unicode:unicode}
        """
        query_args = {}
        i = 0
        for (ns_uri, ns) in self.args.iteritems():
            ns_alias = self.namespace_aliases.get(ns_uri, str(i))
            query_args['openid.ns.%s' % (ns_alias,)] = ns_uri
            for ns_key, ns_val in ns.iteritems():
                query_args['openid.%s.%s' % (ns_alias, ns_key)] = ns_val

            i += 1

        return query_args

    def fromQueryArgs(cls, query):
        """Construct a ExtensionCollection from a query

        This method should be the inverse of toQueryArgs

        @param query: The parsed query string or form post parameters
        @type query: {unicode:unicode}

        @rtype: ExtensionCollection
        """
        # Build alias table mapping from alias to extension URI
        aliases = {}
        for k, v in query.iteritems():
            if k.startswith('openid.ns.'):
                aliases[k[10:]] = v

        args = {}
        # Put the parameters in the query under their respective
        # namespace URI, if one is defined. A parameter whose key is a
        # namespace alias gets put in the collection with a key of None
        for k, v in query.iteritems():
            if k.startswith('openid.'):
                parts = k[7:].split('.', 1)
                alias = parts[0]
                try:
                    namespace_uri = aliases[alias]
                except KeyError:
                    # Backwards-compatibility hack for sreg
                    if alias == 'sreg':
                        namespace_uri = 'http://openid.net/sreg/1.0'
                    else:
                        continue # No namespace with that alias defined

                # Get the namespace args dictionary
                try:
                    namespace_args = args[namespace_uri]
                except KeyError:
                    namespace_args = args[namespace_uri] = {}

                if len(parts) == 1:
                    namespace_args[None] = v
                else:
                    namespace_args[parts[1]] = v

        self = cls()
        self.args = args
        return self

    fromQueryArgs = classmethod(fromQueryArgs)

    def addArg(self, namespace_uri, key, value):
        """Add a single argument to this namespace"""
        try:
            ns_args = self.args[namespace_uri]
        except KeyError:
            ns_args = self.args[namespace_uri] = {}

        ns_args[key] = value

    def addArgs(self, namespace_uri, values):
        """Add a set of values to this namespace. Takes the same
        type as a second parameter as dict.update."""
        try:
            ns_args = self.args[namespace_uri]
        except KeyError:
            ns_args = self.args[namespace_uri] = {}

        ns_args.update(values)

    def isNamespaceDefined(self, namespace_uri):
        """Does this namespace have any arguments defined for it?"""
        return namespace_uri in self.args

    def getNamespaceArgs(self, namespace_uri):
        """Get the arguments that are defined for this namespace URI

        @returns: mapping from namespaced keys to values
        @returntype: dict
        """
        return self.args.get(namespace_uri, {})
