"""
This module contains the definition of the C{L{OpenIDStore}}
interface.
"""

class OpenIDStore(object):
    """
    This is the interface for the store objects the OpenID library
    uses.  It is a single class that provides all of the persistence
    mechanisms that the OpenID library needs, for both servers and
    consumers.

    @change: Version 2.0 removed the C{storeNonce} and C{getAuthKey} methods,
        and changed the behavior of the C{L{useNonce}} method to support
        one-way nonces.

    @sort: storeAssociation, getAssociation, removeAssociation,
        useNonce, isDumb
    """

    def storeAssociation(self, server_url, association):
        """
        This method puts a C{L{Association
        <openid.association.Association>}} object into storage,
        retrievable by server URL and handle.


        @param server_url: The URL of the identity server that this
            association is with.  Because of the way the server
            portion of the library uses this interface, don't assume
            there are any limitations on the character set of the
            input string.  In particular, expect to see unescaped
            non-url-safe characters in the server_url field.

        @type server_url: C{str}


        @param association: The C{L{Association
            <openid.association.Association>}} to store.

        @type association: C{L{Association
            <openid.association.Association>}}


        @return: C{None}

        @rtype: C{NoneType}
        """
        raise NotImplementedError

    def getAssociation(self, server_url, handle=None):
        """
        This method returns an C{L{Association
        <openid.association.Association>}} object from storage that
        matches the server URL and, if specified, handle. It returns
        C{None} if no such association is found or if the matching
        association is expired.

        If no handle is specified, the store may return any
        association which matches the server URL.  If multiple
        associations are valid, the recommended return value for this
        method is the one that will remain valid for the longest
        duration.

        This method is allowed (and encouraged) to garbage collect
        expired associations when found. This method must not return
        expired associations.


        @param server_url: The URL of the identity server to get the
            association for.  Because of the way the server portion of
            the library uses this interface, don't assume there are
            any limitations on the character set of the input string.
            In particular, expect to see unescaped non-url-safe
            characters in the server_url field.

        @type server_url: C{str}


        @param handle: This optional parameter is the handle of the
            specific association to get.  If no specific handle is
            provided, any valid association matching the server URL is
            returned.

        @type handle: C{str} or C{NoneType}


        @return: The C{L{Association
            <openid.association.Association>}} for the given identity
            server.

        @rtype: C{L{Association <openid.association.Association>}} or
            C{NoneType}
        """
        raise NotImplementedError

    def removeAssociation(self, server_url, handle):
        """
        This method removes the matching association if it's found,
        and returns whether the association was removed or not.


        @param server_url: The URL of the identity server the
            association to remove belongs to.  Because of the way the
            server portion of the library uses this interface, don't
            assume there are any limitations on the character set of
            the input string.  In particular, expect to see unescaped
            non-url-safe characters in the server_url field.

        @type server_url: C{str}


        @param handle: This is the handle of the association to
            remove.  If there isn't an association found that matches
            both the given URL and handle, then there was no matching
            handle found.

        @type handle: C{str}


        @return: Returns whether or not the given association existed.

        @rtype: C{bool} or C{int}
        """
        raise NotImplementedError

    def useNonce(self, nonce):
        """Called when using a nonce.

        This method should return C{True} if the nonce has not been
        used before, and store it for a while to make sure nobody
        tries to use the same value again.  If the nonce has already
        been used, return C{False}.

        @change: In earlier versions, round-trip nonces were used and
           a nonce was only valid if it had been previously stored
           with C{storeNonce}.  Version 2.0 uses one-way nonces,
           requiring a different implementation here that does not
           depend on a C{storeNonce} call.  (C{storeNonce} is no
           longer part of the interface.

        @param nonce: The nonce to use.

        @type nonce: C{str}


        @return: Whether or not the nonce was valid.

        @rtype: C{bool}
        """
        raise NotImplementedError

    def getExpired(self):
        """Return all server URLs that have expired associations

        @rtype: C{[str]}
        """
        raise NotImplementedError
