"""
This module contains an C{L{OpenIDStore}} implementation with no
persistent backing, for use only by limited consumers.
"""

from openid.store.interface import OpenIDStore

class DumbStore(OpenIDStore):
    """
    This is a store for use in the worst case, when you have no way of
    saving state on the consumer site. Using this store with protocol
    version 1 makes the consumer vulnerable to replay attacks, as it's
    unable to use nonces. In protocol version 2, the server will
    prevent replay attacks in stateless mode.

    Most of the methods of this class are implementation details.
    Users of this class need to worry only about the C{L{__init__}}
    method.
    """

    def storeAssociation(self, server_url, association):
        """
        This implementation does nothing.
        """
        pass

    def getAssociation(self, server_url, handle=None):
        """
        This implementation always returns C{None}.


        @return: C{None}

        @rtype: C{None}
        """
        return None

    def removeAssociation(self, server_url, handle):
        """
        This implementation always returns C{False}.


        @return: C{False}

        @rtype: C{bool}
        """
        return False

    def useNonce(self, server_url, timestamp, salt):
        """
        In a system truly limited to dumb mode, nonces must all be
        accepted.  This therefore always returns C{True}, which makes
        replay attacks feasible during the lifespan of the token.


        @return: C{True}

        @rtype: C{bool}
        """
        return True

    def isDumb(self):
        """
        This store is a dumb mode store, so this method is overridden
        to return C{True}.


        @return: C{True}

        @rtype: C{bool}
        """
        return True
