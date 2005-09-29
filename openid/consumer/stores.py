import time

class ConsumerAssociation(object):
    """This class represents a consumer's view of an association."""

    @classmethod
    def fromExpiresIn(cls, expires_in, *args, **kwargs):
        kwargs['issued'] = int(time.time())
        kwargs['lifetime'] = expires_in
        return cls(*args, **kwargs)

    def __init__(self, server_url, handle, secret, issued, lifetime):
        self.server_url = server_url
        self.handle = handle
        self.secret = secret
        self.issued = issued
        self.lifetime = lifetime

    def getExpiresIn(self):
        return max(0, self.issued + self.lifetime - int(time.time()))

    expiresIn = property(get_expires_in)

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return self.__dict__ != other.__dict__


class OpenIDStore(object):
    """This is the interface for the consumer's store."""

    def storeAssociation(self, association):
        """Puts a ConsumerAssociation object into storage. No return."""
        raise NotImplementedError
    

    def getAssociation(self, server_url, handle):
        """Returns a ConsumerAssocation object from storage.  Returns
        None if no such association is found.  (Is allowed to gc
        expired associations when found and return None instead of the
        invalid association.)"""
        raise NotImplementedError

    def removeAssociation(self, server_url, handle):
        """If there is a matching association, remove it from the
        store and return True.  Otherwise return False."""
        raise NotImplementedError


    def storeNonce(self, nonce):
        """Stores a nonce (which is passed in as a string)."""
        raise NotImplementedError

    def useNonce(self, nonce):
        """If the nonce is in the store, removes it and returns True.
        Otherwise returns False.

        This method is allowed and encouraged to treat nonces older
        than some period (like 6 hours) as no longer existing, and
        return False and remove them."""
        raise NotImplementedError



