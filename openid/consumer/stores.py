import time
from openid import oidUtil

class OpenIDStore(object):
    """
    This is the interface for the store objects the OpenID consumer
    library uses.  It is 
    """

    AUTH_KEY_LEN = 20

    def storeAssociation(self, association):
        """Puts a ConsumerAssociation object into storage. No return."""
        raise NotImplementedError
    

    def getAssociation(self, server_url):
        """Returns a ConsumerAssocation object from storage that
        matches the server_url.  Returns None if no such association
        is found or if the matching association is expired.  (Is
        allowed to gc expired associations when found.)"""
        raise NotImplementedError

    def removeAssociation(self, server_url, handle):
        """If there is a matching association, remove it from the
        store and return True.  Otherwise return False."""
        raise NotImplementedError


    def storeNonce(self, nonce):
        """Stores a nonce (which is passed in as a string).  No return."""
        raise NotImplementedError

    def useNonce(self, nonce):
        """If the nonce is in the store, removes it and returns True.
        Otherwise returns False.

        This method is allowed and encouraged to treat nonces older
        than some period (like 6 hours) as no longer existing, and
        return False and remove them."""
        raise NotImplementedError

    def getAuthKey(self):
        """This method returns a 20-byte key used to sign the tokens,
        to ensure that they haven't been tampered with in transit.  It
        should return the same key every time it is called."""
        raise NotImplementedError

    def isDumb(self):
        """This method must return True if the store is a dumb mode
        style store"""
        return False

class DumbStore(OpenIDStore):
    def __init__(self, secret_phrase):
        self.auth_key = oidUtil.sha1(secret_phrase)

    def storeAssociation(self, unused_association):
        pass

    def getAssociation(self, unused_server_url):
        return None

    def removeAssociation(self, unused_server_url, unused_handle):
        return False

    def storeNonce(self, nonce):
        pass

    def useNonce(self, nonce):
        """In a system truly limited to dumb mode, nonces must all be
        accepted."""
        return True

    def getAuthKey(self):
        return self.auth_key

    def isDumb(self):
        return True


class ConsumerAssociation(object):
    """This class represents a consumer's view of an association."""

    def fromExpiresIn(cls, expires_in, server_url, handle, secret):
        """\
        @param expires_in: how long to keep this association valid
        @type expires_in: int
        """
        issued = int(time.time())
        lifetime = expires_in
        return cls(server_url, handle, secret, issued, lifetime)

    fromExpiresIn = classmethod(fromExpiresIn)

    def __init__(self, server_url, handle, secret, issued, lifetime):
        self.server_url = server_url
        self.handle = handle
        self.secret = secret
        self.issued = issued
        self.lifetime = lifetime

    def getExpiresIn(self):
        return max(0, self.issued + self.lifetime - int(time.time()))

    expiresIn = property(getExpiresIn)

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return self.__dict__ != other.__dict__

