import time

class ServerAssociation(object):
    def fromExpiresIn(cls, expires_in, *args, **kwargs):
        kwargs['issued'] = int(time.time())
        kwargs['lifetime'] = expires_in
        return cls(*args, **kwargs)

    fromExpiresIn = classmethod(fromExpiresIn)

    def __init__(self, handle, secret, issued, lifetime):
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

class ServerAssociationStore(object):
    """
    """

    def get(self, assoc_type):
        """
        """
        raise NotImplementedError

    def lookup(self, assoc_handle, assoc_type):
        """
        """
        raise NotImplementedError

    def remove(self, handle):
        """
        """
        raise NotImplementedError

