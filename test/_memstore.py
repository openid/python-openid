from openid import cryptutil
import copy

class ServerAssocs(object):
    def __init__(self):
        self.assocs = {}

    def set(self, assoc):
        self.assocs[assoc.handle] = assoc

    def get(self, handle):
        return self.assocs.get(handle)

    def remove(self, handle):
        try:
            del self.assocs[handle]
        except KeyError:
            return False
        else:
            return True

    def best(self):
        """Returns association with the oldest issued date.

        or None if there are no associations.
        """
        best = None
        for assoc in self.assocs.values():
            if best is None or best.issued < assoc.issued:
                best = assoc
        return best

class MemoryStore(object):
    """In-process memory store.

    Use for single long-running processes.  No persistence supplied.
    """
    AUTH_KEY_LEN = 20

    def __init__(self):
        self.server_assocs = {}
        self.nonces = {}
        self.auth_key = cryptutil.randomString(self.AUTH_KEY_LEN)

    def _getServerAssocs(self, server_url):
        try:
            return self.server_assocs[server_url]
        except KeyError:
            assocs = self.server_assocs[server_url] = ServerAssocs()
            return assocs

    def isDumb(self):
        return False

    def storeAssociation(self, server_url, assoc):
        assocs = self._getServerAssocs(server_url)
        assocs.set(copy.deepcopy(assoc))

    def getAssociation(self, server_url, handle=None):
        assocs = self._getServerAssocs(server_url)
        if handle is None:
            return assocs.best()
        else:
            return assocs.get(handle)

    def removeAssociation(self, server_url, handle):
        assocs = self._getServerAssocs(server_url)
        return assocs.remove(handle)

    def useNonce(self, nonce):
        try:
            del self.nonces[nonce]
        except KeyError:
            return False
        else:
            return True

    def storeNonce(self, nonce):
        self.nonces[nonce] = None

    def getAuthKey(self):
        return self.auth_key

    def __eq__(self, other):
        return ((self.server_assocs == other.server_assocs) and
                (self.nonces == other.nonces) and
                (self.auth_key == other.auth_key))

    def __ne__(self, other):
        return not (self == other)
