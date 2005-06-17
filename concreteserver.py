import random, time

from openid.server import OpenIDServer

class ConcreteLinuxServer(OpenIDServer):
    def __init__(self):
        OpenIDServer.__init__(self, random.SystemRandom())
        self.secret = '12345678900987654321'
        self._handle = 'huh' # XXX: we already have a method called handle
        self.issued = time.time()
        self.replace_after = self.issued + (60 * 60 * 24 * 29) 
        self.expiry = self.replace_after + (60 * 60 * 24)

    def get_new_secret(self, size):
        assert size == 20
        return (self.secret, self._handle, self.issued,
                self.replace_after, self.expiry)

    def get_secret(self, assoc_handle):
        if assoc_handle == self._handle:
            return self.secret, self.expiry 
        else:
            return None

    def get_server_secret(self, size):
        # XXX: do something with size
        return self.secret, self._handle, self.issued, self.expiry

    def id_allows_authentication(self, identity, trust_root):
        "Every identity trusts every trust_root!  Yay!"
        now = time.time()
        in_an_hour = now + (60 * 60)
        return now, in_an_hour

    def get_lifetime(self, identity):
        return 50
