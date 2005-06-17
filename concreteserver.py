import random, time

from openid.server import OpenIDServer

class ConcreteLinuxServer(OpenIDServer):
    def __init__(self):
        OpenIDServer.__init__(self, random.SystemRandom())
        self.secret = '12345678900987654321'
        self.handle = 'huh'
        self.issued = time.time()
        self.replace_after = issued + (60 * 60 * 24 * 29) 
        self.expiry = replace_after + (60 * 60 * 24)

    def get_new_secret(self, size):
        assert size == 20
        return (self.secret, self.handle, self.issued,
                self.replace_after, self.expiry)

    def get_secret(self, assoc_handle):
        if assoc_handle == self.handle:
            return self.secret, self.expiry 
        else:
            return None

    def id_allows_authentication(self, identity, trust_root):
        "Every identity trusts every trust_root!  Yay!"
        now = time.time()
        in_an_hour = now + (60 * 60)
        return now, in_an_hour
