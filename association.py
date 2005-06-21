import datetime
import random
import urllib

from openid.constants import *
from openid.util import *

class Association(object):
    def __init__(self, server_url, handle, key, expiry, replace_after):
        self.server_url = str(server_url)
        self.handle = str(handle)
        self.key = str(key)
        self.expiry = float(expiry)
        self.replace_after = float(replace_after)


class DumbAssociationManager(object):
    """Using this class will cause a consumer to behave in dumb mode."""
    def put(self, server_url, handle, key, expiry, replace_after): pass
    def associate(self, server_url): pass
    def get_secret(self, server_url, assoc_handle): pass


class BaseAssociationManager(DumbAssociationManager):
    """Abstract base class for association manager implementations."""

    def __init__(self, associator):
        self.associator = associator

    def associate(self, server_url):
        """Returns assoc_handle associated with server_url"""
        now = time.time()
        expired = []
        assoc = None
        for current in self.get_all(server_url):
            if current.expiry < now:
                expired.append(current)
            elif assoc is None:
                if current.replace_after > now:
                    assoc = current
            elif current.replace_after > assoc.replace_after:
                assoc = current

        new_assoc = None
        if assoc is None:
            assoc = new_assoc = self.associator.associate(server_url)

        if new_assoc or expired:
            self.update(new_assoc, expired)
        
        return assoc.handle

    def get_secret(self, server_url, assoc_handle):
        # Find the secret matching server_url and assoc_handle
        associations = self.get_all(server_url)
        for assoc in associations:
            if assoc.handle == assoc_handle:
                return assoc.secret

        return None

    # Subclass need to implement the rest of this classes methods.
    def update(self, new_assoc, expired):
        """Subclasses should add new_assoc if it is not None and
        expire each association in the expired."""
        raise NotImplementedError
    
    def get_all(self, server_url):
        """Subclasses should return a list of Association objects whos
        server_url attribute is equal to server_url."""
        raise NotImplementedError


class DiffieHelmanAssociator(object):
    def __init__(self, http_client):
        self.http_client = http_client

    def get_mod_gen(self):
        """-> (modulus, generator) for Diffie-Helman

        override this function to use different values"""
        return (default_dh_modulus, default_dh_gen)

    def associate(self, server_url):
        p, g = self.get_mod_gen()
        priv_key = random.randrange(1, p-1)

        args = {
            'openid.mode': 'associate',
            'openid.assoc_type':'HMAC-SHA1',
            'openid.session_type':'DH-SHA1',
            'openid.dh_modulus': to_b64(long2a(p)),
            'openid.dh_gen': to_b64(long2a(g)),
            'openid.dh_consumer_public': to_b64(long2a(pow(p, priv_key, p))),
            }

        body = urllib.urlencode(args)

        url, data = self.http_client.post(server_url, body)
        results = parsekv(data)
        # XXX: check results?
        # XXX: We need to handle the case where the server isn't up for
        #      DH and just returns mac_key in the clear.
        dh_server_pub = a2long(from_b64(
            results.get('dh_server_public')))
        enc_mac_key = results.get('enc_mac_key')
        assoc_handle = results.get('assoc_handle')

        now = datetime.datetime.utcnow()
        expiry = w3c2datetime(results.get('expiry'))
        replace_after = w3c2datetime(results.get('replace_after'))
        issued = w3c2datetime(results.get('issued'))
        delta = now - issued
        expiry = time.mktime(delta + expiry)
        replace_after = time.mktime(delta + replace_after)

        dh_shared = pow(dh_server_pub, priv_key, p)
        secret = strxor(from_b64(enc_mac_key), sha1(long2a(dh_shared)))
        return Association(server_url, assoc_handle, secret,
                           expiry, replace_after)
        
