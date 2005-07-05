import datetime
import random
import urllib
import time

from openid.constants import *
from openid.util import *

class Association(object):
    def __init__(self, handle, secret, expiry, replace_after):
        self.handle = str(handle)
        self.secret = str(secret)
        if replace_after is None:
            self.replace_after = replace_after
        else:
            self.replace_after = float(replace_after)
        self.expiry = float(expiry)

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return self.__dict__ != other.__dict__

class ConsumerAssociation(Association):
    def __init__(self, server_url, *args, **kwargs):
        Association.__init__(self, *args, **kwargs)
        self.server_url = str(server_url)

    def get_replace_after(self):
        if self.replace_after is None:
            return self.expiry
        else:
            return self.replace_after

class ServerAssociation(Association):
    def __init__(self, handle, secret, expiry_off, replace_after_off):
        now = time.time()
        expiry = now + expiry_off
        replace_after = now + replace_after_off
        Association.__init__(self, handle, secret, expiry, replace_after)
        self.issued = now

class DumbAssociationManager(object):
    """Using this class will cause a consumer to behave in dumb mode."""
    def get_association(self, server_url, assoc_handle): return None
    def associate(self, server_url): return None
    def invalidate(self, server_url, assoc_handle): pass


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
            replace_after = current.get_replace_after()
            if current.expiry < now:
                expired.append(current)
            elif assoc is None:
                if replace_after > now:
                    assoc = current
            elif replace_after > assoc.replace_after:
                assoc = current

        new_assoc = None
        if assoc is None:
            assoc = new_assoc = self.associator.associate(server_url)

        if new_assoc or expired:
            self.update(new_assoc, expired)
        
        return assoc.handle

    def get_association(self, server_url, assoc_handle):
        # Find the secret matching server_url and assoc_handle
        associations = self.get_all(server_url)
        for assoc in associations:
            if assoc.handle == assoc_handle:
                return assoc

        return None

    # Subclass need to implement the rest of this classes methods.
    def update(self, new_assoc, expired):
        """new_assoc is either a new association object or None.
        Expired is a possibly empty list of expired associations.
        Subclasses should add new_assoc if it is not None and expire
        each association in the expired list."""
        raise NotImplementedError
    
    def get_all(self, server_url):
        """Subclasses should return a list of Association objects
        whose server_url attribute is equal to server_url."""
        raise NotImplementedError

    def invalidate(self, server_url, assoc_handle):
        """Subclasses should remove the association for the given
        server_url and assoc_handle from their stores."""
        raise NotImplementedError


class DiffieHelmanAssociator(object):
    def __init__(self, http_client, srand=None):
        self.http_client = http_client
        self.srand = srand or random.SystemRandom()

    def get_mod_gen(self):
        """-> (modulus, generator) for Diffie-Helman

        override this function to use different values"""
        return (default_dh_modulus, default_dh_gen)

    def associate(self, server_url):
        p, g = self.get_mod_gen()
        priv_key = self.srand.randrange(1, p-1)

        args = {
            'openid.mode': 'associate',
            'openid.assoc_type':'HMAC-SHA1',
            'openid.session_type':'DH-SHA1',
            'openid.dh_modulus': to_b64(long2a(p)),
            'openid.dh_gen': to_b64(long2a(g)),
            'openid.dh_consumer_public': to_b64(long2a(pow(g, priv_key, p))),
            }

        body = urllib.urlencode(args)

        url, data = self.http_client.post(server_url, body)
        now = utc_now()

        results = parsekv(data)

        def getResult(key):
            try:
                return results[key]
            except KeyError:
                raise ProtocolError(
                    'Association server response missing argument %r:\n%r'
                    % (key, data))
            
        assoc_type = getResult('assoc_type')
        if assoc_type != 'HMAC-SHA1':
            raise RuntimeError("Unknown association type: %r" % (assoc_type,))
        
        assoc_handle = getResult('assoc_handle')
        issued = w3c2datetime(getResult('issued'))
        expiry = w3c2datetime(getResult('expiry'))
        
        delta = now - issued
        expiry = datetime2timestamp(delta + expiry)

        replace_after_s = results.get('replace_after')
        if replace_after_s is None:
            replace_after = None
        else:
            replace_after = w3c2datetime(replace_after_s)
            replace_after = datetime2timestamp(delta + replace_after)

        session_type = results.get('session_type')
        if session_type is None:
            secret = from_b64(getResult('mac_key'))
        else:
            if session_type != 'DH-SHA1':
                raise RuntimeError("Unknown Session Type: %r"
                                   % (session_type,))
            
            dh_server_pub = a2long(from_b64(getResult('dh_server_public')))
            enc_mac_key = getResult('enc_mac_key')

            dh_shared = pow(dh_server_pub, priv_key, p)
            secret = strxor(from_b64(enc_mac_key), sha1(long2a(dh_shared)))

        return ConsumerAssociation(server_url, assoc_handle, secret,
                                   expiry, replace_after)
