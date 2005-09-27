import random
import urllib
import time

from openid.errors import ProtocolError

from openid.util import (DiffieHellman, long2a, to_b64, parsekv,
                         from_b64, a2long, sha1, strxor)

class Association(object):
    """This class represents an association between a consumer and a
    server.  This class only contains the information necessary for
    the server to keep track of.  The consumer needs additional
    information, which is stored in the ConsumerAssociation class
    listed below."""
    @classmethod
    def from_expires_in(cls, expires_in, *args, **kwargs):
        kwargs['issued'] = int(time.time())
        kwargs['lifetime'] = expires_in
        return cls(*args, **kwargs)

    def __init__(self, handle, secret, issued, lifetime):
        self.handle = handle
        self.secret = secret
        self.issued = issued
        self.lifetime = lifetime

    def get_expires_in(self):
        return max(0, self.issued + self.lifetime - int(time.time()))

    expires_in = property(get_expires_in)

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return self.__dict__ != other.__dict__

class ConsumerAssociation(Association):
    """This class is a subclass of Association that adds the
    additional information the consumer needs to track which server
    issued the association."""
    def __init__(self, server_url, *args, **kwargs):
        Association.__init__(self, *args, **kwargs)
        self.server_url = server_url


class ConsumerAssociationManager(object):
    """Base class for type unification of Association Managers.  Most
    implementations of this should extend the BaseAssociationManager
    class below."""
    def get_association(self, server_url, assoc_handle):
        raise NotImplementedError
    
    def associate(self, server_url):
        raise NotImplementedError
    
    def invalidate(self, server_url, assoc_handle):
        raise NotImplementedError


class DumbAssociationManager(ConsumerAssociationManager):
    """Using this class will cause a consumer to behave in dumb mode."""
    def get_association(self, server_url, assoc_handle):
        return None
    
    def associate(self, server_url):
        return None
    
    def invalidate(self, server_url, assoc_handle):
        pass


class AbstractConsumerAssociationManager(ConsumerAssociationManager):
    """Abstract base class for association manager implementations."""

    def __init__(self, associator):
        self.associator = associator

    def associate(self, server_url):
        """Returns assoc_handle associated with server_url"""
        expired = []
        assoc = None
        for current in self.get_all(server_url):
            if current.expires_in <= 0:
                expired.append(current)
            elif assoc is None or current.expires_in > assoc.expires_in:
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

    # Subclass need to implement the following methods:
    def update(self, new_assoc, expired):
        """new_assoc is either a new association object or None.
        Expired is a possibly empty list of expired associations.
        Subclasses should add new_assoc if it is not None and expire
        each association in the expired list."""
        raise NotImplementedError
    
    def get_all(self, server_url):
        """Subclasses should return a list of ConsumerAssociation
        objects whose server_url attribute is equal to server_url."""
        raise NotImplementedError

    def invalidate(self, server_url, assoc_handle):
        """Subclasses should remove the ConsumerAssociation for the
        given server_url and assoc_handle from their stores."""
        raise NotImplementedError


class DiffieHelmanAssociator(object):
    def __init__(self, http_client, srand=None):
        self.http_client = http_client
        self.srand = srand or random.SystemRandom()

    def get_mod_gen(self):
        """-> (modulus, generator) for Diffie-Helman

        override this function to use different values"""
        return (DiffieHellman.DEFAULT_MOD, DiffieHellman.DEFAULT_GEN)

    def associate(self, server_url):
        p, g = self.get_mod_gen()
        dh = DiffieHellman(p, g, srand=self.srand)
        cpub = dh.createKeyExchange()

        args = {
            'openid.mode': 'associate',
            'openid.assoc_type':'HMAC-SHA1',
            'openid.session_type':'DH-SHA1',
            'openid.dh_modulus': to_b64(long2a(dh.p)),
            'openid.dh_gen': to_b64(long2a(dh.g)),
            'openid.dh_consumer_public': to_b64(long2a(cpub)),
            }

        body = urllib.urlencode(args)

        url, data = self.http_client.post(server_url, body)
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
        expires_in = results.get('expires_in', '0')

        session_type = results.get('session_type')
        if session_type is None:
            secret = from_b64(getResult('mac_key'))
        else:
            if session_type != 'DH-SHA1':
                raise RuntimeError("Unknown Session Type: %r"
                                   % (session_type,))

            spub = a2long(from_b64(getResult('dh_server_public')))
            dh_shared = dh.decryptKeyExchange(spub)
            enc_mac_key = getResult('enc_mac_key')
            secret = strxor(from_b64(enc_mac_key), sha1(long2a(dh_shared)))

        return ConsumerAssociation.from_expires_in(
            expires_in, server_url, assoc_handle, secret)



class ServerAssociationStore(object):
    """This is the interface the OpenIDServer class expects its
    internal_store and external_store objects to support."""

    def get(self, assoc_type):
        """This method returns an association handle for the given
        association type.  For the internal_store, implementations may
        return either a new association, or an existing one, as long
        as the association it returns won't expire too soon to be
        useable.  For the external_store, implementations must return
        a new association each time this method is called."""
        raise NotImplementedError

    def lookup(self, assoc_handle, assoc_type):
        """This method returns the stored association for a given
        handle and association type.  If there is no such stored
        association, it should return None."""
        raise NotImplementedError

    def remove(self, handle):
        """If the server code notices that an association it retrieves
        has expired, it will call this method to let the store know it
        should remove the given association.  In general, the
        implementation should take care of that without the server
        code getting involved.  This exists primarily to deal with
        corner cases correctly."""
        raise NotImplementedError
