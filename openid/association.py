# -*- test-case-name: openid.test.test_association -*-
"""
This module contains code for dealing with associations between
consumers and servers.
"""

import time

from openid import cryptutil
from openid import kvform
from openid import oidutil
from openid.message import OPENID_NS

all_association_types = [
    'HMAC-SHA1',
    'HMAC-SHA256',
    ]

if hasattr(cryptutil, 'hmacSha256'):
    supported_association_types = list(all_association_types)

    default_association_order = [
        ('HMAC-SHA1', 'DH-SHA1'),
        ('HMAC-SHA1', 'no-encryption'),
        ('HMAC-SHA256', 'DH-SHA256'),
        ('HMAC-SHA256', 'no-encryption'),
        ]

    only_encrypted_association_order = [
        ('HMAC-SHA1', 'DH-SHA1'),
        ('HMAC-SHA256', 'DH-SHA256'),
        ]
else:
    supported_association_types = ['HMAC-SHA1']

    default_association_order = [
        ('HMAC-SHA1', 'DH-SHA1'),
        ('HMAC-SHA1', 'no-encryption'),
        ]

    only_encrypted_association_order = [
        ('HMAC-SHA1', 'DH-SHA1'),
        ]

def getSessionTypes(assoc_type):
    """Return the allowed session types for a given association type"""
    assoc_to_session = {
        'HMAC-SHA1': ['DH-SHA1', 'no-encryption'],
        'HMAC-SHA256': ['DH-SHA256', 'no-encryption'],
        }
    return assoc_to_session.get(assoc_type, [])

def checkSessionType(assoc_type, session_type):
    """Check to make sure that this pair of assoc type and session
    type are allowed"""
    if session_type not in getSessionTypes(assoc_type):
        raise ValueError(
            'Session type %r not valid for assocation type %r'
            % (session_type, assoc_type))

class SessionNegotiator(object):
    def __init__(self, allowed_types):
        self.allowed_types = allowed_types

    def copy(self):
        return self.__class__(list(self.allowed_types))

    def setAllowedTypes(self, allowed_types):
        """Set the allowed association types, checking to make sure
        each combination is valid."""
        for (assoc_type, session_type) in allowed_types:
            checkSessionType(assoc_type, session_type)

        self.allowed_types = allowed_types

    def addAllowedType(self, assoc_type, session_type=None):
        """Add an association type and session type to the allowed
        types list. The assocation/session pairs are tried in the
        order that they are added."""
        if self.allowed_types is None:
            self.allowed_types = []

        if session_type is None:
            for session_type in getSessionTypes(assoc_type):
                self.addAllowedType(assoc_type, session_type)
            else:
                raise ValueError('No session available for association type %r'
                                 % (assoc_type,))
        else:
            checkSessionType(assoc_type, session_type)
            self.allowed_types.append((assoc_type, session_type))


    def isAllowed(self, assoc_type, session_type):
        """Is this combination of association type and session type allowed?"""
        assoc_good = (assoc_type, session_type) in self.allowed_types
        matches = session_type in getSessionTypes(assoc_type)
        return assoc_good and matches

    def getAllowedType(self):
        """Get a pair of assocation type and session type that are
        supported"""
        try:
            return self.allowed_types[0]
        except IndexError:
            return (None, None)

default_negotiator = SessionNegotiator(default_association_order)
encrypted_negotiator = SessionNegotiator(only_encrypted_association_order)

def getSecretSize(assoc_type):
    if assoc_type == 'HMAC-SHA1':
        return 20
    elif assoc_type == 'HMAC-SHA256':
        return 32
    else:
        raise ValueError('Unsupported association type: %r' % (assoc_type,))

class Association(object):
    """
    This class represents an association between a server and a
    consumer.  In general, users of this library will never see
    instances of this object.  The only exception is if you implement
    a custom C{L{OpenIDStore<openid.store.interface.OpenIDStore>}}.

    If you do implement such a store, it will need to store the values
    of the C{L{handle}}, C{L{secret}}, C{L{issued}}, C{L{lifetime}}, and
    C{L{assoc_type}} instance variables.

    @ivar handle: This is the handle the server gave this association.

    @type handle: C{str}


    @ivar secret: This is the shared secret the server generated for
        this association.

    @type secret: C{str}


    @ivar issued: This is the time this association was issued, in
        seconds since 00:00 GMT, January 1, 1970.  (ie, a unix
        timestamp)

    @type issued: C{int}


    @ivar lifetime: This is the amount of time this association is
        good for, measured in seconds since the association was
        issued.

    @type lifetime: C{int}


    @ivar assoc_type: This is the type of association this instance
        represents.  The only valid value of this field at this time
        is C{'HMAC-SHA1'}, but new types may be defined in the future.

    @type assoc_type: C{str}


    @sort: __init__, fromExpiresIn, getExpiresIn, __eq__, __ne__,
        handle, secret, issued, lifetime, assoc_type
    """

    # The ordering and name of keys as stored by serialize
    assoc_keys = [
        'version',
        'handle',
        'secret',
        'issued',
        'lifetime',
        'assoc_type',
        ]


    _macs = {
        'HMAC-SHA1': cryptutil.hmacSha1,
        'HMAC-SHA256': cryptutil.hmacSha256,
        }


    def fromExpiresIn(cls, expires_in, handle, secret, assoc_type):
        """
        This is an alternate constructor used by the OpenID consumer
        library to create associations.  C{L{OpenIDStore
        <openid.store.interface.OpenIDStore>}} implementations
        shouldn't use this constructor.


        @param expires_in: This is the amount of time this association
            is good for, measured in seconds since the association was
            issued.

        @type expires_in: C{int}


        @param handle: This is the handle the server gave this
            association.

        @type handle: C{str}


        @param secret: This is the shared secret the server generated
            for this association.

        @type secret: C{str}


        @param assoc_type: This is the type of association this
            instance represents.  The only valid value of this field
            at this time is C{'HMAC-SHA1'}, but new types may be
            defined in the future.

        @type assoc_type: C{str}
        """
        issued = int(time.time())
        lifetime = expires_in
        return cls(handle, secret, issued, lifetime, assoc_type)

    fromExpiresIn = classmethod(fromExpiresIn)

    def __init__(self, handle, secret, issued, lifetime, assoc_type):
        """
        This is the standard constructor for creating an association.


        @param handle: This is the handle the server gave this
            association.

        @type handle: C{str}


        @param secret: This is the shared secret the server generated
            for this association.

        @type secret: C{str}


        @param issued: This is the time this association was issued,
            in seconds since 00:00 GMT, January 1, 1970.  (ie, a unix
            timestamp)

        @type issued: C{int}


        @param lifetime: This is the amount of time this association
            is good for, measured in seconds since the association was
            issued.

        @type lifetime: C{int}


        @param assoc_type: This is the type of association this
            instance represents.  The only valid value of this field
            at this time is C{'HMAC-SHA1'}, but new types may be
            defined in the future.

        @type assoc_type: C{str}
        """
        if assoc_type not in all_association_types:
            fmt = '%r is not a supported association type'
            raise ValueError(fmt % (assoc_type,))

#         secret_size = getSecretSize(assoc_type)
#         if len(secret) != secret_size:
#             fmt = 'Wrong size secret (%s bytes) for association type %s'
#             raise ValueError(fmt % (len(secret), assoc_type))

        self.handle = handle
        self.secret = secret
        self.issued = issued
        self.lifetime = lifetime
        self.assoc_type = assoc_type

    def getExpiresIn(self, now=None):
        """
        This returns the number of seconds this association is still
        valid for, or C{0} if the association is no longer valid.


        @return: The number of seconds this association is still valid
            for, or C{0} if the association is no longer valid.

        @rtype: C{int}
        """
        if now is None:
            now = int(time.time())

        return max(0, self.issued + self.lifetime - now)

    expiresIn = property(getExpiresIn)

    def __eq__(self, other):
        """
        This checks to see if two C{L{Association}} instances
        represent the same association.


        @return: C{True} if the two instances represent the same
            association, C{False} otherwise.

        @rtype: C{bool}
        """
        return type(self) is type(other) and self.__dict__ == other.__dict__

    def __ne__(self, other):
        """
        This checks to see if two C{L{Association}} instances
        represent different associations.


        @return: C{True} if the two instances represent different
            associations, C{False} otherwise.

        @rtype: C{bool}
        """
        return not (self == other)

    def serialize(self):
        """
        Convert an association to KV form.

        @return: String in KV form suitable for deserialization by
            deserialize.

        @rtype: str
        """
        data = {
            'version':'2',
            'handle':self.handle,
            'secret':oidutil.toBase64(self.secret),
            'issued':str(int(self.issued)),
            'lifetime':str(int(self.lifetime)),
            'assoc_type':self.assoc_type
            }

        assert len(data) == len(self.assoc_keys)
        pairs = []
        for field_name in self.assoc_keys:
            pairs.append((field_name, data[field_name]))

        return kvform.seqToKV(pairs, strict=True)

    def deserialize(cls, assoc_s):
        """
        Parse an association as stored by serialize().

        inverse of serialize


        @param assoc_s: Association as serialized by serialize()

        @type assoc_s: str


        @return: instance of this class
        """
        pairs = kvform.kvToSeq(assoc_s, strict=True)
        keys = []
        values = []
        for k, v in pairs:
            keys.append(k)
            values.append(v)

        if keys != cls.assoc_keys:
            raise ValueError('Unexpected key values: %r', keys)

        version, handle, secret, issued, lifetime, assoc_type = values
        if version != '2':
            raise ValueError('Unknown version: %r' % version)
        issued = int(issued)
        lifetime = int(lifetime)
        secret = oidutil.fromBase64(secret)
        return cls(handle, secret, issued, lifetime, assoc_type)

    deserialize = classmethod(deserialize)

    def sign(self, pairs):
        """
        Generate a signature for a sequence of (key, value) pairs


        @param pairs: The pairs to sign, in order

        @type pairs: sequence of (str, str)


        @return: The binary signature of this sequence of pairs

        @rtype: str
        """
        kv = kvform.seqToKV(pairs)

        try:
            mac = self._macs[self.assoc_type]
        except KeyError:
            raise ValueError(
                'Unknown association type: %r' % (self.assoc_type,))

        return mac(self.secret, kv)


    def getMessageSignature(self, message):
        """Return the signature of a message.

        If I am not a sign-all association, the message must have a
        signed list.

        @return: the signature, base64 encoded

        @rtype: str

        @raises ValueError: If there is no signed list and I am not a sign-all
            type of association.
        """
        pairs = self._makePairs(message)
        return oidutil.toBase64(self.sign(pairs))

    def signMessage(self, message):
        """Add a signature (and a signed list) to a message.

        @return: a new Message object with a signature
        @rtype: L{openid.message.Message}
        """
        if (message.hasKey(OPENID_NS, 'sig') or
            message.hasKey(OPENID_NS, 'signed')):
            raise ValueError('Message already has signed list or signature')

        extant_handle = message.getArg(OPENID_NS, 'assoc_handle')
        if extant_handle and extant_handle != self.handle:
            raise ValueError("Message has a different association handle")

        signed_message = message.copy()
        signed_message.setArg(OPENID_NS, 'assoc_handle', self.handle)
        message_keys = signed_message.toPostArgs().keys()
        signed_list = [k[7:] for k in message_keys
                       if k.startswith('openid.')]
        signed_list.append('signed')
        signed_list.sort()
        signed_message.setArg(OPENID_NS, 'signed', ','.join(signed_list))
        sig = self.getMessageSignature(signed_message)
        signed_message.setArg(OPENID_NS, 'sig', sig)
        return signed_message

    def checkMessageSignature(self, message):
        """Given a message with a signature, calculate a new signature
        and return whether it matches the signature in the message.

        @raises ValueError: if the message has no signature or no signature
            can be calculated for it.
        """        
        message_sig = message.getArg(OPENID_NS, 'sig')
        if not message_sig:
            raise ValueError("%s has no sig." % (message,))
        calculated_sig = self.getMessageSignature(message)
        return calculated_sig == message_sig


    def _makePairs(self, message):
        signed = message.getArg(OPENID_NS, 'signed')
        if not signed:
            raise ValueError('Message has no signed list: %s' % (message,))

        signed_list = signed.split(',')
        pairs = []
        data = message.toPostArgs()
        for field in signed_list:
            pairs.append((field, data.get('openid.' + field, '')))
        return pairs

    def __repr__(self):
        return "<%s.%s %s %s>" % (
            self.__class__.__module__,
            self.__class__.__name__,
            self.assoc_type,
            self.handle)
