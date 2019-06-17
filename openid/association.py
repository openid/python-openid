# -*- test-case-name: openid.test.test_association -*-
"""
This module contains code for dealing with associations between
consumers and servers. Associations contain a shared secret that is
used to sign C{openid.mode=id_res} messages.

Users of the library should not usually need to interact directly with
associations. The L{store<openid.store>},
L{server<openid.server.server>} and
L{consumer<openid.consumer.consumer>} objects will create and manage
the associations. The consumer and server code will make use of a
C{L{SessionNegotiator}} when managing associations, which enables
users to express a preference for what kind of associations should be
allowed, and what kind of exchange should be done to establish the
association.

@var default_negotiator: A C{L{SessionNegotiator}} that allows all
    association types that are specified by the OpenID
    specification. It prefers to use HMAC-SHA1/DH-SHA1, if it's
    available.

@var encrypted_negotiator: A C{L{SessionNegotiator}} that
    does not support C{'no-encryption'} associations. It prefers
    HMAC-SHA1/DH-SHA1 association types if available.
"""
from __future__ import unicode_literals

import time

import six
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.constant_time import bytes_eq
from cryptography.hazmat.primitives.hmac import HMAC

from openid import kvform, oidutil
from openid.message import OPENID_NS

from .oidutil import string_to_text

__all__ = [
    'default_negotiator',
    'encrypted_negotiator',
    'SessionNegotiator',
    'Association',
]


all_association_types = [
    'HMAC-SHA256',
    'HMAC-SHA1',
]

default_association_order = [
    ('HMAC-SHA256', 'DH-SHA256'),
    ('HMAC-SHA256', 'no-encryption'),
    ('HMAC-SHA1', 'DH-SHA1'),
    ('HMAC-SHA1', 'no-encryption'),
]

only_encrypted_association_order = [
    ('HMAC-SHA256', 'DH-SHA256'),
    ('HMAC-SHA1', 'DH-SHA1'),
]


def getSessionTypes(assoc_type):
    """Return the allowed session types for a given association type"""
    assoc_to_session = {
        'HMAC-SHA256': ['DH-SHA256', 'no-encryption'],
        'HMAC-SHA1': ['DH-SHA1', 'no-encryption'],
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
    """A session negotiator controls the allowed and preferred
    association types and association session types. Both the
    C{L{Consumer<openid.consumer.consumer.Consumer>}} and
    C{L{Server<openid.server.server.Server>}} use negotiators when
    creating associations.

    You can create and use negotiators if you:

     - Do not want to do Diffie-Hellman key exchange because you use
       transport-layer encryption (e.g. SSL)

     - Want to use only SHA-256 associations

     - Do not want to support plain-text associations over a non-secure
       channel

    It is up to you to set a policy for what kinds of associations to
    accept. By default, the library will make any kind of association
    that is allowed in the OpenID 2.0 specification.

    Use of negotiators in the library
    =================================

    When a consumer makes an association request, it calls
    C{L{getAllowedType}} to get the preferred association type and
    association session type.

    The server gets a request for a particular association/session
    type and calls C{L{isAllowed}} to determine if it should
    create an association. If it is supported, negotiation is
    complete. If it is not, the server calls C{L{getAllowedType}} to
    get an allowed association type to return to the consumer.

    If the consumer gets an error response indicating that the
    requested association/session type is not supported by the server
    that contains an assocation/session type to try, it calls
    C{L{isAllowed}} to determine if it should try again with the
    given combination of association/session type.

    @ivar allowed_types: A list of association/session types that are
        allowed by the server. The order of the pairs in this list
        determines preference. If an association/session type comes
        earlier in the list, the library is more likely to use that
        type.
    @type allowed_types: List[Tuple[six.text_type, six.text_type]]
    """

    def __init__(self, allowed_types):
        self.setAllowedTypes(allowed_types)

    def copy(self):
        return self.__class__(list(self.allowed_types))

    def setAllowedTypes(self, allowed_types):
        """Set the allowed association types, checking to make sure
        each combination is valid."""
        # Convert strings to text
        allowed_types = [
            (string_to_text(a, "Binary values for assoc_type are deprecated. Use text input instead."),
             string_to_text(s, "Binary values for session_type are deprecated. Use text input instead."))
            for a, s in allowed_types]
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
            available = getSessionTypes(assoc_type)

            if not available:
                raise ValueError('No session available for association type %r'
                                 % (assoc_type,))

            for session_type in getSessionTypes(assoc_type):
                self.addAllowedType(assoc_type, session_type)
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
    @type handle: six.text_type


    @ivar secret: This is the shared secret the server generated for
        this association.
    @type secret: six.binary_type


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
    @type assoc_type: six.text_type

    @cvar hmac_algorithms: Mapping of association type to hash algorithm.
    @type hmac_algorithms: Dict[six.text_type, hashes.HashAlgorithm]

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

    hmac_algorithms = {
        'HMAC-SHA1': hashes.SHA1(),
        'HMAC-SHA256': hashes.SHA256(),
    }

    @classmethod
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
        @type handle: six.text_type, six.binary_type is deprecated

        @param secret: This is the shared secret the server generated
            for this association.
        @type secret: six.binary_type

        @param assoc_type: This is the type of association this
            instance represents.  The only valid value of this field
            at this time is C{'HMAC-SHA1'}, but new types may be
            defined in the future.
        @type assoc_type: six.text_type, six.binary_type is deprecated
        """
        issued = int(time.time())
        lifetime = expires_in
        return cls(handle, secret, issued, lifetime, assoc_type)

    def __init__(self, handle, secret, issued, lifetime, assoc_type):
        """
        This is the standard constructor for creating an association.


        @param handle: This is the handle the server gave this
            association.
        @type handle: six.text_type, six.binary_type is deprecated


        @param secret: This is the shared secret the server generated
            for this association.
        @type secret: six.binary_type


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
        @type assoc_type: six.text_type, six.binary_type is deprecated
        """
        assoc_type = string_to_text(assoc_type, "Binary values for assoc_type are deprecated. Use text input instead.")
        if assoc_type not in all_association_types:
            fmt = '%r is not a supported association type'
            raise ValueError(fmt % (assoc_type,))

#         secret_size = getSecretSize(assoc_type)
#         if len(secret) != secret_size:
#             fmt = 'Wrong size secret (%s bytes) for association type %s'
#             raise ValueError(fmt % (len(secret), assoc_type))

        self.handle = string_to_text(handle, "Binary values for handle are deprecated. Use text input instead.")
        assert isinstance(secret, six.binary_type)
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
        return type(self) == type(other) and self.__dict__ == other.__dict__

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

        @rtype: six.text_type
        """
        data = {
            'version': '2',
            'handle': self.handle,
            'secret': oidutil.toBase64(self.secret),
            'issued': six.text_type(int(self.issued)),
            'lifetime': six.text_type(int(self.lifetime)),
            'assoc_type': self.assoc_type
        }

        assert len(data) == len(self.assoc_keys)
        pairs = []
        for field_name in self.assoc_keys:
            pairs.append((field_name, data[field_name]))

        return kvform.seqToKV(pairs, strict=True)

    @classmethod
    def deserialize(cls, assoc_s):
        """
        Parse an association as stored by serialize().

        inverse of serialize


        @param assoc_s: Association as serialized by serialize()
        @type assoc_s: six.text_type, six.binary_type is deprecated

        @return: instance of this class
        """
        pairs = kvform.kvToSeq(
            string_to_text(assoc_s, "Binary values for assoc_s are deprecated. Use text input instead."), strict=True)
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

    def sign(self, pairs):
        """
        Generate a signature for a sequence of (key, value) pairs


        @param pairs: The pairs to sign, in order
        @type pairs: Iterable[six.text_type, six.text_type], six.binary_type is deprecated

        @return: The binary signature of this sequence of pairs
        @rtype: six.binary_type
        """
        warning_msg = "Binary values for pairs are deprecated. Use text input instead."
        pairs = [(string_to_text(a, warning_msg), string_to_text(b, warning_msg)) for a, b in pairs]
        kv = kvform.seqToKV(pairs)

        try:
            algorithm = self.hmac_algorithms[self.assoc_type]
        except KeyError:
            raise ValueError(
                'Unknown association type: %r' % (self.assoc_type,))

        hmac = HMAC(self.secret, algorithm, backend=default_backend())
        hmac.update(kv.encode('utf-8'))
        return hmac.finalize()

    def getMessageSignature(self, message):
        """Return the signature of a message.

        If I am not a sign-all association, the message must have a
        signed list.

        @return: the signature, base64 encoded
        @rtype: six.text_type

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
        if (message.hasKey(OPENID_NS, 'sig') or message.hasKey(OPENID_NS, 'signed')):
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
        return bytes_eq(calculated_sig.encode('utf-8'), message_sig.encode('utf-8'))

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
