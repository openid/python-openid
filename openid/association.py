"""
This module contains code for dealing with associations between
consumers and servers.
"""

import time

from openid import cryptutil
from openid import kvform
from openid import oidutil

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

    # This is a HMAC-SHA1 specific value.
    SIG_LENGTH = 20

    # The ordering and name of keys as stored by serialize
    assoc_keys = [
        'version',
        'handle',
        'secret',
        'issued',
        'lifetime',
        'assoc_type',
        ]

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
        if assoc_type != 'HMAC-SHA1':
            fmt = 'HMAC-SHA1 is the only supported association type (got %r)'
            raise ValueError(fmt % (assoc_type,))

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
        assert self.assoc_type == 'HMAC-SHA1'
        kv = kvform.seqToKV(pairs)
        return cryptutil.hmacSha1(self.secret, kv)

    def signDict(self, fields, data, prefix='openid.'):
        """
        Generate a signature for some fields in a dictionary


        @param fields: The fields to sign, in order

        @type fields: sequence of str


        @param data: Dictionary of values to sign

        @type data: {str:str}


        @return: the signature, base64 encoded

        @rtype: str
        """
        pairs = []
        for field in fields:
            pairs.append((field, data.get(prefix + field, '')))

        return oidutil.toBase64(self.sign(pairs))

    def addSignature(self, fields, data, prefix='openid.'):
        sig = self.signDict(fields, data, prefix)
        signed = ','.join(fields)
        data[prefix + 'sig'] = sig
        data[prefix + 'signed'] = signed

    def checkSignature(self, data, prefix='openid.'):
        try:
            signed = data[prefix + 'signed']
            fields = signed.split(',')
            expected_sig = self.signDict(fields, data, prefix)
            request_sig = data[prefix + 'sig']
        except KeyError:
            return False

        return request_sig == expected_sig
