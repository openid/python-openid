from openid import cryptutil

class DiffieHellman(object):
    DEFAULT_MOD = 155172898181473697471232257763715539915724801966915404479707795314057629378541917580651227423698188993727816152646631438561595825688188889951272158842675419950341258706556549803580104870537681476726513255747040765857479291291572334510643245094715007229621094194349783925984760375594985848253359305585439638443L

    DEFAULT_GEN = 2

    def _fromBase64(cls, modulus=None, generator=None):
        if modulus is not None:
            modulus = cryptutil.base64ToLong(modulus)
        if generator is not None:
            generator = cryptutil.base64ToLong(generator)

        return cls(modulus, generator)

    fromBase64 = classmethod(_fromBase64)

    def __init__(self, modulus=None, generator=None):
        if (modulus is None and generator is not None or
            generator is None and modulus is not None):

            if modulus is None:
                missing = 'modulus'
            else:
                missing = 'generator'

            raise ValueError('If non-default modulus or generator is '
                             'supplied, both must be supplied. Missing %s'
                             % (missing,))

        if modulus is None:
            modulus = self.DEFAULT_MOD
        self.modulus = long(modulus)

        if generator is None:
            generator = self.DEFAULT_GEN
        self.generator = long(generator)

        self._setPrivate(cryptutil.randrange(1, modulus - 1))

    def _setPrivate(self, private):
        """This is here to make testing easier"""
        self.private = private
        self.public = pow(self.generator, self.private, self.modulus)

    def getSharedSecret(self, composite):
        return pow(composite, self.private, self.modulus)

    def xorSecret(self, composite, secret):
        dh_shared = self.getSharedSecret(composite)
        sha1_dh_shared = cryptutil.sha1(cryptutil.longToBinary(dh_shared))
        return cryptutil.strxor(secret, sha1_dh_shared)
