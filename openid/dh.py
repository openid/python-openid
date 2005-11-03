from openid import cryptutil

class DiffieHellman(object):
    DEFAULT_MOD = 155172898181473697471232257763715539915724801966915404479707795314057629378541917580651227423698188993727816152646631438561595825688188889951272158842675419950341258706556549803580104870537681476726513255747040765857479291291572334510643245094715007229621094194349783925984760375594985848253359305585439638443L

    DEFAULT_GEN = 2

    def _fromBase64(cls, p=None, g=None):
        if p is not None:
            p = cryptutil.base64ToLong(p)
        if g is not None:
            g = cryptutil.base64ToLong(g)

        return cls(p, g)

    fromBase64 = classmethod(_fromBase64)

    def __init__(self, p=None, g=None):
        if p is None:
            p = self.DEFAULT_MOD
        self.p = long(p)

        if g is None:
            g = self.DEFAULT_GEN
        self.g = long(g)

        self.x = cryptutil.randrange(1, p - 1)

    def createKeyExchange(self):
        return pow(self.g, self.x, self.p)

    def xorSecret(self, composite, secret):
        dh_shared = pow(composite, self.x, self.p)
        sha1_dh_shared = cryptutil.sha1(cryptutil.longToBinary(dh_shared))
        return cryptutil.strxor(secret, sha1_dh_shared)
