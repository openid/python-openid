"""Test utilities."""
from openid import message


class OpenIDTestMixin(object):
    """Mixin providing custom asserts."""

    def assertOpenIDValueEqual(self, msg, key, expected, ns=None):
        """Check OpenID message contains key with expected value."""
        if ns is None:
            ns = message.OPENID_NS

        actual = msg.getArg(ns, key)
        error_format = 'Wrong value for openid.%s: expected=%s, actual=%s'
        error_message = error_format % (key, expected, actual)
        self.assertEqual(actual, expected, error_message)

    def assertOpenIDKeyMissing(self, msg, key, ns=None):
        if ns is None:
            ns = message.OPENID_NS

        error_message = 'openid.%s unexpectedly present' % key
        self.assertFalse(msg.hasKey(ns, key), error_message)
