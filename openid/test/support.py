from openid import message
from logging.handlers import BufferingHandler
import logging

class TestHandler(BufferingHandler):
    def __init__(self, messages):
        BufferingHandler.__init__(self, 0)
	self.messages = messages

    def shouldFlush(self):
        return False

    def emit(self, record):
        self.messages.append(record.__dict__)

class OpenIDTestMixin(object):
    def failUnlessOpenIDValueEquals(self, msg, key, expected, ns=None):
        if ns is None:
            ns = message.OPENID_NS

        actual = msg.getArg(ns, key)
        error_format = 'Wrong value for openid.%s: expected=%s, actual=%s'
        error_message = error_format % (key, expected, actual)
        self.failUnlessEqual(expected, actual, error_message)

    def failIfOpenIDKeyExists(self, msg, key, ns=None):
        if ns is None:
            ns = message.OPENID_NS

        actual = msg.getArg(ns, key)
        error_message = 'openid.%s unexpectedly present: %s' % (key, actual)
        self.failIf(actual is not None, error_message)

class CatchLogs(object):
    def setUp(self):
	self.messages = []
	root_logger = logging.getLogger()
	self.old_log_level = root_logger.getEffectiveLevel()
	root_logger.setLevel(logging.DEBUG)

	self.handler = TestHandler(self.messages)
	formatter = logging.Formatter("%(message)s [%(asctime)s - %(name)s - %(levelname)s]")
	self.handler.setFormatter(formatter)
	root_logger.addHandler(self.handler)

    def tearDown(self):
        root_logger = logging.getLogger()
	root_logger.removeHandler(self.handler)
	root_logger.setLevel(self.old_log_level)

    def failUnlessLogMatches(self, *prefixes):
        """
        Check that the log messages contained in self.messages have
        prefixes in *prefixes.  Raise AssertionError if not, or if the
        number of prefixes is different than the number of log
        messages.
        """
	messages = [r['msg'] for r in self.messages]
	assert len(prefixes) == len(messages), \
               "Expected log prefixes %r, got %r" % (prefixes,
                                                     messages)

        for prefix, message in zip(prefixes, messages):
            assert message.startswith(prefix), \
                   "Expected log prefixes %r, got %r" % (prefixes,
                                                         messages)

    def failUnlessLogEmpty(self):
        self.failUnlessLogMatches()
