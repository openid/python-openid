"""Events for oiddiag.
"""

import time
from xml.sax.saxutils import escape

class Event(object):
    def __init__(self):
        self.time = time.time()

    def to_html(self):
        return escape(str(self))

class TextEvent(Event):
    """An event described by a line of text.

    Used for prototyping, these should be phased out.
    """

    def __init__(self, text):
        Event.__init__(self)
        self.text = text

    def to_html(self):
        return '<span class="event">%s</span>' % (escape(self.text),)

    def __repr__(self):
        return '<%s %r %s>' % (self.__class__.__name__, self.text, self.time)

    def __str__(self):
        return self.text

class IdentityAuthenticated(Event):
    def __init__(self, identity):
        Event.__init__(self)
        self.identity = identity

    def __str__(self):
        return "Identity authenticated as %s" % (self.identity,)

class SetupNeeded(Event):
    def __init__(self, url):
        Event.__init__(self)
        self.url = url

    def __str__(self):
        return "Server requires setup at %s" % (self.url,)

class OpenIDFailure(Event):
    explanation = None
    def __init__(self, code, info, explanation=None):
        Event.__init__(self)
        self.code = code
        self.info = info
        if explanation is not None:
            self.explanation = explanation

    def to_html(self):
        if self.explanation:
            text = self.explanation
        else:
            text = "Open ID Failure: %s %s" % (self.code, self.info)
        return ('<span class="event">%s</span>'
                % (escape(text),))


class OperationCancelled(TextEvent):
    text = "Operation Cancelled."

    def __init__(self):
        TextEvent.__init__(self, self.text)

class ResponseReceived(Event):
    def __init__(self, raw_uri, query):
        Event.__init__(self)
        self.raw_uri = raw_uri
        self.query = query

    def to_html(self):
        return ('<span class="event">Response received: %s</span>'
                % (escape(str(self.query)),))


class FatalEvent(TextEvent):
    pass

class Failure(Exception):
    def event(self):
        return FatalEvent(self.args[0])



# Not an event at all, but creating a new module for it seemed silly at
# this stage.
class Instruction(object):
    pass

class DoRedirect(Instruction):
    def __init__(self, redirectURL):
        self.redirectURL = redirectURL
