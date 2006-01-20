
from mod_python import apache
from mod_python.util import FieldStorage, redirect
from mod_python.Session import Session

from xml.sax.saxutils import escape

from openid.tools import events

SESSION_TIMEOUT = 3600 * 24 * 4

class IWebFace:
    """

    @ivar req: A Request object.
    @ivar session: Session.
    """

    def log(message):
        pass

    def log_error(message, priority=None):
        pass

    def getBaseURL():
        pass

    def fixedLength(fixed):
        """Is this web page fixed in length?

        (As opposed to streaming.)

        @type fixed: bool
        """
        pass

    def write(some_bytes):
        pass

    def redirect(url):
        pass

    def displayEvent(event):
        # This is a bit higher-level than the others...
        pass

    def statusMsg(msg):
        pass

    def onCleanup(callback):
        pass

def getBaseURL(req):
    """Return a URL to the base of this script's URLspace.

    e.g. http://openidenabled.com/resources/oiddiag/

    (note the trailing slash.)

    mod_python.Request -> str
    """
    # This code currently doesn't have unit test coverage.
    # It looks like any bug in this code would arise from a failure in my
    # expectations of the attributes of the request object.  However,
    # I don't have a test harness that allows me to use actual apache request
    # objects, so I can't test for that with the current test environment.
    host = req.hostname or req.server.server_hostname
    port = req.connection.local_addr[1]

    # Don't include the default port number in the URL
    # XXX: Do I need to call add_common_vars before checking subprocess_env?
    if req.subprocess_env.get('HTTPS', 'off') == 'on':
        default_port = 443
        proto = 'https'
    else:
        default_port = 80
        proto = 'http'

    if req.path_info:
        script_name = req.uri[:-len(req.path_info)]
    else:
        script_name = req.uri

    if port == default_port:
        base_url = '%s://%s%s/' % (proto, host, script_name)
    else:
        base_url = '%s://%s:%s%s/' % (proto, host, port, script_name)

    return base_url


class ApacheFace(object):
    fixed_length = False
    def __init__(self, req):
        self.req = req
        self._cleanupCalls = []
        try:
            self.session = Session(req, timeout=SESSION_TIMEOUT)
        except Exception, e:
            self.log_error(str(e))
            self.session = Session(req, sid="NEW_SESSION_PLEASE",
                                   timeout=SESSION_TIMEOUT)
        self.req.fields = FieldStorage(req)
        self._buffer = []

    def fixedLength(self, fixed):
        self.fixed_length = fixed

    def write(self, bytes):
        if self.fixed_length:
            self._buffer.append(bytes)
        else:
            self.req.write(bytes)

    def redirect(self, url):
        # Will raise apache.SERVER_RETURN
        redirect(self.req, url)

    def finish(self):
        if self._buffer:
            length = reduce(int.__add__, map(len, self._buffer))
            self.req.set_content_length(length)
            self.req.write(''.join(self._buffer))

    def statusMsg(self, msg):
        self.write('<span class="status">%s</span><br />\n' % (escape(msg),))

    def handle(self, rendermethod):
        self.req.register_cleanup(self.cleanup)
        self.req.content_type = "text/html"
        try:
            rendermethod(self.req)
        finally:
            self.finish()
        return apache.OK

    def displayEvent(self, event):
        self.write(event.to_html() + '<br />\n')

    def onCleanup(self, callback):
        self._cleanupCalls.append(callback)

    def log(self, msg):
        self.write('<span class="log">%s</span><br />\n' % (escape(msg),))

    def cleanup(self, unused=None):
        try:
            self.session.save()
        except:
            self.req.log_error("Error saving session: %s" % (self.session,))
            raise
        for c in self._cleanupCalls:
            c()

    def getBaseURL(self):
        return getBaseURL(self.req)

    def log_error(self, msg, priority=apache.APLOG_ERR):
        self.req.log_error(msg, priority)
