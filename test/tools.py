

class DummyFieldStorage(object):
    def __init__(self, req):
        self.req = req

    def getfirst(self, key):
        l = self.req._fields.get(key)
        if not l:
            return None
        else:
            return l[0]

    def get(self, key, defvalue=None):
        return self.req._fields.get(key, defvalue)

    def keys(self):
        return self.req._fields.keys()


class DummyRequest(object):
    def __init__(self):
        self.options = {}
        self.logmsgs = []
        self._fields = {}
        self.fields = DummyFieldStorage(self)
        self.uri = "http://unittest.example/myapp"
        self.subprocess_env = {}
        class DummyConnection(object):
            local_addr = ('127.0.0.1', 80)
        self.connection = DummyConnection()
        self.hostname = 'unittest.example'
        self.path_info = ''
        self.unparsed_uri = self.uri

    def log_error(self, msg, priority):
        self.logmsgs.append((priority, msg))


