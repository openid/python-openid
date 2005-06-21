from openid.errors import ProtocolError

class Response(object):
    def __init__(self, **kwargs):
        for attr in ['code', 'content_type', 'body', 'redirect_url']:
            setattr(self, attr, kwargs.get(attr))

def redirect(url):
    return Response(code=302, redirect_url=url)

def response_page(body):
    return Response(code=200, content_type='text/plain', body=body)

def error_page(body):
    return Response(code=400, content_type='text/plain', body=body)

class Request(object):
    def __init__(self, args, http_method, authentication=None):
        """Creates a new Request object, used by both the consumer and
        server APIs.  args should be a dictionary of http arguments,
        whether via post or GET request.  http_method should be set to
        either POST or GET, indicating how this request was made.

        authentication is a field that isn't used by any library code,
        but exists purely as a pass-through, so that users of the
        server library can verify that a given request has whatever
        authentication credentials are needed to allow it correctly
        calculate the return from get_auth_range.  A typical value of
        the authentication field would be the username of the
        logged-in user making the http request from the server."""
        self.args = args
        self.http_method = http_method.upper()
        self.authentication = authentication

    def hasOpenIDParams(self):
        for k in self.args:
            if k.startswith('openid.'):
                return True

        return False

    def get(self, key, default=None):
        return self.args.get('openid.' + key, default)

    def __getattr__(self, attr):
        if attr[0] == '_':
            raise AttributeError

        val = self.get(attr)
        if val is None:
            raise ProtocolError('Query argument %r not found' % (attr,))

        return val

    def get_by_full_key(self, key, default=None):
        return self.args.get(key, default)
