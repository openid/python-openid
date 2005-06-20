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
    def __init__(self, args, http_method):
        self.args = args
        self.http_method = http_method.upper()

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
