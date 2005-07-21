from openid.errors import ProtocolError, NoOpenIDArgs

class ServerResponse(object):
    def __init__(self, **kwargs):
        for attr in ['code', 'content_type', 'body', 'redirect_url']:
            setattr(self, attr, kwargs.get(attr))

def redirect(url):
    return ServerResponse(code=302, redirect_url=str(url))

def response_page(body):
    return ServerResponse(code=200, content_type='text/plain', body=body)

def error_page(body):
    return ServerResponse(code=400, content_type='text/plain', body=body)



class ConsumerResponse(object):
    """This is a superclass to provide type unification for all the
    various responses the consumer library can provide after
    interpreting an openid query.

    A Visitor pattern interface for dispatching to the various
    subclasses is provided for users of the library who wish to use
    it."""
    def doAction(self, handler):
        raise NotImplementedError

class ValidLogin(ConsumerResponse):
    """This subclass is used when the login succeeded.  The identity
    parameter is the value that the id server has confirmed.

    This method passes itself into its visitor pattern implementation.
    This is so that its verifyIdentity method can be used in the
    handler funtion."""
    def __init__(self, consumer, identity):
        self.consumer = consumer
        self.identity = identity

    def doAction(self, handler):
        return handler.doValidLogin(self)

    def verifyIdentity(self, identity):
        """This method verifies that the identity passed in is one
        that this response is actually claiming is valid.  It takes
        care of checking if the identity url that the server actually
        verified is delegated to by the identity passed in, if such a
        check is needed.  Returns True if the identity passed in was
        authenticated by the server, False otherwise."""
        if identity == self.identity:
            return True

        try:
            ret = self.consumer.find_identity_info(identity)
        except:
            # if anything goes wrong, it's not a valid login
            return False

        if ret is None:
            return False

        return ret[1] == self.identity

class InvalidLogin(ConsumerResponse):
    """This subclass is used when the login wasn't valid."""
    def doAction(self, handler):
        return handler.doInvalidLogin()

class UserCancelled(ConsumerResponse):
    """This subclass is used when the user cancelled the login."""
    def doAction(self, handler):
        return handler.doUserCancelled()

class UserSetupNeeded(ConsumerResponse):
    """This subclass is used when the UA needs to be sent to the given
    user_setup_url to complete their login."""
    def __init__(self, user_setup_url):
        self.user_setup_url = user_setup_url

    def doAction(self, handler):
        return handler.doUserSetupNeeded(self.user_setup_url)

class ErrorFromServer(ConsumerResponse):
    """This subclass is used"""
    def __init__(self, message):
        self.message = message

    def doAction(self, handler):
        return handler.doErrorFromServer(self.message)

class CheckAuthRequired(ConsumerResponse):
    def __init__(self, server_url, return_to, post_data):
        self.server_url = server_url
        self.return_to = return_to
        self.post_data = post_data

    def doAction(self, handler):
        return handler.doCheckAuthRequired(
            self.server_url, self.return_to, self.post_data)


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
        logged-in user making the http request from the server.

        If an instance of this is created with any openid.* arguments,
        a NoOpenIDArgs exception is raised.  This should be caught and
        handled appropriately."""
        self.args = args
        self.http_method = http_method.upper()
        self.authentication = authentication

        for k in self.args:
            if k.startswith('openid.'):
                break
        else:
            raise NoOpenIDArgs

    def get(self, key, default=None):
        return self.args.get('openid.' + key, default)

    def __getattr__(self, attr):
        if attr[0] == '_':
            raise AttributeError

        val = self.get(attr)
        if val is None:
            if attr == 'trust_root':
                return self.return_to
            else:
                raise ProtocolError('Query argument %r not found' % (attr,))

        return val

    def get_by_full_key(self, key, default=None):
        return self.args.get(key, default)
