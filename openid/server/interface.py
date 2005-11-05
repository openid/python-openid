"""
This module documents the interface to the OpenID server library.
"""

REDIRECT = 'redirect'
DO_AUTH  = 'do_auth'
DO_ABOUT = 'do_about'

OK = 'ok'
ERROR  = 'error'

class OpenIDServer(object):
    def __init__(self, server_url, store):
        from openid.server.impl import OpenIDServerImpl
        self.impl = OpenIDServerImpl(server_url, store)

    def getAuthData(self, args):
        """
        returns identity, trust_root
        """
        return self.impl.getAuthData(args)
    
    def getAuthenticationResponse(self, authorized, args):
        """
        authorized is a boolean, True if the user making this request
        can authorize the identity in question, and has chosen to do
        so for the trust_root in question.  False otherwise.

        returns status, info

        status is one of:
        1. Redirect - info is the url
        2. Do Auth - info is a pair, (retry url, cancel url)
        3. Do 'About' page - info is None
        4. Error - info is the error message.
        """
        return self.impl.getAuthenticationResponse(authorized, args)

    def processPost(self, args):
        """
        returns status, body

        status is one of:
        1. ok
        2. Error
        """
        return self.impl.processPost(args)

