#
# XXX: SKELETON ONLY!  DO NOT USE WITHOUT MASSIVE DOC EFFORT!  And
#      what's in here now is far from the massive effort I was talking
#      about.
#

class OpenIDConsumerFacade(object):
    """ """

    def __init__(self, store=None, fetcher=None, immediate=False, split=False):
        """ """
        if fetcher is None:
            from openid.consumer.fetchers import getHTTPFetcher
            fetcher = getHTTPFetcher()

        if store is None:
            store = None # XXX: Fix this

        from openid.consumer.impl import OpenIDConsumer
        self.impl = OpenIDConsumer(store, fetcher, immediate, split)

    def constructRedirect(self, proxy):
        """returns the redirect to send the user to proceed with the login."""
        return self.impl.constructRedirect(proxy)

    def processServerResponse(self, proxy):
        """returns the value returned by whichever of the proxy's
        handler methods was invoked"""
        return self.impl.processServerResponse(proxy)

    def checkAuth(self, proxy):
        """returns the value returned by whichever of the proxy's
        handler methods was invoked"""
        return self.impl.checkAuth(proxy)


class OpenIDProxy(object):
    """This is a proxy the openid library will use to get information
    from its environment."""

    def getUserInput(self):
        """This method returns the string the user entered as their
        openid.  This is called during constructRedirect.  If there is
        no such value, return None."""
        raise NotImplementedError

    def getOpenIDQueryParameter(self, name):
        """This method returns the unescaped value for the query
        parameter openid.<name>.  If no such parameter exists, return
        None.  If there are multiple parameters with that name, return
        one of them.  This is called during processServerResponse."""
        raise NotImplementedError

    def getCheckAuthParams(self):
        """This method returns the check_auth_params blob necessary
        for the checkAuth call to succeed.  See the checkAuthRequired
        method below for more information.

        ** Split mode only
        """
        raise NotImplementedError



    def getReturnTo(self, token):
        """This method returns an appropriate return_to url. Used
        by constructRedirect"""
        raise NotImplementedError

    def verifyReturnTo(self, return_to):
        """This method verifies that the given return_to url is valid
        for this server.  Used by processServerResponse and checkAuth.
        Returns the token given to the corresponding getReturnTo if
        the return_to is valid, None if it's not."""
        raise NotImplementedError



    # The following methods are all callbacks used by
    # processServerResponse and checkAuth.  For all of them, their
    # return values are passed through, and returned from the call to
    # OpenIDConsumerFacade that led to them being called.  During
    # normal execution (no exception raised) exactly one of these will
    # be called per call to processServerResponse or checkAuth.

    def loginGood(self, normalized_id):
        """Called when a login is successful.  normalized_id is the
        openid that was authenticated, after normalizing and following
        redirects.  Any value returned by this method is returned by
        the call to processServerRequest or checkAuth that led to this
        method being called."""
        raise NotImplementedError

    def loginError(self):
        """Called when a login fails.  This usually indicates either a
        malfunctioning server or an attempt to forge a login.  As it's
        generally impossible to determine which, no additional
        information can be provided.  Any value returned by this
        method is returned by the call to processServerRequest or
        checkAuth that led to this method being called."""
        raise NotImplementedError

    def loginCancelled(self):
        """Called when a user cancels a login.  Since no additional
        information can be extracted from the openid parameters, this
        doesn't provide any additional information.  Any value
        returned by this method is returned by the call to
        processServerRequest that led to this method being called.
        (This method is not called from checkAuth.)"""
        raise NotImplementedError

    def setupNeeded(self, user_setup_url):
        """Called when the consumer is in immediate mode and the
        server returns a user_setup_url.  Any value returned by this
        method is returned by the call to processServerRequest that
        led to this method being called.  (This method is not called
        from checkAuth.)"""
        raise NotImplementedError

    def serverError(self, message):
        """Called when the server sends an error message to the
        consumer.  This should be a rare occurance, but can happen.
        message is the error message the server sent.  Any value
        returned by this method is returned by the call to
        processServerRequest or checkAuth that led to this method
        being called."""
        raise NotImplementedError

    def checkAuthRequired(self, check_auth_params):
        """Called when the OpenIDConsumerFacade was created with
        split=True.  This returns an opaque blob (in the form of a
        string) containing the information necessary to make a call to
        checkAuth.  That blob must be available via the getAuthPArams
        call when checkAuth is called to verify the login.  Any value
        returned by this method is returned by the call to
        processServerRequest that led to this method being called.
        (This method is not called from checkAuth, and is only called
        if the OpenIDConsumerFacade was created with split=True.)

        ** Split mode only
        """
        raise NotImplementedError




