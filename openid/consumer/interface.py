#
# XXX: SKELETON ONLY!  DO NOT USE WITHOUT MASSIVE DOC EFFORT!  And
#      what's in here now is far from the massive effort I was talking
#      about.
#

class OpenIDConsumerFacade(object):
    """ """

    def __init__(self, store, fetcher=None, immediate=False):
        """ """
        if fetcher is None:
            from openid.consumer.fetchers import getHTTPFetcher
            fetcher = getHTTPFetcher()

        from openid.consumer.impl import OpenIDConsumer
        self.impl = OpenIDConsumer(store, fetcher, immediate)

    def constructRedirect(self, proxy):
        """returns the redirect to send the user to proceed with the
        login.  Returns None if the user input didn't lead to a valid
        openid."""
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

    def getTrustRoot(self):
        """This method returns the server's trust root, or if the
        server doesn't wish to specify a trust root, it returns None.
        This is called during constructRedirect."""

    def getParameters(self):
        """This method returns all the query parameters that the
        server sent back to the consumer.  It returns them as a
        dictionary from full parameter name (ie, including the
        'openid.' prefix) to the parameter value, both unescaped from
        whatever urlencoding was applied to them.  Used in
        processServerResponse."""
        raise NotImplementedError


    def getReturnTo(self, token):
        """This method returns an appropriate return_to url. Used
        by constructRedirect"""
        raise NotImplementedError

    def verifyReturnTo(self, return_to):
        """Used by processServerResponse.  Returns true if the
        return_to url matches the url this request came to, including
        query args.  Otherwise returns false."""
        raise NotImplementedError

    def getToken(self):
        """Used by processServerResponse.  Returns the token set
        during the call to getReturnTo, if available, None otherwise."""
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

    def loginCancelled(self):
        """Called when a user cancels a login.  No additional
        information is included, so none is passed in.  Any value
        returned by this method is returned by the call to
        processServerRequest that led to this method being called.
        (This method is not called from checkAuth.)"""
        raise NotImplementedError

    def loginFailure(self, normalized_id):
        """Called when a login fails.  This usually indicates either a
        malfunctioning server, an attempt to forge a login, or an
        association with a server getting lost or expiring during the
        transaction.  As it's generally impossible to determine which,
        no additional information can be provided.  Any value returned
        by this method is returned by the call to processServerRequest
        or checkAuth that led to this method being called."""
        raise NotImplementedError

    def serverError(self, message):
        """Called when the server sends an error message to the
        consumer.  This should be a rare occurance, but can happen.
        message is the error message the server sent.  Any value
        returned by this method is returned by the call to
        processServerRequest or checkAuth that led to this method
        being called."""
        raise NotImplementedError

    def setupNeeded(self, user_setup_url):
        """Called when the consumer is in immediate mode and the
        server returns a user_setup_url.  Any value returned by this
        method is returned by the call to processServerRequest that
        led to this method being called.  (This method is not called
        from checkAuth.)"""
        raise NotImplementedError




