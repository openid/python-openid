"""
This module is intended to document the main interface with the OpenID
consumer libary.  The only part of the library which has to be used
and isn't documented in full here is the store required to create an
OpenIDConsumerFacade instance.  More on the abstract store type and
concrete implementations of it that are provided in the documentation
for the __init__ method of the OpenIDConsumerFacade class.


== OVERVIEW ==

The OpenID identity verification process most commonly uses the
following steps, as visible to the user of this library:

1. The user enters their OpenID into a field on the consumer's site,
   and hits some sort of log in button.

2. The consumer site sends the browser a redirect, sending the browser
   to the identity server's site.

3. The identity server's site sends the browser a redirect, sending
   the browser back to the consumer's site with the information
   necessary to confirm the user's identity.

There are a lot of conditional extras in the process, but that is the
basic flow of an OpenID login from the consumer's point of view.  The
most important part of that flow is noting that the consumer's site
must handle two separate HTTP requests in order to perform the full
identity check.


== LIBRARY DESIGN ==

This consumer library is designed with that flow in mind.  Our goal is
to make it as easy as possible to perform the above steps securely.

*************  Stuff that may depend on what Josh is doing....


== STORES AND DUMB MODE ==

OpenID is a protocol that works best when the consumer site is able to
store some state.  This is the normal mode of operation for the
protocol, and is sometimes referred to as smart mode.  There is also a
fallback mode, known as dumb mode, which is available when the
consumer site is not able to store state.  This mode should be avoided
when possible, as it leaves the implementation more vulnerable to
replay attacks.

The mode the library works in for normal operation* is determined by
the store that it is given.  The store is an abstraction that handles
the data that the consumer needs to manage between http requests in
order to operate efficiently and securely.

Several store implementation are provided, and the interface is fully
documented so that custom stores can be used as well.  See the
documentation for the OpenIDConsumerFacade class for more information
on the interface for stores.  The concrete implementations that are
provided allow the consumer site to store the necessary data in
several different ways: in the filesystem, in a MySQL database, or in
an SQLite database.

There is an additional concrete store provided that puts the system in
dumb mode.  This is not recommended, as it removes the library's
ability to stop replay attacks reliably.  It still uses time-based
checking to make replay attacks only possible within a small window,
but they remain possible within that window.  This store should only
be used if the consumer site has no way to store data between requests
at all.

*: There are fallback cases in the protocol, where even a consumer
usually running in smart mode acts like it's in dumb mode for one
request, but those cases are not the normal operation.  Additionally,
the fallback cases are much more secure than pure dumb mode, as they
still are making use the consumer's ability to store state.


== IMMEDIATE MODE ==

In the flow described above, there's a step which may occur if the
user needs to confirm to the identity server that it's ok to authorize
his or her identity.  The server may draw pages asking for information
from the user before it redirects the browser back to the consumer's
site.  This is generally transparent to the consumer site, so it is
typically ignored as an implementation detail.

There can be times, however, where the consumer site wants to get a
response immediately.  When this is the case, the consumer can put the
library in immediate mode.  In immediate mode, there is an extra
response possible from the server, which is essentially the server
reporting that it doesn't have enough information to answer the
question yet.  In addition to saying that, the identity server
provides a URL to which the user can be sent to provide the needed
information and let the server finish handling the original request.


== USING THIS LIBRARY ==

*********  Waiting on resolution of structure
"""

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




