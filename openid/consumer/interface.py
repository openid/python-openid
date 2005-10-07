"""
This module is intended to document the main interface with the OpenID
consumer libary.  The only part of the library which has to be used
and isn't documented in full here is the store required to create an
C{OpenIDConsumer instance}.  More on the abstract store type and
concrete implementations of it that are provided in the documentation
for the C{__init__} method of the C{OpenIDConsumer} class.


OVERVIEW
========

    The OpenID identity verification process most commonly uses the
    following steps, as visible to the user of this library:

    1. The user enters their OpenID into a field on the consumer's
       site, and hits some sort of log in button.

    2. The consumer site sends the browser a redirect, sending the
       browser to the identity server's site.

    3. The identity server's site sends the browser a redirect,
       sending the browser back to the consumer's site with the
       information necessary to confirm the user's identity.

    There are a lot of conditional extras in the process, but that is
    the basic flow of an OpenID login from the consumer's point of
    view.  The most important part of the flow to note is the
    consumer's site must handle two separate HTTP requests in order to
    perform the full identity check.


LIBRARY DESIGN
==============

    This consumer library is designed with that flow in mind.  Our
    goal is to make it as easy as possible to perform the above steps
    securely.

    Waiting on resolution of structure.


STORES AND DUMB MODE
====================

    OpenID is a protocol that works best when the consumer site is
    able to store some state.  This is the normal mode of operation
    for the protocol, and is sometimes referred to as smart mode.
    There is also a fallback mode, known as dumb mode, which is
    available when the consumer site is not able to store state.  This
    mode should be avoided when possible, as it leaves the
    implementation more vulnerable to replay attacks.

    The mode the library works in for normal operation* is determined
    by the store that it is given.  The store is an abstraction that
    handles the data that the consumer needs to manage between http
    requests in order to operate efficiently and securely.

    Several store implementation are provided, and the interface is
    fully documented so that custom stores can be used as well.  See
    the documentation for the C{OpenIDConsumer} class for more
    information on the interface for stores.  The concrete
    implementations that are provided allow the consumer site to store
    the necessary data in several different ways: in the filesystem,
    in a MySQL database, or in an SQLite database.

    There is an additional concrete store provided that puts the
    system in dumb mode.  This is not recommended, as it removes the
    library's ability to stop replay attacks reliably.  It still uses
    time-based checking to make replay attacks only possible within a
    small window, but they remain possible within that window.  This
    store should only be used if the consumer site has no way to store
    data between requests at all.

    *: There are fallback cases in the protocol, where even a consumer
    usually running in smart mode acts like it's in dumb mode for one
    request, but those cases are not the normal operation.
    Additionally, the fallback cases are much more secure than pure
    dumb mode, as they still are making use the consumer's ability to
    store state.


IMMEDIATE MODE
==============

    In the flow described above, there's a step which may occur if the
    user needs to confirm to the identity server that it's ok to
    authorize his or her identity.  The server may draw pages asking
    for information from the user before it redirects the browser back
    to the consumer's site.  This is generally transparent to the
    consumer site, so it is typically ignored as an implementation
    detail.

    There can be times, however, where the consumer site wants to get
    a response immediately.  When this is the case, the consumer can
    put the library in immediate mode.  In immediate mode, there is an
    extra response possible from the server, which is essentially the
    server reporting that it doesn't have enough information to answer
    the question yet.  In addition to saying that, the identity server
    provides a URL to which the user can be sent to provide the needed
    information and let the server finish handling the original
    request.


USING THIS LIBRARY
==================

    Waiting on resolution of structure.
"""

class OpenIDConsumer(object):
    """
    """

    def __init__(self, store, immediate=False, fetcher=None):
        """
        This method initializes a new OpenIDConsumer instance.  Users
        of this OpenID consumer library need to create on
        OpenIDConsumer instance to act as their gateway to the
        library.

        OpenIDConsumer instances store no per-request state, so they
        may be used repeatedly in cases where they can remain in
        memory between requests to the server.


        @param store: This must be an object that implements the
            interface in C{openid.consumer.stores.OpenIDStore}.
            Several concrete implementations are provided, to cover
            most common use cases.  For stores backed by MySQL or
            SQLite, see the openid.consumer.sqlstore package.  For a
            filesystem-backed store, see the
            C{openid.consumer.filestore} package.

            As a last resort, if it isn't possible for the server to
            store state at all, an instance of
            C{openid.consumer.stores.DumbStore} can be used.  This
            should be an absolute last resort, though, as it makes the
            consumer vulnerable to replay attacks over the lifespan of
            the tokens the library creates.  See XXX for more
            information on controlling the lifespan of tokens.

        @type store: C{openid.consumer.stores.OpenIDStore}


        @param immediate: This is an optional boolean value.  It
            controls whether the library uses immediate mode, as
            explained in the module description.  The default value is
            False, which disables immediate mode.

        @type immediate: C{bool}

        @param fetcher: This is an optional instance of
            C{openid.consumer.fetchers.OpenIDHTTPFetcher}.  If
            present, the provided fetcher is used by the library to
            fetch user's identity pages and make direct requests to
            the identity server.  If it's not present, a default
            fetcher is used.  The default fetcher uses curl if the
            pycurl bindings are available, and uses urllib if not.

        @type fetcher: C{openid.consumer.fetchers.OpenIDHTTPFetcher}


        @return: As an initializer, this method has no return value.
        """
        if fetcher is None:
            from openid.consumer.fetchers import getHTTPFetcher
            fetcher = getHTTPFetcher()

        from openid.consumer.impl import OpenIDConsumerImpl
        self.impl = OpenIDConsumerImpl(store, immediate, fetcher)

    def constructRedirect(self, proxy):
        """
        This method is called by the user of the consumer library to
        construct the redirect URL used in step 2 of the flow
        described above.  The user who is authenticating themselves
        via OpenID should be sent a redirect to the generated URL.

        First, the user's claimed identity page is fetched, to
        determine their identity server.  Second, unless the library
        is using a dumb store, it checks to see if it has an
        association with that identity server, and creates and stores
        one if it does not.

        It then generates a signed token for this authentication
        transaction, which contains a timestamp, a nonce, and the
        information needed to finish the transaction.  This token
        is passed in to the C{XXX} method, .

        Finally, if all those steps completed successfully, the
        generated URL is returned.  Otherwise C{None} is returned.

        Calling this method can result in the following other methods
        being called.
        * XXX list of methods called indirectly

        @param proxy: This is an object implementing the
            C{OpenIDProxy} interface which can be used to help with
            app-specific parts of constructing the redirect URL.

        @type proxy: This is an instance of an object implementing the
            C{OpenIDProxy} interface.

        @return: This method returns a string containing the URL to
            redirect to when such a URL is successfully constructed.

            It returns C{None} when no such URL can be constructed.

        @raise Exception: This method does not handle any exceptions
            raised by the fetcher, the store, or any of the proxy's
            methods that it calls.

            It raises no exceptions itself.
        """
        return self.impl.constructRedirect(proxy)

    def processServerResponse(self, proxy):
        """
        returns the value returned by whichever of the proxy's
        handler methods was invoked

        @param proxy: This is an object implementing the
            C{OpenIDProxy} interface which can be used to help with
            app-specific parts of constructing the redirect URL.

        @type proxy: This is an instance of an object implementing the
            C{OpenIDProxy} interface.

        @return: During the course of the execution of this method, it
            calls exactly one of the callback methods in the C{XXX}
            object passed in to it.  The value returned by that
            callback method is returned by this method.
        
        @raise Exception: This method does not handle any exceptions
            raised by the fetcher, the store, or any of the proxy's
            methods that it calls.

            It raises no exceptions itself.
        """
        return self.impl.processServerResponse(proxy)


class OpenIDProxy(object):
    """This is a proxy the openid library will use to get information
    from its environment."""

    def getUserInput(self):
        """
        This method is called by the OpenID consumer library 

        @return: This method returns the value the user gave as their
            identity url.  If there is no such value available, it
            returns C{None}.
        """
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

    def log(self, message):
        pass

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

    def setupNeeded(self, user_setup_url):
        """Called when the consumer is in immediate mode and the
        server returns a user_setup_url.  Any value returned by this
        method is returned by the call to processServerRequest that
        led to this method being called.  (This method is not called
        from checkAuth.)"""
        raise NotImplementedError




