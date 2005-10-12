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
       site, and hits a log in button.

    2. The consumer site checks that the entered URL describes an
       OpenID page by fetching it and looking for appropriate
       link tags in the head section.

    3. The consumer site sends the browser a redirect to the identity
       server.  This is the authentication request as described in the
       OpenID specification.

    4. The identity server's site sends the browser a redirect back to
       the consumer site.  This redirect contains the server's
       response to the authentication request.

    The most important part of the flow to note is the consumer's site
    must handle two separate HTTP requests in order to perform the
    full identity check.


LIBRARY DESIGN
==============

    This consumer library is designed with that flow in mind.  The
    goal is to make it as easy as possible to perform the above steps
    securely.

    At a high level, there are two important parts in the consumer
    library.  The first important part is this module, which contains
    the interface to actually use this library.  The second is the
    C{openid.consumer.stores} module, which describes the interface to
    use if you need to create a custom method for storing the state
    this library needs to maintain between requests.

    In general, the scond part is less important for users of the
    library to know about, as several implementations are provided
    which cover a wide variety of situations in which consumers may
    use the library.

    This module contains a class, C{OpenIDConsumer}, with methods
    corresponding to the actions necessary in each of steps 2, 3, and
    4 listed in the overview.  Use of this library should be as easy
    as creating an C{OpenIDConsumer} instance and calling the methods
    appropriate for the action the site wants to take.


STORES AND DUMB MODE
====================

    OpenID is a protocol that works best when the consumer site is
    able to store some state.  This is the normal mode of operation
    for the protocol, and is sometimes referred to as smart mode.
    There is also a fallback mode, known as dumb mode, which is
    available when the consumer site is not able to store state.  This
    mode should be avoided when possible, as it leaves the
    implementation more vulnerable to replay attacks.

    The mode the library works in for normal operation is determined
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

    Integrating this library into an application is usually a
    relatively straightforward process.  The process should basically
    follow this plan:

    Add an OpenID login field somewhere on your site.  When an OpenID
    is entered in that field and the form is submitted, it should make
    a request to the your site which includes that OpenID URL.

    When your site receives that request, it should create an
    C{openid.consumer.interface.OpenIDConsumer} instance, and call
    C{beginAuth} on it.  If C{beginAuth} completes successfully, it
    will return an C{openid.consumer.impl.OpenIDAuthRequest}.
    Otherwise it will provide some useful information for giving your
    user an error message.

    Now that you have the C{OpenIDAuthRequest} object, you need to
    preserve the value in its C{token} field for lookup on the user's
    next request from your site.  There are several approaches for
    doing this which will work.  If your environment has any kind of
    session-tracking system, storing the token in the session is a
    good approach.  If it doesn't you can store the token in either a
    cookie or in the return_to url provided in the next step.

    The next step is to call the C{constructRedirect} method on the
    C{OpenIDConsumer} object.  Pass it the C{OpenIDAuthRequest} object
    returned by the previous call to C{beginAuth} along with the
    return_to and trust_root URLs.  The return_to URL is the URL that
    the OpenID server will send the user back to after attempting to
    verify his or her identity.  The trust_root is the URL (or URL
    pattern) that identifies your web site to the user when he or she
    is authorizing it.

    Next, send the user a redirect to the URL generated by
    C{constructRedirect}.

    That's the first half of the process.  The second half of the
    process depends on the user's ID server sending the user a
    redirect back to your site to complete their login.

    When that happens, the user will contact your site at the URL
    given as the return_to URL to the C{constructRedirect} call made
    above.  The request will have several query parameters added to
    the URL by the identity server as the information necessary to
    finish the request.

    When handling this request, the first thing to do is check the
    openid.return_to parameter.  If it doesn't match the URL that the
    request was actually sent to (the URL the request was actually
    sent to will contain the openid parameters in addition to any in
    the return_to URL, but they should match other than that), that is
    clearly suspicious, and the request shouldn't be allowed to
    proceed.

    Otherwise, the next step is to extract the token value set in the
    first half of the OpenID login.  Create a C{OpenIDConsumer}
    object, and call its C{completeAuth} method with that token and a
    dictionary of all the query arguments.  This call will return a
    status code and some additional information describing the result
    of interpreting the server's response.  See the documentation for
    C{completeAuth} below for a full explanation of the possible
    responses.

    At this point, you have an identity URL that you know belongs to
    the user who made that request.  Some sites will use that URL
    directly as the user name.  Other sites will want to map that URL
    to a username in the site's traditional namespace.  At this point,
    you can take whichever action makes the most sense.
"""

__all__ = ['SUCCESS', 'FAILURE', 'SETUP_NEEDED', 'HTTP_FAILURE', 'PARSE_ERROR',
           'OpenIDAuthRequest', 'OpenIDConsumer']

from openid.consumer.impl import \
     SUCCESS, FAILURE, SETUP_NEEDED, PARSE_ERROR, HTTP_FAILURE, \
     OpenIDAuthRequest

class OpenIDConsumer(object):
    """
    
    
    @ivar impl: blah
    """

    def __init__(self, store, fetcher=None, immediate=False):
        """
        This method initializes a new C{OpenIDConsumer} instance.
        Users of the OpenID consumer library need to create an
        C{OpenIDConsumer} instance to access the library.

        OpenIDConsumer instances store no per-request state, so they
        may be used repeatedly when it is desired.


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
            the tokens the library creates.  See L{impl} for
            information on controlling the lifespan of those tokens.

        @type store: C{openid.consumer.stores.OpenIDStore}


        @param fetcher: This is an optional instance of
            C{openid.consumer.fetchers.OpenIDHTTPFetcher}.  If
            present, the provided fetcher is used by the library to
            fetch user's identity pages and make direct requests to
            the identity server.  If it's not present, a default
            fetcher is used.  The default fetcher uses curl if the
            pycurl bindings are available, and uses urllib if not.

        @type fetcher: C{openid.consumer.fetchers.OpenIDHTTPFetcher}


        @param immediate: This is an optional boolean value.  It
            controls whether the library uses immediate mode, as
            explained in the module description.  The default value is
            False, which disables immediate mode.

        @type immediate: C{bool}
        """
        if fetcher is None:
            from openid.consumer.fetchers import getHTTPFetcher
            fetcher = getHTTPFetcher()

        from openid.consumer.impl import OpenIDConsumerImpl
        self.impl = OpenIDConsumerImpl(store, immediate, fetcher)

    def beginAuth(self, user_url):
        """
        This method is called to start the OpenID login process.

        First, the user's claimed identity page is fetched, to
        determine their identity server.  If the page cannot be
        fetched or if the page does not have the necessary link tags
        in it, this method returns C{None}.

        Second, unless the store provided is a dumb store, it checks
        to see if it has an association with that identity server, and
        creates and stores one if not.

        Third, it then generates a signed token for this
        authentication transaction, which contains a timestamp, a
        nonce, and the information needed in step 5 in the overview
        above.  The token is used by the library to make handling the
        various pieces of information needed in step 5 easy and
        secure.

        The token generated must be preserved until step 5, which is
        after the redirect to the OpenID server takes place.  This
        means that the token must be preserved across http requests.
        There are three basic approaches that might be used for
        storing the token.  First, the token could be put in the
        return_to URL passed into the C{constructRedirect} method.
        Second, the token could be stored in a cookie.  Third, in an
        environment that supports user sessions, the session is a good
        spot to store the token.

        @param user_url: This is the url the user entered as their
            OpenID.  This call takes care of normalizing it and
            resolving any redirects the server might issue.  If the
            value passed in is a C{unicode} object, this performs a
            minimal translation on it to make it a valid URL.

        @type user_url: C{basestring}, the parent class of C{str} and
            C{unicode}.


        @return: If the URL given could not be fetched, or if the page
            fetched didn't contain the necessary tags, this method
            returns C{None}.

            Otherwise, this method returns an C{OpenIDAuthRequest}
            object.  C{OpenIDAuthRequest} objects have a C{token}
            field, which contains the generated token.  The other
            contents of the object are implementation details, used in
            the subsequent call to C{constructRedirect}.


        @raise Exception: This method does not handle any exceptions
            raised by the store or fetcher it is using.

            It raises no exceptions itself.
        """
        return self.impl.beginAuth(user_url)

    def constructRedirect(self, auth_request, return_to, trust_root):
        """
        This method is called to construct the redirect URL used in
        step 3 of the flow described in the overview.  The generated
        redirect should be sent to the browser which initiated the
        authorization request.

        @param auth_request: This must be an C{OpenIDAuthRequest}
            instance which was returned from a previous call to
            C{L{beginAuth}}.  It contains information found during the
            beginAuth call which is needed to build the redirect URL.

        @type auth_request: C{OpenIDAuthRequest}


        @param return_to: This is the URL that will be included in the
            generated redirect as the URL the OpenID server will send
            its response to.  The URL passed in must handle OpenID
            authentication responses.

        @type return_to: C{str}


        @param trust_root: This is a URL that will be sent to the
            server to identify this site.  U{The OpenID
            spec<http://www.openid.net/specs.bml#mode-checkid_immediate>}
            has more information on what the trust_root value is for
            and what its form can be.  While the trust root is
            officially optional in the OpenID specification, this
            implementation requires that it be set.  Nothing is
            actually gained by leaving out the trust root, as you can
            get identical behavior by specifying the return_to URL as
            the trust root.

        @type trust_root: C{str}


        @return: This method returns a string containing the URL to
            redirect to when such a URL is successfully constructed.

        @rtype: C{str}


        @raise Exception: This method does not handle any exceptions
            raised by the store it is using.

            It raises no exceptions itself.
        """
        return self.impl.constructRedirect(auth_request, return_to, trust_root)

    def completeAuth(self, token, query):
        """
        This method is called in step 5 of the flow listed in the
        overview.  It is responsible for interpreting the server's
        response and returning that information in a useful form.

        The return value is a pair, consisting of a status and
        additional information.  The status values are strings, but
        should be referred to by their symbolic values:
        C{openid.consumer.interface.SUCCESS},
        C{openid.consumer.interface.FAILURE}, and
        C{openid.consumer.interface.SETUP_NEEDED}.

        When C{SUCCESS} is returned, the additional information
        returned is either C{None} or a C{str}.  If it is C{None}, it
        means the user cancelled the login, and no further information
        can be determined.  If the additional information is a C{str},
        it is the identity that has been verified as belonging to the
        user making this request.

        When C{FAILURE} is returned, the additional information is
        either C{None} or a C{str}.  In either case, this code means
        that the identity verification failed.  If it can be
        determined, the identity that failed to verify is returned.
        Otherwise C{None} is returned.

        @param token: This is the token for this authentication
            transaction, generated by the call to C{beginAuth}.  

        @type token: C{str}


        @param query: This is a dictionary-like object containing the
            query parameters the OpenID server included in its
            redirect back to the return_to URL.  The keys and values
            should both be url-unescaped.

        @type query: a C{dict}-like object


        @return: Returns the status of the response and any additional
            information, as described above.

        @rtype: A pair, consisting of either two C{str} objects, or a
            C{str} and C{None}.


        @Raise Exception: This method does not handle any exceptions
            raised by the fetcher or the store.

            It raises no exceptions itself.
        """
        return self.impl.processServerResponse(token, query)
