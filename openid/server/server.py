"""
This module documents the interface to the OpenID server library.  The
only part of the library which has to be used and isn't documented
here is the store for associations.  See the C{L{openid.stores}}
package for more information on stores.


OVERVIEW
========

    From an identity server's perspective, there are two different
    classes of requests that it has to handle on its OpenID URL.

    The first class are the requests made to it directly by identity
    consumers.  These are HTTP POST requests made to the published
    OpenID server URL.  There are two types of POST requests, requests
    to create an association, and requests to verify identity requests
    signed with a secret that is entirely private to the server.

    The second class are the requests made through redirects.  These
    are HTTP GET requests coming from the user's web browser.  For
    these requests, the identity server must perform several steps.
    It has to determine the identity of the user performing the GET
    request, determine if they are allowed to use the identity
    requested, and then take the correct action depending on the exact
    form of the request and the answers to those questions.


LIBRARY DESIGN
==============

    This server library is designed to make dealing with those two
    classes of requests as straightforward as possible.

    At a high level, there are two parts of the library which are
    important.  First, there is the C{L{OpenIDServer}} class in this
    module.  Second, there is the C{L{openid.stores}} package, which
    contains information on the necessary persistent state mechanisms,
    and several implementations.

STORES
======

    The OpenID server needs to maintain state between requests in
    order to function.  Its mechanism for doing this is called a
    store.  The store interface is defined in
    C{L{openid.stores.interface.OpenIDStore}}.  Additionally, several
    concrete store implementations are provided, so that most sites
    won't need to implement a custom store.  For a store backed by
    flat files on disk, see
    C{L{openid.stores.filestore.FileOpenIDStore}}.  For stores based
    on MySQL or SQLite, see the C{L{openid.stores.sqlstore}} module.
    For a store using Danga's memcached caching system, see the
    C{L{openid.stores.memcachestore}} module.


USING THIS LIBRARY
==================

    This library is designed to be easy to use for handling OpenID
    requests.  There is, however, additional work a site has to do as
    an OpenID server which is beyond the scope of this library.  That
    work consists primarily of creating a couple additional pages for
    handling verifying that the user wants to confirm their identity
    to the consumer site.  Implementing an OpenID server using this
    library should follow this basic plan:

    First, you need to choose a URL to be your OpenID server URL.
    This URL needs to be able to handle both GET and POST requests,
    and distinguish between them.

    Next, you need to have some system for mapping identity URLs to
    users of your system.  The easiest method to do this is to insert
    an appropriate <link> tag into your users' public pages.  See the
    U{OpenID spec<http://openid.net/specs.bml#linkrel>} for the
    precise format the <link> tag needs to follow.  Then, each user's
    public page URL is that user's identity URL.  There are many
    alternative approaches, most of which should be fairly obvious.

    The next step is to write the code to handle requests to the
    server URL.  This can be divided into two tasks, one for POSTs and
    one for GETs.  Handling POST requests is more straightforward, so
    it's easier to tackle first.

    When a POST request comes in, get an C{L{OpenIDServer}} instance
    with an appropriate store, and call its
    C{L{processPost<OpenIDServer.processPost}} method with the parsed
    POST parameters.  The return value is a pair, consisting of a
    status value and a response body.  If the status value is
    C{L{openid.server.server.OK}}, send the body back with an HTTP
    status code of 200.  If the status value is
    C{L{openid.server.server.ERROR}}, send the body back with an HTTP
    status code of 400.  Both of those response codes are prescribed
    by the U{OpenID spec<http://openid.net/specs.bml>}.  The content
    type for the responses is explicitly not defined, but text/plain
    is suggested.

    When a GET request comes in, several steps need to take place:

        1. Get an C{L{OpenIDServer}} instance with an appropriate
           store.

        2. Call its
           C{L{getAuthenticationData<OpenIDServer.getAuthentication>}}
           method with the arguments provided for this GET request.
           The return value is a pair (identity URL, trust root) that this
           request is asking to authorize.

        3. Determine if the user making this request is authorized to
           identify himself or herself as the owner of the identity
           URL in question.  If so, determine whether the user has
           authorized telling the consumer identified by trust root
           that he owns the identity URL.  Both of those are very
           application-specific bits of logic, and depend heavily on
           design choices you've made as an identity server.  The end
           result of these checks should be a boolean value indicating
           whether the request is correctly authorized or not.

        4. Call the C{L{OpenIDServer}} instance's
           C{L{getAuthenticationResponse<OpenIDServer.getAuthenticationResponse>}}
           method.  The first argument is the value calculated in the
           previous state, a boolean value indicating whether the
           request is properly authorized.  The second argument is the
           arguments provided for this GET request.

        5. The return value from that call is a pair, (status, info).
           Depending on the status value returned, there are several
           different actions you might take.  See the documentation
           for the
           C{L{getAuthenticationResponse<OpenIDServer.getAuthenticationResponse>}}
           method for a full list of possible results, what they mean,
           and what the appropriate action for each is.

    Processing all the results from that last step is fairly simple,
    but it involves adding a few additional pages to your site.  There
    needs to be a page about OpenID that users who visit the server
    URL directly can be shown, so they have some idea what the URL is
    for.  It doesn't need to be a fancy page, but there should be one.

    Usually the C{L{DO_AUTH}} case will also require at least one
    page, and perhaps more.  These pages could be arranged many
    different ways, depending on your site's policies on interacting
    with its users.

    Overall, implementing an OpenID server is a fairly straightforward
    process, but it requires significant application-specific work
    above what this library provides.


@var OK: This is the status code returned by
    C{L{processPost<OpenIDServer.processPost>}} to indicate that the
    response should have a 200 HTTP code.


@var ERROR: This status code is returned in two different
    places. C{L{processPost<OpenIDServer.processPost>}} returns this
    code to inidcate that the response should have a 400 HTTP code.
    C{L{getAuthenticationResponse<OpenIDServer.getAuthenticationResponse>}}
    returns this code to indicate that something has gone wrong, and
    the best you can do is tell the user.


@var REDIRECT: This status code is returned by
    C{L{getAuthenticationResponse<OpenIDServer.getAuthenticationResponse>}}
    when user should be sent a redirect.


@var DO_AUTH: This status code is returned by
    C{L{getAuthenticationResponse<OpenIDServer.getAuthenticationResponse>}}
    when the library has determined that it's up to the application
    and user to fix the reason the library isn't authorized to return
    a successful authentication response.


@var DO_ABOUT: This status code is returned by
    C{L{getAuthenticationResponse<OpenIDServer.getAuthenticationResponse>}}
    when there were no OpenID arguments provided at all.  This is
    typically the case when somebody notices the <link> tag in a web
    page, wonders what it's there for, and decides to type it in.  The
    standard behavior in this case is to show a page with a small
    explanation of OpenID.


@sort: OK, ERROR, REDIRECT, DO_AUTH, DO_ABOUT, OpenIDServer
"""

REDIRECT = 'redirect'
DO_AUTH  = 'do_auth'
DO_ABOUT = 'do_about'

OK       = 'ok'
ERROR    = 'error'

class OpenIDServer(object):
    """
    This class is the interface to the OpenID server logic.  Instances
    contain no per-request state, so a single instance can be reused
    (or even used concurrently by multiple threads) as needed.

    @sort: __init__, getAuthenticationData, getAuthenticationResponse,
        processPost
    """

    def __init__(self, server_url, store):
        """
        This method initializes a new C{L{OpenIDServer}} instance to
        access the library.


        @param server_url: This is the server's OpenID URL.  It is
            used whenever the server needs to generate a URL that will
            cause another OpenID request to be made, which can happen
            in authentication requests.

        @type server_url: C{str}


        @param store: This is the instance of an object implementing
            C{L{openid.stores.interface.OpenIDStore}} interface which
            the library will use for persistent storage.  See the
            C{L{OpenIDStore<openid.stores.interface.OpenIDStore>}
            documentation for more information on stores and various
            implementations.  Note that the store used for the server
            must not be a dumb-style store.  It's not possible to be a
            functional OpenID server without persistent storage.

        @type store: An object implementing the
            C{L{openid.stores.interface.OpenIDStore}} interface
        """
        from openid.server.impl import OpenIDServerImpl
        self.impl = OpenIDServerImpl(server_url, store)

    def getAuthenticationData(self, args):
        """
        This method extracts the requested identity URL and trust root
        from the parameters supplied to the GET request to the OpenID
        server URL.


        @param args: This should be a C{dict}-like object that
            contains the parsed, unescaped query arguments that were
            sent with the OpenID request being handled.  The keys and
            values in the dictionary should both be either C{str} or
            C{unicode} objects.

        @type args: a C{dict}-like object


        @return: This returns a pair, consisting of the identity url
            and trust root in the request.  If either value is not
            present in the request, C{None} is returned for that value
            in the pair.  The values returned otherwise are either
            C{str} or C{unicode} instances, depending on what the
            values in C{args} are.

        @rtype: (C{str} or C{unicode} or C{NoneType}, C{str} or
            C{unicode} or C{NoneType})
        """
        return self.impl.getAuthenticationData(args)
    
    def getAuthenticationResponse(self, authorized, args):
        """
        This method determines the correct response to make to an
        authentication request.

        This method always returns a pair.  The first value of the
        pair indicates what action the server should take to respond
        to this request.  The second value is additional information
        to use when taking that action.

        1. Sending a redirect to the user's browser: The second value
           is the URL to redirect the the browser to.

        2. Asking the user for additional information to complete the
           authentication procedure: The second value is another pair.
           The pair contains two URLs.  The first is a URL to retry
           this authentication request.  The second is a URL to
           redirect the browser to if the user decides to cancel.

           The general plan this supports is to present the user a
           page asking for additional information, and present the
           user with 'ok' and 'cancel' buttons.  When the user hits
           the 'ok' button, process the additional information they
           gave, and then redirect them to the retry URL.  If they hit
           the 'cancel' button, send them to the cancel URL.  This is
           a convenient pattern for dealing with OpenID requests that
           need additional information for the user.

        3. Showing a page with a short description of OpenID: This is
           for the case when the user visits the OpenID server URL
           directly, without making an OpenID request.  In these
           cases, the best behavior is to show a page with a short
           description of OpenID, as the user typically found an
           OpenID server URL in a web page and is curious what it is
           for.  When this is the case, the second value of the return
           pair is C{None}.

        4. Showing an error page: If the request contained an error
           that couldn't be recovered from, the second value will be
           an error message which may help the user determine what
           went wrong.  Showing them an error page including the error
           message is probably the best approach.

        The exact value of the first parameter to select each of those
        options is covered in the return value documentation.


        @param authorized: This is a value which indicates whether the
            server is authorized to tell the consumer that the user
            owns the identity URL in question.  For this to be true,
            the server must check that the user making this request is
            the owner of the identity URL in question, and that the
            user has given the consumer permission to learn his or her
            identity.  The C{L{getAuthenticationData}} method is
            provided to make extracting the identity url and trust
            root easy, to aid in the calculation of this value.

        @type authorized: Anything which will be correctly evaluated
            by C{if authorized:}.  Typically, this is a C{bool} value,
            but that type wasn't available in some older versions of
            Python.  For those versions, this will probably be an
            C{int}.


        @param args: This should be a C{dict}-like object that
            contains the parsed, unescaped query arguments that were
            sent with the OpenID request being handled.  The keys and
            values in the dictionary should both be either C{str} or
            C{unicode} objects.

        @type args: a C{dict}-like object


        @return: A pair indicating what action to take.  The first
            value is a C{str} object, and the second varies as
            described above.  The first value will be one of
            C{L{REDIRECT}}, C{L{DO_AUTH}}, C{L{DO_ABOUT}}, or
            C{L{ERROR}}.  The action the server should take for each
            case is described above.

        @rtype: (C{str}, C{str} or C{(str, str)} or C{NoneType})
        """
        return self.impl.getAuthenticationResponse(authorized, args)

    def processPost(self, args):
        """
        This method processes POST requests to the OpenID server URL.
        See the L{module documentation<openid.server.server>} for
        more notes on when to use this method.


        @param args: This should be a C{dict}-like object that
            contains the parsed, unescaped post arguments that were
            sent with the OpenID request being handled.  The keys and
            values in the dictionary should both be either C{str} or
            C{unicode} objects.

        @type args: a C{dict}-like object


        @return: This method returns a pair, consisting of a status
            value and the content to return from the request.  The
            status value is either C{L{OK}} or C{L{ERROR}}.  When it's
            C{L{OK}}, the response to this request should have HTTP
            status code 200.  If the status is C{L{ERROR}}, the
            response should have HTTP status code 400.  In either
            case, the body of the response should be the second value
            in the pair.

        @rtype: (C{str}, C{str})
        """
        return self.impl.processPost(args)

