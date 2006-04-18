"""
This module documents the main interface with the OpenID consumer
libary.  The only part of the library which has to be used and isn't
documented in full here is the store required to create an
C{L{OpenIDConsumer}} instance.  More on the abstract store type and
concrete implementations of it that are provided in the documentation
for the C{L{__init__<OpenIDConsumer.__init__>}} method of the
C{L{OpenIDConsumer}} class.


OVERVIEW
========

    The OpenID identity verification process most commonly uses the
    following steps, as visible to the user of this library:

        1. The user enters their OpenID into a field on the consumer's
           site, and hits a login button.

        2. The consumer site checks that the entered URL describes an
           OpenID page by fetching it and looking for appropriate link
           tags in the head section.

        3. The consumer site sends the browser a redirect to the
           identity server.  This is the authentication request as
           described in the OpenID specification.

        4. The identity server's site sends the browser a redirect
           back to the consumer site.  This redirect contains the
           server's response to the authentication request.

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
    C{L{openid.store.interface}} module, which describes the
    interface to use if you need to create a custom method for storing
    the state this library needs to maintain between requests.

    In general, the second part is less important for users of the
    library to know about, as several implementations are provided
    which cover a wide variety of situations in which consumers may
    use the library.

    This module contains a class, C{L{OpenIDConsumer}}, with methods
    corresponding to the actions necessary in each of steps 2, 3, and
    4 described in the overview.  Use of this library should be as easy
    as creating an C{L{OpenIDConsumer}} instance and calling the methods
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
    the documentation for the C{L{OpenIDConsumer}} class for more
    information on the interface for stores.  The concrete
    implementations that are provided allow the consumer site to store
    the necessary data in several different ways: in the filesystem,
    in a MySQL database, or in an SQLite database.

    There is an additional concrete store provided that puts the
    system in dumb mode.  This is not recommended, as it removes the
    library's ability to stop replay attacks reliably.  It still uses
    time-based checking to make replay attacks only possible within a
    small window, but they remain possible within that window.  This
    store should only be used if the consumer site has no way to
    retain data between requests at all.


IMMEDIATE MODE
==============

    In the flow described above, the user may need to confirm to the
    identity server that it's ok to authorize his or her identity.
    The server may draw pages asking for information from the user
    before it redirects the browser back to the consumer's site.  This
    is generally transparent to the consumer site, so it is typically
    ignored as an implementation detail.

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
    C{L{openid.consumer.consumer.OpenIDConsumer}} instance, and call
    C{L{beginAuth<OpenIDConsumer.beginAuth>}} on it.  If
    C{L{beginAuth<OpenIDConsumer.beginAuth>}} completes successfully,
    it will return an C{L{OpenIDAuthRequest}}.  Otherwise it will
    provide some useful information for giving the user an error
    message.

    Now that you have the C{L{OpenIDAuthRequest}} object, you need to
    preserve the value in its C{L{token<OpenIDAuthRequest.token>}}
    field for lookup on the user's next request from your site.  There
    are several approaches for doing this which will work.  If your
    environment has any kind of session-tracking system, storing the
    token in the session is a good approach.  If it doesn't you can
    store the token in either a cookie or in the return_to url
    provided in the next step.

    The next step is to call the
    C{L{constructRedirect<OpenIDConsumer.constructRedirect>}} method
    on the C{L{OpenIDConsumer}} object.  Pass it the
    C{L{OpenIDAuthRequest}} object returned by the previous call to
    C{L{beginAuth<OpenIDConsumer.beginAuth>}} along with the return_to
    and trust_root URLs.  The return_to URL is the URL that the OpenID
    server will send the user back to after attempting to verify his
    or her identity.  The trust_root is the URL (or URL pattern) that
    identifies your web site to the user when he or she is authorizing
    it.

    Next, send the user a redirect to the URL generated by
    C{L{constructRedirect<OpenIDConsumer.constructRedirect>}}.

    That's the first half of the process.  The second half of the
    process is done after the user's ID server sends the user a
    redirect back to your site to complete their login.

    When that happens, the user will contact your site at the URL
    given as the return_to URL to the
    C{L{constructRedirect<OpenIDConsumer.constructRedirect>}} call
    made above.  The request will have several query parameters added
    to the URL by the identity server as the information necessary to
    finish the request.

    When handling this request, the first thing to do is check the
    C{openid.return_to} parameter.  If it doesn't match the URL that
    the request was actually sent to (the URL the request was actually
    sent to will contain the openid parameters in addition to any in
    the return_to URL, but they should be identical other than that),
    that is clearly suspicious, and the request shouldn't be allowed
    to proceed.

    Otherwise, the next step is to extract the token value set in the
    first half of the OpenID login.  Create a C{L{OpenIDConsumer}}
    object, and call its
    C{L{completeAuth<OpenIDConsumer.completeAuth>}} method with that
    token and a dictionary of all the query arguments.  This call will
    return a status code and some additional information describing
    the the server's response.  See the documentation for
    C{L{completeAuth<OpenIDConsumer.completeAuth>}} for a full
    explanation of the possible responses.

    At this point, you have an identity URL that you know belongs to
    the user who made that request.  Some sites will use that URL
    directly as the user name.  Other sites will want to map that URL
    to a username in the site's traditional namespace.  At this point,
    you can take whichever action makes the most sense.


@var SUCCESS: This is the status code returned when either the of the
    C{L{beginAuth<openid.consumer.consumer.OpenIDConsumer.beginAuth>}}
    or
    C{L{completeAuth<openid.consumer.consumer.OpenIDConsumer.completeAuth>}}
    methods return successfully.

@var HTTP_FAILURE: This is the status code
    C{L{beginAuth<openid.consumer.consumer.OpenIDConsumer.beginAuth>}}
    returns when it is unable to fetch the OpenID URL the user
    entered.

@var PARSE_ERROR: This is the status code
    C{L{beginAuth<openid.consumer.consumer.OpenIDConsumer.beginAuth>}}
    returns when the page fetched from the entered OpenID URL doesn't
    contain the necessary link tags to function as an identity page.

@var FAILURE: This is the status code
    C{L{completeAuth<openid.consumer.consumer.OpenIDConsumer.completeAuth>}}
    returns when the value it received indicated an invalid login.

@var SETUP_NEEDED: This is the status code
    C{L{completeAuth<openid.consumer.consumer.OpenIDConsumer.completeAuth>}}
    returns when the C{L{OpenIDConsumer}} instance is in immediate
    mode, and the identity server sends back a URL to send the user to
    to complete his or her login.

@sort: OpenIDConsumer, OpenIDAuthRequest, SUCCESS, HTTP_FAILURE,
    PARSE_ERROR, FAILURE, SETUP_NEEDED
"""

import string
import time
import urllib
from urlparse import urlparse

from urljr import fetchers

from openid import cryptutil
from openid import kvform
from openid import oidutil
from openid.association import Association
from openid.dh import DiffieHellman

__all__ = ['SUCCESS', 'FAILURE', 'SETUP_NEEDED', 'HTTP_FAILURE', 'PARSE_ERROR',
           'OpenIDAuthRequest', 'OpenIDConsumer']

SUCCESS = 'success'
FAILURE = 'failure'
SETUP_NEEDED = 'setup needed'

HTTP_FAILURE = 'http failure'
PARSE_ERROR = 'parse error'


class OpenIDConsumer(object):
    """
    This class is the interface to the OpenID consumer logic.
    Instances of it maintain no per-request state, so they can be
    reused (or even used by multiple threads concurrently) as needed.


    @cvar TOKEN_LIFETIME: This is the number of seconds the tokens
        generated by this library will be valid for.  If you want to
        change the lifetime of a token, set this value to the desired
        lifespan, in seconds.

    @type TOKEN_LIFETIME: C{int}


    @cvar NONCE_LEN: This is the number of characters in the generated
        nonce for each transaction.

    @type NONCE_LEN: C{int}


    @cvar NONCE_CHRS: This is the characters that the nonces are made from.

    @type NONCE_CHRS: C{str}


    @sort: TOKEN_LIFETIME, NONCE_LEN, NONCE_CHRS, __init__, beginAuth,
        constructRedirect, completeAuth
    """

    TOKEN_LIFETIME = 60 * 5 # five minutes
    NONCE_LEN = 8
    NONCE_CHRS = string.letters + string.digits

    sessionKeyPrefix = "_openid_consumer_"

    _server_list = 'servers'
    _visited_list = 'visited'
    _last_uri = 'last_uri'
    _token = 'last_token'

    def __init__(self, trust_root, store, session):
        """
        This method initializes a new C{L{OpenIDConsumer}} instance to
        access the library.


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


        @param store: This must be an object that implements the
            interface in C{L{openid.store.interface.OpenIDStore}}.
            Several concrete implementations are provided, to cover
            most common use cases.  For stores backed by MySQL or
            SQLite, see the C{L{openid.store.sqlstore.SQLStore}}
            class and its sublcasses.  For a filesystem-backed store,
            see the C{L{openid.store.filestore}} module.

            As a last resort, if it isn't possible for the server to
            store state at all, an instance of
            C{L{openid.store.dumbstore.DumbStore}} can be used.  This
            should be an absolute last resort, though, as it makes the
            consumer vulnerable to replay attacks over the lifespan of
            the tokens the library creates.

        @type store: C{L{openid.store.interface.OpenIDStore}}


        @param session: FIXME - to be documented
        """
        self.trust_root = trust_root
        self.store = store
        self.session = session

    def beginAuth(self, service_endpoint, return_to, immediate=False):
        """
        XXX: docs need to be updated

        This method is called to start the OpenID login process.

        First, the user's claimed identity page is fetched, to
        determine their identity server.  If the page cannot be
        fetched or if the page does not have the necessary link tags
        in it, this method returns one of C{L{HTTP_FAILURE}} or
        C{L{PARSE_ERROR}}, depending on where the process failed.

        Second, unless the store provided is a dumb store, it checks
        to see if it has an association with that identity server, and
        creates and stores one if not.

        Third, it generates a signed token for this authentication
        transaction, which contains a timestamp, a nonce, and the
        information needed in L{step 4<openid.consumer.consumer>} in
        the module overview.  The token is used by the library to make
        handling the various pieces of information needed in L{step
        4<openid.consumer.consumer>} easy and secure.

        The token generated must be preserved until L{step
        4<openid.consumer.consumer>}, which is after the redirect to
        the OpenID server takes place.  This means that the token must
        be preserved across http requests.  There are three basic
        approaches that might be used for storing the token.  First,
        the token could be put in the return_to URL passed into the
        C{L{constructRedirect}} method.  Second, the token could be
        stored in a cookie.  Third, in an environment that supports
        user sessions, the session is a good spot to store the token.

        @param user_url: This is the url the user entered as their
            OpenID.  This call takes care of normalizing it and
            resolving any redirects the server might issue.  If the
            value passed in is a C{unicode} object, this performs a
            minimal translation on it to make it a valid URL.

        @type user_url: C{basestring}, the parent class of C{str} and
            C{unicode}.


        @param return_to: This is the URL that will be included in the
            generated redirect as the URL the OpenID server will send
            its response to.  The URL passed in must handle OpenID
            authentication responses.

        @type return_to: C{str}


        @param immediate: This is an optional boolean value.  It
            controls whether the library uses immediate mode, as
            explained in the module description.  The default value is
            False, which disables immediate mode.

        @type immediate: C{bool}

        @return: This method returns a status code and additional
            information about the code.

            If there was a problem fetching the identity page the user
            gave, the status code is set to C{L{HTTP_FAILURE}}, and
            the additional information value is either set to C{None}
            if the HTTP transaction failed or the HTTP return code,
            which will be in the 400-500 range. This additional
            information value may change in a future release.

            If the identity page fetched successfully, but didn't
            include the correct link tags, the status code is set to
            C{L{PARSE_ERROR}}, and the additional information value is
            currently set to C{None}.  The additional information
            value may change in a future release.

            Otherwise, the status code is set to C{L{SUCCESS}}, and
            the additional information is an instance of
            C{L{OpenIDAuthRequest}}.  The
            C{L{token<OpenIDAuthRequest.token>}} attribute contains
            the token to be preserved for the next HTTP request.  The
            C{L{server_url<OpenIDAuthRequest.server_url>}} might also be
            of interest, if you wish to blacklist or whitelist OpenID
            servers.  The other contents of the object are information
            needed in the C{L{constructRedirect}} call.

        @rtype: A pair, where the first element is a C{str} object,
            and the second depends on the value of the first.


        @raise Exception: This method does not handle any exceptions
            raised by the store or fetcher it is using.

            It raises no exceptions itself.
        """
        nonce = cryptutil.randomString(self.NONCE_LEN, self.NONCE_CHRS)

        consumer_id = service_endpoint.identity_url
        server_id = service_endpoint.getServerID()
        server_url = service_endpoint.server_url

        token = self._genToken(nonce, consumer_id, server_id, server_url)

        auth_request = OpenIDAuthRequest(
            token, consumer_id, server_id, server_url, nonce)

        auth_request.redirect_url = self.constructRedirect(auth_request,
                                                           return_to,
                                                           immediate)
        self.session[self.sessionKeyPrefix + self._token] = token
        return auth_request

    def constructRedirect(self, auth_request, return_to, immediate=False):
        """
        This method is called to construct the redirect URL sent to
        the browser to ask the server to verify its identity.  This is
        called in L{step 3<openid.consumer.consumer>} of the flow
        described in the overview.  The generated redirect should be
        sent to the browser which initiated the authorization request.

        @param auth_request: This must be an C{L{OpenIDAuthRequest}}
            instance which was returned from a previous call to
            C{L{beginAuth}}.  It contains information found during the
            beginAuth call which is needed to build the redirect URL.

        @type auth_request: C{L{OpenIDAuthRequest}}


        @param return_to: This is the URL that will be included in the
            generated redirect as the URL the OpenID server will send
            its response to.  The URL passed in must handle OpenID
            authentication responses.

        @type return_to: C{str}


        @param immediate: This is an optional boolean value.  It
            controls whether the library uses immediate mode, as
            explained in the module description.  The default value is
            False, which disables immediate mode.

        @type immediate: C{bool}

        @return: This method returns a string containing the URL to
            redirect to when such a URL is successfully constructed.

        @rtype: C{str}


        @raise Exception: This method does not handle any exceptions
            raised by the store it is using.

            It raises no exceptions itself.
        """
        assoc = self._getAssociation(auth_request.server_url, replace=1)
        # Because _getAssociation could be asynchronous if the
        # association is not already in the store.
        return self._constructRedirect(assoc, auth_request,
                                       return_to, self.trust_root, immediate)

    def completeAuth(self, query):
        """
        This method is called to interpret the server's response to an
        OpenID request.  It is called in L{step
        4<openid.consumer.consumer>} of the flow described in the
        overview.

        The return value is a pair, consisting of a status and
        additional information.  The status values are strings, but
        should be referred to by their symbolic values: C{L{SUCCESS}},
        C{L{FAILURE}}, and C{L{SETUP_NEEDED}}.

        When C{L{SUCCESS}} is returned, the additional information
        returned is either C{None} or a C{str}.  If it is C{None}, it
        means the user cancelled the login, and no further information
        can be determined.  If the additional information is a C{str},
        it is the identity that has been verified as belonging to the
        user making this request.

        When C{L{FAILURE}} is returned, the additional information is
        either C{None} or a C{str}.  In either case, this code means
        that the identity verification failed.  If it can be
        determined, the identity that failed to verify is returned.
        Otherwise C{None} is returned.

        When C{L{SETUP_NEEDED}} is returned, the additional
        information is the user setup URL.  This is a URL returned
        only as a response to requests made with
        C{openid.mode=immediate}, which indicates that the login was
        unable to proceed, and the user should be sent to that URL if
        they wish to proceed with the login.


        @param token: This is the token for this authentication
            transaction, generated by the call to C{L{beginAuth}}.

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


        @raise Exception: This method does not handle any exceptions
            raised by the fetcher or the store.

            It raises no exceptions itself.
        """
        mode = query.get('openid.mode', '')
        if mode == 'cancel':
            # Remove the server from the visited list.
            token = self.session.get(self.sessionKeyPrefix + self._token,
                                     None)
            if token:
                self._splitToken(token)
                fields = self._splitToken(token)
                # XXX: would return cancel for the identity url
            else:
                oidutil.log("Failed to retrieve token from session.")

            return SUCCESS, None
        elif mode == 'error':
            error = query.get('openid.error')
            if error is not None:
                oidutil.log(error)
            return FAILURE, None
        elif mode == 'id_res':
            token = self.session.get(self.sessionKeyPrefix + self._token,
                                     None)
            if not token:
                oidutil.log("Failed to retrieve token from session.")
                return FAILURE, None
            return self._doIdRes(token, query)
        else:
            return FAILURE, None

    def _makeKVPost(self, args, server_url):
        mode = args['openid.mode']
        body = urllib.urlencode(args)

        resp = fetchers.fetch(server_url, body=body)
        if resp is None:
            fmt = 'openid.mode=%s: failed to fetch URL: %s'
            oidutil.log(fmt % (mode, server_url))
            return None

        response = kvform.kvToDict(resp.body)
        if resp.status == 400:
            server_error = results.get('error', '<no message from server>')
            fmt = 'openid.mode=%s: error returned from server %s: %s'
            oidutil.log(fmt % (mode, server_url, server_error))
            return None
        elif resp.status != 200:
            fmt = 'openid.mode=%s: bad status code from server %s: %s'
            oidutil.log(fmt % (mode, server_url, resp.status))
            return None

        return response

    def _constructRedirect(self, assoc, auth_req, return_to, trust_root,
                           immediate=False):

        if immediate:
            mode = 'checkid_immediate'
        else:
            mode = 'checkid_setup'

        redir_args = {
            'openid.identity': auth_req.server_id,
            'openid.return_to': return_to,
            'openid.trust_root': trust_root,
            'openid.mode': mode,
            }

        if assoc is not None:
            redir_args['openid.assoc_handle'] = assoc.handle

        self.store.storeNonce(auth_req.nonce)
        return str(oidutil.appendArgs(auth_req.server_url, redir_args))

    def _doIdRes(self, token, query):
        ret = self._splitToken(token)
        if ret is None:
            oidutil.log('Bad token')
            return FAILURE, None

        nonce, consumer_id, server_id, server_url = ret

        user_setup_url = query.get('openid.user_setup_url')
        if user_setup_url is not None:
            return SETUP_NEEDED, user_setup_url

        return_to = query.get('openid.return_to')
        server_id2 = query.get('openid.identity')
        assoc_handle = query.get('openid.assoc_handle')

        if return_to is None or server_id is None or assoc_handle is None:
            oidutil.log('Missing required field')
            return FAILURE, consumer_id

        if server_id != server_id2:
            oidutil.log('Server ID mismatch')
            return FAILURE, consumer_id

        assoc = self.store.getAssociation(server_url, assoc_handle)

        if assoc is None:
            # It's not an association we know about.  Dumb mode is our
            # only possible path for recovery.
            return self._checkAuth(nonce, query, server_url), consumer_id

        if assoc.expiresIn <= 0:
            # XXX: It might be a good idea sometimes to re-start the
            # authentication with a new association. Doing it
            # automatically opens the possibility for
            # denial-of-service by a server that just returns expired
            # associations (or really short-lived associations)
            oidutil.log('Association with %s expired' % (server_url,))
            return FAILURE, consumer_id

        # Check the signature
        sig = query.get('openid.sig')
        signed = query.get('openid.signed')
        if sig is None or signed is None:
            oidutil.log('Missing argument signature')
            return FAILURE, consumer_id

        signed_list = signed.split(',')
        v_sig = assoc.signDict(signed_list, query)

        if v_sig != sig:
            oidutil.log('Bad argument signature')
            return FAILURE, consumer_id

        if not self.store.useNonce(nonce):
            oidutil.log('Nonce not present')
            return FAILURE, consumer_id

        return SUCCESS, consumer_id

    def _checkAuth(self, nonce, query, server_url):
        signed = query.get('openid.signed')
        if signed is None:
            oidutil.log('No signature present; checkAuth aborted')
            return FAILURE

        whitelist = ['assoc_handle', 'sig', 'signed', 'invalidate_handle']
        signed = signed.split(',') + whitelist

        arg_filter = lambda (k, v): k[7:] in signed
        check_args = dict(filter(arg_filter, query.iteritems()))

        check_args['openid.mode'] = 'check_authentication'
        response = self._makeKVPost(check_args, server_url)
        if response is None:
            return FAILURE

        is_valid = results.get('is_valid', 'false')

        if is_valid == 'true':
            invalidate_handle = results.get('invalidate_handle')
            if invalidate_handle is not None:
                self.store.removeAssociation(server_url, invalidate_handle)

            if not self.store.useNonce(nonce):
                oidutil.log('Nonce already used')
                return FAILURE

            return SUCCESS

        oidutil.log('Server responds that checkAuth call is not valid')
        return FAILURE

    def _getAssociation(self, server_url, replace=0):
        if self.store.isDumb():
            return None

        assoc = self.store.getAssociation(server_url)

        if assoc is None or \
               (replace and assoc.expiresIn < self.TOKEN_LIFETIME):
            proto = urlparse(server_url)[0]
            if proto == 'https':
                dh = None
            else:
                dh = DiffieHellman()

            args = self._createAssociateRequest(dh)
            response = self._makeKVPost(args, server_url)
            assoc = self._parseAssociation(response, dh, server_url)

        return assoc

    def _genToken(self, nonce, consumer_id, server_id, server_url):
        timestamp = str(int(time.time()))
        elements = [timestamp, nonce, consumer_id, server_id, server_url]
        joined = '\x00'.join(elements)
        sig = cryptutil.hmacSha1(self.store.getAuthKey(), joined)

        return oidutil.toBase64('%s%s' % (sig, joined))

    def _splitToken(self, token):
        token = oidutil.fromBase64(token)
        if len(token) < 20:
            oidutil.log('Bad token length: %d' % len(token))
            return None

        sig, joined = token[:20], token[20:]
        if cryptutil.hmacSha1(self.store.getAuthKey(), joined) != sig:
            oidutil.log('Bad token signature')
            return None

        split = joined.split('\x00')
        if len(split) != 5:
            oidutil.log('Bad token contents (not enough fields)')
            return None

        try:
            ts = int(split[0])
        except ValueError:
            oidutil.log('Bad token contents (timestamp bad)')
            return None

        if ts + self.TOKEN_LIFETIME < time.time():
            oidutil.log('Token expired')
            return None

        return tuple(split[1:])

    def _createAssociateRequest(self, dh=None, args=None):
        if args is None:
            args = {}

        args.update({
            'openid.mode': 'associate',
            'openid.assoc_type':'HMAC-SHA1',
            })

        if dh:
            cpub = cryptutil.longToBase64(dh.public)

            args.update({
                'openid.session_type':'DH-SHA1',
                'openid.dh_consumer_public': cpub,
                })

            if not dh.usingDefaultValues():
                args.update({
                    'openid.dh_modulus': cryptutil.longToBase64(dh.modulus),
                    'openid.dh_gen': cryptutil.longToBase64(dh.generator),
                    })

        return args

    def _parseAssociation(self, results, dh, server_url):
        try:
            assoc_type = results['assoc_type']
            if assoc_type != 'HMAC-SHA1':
                fmt = 'Unsupported assoc_type returned from server %s: %s'
                oidutil.log(fmt % (server_url, assoc_type))
                return None

            assoc_handle = results['assoc_handle']
            try:
                expires_in = int(results.get('expires_in', '0'))
            except ValueError, e:
                fmt = 'Getting Association: invalid expires_in field: %s'
                oidutil.log(fmt % (e[0],))
                return None

            session_type = results.get('session_type')
            if session_type is None:
                secret = oidutil.fromBase64(results['mac_key'])
            else:
                if session_type != 'DH-SHA1':
                    fmt = 'Unsupported session_type from server %s: %s'
                    oidutil.log(fmt % (server_url, session_type))
                    return None
                if dh is None:
                    fmt = 'Not expecting a DH-SHA1 session from server %s'
                    oidutil.log(fmt % (server_url))
                    return None

                spub = cryptutil.base64ToLong(results['dh_server_public'])
                enc_mac_key = oidutil.fromBase64(results['enc_mac_key'])
                secret = dh.xorSecret(spub, enc_mac_key)

            assoc = Association.fromExpiresIn(
                expires_in, assoc_handle, secret, assoc_type)
            self.store.storeAssociation(server_url, assoc)

            return assoc

        except KeyError, e:
            fmt = 'Getting association: missing key in response from %s: %s'
            oidutil.log(fmt % (server_url, e[0]))
            return None

    def __eq__(self, other):
        return (self.store == other.store)

    def __ne__(self, other):
        return not (self == other)


class OpenIDAuthRequest(object):
    """
    This class represents an in-progress OpenID authentication
    request.  It exists to make transferring information between the
    C{L{beginAuth<OpenIDConsumer.beginAuth>}} and
    C{L{constructRedirect<OpenIDConsumer.constructRedirect>}} methods
    easier.  Users of the OpenID consumer library will need to be
    aware of the C{L{token}} value, and may care about the
    C{L{server_url}} value.  All other fields are internal information
    for the library which the user of the library shouldn't touch at
    all.


    @ivar token: This is the token generated by the library.  It must
        be saved until the user's return request, via whatever
        mechanism works best for this consumer application.


    @ivar server_url: This is the URL of the identity server that will
        be used.  It isn't necessary to do anything with this value,
        but it is available for consumers that wish to either
        blacklist or whitelist OpenID servers.


    @sort: token, server_url
    """

    redirect_url = None

    def __init__(self, token, identity_url, server_id, server_url, nonce):
        """
        Creates a new OpenIDAuthRequest object.  This just stores each
        argument in an appropriately named field.

        Users of this library should not create instances of this
        class.  Instances of this class are created by the library
        when needed.
        """
        self.token = token
        self.identity_url = identity_url
        self.server_id = server_id
        self.server_url = server_url
        self.nonce = nonce

    def __eq__(self, other):
        return ((self.token == other.token) and
                (self.server_id == other.server_id) and
                (self.server_url == other.server_url) and
                (self.nonce == other.nonce) and
                (self.identity_url == other.identity_url) and
                (self.redirect_url == other.redirect_url))

    def __ne__(self, other):
        return not (self == other)
