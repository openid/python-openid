"""
This module documents the interface to the OpenID server library.  The
only part of the library which has to be used and isn't documented
here is the store for associations.  See the C{L{openid.store}}
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
    module.  Second, there is the C{L{openid.store}} package, which
    contains information on the necessary persistent state mechanisms,
    and several implementations.

STORES
======

    The OpenID server needs to maintain state between requests in
    order to function.  Its mechanism for doing this is called a
    store.  The store interface is defined in
    C{L{openid.store.interface.OpenIDStore}}.  Additionally, several
    concrete store implementations are provided, so that most sites
    won't need to implement a custom store.  For a store backed by
    flat files on disk, see
    C{L{openid.store.filestore.FileOpenIDStore}}.  For stores based
    on MySQL or SQLite, see the C{L{openid.store.sqlstore}} module.
    For a store using Danga's memcached caching system, see the
    C{L{openid.store.memcachestore}} module.


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
    C{L{processPost<OpenIDServer.processPost>}} method with the parsed
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
           C{L{getAuthenticationData<OpenIDServer.getAuthenticationData>}}
           method with the arguments provided for this GET request.
           The return value is a pair (identity URL, trust root) that
           this request is asking to authorize.

        3. Authenticate the user as the owner of the identity
           URL in question.  Then determine whether the user has
           authorized telling the consumer (as identified by trust root)
           that he owns the identity URL.  Both of those are very
           application-specific bits of logic, and depend heavily on
           design choices you've made as an identity server.  The end
           result of these checks should be a boolean value indicating
           whether the request is correctly authorized or not.

        4. Call the C{L{OpenIDServer}} instance's
           C{L{getAuthenticationResponse
           <OpenIDServer.getAuthenticationResponse>}} method.  The
           first argument is the value calculated in the previous
           state, a boolean value indicating whether the request is
           properly authorized.  The second argument is the arguments
           provided for this GET request.

        5. The return value from that call is a pair, (status, info).
           Depending on the status value returned, there are several
           different actions you might take.  See the documentation
           for the C{L{getAuthenticationResponse
           <OpenIDServer.getAuthenticationResponse>}} method for a
           full list of possible results, what they mean, and what the
           appropriate action for each is.

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


@var REDIRECT: This status code is returned by
    C{L{getOpenIDResponse<OpenIDServer.getOpenIDResponse>}} when the
    user should be sent a redirect.


@var DO_AUTH: This status code is returned by
    C{L{getOpenIDResponse<OpenIDServer.getOpenIDResponse>}} when the
    library has determined that it's up to the application and user to
    fix the reason the library isn't authorized to return a successful
    authentication response.


@var DO_ABOUT: This status code is returned by
    C{L{getOpenIDResponse<OpenIDServer.getOpenIDResponse>}} when there
    were no OpenID arguments provided at all.  This is typically the
    case when somebody notices the <link> tag in a web page, wonders
    what it's there for, and decides to type it in.  The standard
    behavior in this case is to show a page with a small explanation
    of OpenID.


@var REMOTE_OK: This status code is returned by
    C{L{getOpenIDResponse<OpenIDServer.getOpenIDResponse>}} when the
    server should send a 200 response code and an exact message body.
    This is for informing a remote site everything worked correctly.


@var REMOTE_ERROR: This status code is returned by
    C{L{getOpenIDResponse<OpenIDServer.getOpenIDResponse>}} when the
    server should send a 400 response code and an exact message body.
    This is for informing a remote site that an error occured while
    processing the request.


@var LOCAL_ERROR: This status code is returned by
    C{L{getOpenIDResponse<OpenIDServer.getOpenIDResponse>}} when
    something went wrong, and the library isn't able to find an
    appropriate in-protocol response.  When this happens, a short
    plaintext description of the error will be provided.  The server
    will probably want to return some sort of error page here, but its
    contents are not strictly prescribed, like those of the
    C{L{REMOTE_ERROR}} case.


@sort: REDIRECT, DO_AUTH, DO_ABOUT, REMOTE_OK, REMOTE_ERROR,
    LOCAL_ERROR, OpenIDServer
"""

import time
import urllib
import cgi

from openid import cryptutil
from openid import kvform
from openid import oidutil
from openid.dh import DiffieHellman
from openid.server.trustroot import TrustRoot
from openid.association import Association

_signed_fields = ['mode', 'identity', 'return_to']

REDIRECT     = 'redirect'
DO_AUTH      = 'do_auth'
DO_ABOUT     = 'do_about'

REMOTE_OK    = 'exact_ok'
REMOTE_ERROR = 'exact_error'

LOCAL_ERROR  = 'local_error'

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


        @param store: This in an object implementing the
            C{L{openid.store.interface.OpenIDStore}} interface which
            the library will use for persistent storage.  See the
            C{L{OpenIDStore<openid.store.interface.OpenIDStore>}}
            documentation for more information on stores and various
            implementations.  Note that the store used for the server
            must not be a dumb-style store.  It's not possible to be a
            functional OpenID server without persistent storage.

        @type store: An object implementing the
            C{L{openid.store.interface.OpenIDStore}} interface


        """
        self.low_level = LowLevelServer(server_url, store)

    def getOpenIDResponse(self, http_method, args, is_authorized):
        """
        This method processes an OpenID request, and determines the
        proper response to it.  It then communicates what that
        response should be back to its caller via return codes.

        The return value of this method is a pair, C{(status, info)}.
        The first value is the status code describing what action
        should be taken.  The second value is additional information
        for taking that action.

        The following return codes are possible:

            1.  C{L{REDIRECT}} - This code indicates that the server
                should respond with an HTTP redirect.  In this case,
                C{info} is the URL to redirect the client to.

            2.  C{L{DO_AUTH}} - This code indicates that the server
                should take whatever actions are necessary to allow
                this authentication to succeed or be cancelled, then
                try again.  In this case C{info} is a
                C{AuthorizationInfo} object, which contains additional
                useful information.

            3.  C{L{DO_ABOUT}} -

            4.  C{L{REMOTE_OK}} -

            5.  C{L{REMOTE_ERROR}} -

            6.  C{L{LOCAL_ERROR}} -


        @param http_method: This is a string describing the HTTP
            method used to make the current request.  The only
            expected values are C{'GET'} and C{'POST'}, though
            capitalization will be ignored.  Any value other than one
            of the expected ones will result in a LOCAL_ERROR return
            code.

        @type http_method: C{str}


        @param args: This should be a C{dict}-like object that
            contains the parsed, unescaped arguments that were sent
            with the OpenID request being handled.  The keys and
            values in the dictionary should both be either C{str} or
            C{unicode} objects.

        @type args: a C{dict}-like object


        @param is_authorized: This is a callback function which this
            C{L{OpenIDServer}} instance will use to determine the
            result of an authentication request.  The function will be
            called with two C{str} arguments, C{identity_url} and
            C{trust_root}.  It should return a C{bool} value
            indicating whether this identity request is authorized to
            succeed.

            The function needs to perform two seperate tasks, and
            return C{True} only if it gets a positive result from
            each.

            The first task is to determine the user making this
            request, and if they are authorized to claim the identity
            URL passed to the function.  If the user making this
            request isn't authorized to claim the identity URL, the
            callback should return C{False}.

            The second task is to determine if the user will allow the
            trust root in question to determine his or her identity.
            If they have not previously authorized the trust root to
            know they're identity the callback should return C{False}.

            If neither of those returned C{False}, the callback should
            return C{True}.  An example callback might look like this::

                def is_authorized(identity_url, trust_root):
                    user = getUserName()
                    if user is None:
                        return False

                    if identity_url != getIdentityUrl(user):
                        return False

                    if trust_root not in getTrustRoots(user):
                        return False

                    return True

            That's obviously a pseudocode-ish example, but it conveys
            the important steps.  This callback should work only with
            information already submitted, ie. the user already logged
            in and the trust roots they've already approved.  It is
            important that this callback does not attempt to interact
            with the user.  Doing so would lead to violating the
            OpenID specification when the server is handling a
            checkid_immediate request.

        @type is_authorized: A function, taking two C{str} objects and
            returning a C{bool}.


        @return: A pair, C{(status, value)} which describes the
            appropriate response to an OpenID request, as above.  The
            first value will always be one of the constants defined in
            this package.

        @rtype: (C{str}, depends on the first)
        """
        if http_method.upper() == 'GET':
            trust_root = args.get('openid.trust_root')
            if not trust_root:
                trust_root = args.get('openid.return_to')

            identity_url = args.get('openid.identity')
            if identity_url is None or trust_root is None:
                authorized = 0 # not False for 2.2 compatibility
            else:
                authorized = is_authorized(identity_url, trust_root)

            return self.low_level.getAuthResponse(authorized, args)

        elif http_method.upper() == 'POST':
            mode = args.get('openid.mode')
            if mode == 'associate':
                return self.low_level.associate(args)

            elif mode == 'check_authentication':
                return self.low_level.checkAuthentication(args)

            else:
                err = 'Unrecognized openid.mode (%r)' % mode
                return self.low_level.postError(err)

        else:
            err = 'HTTP method %r is not valid with OpenID' % (http_method,)
            return LOCAL_ERROR, err


class AuthorizationInfo(object):
    """
    This is a class to 
    """

    def __init__(self, args):
        """
        
        """
        return_to = args.get('openid.return_to')

        self.identity_url = args.get('openid.identity')
        self.trust_root = args.get('openid.trust_root') or return_to

        cancel_args = {'openid.mode': 'cancel'}
        self.cancel_url = oidutil.appendArgs(return_to, cancel_args)

        self.args = dict(args.iteritems())

    def retry(self, openid_server, is_authorized):
        return openid_server.getOpenIDResponse(
            'GET', self.args, is_authorized)

    def cancel(self):
        return REDIRECT, self.cancel_url

    def serialize(self):
        return urllib.urlencode(self.args)

    def deserialize(cls, string_form):
        return cls(dict(cgi.parse_qsl(string_form)))

    deserialize = classmethod(deserialize)


class LowLevelServer(object):
    """
    @cvar SECRET_LIFETIME: This is the lifetime that secrets generated
        by this library are valid for, in seconds.

    @type SECRET_LIFETIME: C{int}

    """
    
    SECRET_LIFETIME = 14 * 24 * 60 * 60 # 14 days, in seconds

    def __init__(self, server_url, store):
        self.url = server_url
        self.normal_key = server_url + '|normal'
        self.dumb_key = server_url + '|dumb'

        if store.isDumb():
            raise ValueError, 'OpenIDServer cannot use a dumb store.'

        self.store = store


    def getAuthResponse(self, authorized, args):
        """
        This method determines the correct response to make to an
        authentication request.

        This method always returns a pair.  The first value of the
        pair indicates what action the server should take to respond
        to this request.  The second value is additional information
        to use when taking that action.

            1. Sending a redirect to the user's browser: The second
               value is the URL to redirect the the browser to.

            2. Asking the user for additional information to complete
               the authentication procedure: The second value is
               another pair.  The pair contains two URLs.  The first
               is a URL to retry this authentication request.  The
               second is a URL to redirect the browser to if the user
               decides to cancel.

               The general plan this supports is to present the user a
               page asking for additional information, and present the
               user with 'ok' and 'cancel' buttons.  When the user
               hits the 'ok' button, process the additional
               information they gave, and then redirect them to the
               retry URL.  If they hit the 'cancel' button, send them
               to the cancel URL.  This is a convenient pattern for
               dealing with OpenID requests that need additional
               information for the user.

            3. Showing a page with a short description of OpenID: This
               is for the case when the user visits the OpenID server
               URL directly, without making an OpenID request.  In
               these cases, the best behavior is to show a page with a
               short description of OpenID, as the user typically
               found an OpenID server URL in a web page and is curious
               what it is for.  When this is the case, the second
               value of the return pair is C{None}.

            4. Showing an error page: If the request contained an
               error that couldn't be recovered from, the second value
               will be an error message which may help the user
               determine what went wrong.  Showing them an error page
               including the error message is probably the best
               approach.

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

        @type authorized: C{bool}

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
        mode = args.get('openid.mode')

        if mode not in ['checkid_immediate', 'checkid_setup']:
            err = 'openid.mode (%r) not understood for this request' % mode
            return self.getError(args, err)

        identity = args.get('openid.identity')
        if identity is None:
            return self.getError(args, 'No identity specified')

        trust_root = args.get('openid.trust_root')
        if trust_root is None:
            trust_root = args.get('openid.return_to')

        tr = TrustRoot.parse(trust_root)
        if tr is None:
            err = 'Malformed trust_root: %r' % (trust_root,)
            return self.getError(args, err)

        return_to = args.get('openid.return_to')
        if return_to is None:
            return self.getError(args, 'No return_to URL specified')

        if not tr.validateURL(return_to):
            err = 'return_to(%s) not valid against trust_root(%s)' % \
                  (return_to, trust_root)
            return self.getError(args, err)

        if not authorized:
            if mode == 'checkid_immediate':
                nargs = dict(args)
                nargs['openid.mode'] = 'checkid_setup'
                return REDIRECT, oidutil.appendArgs(self.url, nargs)

            elif mode == 'checkid_setup':
                return DO_AUTH, AuthorizationInfo(args)

            else:
                raise AssertionError, 'unreachable'

        reply = {
            'openid.mode': 'id_res',
            'openid.return_to': return_to,
            'openid.identity': identity,
            }

        store = self.store
        assoc_handle = args.get('openid.assoc_handle')
        if assoc_handle:
            assoc = store.getAssociation(self.normal_key, assoc_handle)

            # fall back to dumb mode if assoc_handle not found,
            # and send the consumer an invalidate_handle message
            if assoc is None or assoc.expiresIn <= 0:
                if assoc is not None and assoc.expiresIn <= 0:
                    store.removeAssociation(self.normal_key, assoc.handle)

                assoc = self.createAssociation('HMAC-SHA1')
                store.storeAssociation(self.dumb_key, assoc)
                reply['openid.invalidate_handle'] = assoc_handle
        else:
            assoc = self.createAssociation('HMAC-SHA1')
            store.storeAssociation(self.dumb_key, assoc)

        reply['openid.assoc_handle'] = assoc.handle

        assoc.addSignature(_signed_fields, reply)

        return REDIRECT, oidutil.appendArgs(return_to, reply)

    def associate(self, args):
        reply = {}
        assoc_type = args.get('openid.assoc_type', 'HMAC-SHA1')
        assoc = self.createAssociation(assoc_type)

        if assoc is None:
            err = 'unable to create an association for type %r' % assoc_type
            return self.postError(err)
        else:
            self.store.storeAssociation(self.normal_key, assoc)

        reply.update({
            'assoc_type': 'HMAC-SHA1',
            'assoc_handle': assoc.handle,
            'expires_in': str(assoc.expiresIn),
            })

        session_type = args.get('openid.session_type')
        if session_type:
            if session_type == 'DH-SHA1':
                p = args['openid.dh_modulus']
                g = args['openid.dh_gen']
                consumer_public = args['openid.dh_consumer_public']

                dh = DiffieHellman.fromBase64(modulus, generator)

                consumer_public = args.get('openid.dh_consumer_public')
                if consumer_public is None:
                    err = 'Missing openid.dh_consumer_public'
                    return self.postError(err)

                cpub = cryptutil.base64ToLong(consumer_public)
                mac_key = dh.xorSecret(cpub, assoc.secret)

                reply.update({
                    'session_type': session_type,
                    'dh_server_public': cryptutil.longToBase64(dh.public),
                    'enc_mac_key': oidutil.toBase64(mac_key),
                    })
            else:
                return self.postError('session_type must be DH-SHA1')
        else:
            reply['mac_key'] = oidutil.toBase64(assoc.secret)

        return REMOTE_OK, kvform.dictToKV(reply)

    def checkAuth(self, args):
        assoc_handle = args.get('openid.assoc_handle')

        if assoc_handle is None:
            return self.postError('Missing openid.assoc_handle')

        assoc = self.store.getAssociation(self.dumb_key, assoc_handle)

        reply = {}
        if assoc and assoc.expiresIn > 0:
            signed = args.get('openid.signed')
            if signed is None:
                return self.postError('Missing openid.signed')

            sig = args.get('openid.sig')
            if sig is None:
                return self.postError('Missing openid.sig')

            to_verify = dict(args)
            to_verify['openid.mode'] = 'id_res'

            signed_fields = signed.strip().split(',')
            tv_sig = assoc.signDict(signed_fields, to_verify)

            if tv_sig == sig:
                self.store.removeAssociation(self.normal_key, assoc_handle)
                is_valid = 'true'

                invalidate_handle = args.get('openid.invalidate_handle')
                if invalidate_handle:
                    if not self.store.getAssociation(self.normal_key,
                                                     invalidate_handle):
                        reply['invalidate_handle'] = invalidate_handle
            else:
                is_valid = 'false'

        else:
            if assoc:
                self.store.removeAssociation(self.dumb_key, assoc_handle)

            is_valid = 'false'

        reply['is_valid'] = is_valid
        return REMOTE_OK, kvform.dictToKV(reply)

    def createAssociation(self, assoc_type):
        if assoc_type == 'HMAC-SHA1':
            secret = cryptutil.getBytes(20)
        else:
            return None

        uniq = oidutil.toBase64(cryptutil.getBytes(4))
        handle = '{%s}{%x}{%s}' % (assoc_type, int(time.time()), uniq)

        assoc = Association.fromExpiresIn(
            self.SECRET_LIFETIME, handle, secret, assoc_type)

        return assoc

    def getError(self, args, msg):
        return_to = args.get('openid.return_to')
        if return_to:
            err = {
                'openid.mode': 'error',
                'openid.error': msg
                }
            return REDIRECT, oidutil.appendArgs(return_to, err)
        else:
            return LOCAL_ERROR, msg

    def postError(self, msg):
        return REMOTE_ERROR, kvform.dictToKV({'error': msg})
