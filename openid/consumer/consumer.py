# -*- test-case-name: openid.test.test_consumer -*-
"""
This module documents the main interface with the OpenID consumer
library.  The only part of the library which has to be used and isn't
documented in full here is the store required to create an
C{L{Consumer}} instance.  More on the abstract store type and
concrete implementations of it that are provided in the documentation
for the C{L{__init__<Consumer.__init__>}} method of the
C{L{Consumer}} class.


OVERVIEW
========

    The OpenID identity verification process most commonly uses the
    following steps, as visible to the user of this library:

        1. The user enters their OpenID into a field on the consumer's
           site, and hits a login button.

        2. The consumer site discovers the user's OpenID server using
           the YADIS protocol.

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

    This module contains a class, C{L{Consumer}}, with methods
    corresponding to the actions necessary in each of steps 2, 3, and
    4 described in the overview.  Use of this library should be as easy
    as creating an C{L{Consumer}} instance and calling the methods
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
    the documentation for the C{L{Consumer}} class for more
    information on the interface for stores.  The implementations that
    are provided allow the consumer site to store the necessary data
    in several different ways, including several SQL databases and
    normal files on disk.

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

    First, the application should instantiate the C{L{Consumer}} class
    using the store of choice.  If the application has any sort of
    session framework that provides per-client state management, a
    dict-like object to access the session should be passed as the
    optional second parameter.  The library just expects the session
    object to support a C{dict}-like interface, if it is provided.

    Next, the application should call the 'begin' method on the
    C{L{Consumer}} instance.  This method takes the OpenID URL.  The
    C{L{begin<Consumer.begin>}} method returns an C{L{AuthRequest}}
    object.

    Next, the application should call the
    C{L{redirectURL<AuthRequest.redirectURL>}} method on the
    C{L{AuthRequest}} object.  The parameter C{return_to} is the URL
    that the OpenID server will send the user back to after attempting
    to verify his or her identity.  The C{realm} parameter is the
    URL (or URL pattern) that identifies your web site to the user
    when he or she is authorizing it.  Send a redirect to the
    resulting URL to the user's browser.

    That's the first half of the authentication process.  The second
    half of the process is done after the user's ID server sends the
    user's browser a redirect back to your site to complete their
    login.

    When that happens, the user will contact your site at the URL
    given as the C{return_to} URL to the
    C{L{redirectURL<AuthRequest.redirectURL>}} call made
    above.  The request will have several query parameters added to
    the URL by the identity server as the information necessary to
    finish the request.

    Get an C{L{Consumer}} instance, and call its
    C{L{complete<Consumer.complete>}} method, passing in all the
    received query arguments.

    There are multiple possible return types possible from that
    method. These indicate the whether or not the login was
    successful, and include any additional information appropriate for
    their type.

@var SUCCESS: constant used as the status for
    L{SuccessResponse<openid.consumer.consumer.SuccessResponse>} objects.

@var FAILURE: constant used as the status for
    L{FailureResponse<openid.consumer.consumer.FailureResponse>} objects.

@var CANCEL: constant used as the status for
    L{CancelResponse<openid.consumer.consumer.CancelResponse>} objects.

@var SETUP_NEEDED: constant used as the status for
    L{SetupNeededResponse<openid.consumer.consumer.SetupNeededResponse>}
    objects.
"""

import time
import cgi
from urlparse import urlparse

from openid import fetchers

from openid.consumer.discover import discover as discoverURL
from openid.consumer.discover import discoverXRI
from openid.consumer.discover import DiscoveryFailure
from openid.message import Message, OPENID_NS, OPENID2_NS, OPENID1_NS, \
     IDENTIFIER_SELECT, no_default
from openid import cryptutil
from openid import kvform
from openid import oidutil
from openid.association import Association, default_negotiator
from openid.dh import DiffieHellman
from openid.store.nonce import mkNonce, split as splitNonce
from openid.yadis.manager import Discovery
from openid.yadis import xri


__all__ = ['AuthRequest', 'Consumer', 'SuccessResponse',
           'SetupNeededResponse', 'CancelResponse', 'FailureResponse',
           'SUCCESS', 'FAILURE', 'CANCEL', 'SETUP_NEEDED',
           ]

class Consumer(object):
    """An OpenID consumer implementation that performs discovery and
    does session management.

    @ivar consumer: an instance of an object implementing the OpenID
        protocol, but doing no discovery or session management.

    @type consumer: GenericConsumer

    @ivar session: A dictionary-like object representing the user's
        session data.  This is used for keeping state of the OpenID
        transaction when the user is redirected to the server.

    @cvar session_key_prefix: A string that is prepended to session
        keys to ensure that they are unique. This variable may be
        changed to suit your application.
    """
    session_key_prefix = "_openid_consumer_"

    _token = 'last_token'

    def __init__(self, session, store):
        """Initialize a Consumer instance.

        You should create a new instance of the Consumer object with
        every HTTP request that handles OpenID transactions.

        @param session: See L{the session instance variable<openid.consumer.consumer.Consumer.session>}

        @param store: an object that implements the interface in
            C{L{openid.store.interface.OpenIDStore}}.  Several
            implementations are provided, to cover common database
            environments.

        @type store: C{L{openid.store.interface.OpenIDStore}}

        @see: L{openid.store.interface}
        @see: L{openid.store}
        """
        self.session = session
        self.consumer = GenericConsumer(store)
        self._token_key = self.session_key_prefix + self._token

    def begin(self, user_url, anonymous=False):
        """Start the OpenID authentication process. See steps 1-2 in
        the overview at the top of this file.

        @param user_url: Identity URL given by the user. This method
            performs a textual transformation of the URL to try and
            make sure it is normalized. For example, a user_url of
            example.com will be normalized to http://example.com/
            normalizing and resolving any redirects the server might
            issue.

        @type user_url: str

        @returns: An object containing the discovered information will
            be returned, with a method for building a redirect URL to
            the server, as described in step 3 of the overview. This
            object may also be used to add extension arguments to the
            request, using its
            L{addExtensionArg<openid.consumer.consumer.AuthRequest.addExtensionArg>}
            method.

        @returntype: L{AuthRequest<openid.consumer.consumer.AuthRequest>}

        @raises openid.consumer.discover.DiscoveryFailure: when I fail to
            find an OpenID server for this URL.  If the C{yadis} package
            is available, L{openid.consumer.discover.DiscoveryFailure} is
            an alias for C{yadis.discover.DiscoveryFailure}.
        """
        if xri.identifierScheme(user_url) == "XRI":
            discoverMethod = discoverXRI
        else:
            discoverMethod = discoverURL

        try:
            disco = Discovery(self.session,
                              user_url,
                              self.session_key_prefix)
            service = disco.getNextService(discoverMethod)
        except fetchers.HTTPFetchingError, e:
            raise DiscoveryFailure('Error fetching XRDS document', e)

        if service is None:
            raise DiscoveryFailure(
                'No usable OpenID services found for %s' % (user_url,), None)
        else:
            return self.beginWithoutDiscovery(service, anonymous)

    def beginWithoutDiscovery(self, service, anonymous=False):
        """Start OpenID verification without doing OpenID server
        discovery. This method is used internally by Consumer.begin
        after discovery is performed, and exists to provide an
        interface for library users needing to perform their own
        discovery.

        @param service: an OpenID service endpoint descriptor.  This
            object and factories for it are found in the
            L{openid.consumer.discover} module.

        @type service:
            L{OpenIDServiceEndpoint<openid.consumer.discover.OpenIDServiceEndpoint>}

        @returns: an OpenID authentication request object.

        @rtype: L{AuthRequest<openid.consumer.consumer.AuthRequest>}

        @See: Openid.consumer.consumer.Consumer.begin
        @see: openid.consumer.discover
        """
        auth_req = self.consumer.begin(service)
        self.session[self._token_key] = auth_req.endpoint
        auth_req.anonymous = anonymous
        return auth_req

    def complete(self, query, return_to=None):
        """Called to interpret the server's response to an OpenID
        request. It is called in step 4 of the flow described in the
        consumer overview.

        @param query: A dictionary of the query parameters for this
            HTTP request.

        @param return_to: The return URL used to invoke the
            application.  Extract the URL from your application's web
            request framework and specify it here to have it checked
            against the openid.return_to value in the response.  If
            the return_to URL check fails, the status of the
            completion will be FAILURE.

        @returns: a subclass of Response. The type of response is
            indicated by the status attribute, which will be one of
            SUCCESS, CANCEL, FAILURE, or SETUP_NEEDED.

        @see: L{SuccessResponse<openid.consumer.consumer.SuccessResponse>}
        @see: L{CancelResponse<openid.consumer.consumer.CancelResponse>}
        @see: L{SetupNeededResponse<openid.consumer.consumer.SetupNeededResponse>}
        @see: L{FailureResponse<openid.consumer.consumer.FailureResponse>}
        """

        endpoint = self.session.get(self._token_key)
        if endpoint is None:
            response = FailureResponse(None, 'No session state found')
        else:
            message = Message.fromPostArgs(query)
            response = self.consumer.complete(message, endpoint, return_to)
            del self.session[self._token_key]

        if (response.status in ['success', 'cancel'] and
            response.identity_url is not None):

            disco = Discovery(self.session,
                              response.identity_url,
                              self.session_key_prefix)
            # This is OK to do even if we did not do discovery in
            # the first place.
            disco.cleanup()

        return response

class DiffieHellmanSHA1ConsumerSession(object):
    session_type = 'DH-SHA1'
    hash_func = staticmethod(cryptutil.sha1)
    secret_size = 20
    allowed_assoc_types = ['HMAC-SHA1']

    def __init__(self, dh=None):
        if dh is None:
            dh = DiffieHellman.fromDefaults()

        self.dh = dh

    def getRequest(self):
        cpub = cryptutil.longToBase64(self.dh.public)

        args = {'dh_consumer_public': cpub}

        if not self.dh.usingDefaultValues():
            args.update({
                'dh_modulus': cryptutil.longToBase64(self.dh.modulus),
                'dh_gen': cryptutil.longToBase64(self.dh.generator),
                })

        return args

    def extractSecret(self, response):
        dh_server_public64 = response.getArg(
            OPENID_NS, 'dh_server_public', no_default)
        enc_mac_key64 = response.getArg(OPENID_NS, 'enc_mac_key', no_default)
        dh_server_public = cryptutil.base64ToLong(dh_server_public64)
        enc_mac_key = oidutil.fromBase64(enc_mac_key64)
        return self.dh.xorSecret(dh_server_public, enc_mac_key, self.hash_func)

class DiffieHellmanSHA256ConsumerSession(DiffieHellmanSHA1ConsumerSession):
    session_type = 'DH-SHA256'
    hash_func = staticmethod(cryptutil.sha256)
    secret_size = 32
    allowed_assoc_types = ['HMAC-SHA256']

class PlainTextConsumerSession(object):
    session_type = 'no-encryption'
    allowed_assoc_types = ['HMAC-SHA1', 'HMAC-SHA256']

    def getRequest(self):
        return {}

    def extractSecret(self, response):
        mac_key64 = response.getArg(OPENID_NS, 'mac_key', no_default)
        return oidutil.fromBase64(mac_key64)

class SetupNeededError(Exception):
    """Internally-used exception that indicates that an immediate-mode
    request cancelled."""
    def __init__(self, user_setup_url=None):
        Exception.__init__(self, user_setup_url)
        self.user_setup_url = user_setup_url

class ProtocolError(ValueError):
    """Exception that indicates that a message violated the
    protocol. It is raised and caught internally to this file."""

class ServerError(Exception):
    """Exception that is raised when the server returns a 400 response
    code to a direct request."""

    def __init__(self, message):
        self.error_text = message.getArg(
            OPENID_NS, 'error', '<no error message supplied>')
        Exception.__init__(self, self.error_text)
        self.error_code = message.getArg(OPENID_NS, 'error_code')
        self.message = message

class GenericConsumer(object):
    """This is the implementation of the common logic for OpenID
    consumers. It is unaware of the application in which it is
    running.
    """

    # The name of the query parameter that gets added to the return_to
    # URL when using OpenID1. You can change this value if you want or
    # need a different name, but don't make it start with openid,
    # because it's not a standard protocol thing for OpenID1. For
    # OpenID2, the library will take care of the nonce using standard
    # OpenID query parameter names.
    openid1_nonce_query_arg_name = 'janrain_nonce'

    session_types = {
        'DH-SHA1':DiffieHellmanSHA1ConsumerSession,
        'DH-SHA256':DiffieHellmanSHA256ConsumerSession,
        'no-encryption':PlainTextConsumerSession,
        }

    def __init__(self, store):
        self.store = store
        self.negotiator = default_negotiator.copy()

    def begin(self, service_endpoint):
        assoc = self._getAssociation(service_endpoint)
        request = AuthRequest(service_endpoint, assoc)
        request.return_to_args[self.openid1_nonce_query_arg_name] = mkNonce()
        return request

    def complete(self, message, endpoint, return_to=None):
        mode = message.getArg(OPENID_NS, 'mode', '<No mode set>')

        if return_to is not None:
            if not self._checkReturnTo(message, return_to):
                return FailureResponse(endpoint,
                                       "openid.return_to does not match return URL")

        if mode == 'cancel':
            return CancelResponse(endpoint)
        elif mode == 'error':
            error = message.getArg(OPENID_NS, 'error')
            contact = message.getArg(OPENID_NS, 'contact')
            reference = message.getArg(OPENID_NS, 'reference')

            return FailureResponse(endpoint, error, contact=contact,
                                   reference=reference)
        elif mode == 'id_res':
            try:
                self._checkSetupNeeded(message)
            except SetupNeededError, why:
                return SetupNeededResponse(endpoint, why.user_setup_url)
            else:
                return self._doIdRes(message, endpoint)
        else:
            return FailureResponse(endpoint,
                                   'Invalid openid.mode: %r' % (mode,))

    def _checkReturnTo(self, message, return_to):
        """Check an OpenID message and its openid.return_to value
        against a return_to URL from an application.  Return True on
        success, False on failure.
        """
        # Check the openid.return_to args against args in the original
        # message.
        try:
            self._verifyReturnToArgs(message.toPostArgs())
        except ValueError:
            return False

        # Check the return_to base URL against the one in the message.
        msg_return_to = message.getArg(OPENID_NS, 'return_to')

        # The URL scheme, authority, and path MUST be the same between
        # the two URLs.
        app_parts = urlparse(return_to)
        msg_parts = urlparse(msg_return_to)

        # (addressing scheme, network location, path) must be equal in
        # both URLs.
        for part in range(0, 3):
            if app_parts[part] != msg_parts[part]:
                return False

        return True

    def _makeKVPost(self, request_message, server_url):
        """Make a Direct Request to an OpenID Provider and return the
        result as a Message object.

        @raises fetchers.HTTPFetchingError
        @rtype: openid.message.Message
        """
        # XXX: TESTME
        resp = fetchers.fetch(server_url, body=request_message.toURLEncoded())
        if resp is None:
            fmt = 'failed making Direct Request to %s'
            raise fetchers.HTTPFetchingError(fmt % (server_url,))

        response_message = Message.fromKVForm(resp.body)
        if resp.status == 400:
            raise ServerError(response_message)

        elif resp.status != 200:
            fmt = 'bad status code from server %s: %s'
            error_message = fmt % (server_url, resp.status)
            raise fetchers.HTTPFetchingError(error_message)

        return response_message

    def _checkSetupNeeded(self, message):
        """Check an id_res message to see if it is a
        checkid_immediate cancel response.

        @raises: SetupNeededError if it is a checkid_immediate cancellation
        """
        if message.isOpenID1():
            # In OpenID 1, we check to see if this is a cancel from
            # immediate mode by the presence of the user_setup_url
            # parameter.
            user_setup_url = message.getArg(OPENID1_NS, 'user_setup_url')
            if user_setup_url is not None:
                raise SetupNeededError(user_setup_url)
        else:
            # In OpenID 2, we check whether the only field present is
            # the mode. This seems questionable, but it's the best way
            # that I can express what it says in the spec.
            openid_args = message.getArgs(OPENID2_NS)
            if openid_args == {'mode':'id_res'}:
                raise SetupNeededError()

    def _doIdRes(self, message, endpoint):
        """Handle id_res responses that are not cancellations of
        immediate mode requests.

        @param message: the response paramaters.
        @param endpoint: the discovered endpoint object. May be None.

        @returntype: L{Response}
        """
        try:
            signed_list = self._idResCheckSignature(message,
                                                    endpoint.server_url)
            # Checks for presence of appropriate fields (and checks
            # signed list fields)
            self._idResCheckForFields(message, signed_list)
        except ValueError, e:
            return FailureResponse(endpoint, e.args[0])

        response_identity = message.getArg(OPENID_NS, 'identity')

        # IdP-driven identifier selection requires another round of
        # discovery:
        if endpoint.isIdentifierSelect():
            try:
                endpoint = self._verifyDiscoveryResults(endpoint, message)
            except DiscoveryFailure, exc:
                return FailureResponse(endpoint, exc.args[0])
        elif endpoint.getLocalID() != response_identity:
            fmt = 'Mismatch between delegate (%r) and server (%r) response'
            return FailureResponse(
                endpoint, fmt % (endpoint.getLocalID(), response_identity))

        if self._idResCheckNonce(message, endpoint):
            signed_fields = ['openid.' + f for f in signed_list]
            return SuccessResponse(endpoint, message, signed_fields)
        else:
            return FailureResponse(endpoint, 'Nonce missing, old or used')

    def _idResGetNonceOpenID1(self, message, endpoint):
        """Extract the nonce from an OpenID 1 response

        See the openid1_nonce_query_arg_name class variable

        @returns: The nonce as a string or None
        """
        return_to = message.getArg(OPENID1_NS, 'return_to', None)
        if return_to is None:
            return None

        parsed_url = urlparse(return_to)
        query = parsed_url[4]
        for k, v in cgi.parse_qsl(query):
            if k == self.openid1_nonce_query_arg_name:
                return v

        return None

    def _idResCheckNonce(self, message, endpoint):
        if message.isOpenID1():
            # This indicates that the nonce was generated by the consumer
            nonce = self._idResGetNonceOpenID1(message, endpoint)
            server_url = ''
        else:
            nonce = message.getArg(OPENID2_NS, 'response_nonce')
            server_url = endpoint.server_url

        if nonce is None:
            oidutil.log('Nonce missing from response')
            return False

        try:
            timestamp, salt = splitNonce(nonce)
        except ValueError:
            oidutil.log('Malformed nonce')
            return False

        if self.store.useNonce(server_url, timestamp, salt):
            return True
        else:
            oidutil.log('Nonce already used or out of range')
            return False

    def _idResCheckSignature(self, message, server_url):
        assoc_handle = message.getArg(OPENID_NS, 'assoc_handle')
        assoc = self.store.getAssociation(server_url, assoc_handle)

        if assoc:
            if assoc.getExpiresIn() <= 0:
                # XXX: It might be a good idea sometimes to re-start the
                # authentication with a new association. Doing it
                # automatically opens the possibility for
                # denial-of-service by a server that just returns expired
                # associations (or really short-lived associations)
                raise ValueError('Association with %s expired' % (server_url,))

            if not assoc.checkMessageSignature(message):
                raise ValueError('Bad signature')

        else:
            # It's not an association we know about.  Stateless mode is our
            # only possible path for recovery.
            # XXX - async framework will not want to block on this call to
            # _checkAuth.
            if not self._checkAuth(message, server_url):
                raise ValueError('Server denied check_authentication')

        return message.getArg(OPENID_NS, 'signed').split(',')


    def _idResCheckForFields(self, message, signed_list):
        basic_fields = ['return_to', 'assoc_handle', 'sig']
        basic_sig_fields = ['return_to', 'identity',]

        require_fields = {
            OPENID2_NS: basic_fields + ['op_endpoint',],
            OPENID1_NS: basic_fields,
            }

        require_sigs = {
            OPENID2_NS: basic_sig_fields + ['response_nonce', 'claimed_id', 'assoc_handle',],
            OPENID1_NS: basic_sig_fields + ['nonce',],
            }

        for field in require_fields[message.getOpenIDNamespace()]:
            if not message.hasKey(OPENID_NS, field):
                raise ValueError('Missing required field %r' % (field,))

        for field in require_sigs[message.getOpenIDNamespace()]:
            # Field is present and not in signed list
            if message.hasKey(OPENID_NS, field) and field not in signed_list:
                # I wish I could just raise a FailureResponse here, but
                # they're not exceptions.  :-/
                raise ValueError('"%s" not signed' % (field,))


    def _verifyReturnToArgs(query):
        """Verify that the arguments in the return_to URL are present in this
        response.
        """
        message = Message.fromPostArgs(query)
        return_to = message.getArg(OPENID_NS, 'return_to')
        if not return_to:
            raise ValueError("no openid.return_to in query %r" % (query,))
        parsed_url = urlparse(return_to)
        rt_query = parsed_url[4]
        for rt_key, rt_value in cgi.parse_qsl(rt_query):
            try:
                value = query[rt_key]
                if rt_value != value:
                    raise ValueError("parameter %s value %r does not match "
                                     "return_to's value %r" % (rt_key, value,
                                                               rt_value))
            except KeyError:
                raise ValueError("return_to parameter %s absent from query %r"
                                 % (rt_key, query))

    _verifyReturnToArgs = staticmethod(_verifyReturnToArgs)


    def _verifyDiscoveryResults(self, orig_endpoint, resp_msg):
        """

        @param identifier: the identifier to perform discovery on.
        @param server_url: the server endpoint I hope to discover.
        """

        # If OpenID 2, do disco on the claimed_id.  Otherwise, use
        # the local_id (openid.identity).
        if resp_msg.getOpenIDNamespace() == OPENID2_NS:
            identifier = resp_msg.getArg(OPENID_NS, 'claimed_id')
        else:
            identifier = resp_msg.getArg(OPENID_NS, 'identity')

        # Identifier absent, so return the original endpoint because
        # we don't have any discovery'ing to do
        if identifier is None:
            return orig_endpoint

        # Pick the right discovery method.
        if xri.identifierScheme(identifier) == "XRI":
            discoverMethod = discoverXRI
        else:
            discoverMethod = discoverURL

        discovered_id, services = discoverMethod(identifier)

        def serviceMatches(endpoint):
            # Claimed ID in response much match the one on the
            # endpoint.
            if OPENID2_NS == resp_msg.getOpenIDNamespace():
                if endpoint.claimed_id != resp_msg.getArg(OPENID_NS, 'claimed_id'):
                    return False

                if endpoint.getLocalID() != resp_msg.getArg(OPENID_NS, 'identity'):
                    return False

            if OPENID1_NS == resp_msg.getOpenIDNamespace():
                # LocalID or canonicalID must be the same as that of
                # the discovered URL.
                if endpoint.getLocalID() != identifier:
                    return False

            return (
                # Check server_url,
                (endpoint.server_url == orig_endpoint.server_url) and
                # Check protocol version of response message against
                # versions advertised.
                (resp_msg.getOpenIDNamespace() in endpoint.type_uris))

        services = filter(serviceMatches, services)

        if not services:
            #msg = ("Discovery information for %r does not include "
            #       "server %r." % (identifier, orig_endpoint.server_url))
            msg = ("Discovery information does not match response "
                   "message values")
            raise DiscoveryFailure(msg, None)

        return services[0]

    def _checkAuth(self, message, server_url):
        request = self._createCheckAuthRequest(message)
        if request is None:
            return False
        try:
            response = self._makeKVPost(request, server_url)
        except (fetchers.HTTPFetchingError, ServerError), e:
            oidutil.log('check_authentication failed: %s' % (e[0],))
            return False
        else:
            return self._processCheckAuthResponse(response, server_url)

    def _createCheckAuthRequest(self, message):
        # Arguments that are always passed to the server and not
        # included in the signature.
        whitelist = ['assoc_handle', 'sig', 'signed', 'invalidate_handle']

        # XXX: should really build a Message object here
        check_args = {}
        for k in whitelist:
            val = message.getArg(OPENID_NS, k)
            if val is not None:
                check_args[k] = val

        signed = message.getArg(OPENID_NS, 'signed')
        if signed:
            for k in signed.split(','):
                val = message.getArg(OPENID_NS, k)

                # Signed value is missing
                if val is None:
                    return None

                check_args[k] = val

        check_args['mode'] = 'check_authentication'
        return Message.fromOpenIDArgs(check_args)

    def _processCheckAuthResponse(self, response, server_url):
        is_valid = response.getArg(OPENID_NS, 'is_valid', 'false')

        invalidate_handle = response.getArg(OPENID_NS, 'invalidate_handle')
        if invalidate_handle is not None:
            self.store.removeAssociation(server_url, invalidate_handle)

        if is_valid == 'true':
            return True
        else:
            oidutil.log('Server responds that checkAuth call is not valid')
            return False

    def _getAssociation(self, endpoint):
        """Get an association for the endpoint's server_url.

        First try seeing if we have a good association in the
        store. If we do not, then attempt to negotiate an association
        with the server.

        If we negotiate a good association, it will get stored.

        @returns: A valid association for the endpoint's server_url or None
        @rtype: openid.association.Association or NoneType
        """
        if self.store.isDumb():
            return None

        assoc = self.store.getAssociation(endpoint.server_url)

        if assoc is None or assoc.expiresIn <= 0:
            assoc = self._negotiateAssociation(endpoint)
            if assoc is not None:
                self.store.storeAssociation(endpoint.server_url, assoc)

        return assoc

    def _negotiateAssociation(self, endpoint):
        """Make association requests to the server, attempting to
        create a new association.

        @returns: a new association object

        @rtype: openid.association.Association

        @raises: errors that the fetcher might raise. These are
            intended to be propagated up to the library's entrance point.
        """
        # Get our preferred session/association type from the negotiatior.
        assoc_type, session_type = self.negotiator.getAllowedType()

        try:
            assoc = self._requestAssociation(
                endpoint, assoc_type, session_type)
        except ServerError, why:
            # Any error message whose code is not 'unsupported-type'
            # should be considered a total failure.
            if why.error_code != 'unsupported-type' or \
                   why.message.isOpenID1():
                oidutil.log(
                    'Server error when requesting an association from %r: %s'
                    % (endpoint.server_url, why.error_text))
                return None

            # The server didn't like the association/session type
            # that we sent, and it sent us back a message that
            # might tell us how to handle it.
            oidutil.log(
                'Unsupported association type %s: %s' % (assoc_type,
                                                         why.error_text,))

            # Extract the session_type and assoc_type from the
            # error message
            assoc_type = why.message.getArg(OPENID_NS, 'assoc_type')
            session_type = why.message.getArg(OPENID_NS, 'session_type')

            if assoc_type is None or session_type is None:
                oidutil.log('Server responded with unsupported association '
                            'session but did not supply a fallback.')
                return None
            elif not self.negotiator.isAllowed(assoc_type, session_type):
                fmt = ('Server sent unsupported session/association type: '
                       'session_type=%s, assoc_type=%s')
                oidutil.log(fmt % (session_type, assoc_type))
                return None
            else:
                # Attempt to create an association from the assoc_type
                # and session_type that the server told us it
                # supported.
                try:
                    assoc = self._requestAssociation(
                        endpoint, assoc_type, session_type)
                except ServerError, why:
                    # Do not keep trying, since it rejected the
                    # association type that it told us to use.
                    oidutil.log('Server %s refused its suggested association '
                                'type: session_type=%s, assoc_type=%s'
                                % (endpoint.server_url, session_type,
                                   assoc_type))
                    return None
                else:
                    return assoc
        else:
            return assoc

    def _requestAssociation(self, endpoint, assoc_type, session_type):
        """Make and process one association request to this endpoint's
        OP endpoint URL.

        @returns: An association object or None if the association
            processing failed.

        @raises: ServerError
        """
        assoc_session, args = self._createAssociateRequest(
            endpoint, assoc_type, session_type)

        try:
            response = self._makeKVPost(args, endpoint.server_url)
        except fetchers.HTTPFetchingError, why:
            oidutil.log('openid.associate request failed: %s' % (why[0],))
            return None

        try:
            assoc = self._extractAssociation(response, assoc_session)
        except KeyError, why:
            oidutil.log('Missing required parameter in response from %s: %s'
                        % (endpoint.server_url, why[0]))
            return None
        except ProtocolError, why:
            oidutil.log('Protocol error parsing response from %s: %s' % (
                endpoint.server_url, why[0]))
            return None
        else:
            return assoc

    def _createAssociateRequest(self, endpoint, assoc_type, session_type):
        """Create an association request for the given assoc_type and
        session_type.

        @param endpoint: The endpoint whose server_url will be
            queried. The important bit about the endpoint is whether
            it's in compatiblity mode (OpenID 1.1)

        @param assoc_type: The association type that the request
            should ask for.
        @type assoc_type: str

        @param session_type: The session type that should be used in
            the association request. The session_type is used to
            create an association session object, and that session
            object is asked for any additional fields that it needs to
            add to the request.
        @type session_type: str

        @returns: a pair of the association session object and the
            request message that will be sent to the server.
        @rtype: (association session type (depends on session_type),
                 openid.message.Message)
        """
        session_type_class = self.session_types[session_type]
        assoc_session = session_type_class()

        args = {
            'mode': 'associate',
            'assoc_type': assoc_type,
            }

        if not endpoint.compatibilityMode():
            args['ns'] = OPENID2_NS

        # Leave out the session type if we're in compatibility mode
        # *and* it's no-encryption.
        if (not endpoint.compatibilityMode() or
            assoc_session.session_type != 'no-encryption'):
            args['session_type'] = assoc_session.session_type

        args.update(assoc_session.getRequest())
        message = Message.fromOpenIDArgs(args)
        return assoc_session, message

    def _getOpenID1SessionType(self, assoc_response):
        """Given an association response message, extract the OpenID
        1.X session type.

        This function mostly takes care of the 'no-encryption' default
        behavior in OpenID 1.

        If the association type is plain-text, this function will
        return 'no-encryption'

        @returns: The association type for this message
        @rtype: str

        @raises: KeyError, if the session_type field is absent.
        """
        # If it's an OpenID 1 message, allow session_type to default
        # to None (which signifies "no-encryption")
        session_type = assoc_response.getArg(OPENID1_NS, 'session_type')

        # Handle the differences between no-encryption association
        # respones in OpenID 1 and 2:

        # no-encryption is not really a valid session type for
        # OpenID 1, but we'll accept it anyway, while issuing a
        # warning.
        if session_type == 'no-encryption':
            oidutil.log('WARNING: OpenID server sent "no-encryption"'
                        'for OpenID 1.X')

        # Missing or empty session type is the way to flag a
        # 'no-encryption' response. Change the session type to
        # 'no-encryption' so that it can be handled in the same
        # way as OpenID 2 'no-encryption' respones.
        elif session_type == '' or session_type is None:
            session_type = 'no-encryption'

        return session_type

    def _extractAssociation(self, assoc_response, assoc_session):
        """Attempt to extract an association from the response, given
        the association response message and the established
        association session.

        @param assoc_response: The association response message from
            the server
        @type assoc_response: openid.message.Message

        @param assoc_session: The association session object that was
            used when making the request
        @type assoc_session: depends on the session type of the request

        @raises: ProtocolError, if data is malformed
        @raises: KeyError, if a field is missing

        @rtype: openid.association.Association
        """
        # Extract the common fields from the response, raising an
        # exception if they are not found
        assoc_type = assoc_response.getArg(
            OPENID_NS, 'assoc_type', no_default)
        assoc_handle = assoc_response.getArg(
            OPENID_NS, 'assoc_handle', no_default)

        # expires_in is a base-10 string. The Python parsing will
        # accept literals that have whitespace around them and will
        # accept negative values. Neither of these are really in-spec,
        # but we think it's OK to accept them.
        expires_in_str = assoc_response.getArg(
            OPENID_NS, 'expires_in', no_default)
        try:
            expires_in = int(expires_in_str)
        except ValueError, e:
            raise ProtocolError('Invalid expires_in field: %s' % (e[0],))

        # OpenID 1 has funny association session behaviour.
        if assoc_response.isOpenID1():
            session_type = self._getOpenID1SessionType(assoc_response)
        else:
            session_type = assoc_response.getArg(
                OPENID2_NS, 'session_type', no_default)

        # Session type mismatch
        if assoc_session.session_type != session_type:
            if (assoc_response.isOpenID1() and
                session_type == 'no-encryption'):
                # In OpenID 1, any association request can result in a
                # 'no-encryption' association response. Setting
                # assoc_session to a new no-encryption session should
                # make the rest of this function work properly for
                # that case.
                assoc_session = PlainTextConsumerSession()
            else:
                # Any other mismatch, regardless of protocol version
                # results in the failure of the association session
                # altogether.
                fmt = 'Session type mismatch. Expected %r, got %r'
                message = fmt % (assoc_session.session_type, session_type)
                raise ProtocolError(message)

        # Make sure assoc_type is valid for session_type
        if assoc_type not in assoc_session.allowed_assoc_types:
            fmt = 'Unsupported assoc_type for session %s returned: %s'
            raise ProtocolError(fmt % (assoc_session.session_type, assoc_type))

        # Delegate to the association session to extract the secret
        # from the response, however is appropriate for that session
        # type.
        try:
            secret = assoc_session.extractSecret(assoc_response)
        except ValueError, why:
            fmt = 'Malformed response for %s session: %s'
            raise ProtocolError(fmt % (assoc_session.session_type, why[0]))

        return Association.fromExpiresIn(
            expires_in, assoc_handle, secret, assoc_type)

class AuthRequest(object):
    def __init__(self, endpoint, assoc):
        """
        Creates a new AuthRequest object.  This just stores each
        argument in an appropriately named field.

        Users of this library should not create instances of this
        class.  Instances of this class are created by the library
        when needed.
        """
        self.assoc = assoc
        self.endpoint = endpoint
        self.return_to_args = {}
        self.message = Message()
        self.message.setOpenIDNamespace(endpoint.preferredNamespace())
        self._anonymous = False

    def setAnonymous(self, is_anonymous):
        """Set whether this request should be made anonymously. If a
        request is anonymous, the identifier will not be sent in the
        request. This is only useful if you are making another kind of
        request with an extension in this request.

        Anonymous requests are not allowed when the request is made
        with OpenID 1.

        @raises: ValueError when attempting to set an OpenID1 request
            as anonymous
        """
        if is_anonymous and self.message.isOpenID1():
            raise ValueError('OpenID 1 requests MUST include the '
                             'identifier in the request')
        else:
            self._anonymous = is_anonymous

    def addExtensionArg(self, namespace, key, value):
        """Add an extension argument to this OpenID authentication
        request.

        Use caution when adding arguments, because they will be
        URL-escaped and appended to the redirect URL, which can easily
        get quite long.

        @param namespace: The namespace for the extension. For
            example, the simple registration extension uses the
            namespace C{sreg}.

        @type namespace: str

        @param key: The key within the extension namespace. For
            example, the nickname field in the simple registration
            extension's key is C{nickname}.

        @type key: str

        @param value: The value to provide to the server for this
            argument.

        @type value: str
        """
        self.message.setArg(namespace, key, value)

    def getMessage(self, realm, return_to=None, immediate=False):
        """Not specifying a return_to URL means that the user will not
        be returned to the site issuing the request upon its
        completion."""
        if return_to:
            return_to = oidutil.appendArgs(return_to, self.return_to_args)
        elif immediate:
            raise ValueError(
                '"return_to" is mandatory when using "checkid_immediate"')
        elif self.message.isOpenID1():
            raise ValueError('"return_to" is mandatory for OpenID 1 requests')
        elif self.return_to_args:
            raise ValueError('extra "return_to" arguments were specified, '
                             'but no return_to was specified')

        if immediate:
            mode = 'checkid_immediate'
        else:
            mode = 'checkid_setup'

        message = self.message.copy()
        if message.isOpenID1():
            realm_key = 'trust_root'
        else:
            realm_key = 'realm'

        message.updateArgs(OPENID_NS,
            {
            realm_key:realm,
            'mode':mode,
            'return_to':return_to,
            })

        if not self._anonymous:
            if self.endpoint.isOPIdentifier():
                # This will never happen when we're in compatibility
                # mode, as long as isOPIdentifier() returns False
                # whenever preferredNamespace() returns OPENID1_NS.
                claimed_id = request_identity = IDENTIFIER_SELECT
            else:
                request_identity = self.endpoint.getLocalID()
                claimed_id = self.endpoint.claimed_id

            # This is true for both OpenID 1 and 2
            message.setArg(OPENID_NS, 'identity', request_identity)

            if message.isOpenID2():
                message.setArg(OPENID2_NS, 'claimed_id', claimed_id)

        if self.assoc:
            message.setArg(OPENID_NS, 'assoc_handle', self.assoc.handle)

        return message

    def redirectURL(self, realm, return_to=None, immediate=False):
        message = self.getMessage(realm, return_to, immediate)
        return message.toURL(self.endpoint.server_url)

    def formMarkup(self, realm, return_to=None, immediate=False,
            form_tag_attrs=None):
        """Get html for a form to submit this request to the IDP.

        @param form_tag_attrs: Dictionary of attributes to be added to
            the form tag. 'accept-charset' and 'enctype' have defaults
            that can be overridden. If a value is supplied for
            'action' or 'method', it will be replaced.
        @type form_tag_attrs: {unicode: unicode}
        """
        message = self.getMessage(realm, return_to, immediate)
        return message.toFormMarkup(self.endpoint.server_url,
                    form_tag_attrs)

FAILURE = 'failure'
SUCCESS = 'success'
CANCEL = 'cancel'
SETUP_NEEDED = 'setup_needed'

class Response(object):
    status = None

    def setEndpoint(self, endpoint):
        self.endpoint = endpoint
        if endpoint is None:
            self.identity_url = None
        else:
            self.identity_url = endpoint.claimed_id

class SuccessResponse(Response):
    """A response with a status of SUCCESS. Indicates that this request is a
    successful acknowledgement from the OpenID server that the
    supplied URL is, indeed controlled by the requesting agent.

    @ivar identity_url: The identity URL that has been authenticated

    @ivar endpoint: The endpoint that authenticated the identifier.  You
        may access other discovered information related to this endpoint,
        such as the CanonicalID of an XRI, through this object.
    @type endpoint: L{OpenIDServiceEndpoint<openid.consumer.discover.OpenIDServiceEndpoint>}

    @ivar signed_fields: The arguments in the server's response that
        were signed and verified.

    @cvar status: SUCCESS
    """

    status = SUCCESS

    def __init__(self, endpoint, message, signed_fields=None):
        # Don't use setEndpoint, because endpoint should never be None
        # for a successfull transaction.
        self.endpoint = endpoint
        self.identity_url = endpoint.claimed_id

        self.message = message

        if signed_fields is None:
            signed_fields = []
        self.signed_fields = signed_fields

    def isOpenID1(self):
        return self.message.isOpenID1()

    def isSigned(self, ns_uri, ns_key):
        """Return whether a particular key is signed, regardless of
        its namespace alias
        """
        return self.message.getKey(ns_uri, ns_key) in self.signed_fields

    def getSigned(self, ns_uri, ns_key, default=None):
        """Return the specified signed field if available,
        otherwise return default
        """
        if self.isSigned(ns_uri, ns_key):
            return self.message.getArg(ns_uri, ns_key, default)
        else:
            return default

    def getReturnTo(self):
        """Get the openid.return_to argument from this response.

        This is useful for verifying that this request was initiated
        by this consumer.

        @returns: The return_to URL supplied to the server on the
            initial request, or C{None} if the response did not contain
            an C{openid.return_to} argument.

        @returntype: str
        """
        return self.getSigned(OPENID_NS, 'return_to')



class FailureResponse(Response):
    """A response with a status of FAILURE. Indicates that the OpenID
    protocol has failed. This could be locally or remotely triggered.

    @ivar identity_url:  The identity URL for which authenitcation was
        attempted, if it can be determined. Otherwise, None.

    @ivar message: A message indicating why the request failed, if one
        is supplied. otherwise, None.

    @cvar status: FAILURE
    """

    status = FAILURE

    def __init__(self, endpoint, message=None, contact=None,
                 reference=None):
        self.setEndpoint(endpoint)
        self.message = message
        self.contact = contact
        self.reference = reference

    def __repr__(self):
        return "<%s.%s id=%r message=%r>" % (
            self.__class__.__module__, self.__class__.__name__,
            self.identity_url, self.message)


class CancelResponse(Response):
    """A response with a status of CANCEL. Indicates that the user
    cancelled the OpenID authentication request.

    @ivar identity_url: The identity URL for which authenitcation was
        attempted, if it can be determined. Otherwise, None.

    @cvar status: CANCEL
    """

    status = CANCEL

    def __init__(self, endpoint):
        self.setEndpoint(endpoint)

class SetupNeededResponse(Response):
    """A response with a status of SETUP_NEEDED. Indicates that the
    request was in immediate mode, and the server is unable to
    authenticate the user without further interaction.

    @ivar identity_url:  The identity URL for which authenitcation was
        attempted.

    @ivar setup_url: A URL that can be used to send the user to the
        server to set up for authentication. The user should be
        redirected in to the setup_url, either in the current window
        or in a new browser window.

    @cvar status: SETUP_NEEDED
    """

    status = SETUP_NEEDED

    def __init__(self, endpoint, setup_url=None):
        self.setEndpoint(endpoint)
        self.setup_url = setup_url
