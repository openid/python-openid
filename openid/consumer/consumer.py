# -*- test-case-name: openid.test.consumer -*-
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
    to verify his or her identity.  The C{trust_root} parameter is the
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

import string
import time
import urllib
import cgi
from urlparse import urlparse

from urljr import fetchers

from openid.consumer.discover import discover as openIDDiscover
from openid.consumer.discover import discoverXRI
from openid.consumer.discover import yadis_available, DiscoveryFailure
from openid import cryptutil
from openid import kvform
from openid import oidutil
from openid.association import Association
from openid.dh import DiffieHellman

__all__ = ['AuthRequest', 'Consumer', 'SuccessResponse',
           'SetupNeededResponse', 'CancelResponse', 'FailureResponse',
           'SUCCESS', 'FAILURE', 'CANCEL', 'SETUP_NEEDED',
           ]

if yadis_available:
    from yadis.manager import Discovery
    from yadis import xri

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

    def begin(self, user_url):
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
        if yadis_available and xri.identifierScheme(user_url) == "XRI":
            discoverMethod = discoverXRI
            openid_url = user_url
        else:
            discoverMethod = openIDDiscover
            openid_url = oidutil.normalizeUrl(user_url)

        if yadis_available:
            try:
                disco = Discovery(self.session,
                                  openid_url,
                                  self.session_key_prefix)
                service = disco.getNextService(discoverMethod)
            except fetchers.HTTPFetchingError, e:
                raise DiscoveryFailure('Error fetching XRDS document', e)
        else:
            # XXX - Untested branch!
            _, services = openIDDiscover(user_url)
            if not services:
                service = None
            else:
                service = services[0]

        if service is None:
            raise DiscoveryFailure(
                'No usable OpenID services found for %s' % (openid_url,), None)
        else:
            return self.beginWithoutDiscovery(service)

    def beginWithoutDiscovery(self, service):
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
        return auth_req

    def complete(self, query):
        """Called to interpret the server's response to an OpenID
        request. It is called in step 4 of the flow described in the
        consumer overview.

        @param query: A dictionary of the query parameters for this
            HTTP request.

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
            response = self.consumer.complete(query, endpoint)
            del self.session[self._token_key]

        if (response.status in ['success', 'cancel'] and
            yadis_available and
            response.identity_url is not None):

            disco = Discovery(self.session,
                              response.identity_url,
                              self.session_key_prefix)
            # This is OK to do even if we did not do discovery in
            # the first place.
            disco.cleanup()

        return response

class DiffieHellmanConsumerSession(object):
    session_type = 'DH-SHA1'

    def __init__(self, dh=None):
        if dh is None:
            dh = DiffieHellman.fromDefaults()

        self.dh = dh

    def getRequest(self):
        cpub = cryptutil.longToBase64(self.dh.public)

        args = {'openid.dh_consumer_public': cpub}

        if not self.dh.usingDefaultValues():
            args.update({
                'openid.dh_modulus': cryptutil.longToBase64(self.dh.modulus),
                'openid.dh_gen': cryptutil.longToBase64(self.dh.generator),
                })

        return args

    def extractSecret(self, response):
        spub = cryptutil.base64ToLong(response['dh_server_public'])
        enc_mac_key = oidutil.fromBase64(response['enc_mac_key'])
        return self.dh.xorSecret(spub, enc_mac_key)

class PlainTextConsumerSession(object):
    session_type = None

    def getRequest(self):
        return {}

    def extractSecret(self, response):
        return oidutil.fromBase64(response['mac_key'])

class GenericConsumer(object):
    """This is the implementation of the common logic for OpenID
    consumers. It is unaware of the application in which it is
    running.
    """

    NONCE_LEN = 8
    NONCE_CHRS = string.ascii_letters + string.digits

    def __init__(self, store):
        self.store = store

    def begin(self, service_endpoint):
        nonce = self._createNonce()
        assoc = self._getAssociation(service_endpoint.server_url)
        request = AuthRequest(service_endpoint, assoc)
        request.return_to_args['nonce'] = nonce
        return request

    def complete(self, query, endpoint):
        mode = query.get('openid.mode', '<no mode specified>')

        if isinstance(mode, list):
            raise TypeError("query dict must have one value for each key, "
                            "not lists of values.  Query is %r" % (query,))

        if mode == 'cancel':
            return CancelResponse(endpoint)
        elif mode == 'error':
            error = query.get('openid.error')
            return FailureResponse(endpoint, error)
        elif mode == 'id_res':
            if endpoint.identity_url is None:
                return FailureResponse(endpoint, 'No session state found')
            try:
                response = self._doIdRes(query, endpoint)
            except fetchers.HTTPFetchingError, why:
                message = 'HTTP request failed: %s' % (str(why),)
                return FailureResponse(endpoint, message)
            else:
                if response.status == 'success':
                    return self._checkNonce(response, query.get('nonce'))
                else:
                    return response
        else:
            return FailureResponse(endpoint,
                                   'Invalid openid.mode: %r' % (mode,))

    def _checkNonce(self, response, nonce):
        parsed_url = urlparse(response.getReturnTo())
        query = parsed_url[4]
        for k, v in cgi.parse_qsl(query):
            if k == 'nonce':
                if v != nonce:
                    return FailureResponse(response, 'Nonce mismatch')
                else:
                    break
        else:
            return FailureResponse(response, 'Nonce missing from return_to: %r'
                                   % (response.getReturnTo()))

        # The nonce matches the signed nonce in the openid.return_to
        # response parameter
        if not self.store.useNonce(nonce):
            return FailureResponse(response,
                                   'Nonce missing from store')

        # If the nonce check succeeded, return the original success
        # response
        return response

    def _createNonce(self):
        nonce = cryptutil.randomString(self.NONCE_LEN, self.NONCE_CHRS)
        self.store.storeNonce(nonce)
        return nonce

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
            server_error = response.get('error', '<no message from server>')
            fmt = 'openid.mode=%s: error returned from server %s: %s'
            oidutil.log(fmt % (mode, server_url, server_error))
            return None
        elif resp.status != 200:
            fmt = 'openid.mode=%s: bad status code from server %s: %s'
            oidutil.log(fmt % (mode, server_url, resp.status))
            return None

        return response

    def _doIdRes(self, query, endpoint):
        """Handle id_res responses.

        @param query: the response paramaters.
        @param consumer_id: The normalized Claimed Identifier.
        @param server_id: The Delegate Identifier.
        @param server_url: OpenID server endpoint URL.

        @returntype: L{Response}
        """
        user_setup_url = query.get('openid.user_setup_url')
        if user_setup_url is not None:
            return SetupNeededResponse(endpoint, user_setup_url)

        return_to = query.get('openid.return_to')
        server_id2 = query.get('openid.identity')
        assoc_handle = query.get('openid.assoc_handle')

        if return_to is None or server_id2 is None or assoc_handle is None:
            return FailureResponse(endpoint, 'Missing required field')

        if endpoint.getServerID() != server_id2:
            return FailureResponse(endpoint, 'Server ID (delegate) mismatch')

        signed = query.get('openid.signed')

        assoc = self.store.getAssociation(endpoint.server_url, assoc_handle)

        if assoc is None:
            # It's not an association we know about.  Dumb mode is our
            # only possible path for recovery.
            if self._checkAuth(query, endpoint.server_url):
                return SuccessResponse.fromQuery(endpoint, query, signed)
            else:
                return FailureResponse(endpoint,
                                       'Server denied check_authentication')

        if assoc.expiresIn <= 0:
            # XXX: It might be a good idea sometimes to re-start the
            # authentication with a new association. Doing it
            # automatically opens the possibility for
            # denial-of-service by a server that just returns expired
            # associations (or really short-lived associations)
            msg = 'Association with %s expired' % (endpoint.server_url,)
            return FailureResponse(endpoint, msg)

        # Check the signature
        sig = query.get('openid.sig')
        if sig is None or signed is None:
            return FailureResponse(endpoint, 'Missing argument signature')

        signed_list = signed.split(',')

        # Fail if the identity field is present but not signed
        if endpoint.identity_url is not None and 'identity' not in signed_list:
            msg = '"openid.identity" not signed'
            return FailureResponse(endpoint, msg)

        v_sig = assoc.signDict(signed_list, query)

        if v_sig != sig:
            return FailureResponse(endpoint, 'Bad signature')

        return SuccessResponse.fromQuery(endpoint, query, signed)

    def _checkAuth(self, query, server_url):
        request = self._createCheckAuthRequest(query)
        if request is None:
            return False
        response = self._makeKVPost(request, server_url)
        if response is None:
            return False
        return self._processCheckAuthResponse(response, server_url)

    def _createCheckAuthRequest(self, query):
        signed = query.get('openid.signed')
        if signed is None:
            oidutil.log('No signature present; checkAuth aborted')
            return None

        # Arguments that are always passed to the server and not
        # included in the signature.
        whitelist = ['assoc_handle', 'sig', 'signed', 'invalidate_handle']
        signed = signed.split(',') + whitelist

        check_args = dict([(k, v) for k, v in query.iteritems()
                           if k.startswith('openid.') and k[7:] in signed])

        check_args['openid.mode'] = 'check_authentication'
        return check_args

    def _processCheckAuthResponse(self, response, server_url):
        is_valid = response.get('is_valid', 'false')

        invalidate_handle = response.get('invalidate_handle')
        if invalidate_handle is not None:
            self.store.removeAssociation(server_url, invalidate_handle)

        if is_valid == 'true':
            return True
        else:
            oidutil.log('Server responds that checkAuth call is not valid')
            return False

    def _getAssociation(self, server_url):
        if self.store.isDumb():
            return None

        assoc = self.store.getAssociation(server_url)

        if assoc is None or assoc.expiresIn <= 0:
            assoc_session, args = self._createAssociateRequest(server_url)
            try:
                response = self._makeKVPost(args, server_url)
            except fetchers.HTTPFetchingError, why:
                oidutil.log('openid.associate request failed: %s' %
                            (str(why),))
                assoc = None
            else:
                assoc = self._parseAssociation(
                    response, assoc_session, server_url)

        return assoc

    def _createAssociateRequest(self, server_url):
        proto = urlparse(server_url)[0]
        if proto == 'https':
            session_type = PlainTextConsumerSession
        else:
            session_type = DiffieHellmanConsumerSession

        assoc_session = session_type()

        args = {
            'openid.mode': 'associate',
            'openid.assoc_type':'HMAC-SHA1',
            }

        if assoc_session.session_type is not None:
            args['openid.session_type'] = assoc_session.session_type

        args.update(assoc_session.getRequest())
        return assoc_session, args

    def _parseAssociation(self, results, assoc_session, server_url):
        try:
            assoc_type = results['assoc_type']
            assoc_handle = results['assoc_handle']
            expires_in_str = results['expires_in']
        except KeyError, e:
            fmt = 'Getting association: missing key in response from %s: %s'
            oidutil.log(fmt % (server_url, e[0]))
            return None

        if assoc_type != 'HMAC-SHA1':
            fmt = 'Unsupported assoc_type returned from server %s: %s'
            oidutil.log(fmt % (server_url, assoc_type))
            return None

        try:
            expires_in = int(expires_in_str)
        except ValueError, e:
            fmt = 'Getting Association: invalid expires_in field: %s'
            oidutil.log(fmt % (e[0],))
            return None

        session_type = results.get('session_type')
        if session_type != assoc_session.session_type:
            if session_type is None:
                oidutil.log('Falling back to plain text association '
                            'session from %s' % assoc_session.session_type)
                assoc_session = PlainTextConsumerSession()
            else:
                oidutil.log('Session type mismatch. Expected %r, got %r' %
                            (assoc_session.session_type, session_type))
                return None

        try:
            secret = assoc_session.extractSecret(results)
        except ValueError, why:
            oidutil.log('Malformed response for %s session: %s' % (
                assoc_session.session_type, why[0]))
            return None
        except KeyError, why:
            fmt = 'Getting association: missing key in response from %s: %s'
            oidutil.log(fmt % (server_url, why[0]))
            return None

        assoc = Association.fromExpiresIn(
            expires_in, assoc_handle, secret, assoc_type)
        self.store.storeAssociation(server_url, assoc)

        return assoc

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
        self.extra_args = {}
        self.return_to_args = {}

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
        arg_name = '.'.join(['openid', namespace, key])
        self.extra_args[arg_name] = value

    def redirectURL(self, trust_root, return_to, immediate=False):
        if immediate:
            mode = 'checkid_immediate'
        else:
            mode = 'checkid_setup'

        return_to = oidutil.appendArgs(return_to, self.return_to_args)

        redir_args = {
            'openid.mode': mode,
            'openid.identity': self.endpoint.getServerID(),
            'openid.return_to': return_to,
            'openid.trust_root': trust_root,
            }

        if self.assoc:
            redir_args['openid.assoc_handle'] = self.assoc.handle

        redir_args.update(self.extra_args)
        return oidutil.appendArgs(self.endpoint.server_url, redir_args)

FAILURE = 'failure'
SUCCESS = 'success'
CANCEL = 'cancel'
SETUP_NEEDED = 'setup_needed'

class Response(object):
    status = None

class SuccessResponse(Response):
    """A response with a status of SUCCESS. Indicates that this request is a
    successful acknowledgement from the OpenID server that the
    supplied URL is, indeed controlled by the requesting agent.

    @ivar identity_url: The identity URL that has been authenticated

    @ivar endpoint: The endpoint that authenticated the identifier.  You
        may access other discovered information related to this endpoint,
        such as the CanonicalID of an XRI, through this object.
    @type endpoint: L{OpenIDServiceEndpoint<openid.consumer.discover.OpenIDServiceEndpoint>}

    @ivar signed_args: The arguments in the server's response that
        were signed and verified.

    @cvar status: SUCCESS
    """

    status = SUCCESS

    def __init__(self, endpoint, signed_args):
        self.endpoint = endpoint
        self.identity_url = endpoint.identity_url
        self.signed_args = signed_args

    def fromQuery(cls, endpoint, query, signed):
        signed_args = {}
        for field_name in signed.split(','):
            field_name = 'openid.' + field_name
            signed_args[field_name] = query.get(field_name, '')
        return cls(endpoint, signed_args)

    fromQuery = classmethod(fromQuery)

    def extensionResponse(self, prefix):
        """extract signed extension data from the server's response.

        @param prefix: The extension namespace from which to extract
            the extension data.
        """
        response = {}
        prefix = 'openid.%s.' % (prefix,)
        prefix_len = len(prefix)
        for k, v in self.signed_args.iteritems():
            if k.startswith(prefix):
                response_key = k[prefix_len:]
                response[response_key] = v

        return response

    def getReturnTo(self):
        """Get the openid.return_to argument from this response.

        This is useful for verifying that this request was initiated
        by this consumer.

        @returns: The return_to URL supplied to the server on the
            initial request, or C{None} if the response did not contain
            an C{openid.return_to} argument.

        @returntype: str
        """
        return self.signed_args.get('openid.return_to', None)



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

    def __init__(self, endpoint, message=None):
        self.endpoint = endpoint
        if endpoint is not None:
            self.identity_url = endpoint.identity_url
        else:
            self.identity_url = None
        self.message = message


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
        self.endpoint = endpoint
        self.identity_url = endpoint.identity_url

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
        self.endpoint = endpoint
        self.identity_url = endpoint.identity_url
        self.setup_url = setup_url
