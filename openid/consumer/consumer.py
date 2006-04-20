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
    the necessary data in several different ways, including several
    SQL databases and normal files on disk.

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

    When the application receives an OpenID URL, it needs to determine
    the OpenID server which is authoritative for that URL.  It gets an
    XXX object containing that information by doing XXX.

    Once the application has the XXX object, the next step is to get
    an C{L{OpenIDConsumer}} instance, and call its XXX method.  This
    method takes the XXX object and, optionally, a session object.  If
    the appliication has any sort of session framework that provides
    per-client state management, that should be used here.  The
    library just expects the session object to support a C{dict}-like
    interface, if it provided.  If no session object is provided, the
    application code needs to store the information that would have
    been put in the session in an alternate location.  See the
    documentation for the XXX call for more information.  The XXX
    method returns a C{L{OpenIDRequestBuilder}} object.

    Next, the application should call the
    C{L{buildRedirect<OpenIDRequestBuilder.buildRedirect>}} method on
    the C{L{OpenIDRequestBuilder}} object.  The return_to URL is the
    URL that the OpenID server will send the user back to after
    attempting to verify his or her identity.  The trust_root is the
    URL (or URL pattern) that identifies your web site to the user
    when he or she is authorizing it.  Send a redirect to the
    resulting URL to the user's browser.

    That's the first half of the authentication process.  The second
    half of the process is done after the user's ID server sends the
    user's browser a redirect back to your site to complete their
    login.

    When that happens, the user will contact your site at the URL
    given as the return_to URL to the
    C{L{buildRedirect<OpenIDRequestBuilder.buildRedirect>}} call made
    above.  The request will have several query parameters added to
    the URL by the identity server as the information necessary to
    finish the request.

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

from openid.consumer.discover import discover as openIDDiscover
from openid.consumer.discover import yadis_available
from openid import cryptutil
from openid import kvform
from openid import oidutil
from openid.association import Association
from openid.dh import DiffieHellman

__all__ = ['OpenIDAuthRequest', 'OpenIDConsumer', 'SuccessResponse',
           'SetupNeededResponse', 'CancelResponse', 'FailureResponse']

if yadis_available:
    from yadis.manager import Discovery

class OpenIDConsumer(object):
    session_key_prefix = "_openid_consumer_"

    _token = 'last_token'

    def __init__(self, session, store):
        self.session = session
        self.consumer = GenericOpenIDConsumer(store)
        self._token_key = self.session_key_prefix + self._token

    def begin(self, user_url):
        openid_url = oidutil.normalizeUrl(user_url)
        if yadis_available:
            disco = Discovery(self.session, openid_url, 'XXX')
            endpoint = disco.getNextService(openIDDiscover)
        else:
            _, endpoints = openIDDiscover(openid_url)
            if not endpoints:
                endpoint = None
            else:
                endpoint = endpoints[0]

        if endpoint is None:
            return None
        else:
            return self.beginWithoutDiscovery(endpoint)

    def beginWithoutDiscovery(self, endpoint):
        auth_req = self.consumer.begin(endpoint)
        self.session[self._token_key] = auth_req.token
        return auth_req

    def complete(self, query):
        token = self.session.get(self._token_key)
        if token is None:
            response = FailureResponse(None, 'No session state found')
        else:
            response = self.consumer.complete(query, token)

        if response.status in ['success',
                               'cancel'#maybe
                               ]:
            if yadis_available and response.identity_url is not None:
                disco = Discovery(self.session, response.identity_url)
                # This is OK to do even if we did not do discovery in
                # the first place.
                disco.cleanup()

        return response

class GenericOpenIDConsumer(object):
    """This is the implementation of the common logic for OpenID
    consumers. It is unaware of the application in which it is
    running.
    """

    TOKEN_LIFETIME = 60 * 5 # five minutes
    NONCE_LEN = 8
    NONCE_CHRS = string.letters + string.digits

    def __init__(self, store):
        """
        This method initializes a new C{L{OpenIDConsumer}} instance to
        access the library.

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

        """
        self.store = store

    def begin(self, service_endpoint):
        nonce = self._createNonce()
        token = self._genToken(
            nonce,
            service_endpoint.identity_url,
            service_endpoint.getServerID(),
            service_endpoint.server_url,
            )
        assoc = self._getAssociation(service_endpoint.server_url)
        return OpenIDAuthRequest(token, assoc, service_endpoint)

    def complete(self, query, token):
        mode = query.get('openid.mode', '<no mode specified>')

        # Get the current request's state
        try:
            pieces = self._splitToken(token)
        except ValueError, why:
            oidutil.log(why[0])
            pieces = (None, None, None, None, None)

        (nonce, identity_url, delegate, server_url) = pieces

        if mode == 'cancel':
            return CancelResponse(identity_url)
        elif mode == 'error':
            error = query.get('openid.error')
            return FailureResponse(identity_url, error)
        elif mode == 'id_res':
            if identity_url is None:
                return FailureResponse(identity_url, 'No session state found')
            try:
                response = self._doIdRes(
                    query, identity_url, delegate, server_url)
            except fetchers.HTTPFetchingError, why:
                message = 'HTTP request failed: %s' % (str(why),)
                return FailureResponse(identity_url, message)
            else:
                if (response.status == 'success' and
                    not self.store.useNonce(nonce)):

                    return FailureResponse(identity_url, 'Nonce already used')
                else:
                    return response
        else:
            return FailureResponse(identity_url,
                                   'Invalid openid.mode: %r' % (mode,))

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

    def _doIdRes(self, query, consumer_id, server_id, server_url):
        user_setup_url = query.get('openid.user_setup_url')
        if user_setup_url is not None:
            return SetupNeededResponse(consumer_id, user_setup_url)

        return_to = query.get('openid.return_to')
        server_id2 = query.get('openid.identity')
        assoc_handle = query.get('openid.assoc_handle')

        if return_to is None or server_id is None or assoc_handle is None:
            return FailureResponse(consumer_id, 'Missing required field')

        if server_id != server_id2:
            return FailureResponse(consumer_id, 'Server ID (delegate) mismatch')

        signed = query.get('openid.signed')

        assoc = self.store.getAssociation(server_url, assoc_handle)

        if assoc is None:
            # It's not an association we know about.  Dumb mode is our
            # only possible path for recovery.
            if self._checkAuth(query, server_url):
                return SuccessResponse.fromQuery(consumer_id, query, signed)
            else:
                return FailureResponse(consumer_id,
                                       'Server denied check_authentication')

        if assoc.expiresIn <= 0:
            # XXX: It might be a good idea sometimes to re-start the
            # authentication with a new association. Doing it
            # automatically opens the possibility for
            # denial-of-service by a server that just returns expired
            # associations (or really short-lived associations)
            msg = 'Association with %s expired' % (server_url,)
            return FailureResponse(consumer_id, msg)

        # Check the signature
        sig = query.get('openid.sig')
        if sig is None or signed is None:
            return FailureResponse(consumer_id, 'Missing argument signature')

        signed_list = signed.split(',')
        v_sig = assoc.signDict(signed_list, query)

        if v_sig != sig:
            return FailureResponse(consumer_id, 'Bad signature')

        return SuccessResponse.fromQuery(consumer_id, query, signed)

    def _checkAuth(self, query, server_url):
        request = self._createCheckAuthRequest(query)
        if request is None:
            return False
        response = self._makeKVPost(request, server_url)
        if response is None:
            return False
        return self._processCheckAuthResponse(response)

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

    def _processCheckAuthResponse(self, response):
        is_valid = response.get('is_valid', 'false')

        if is_valid == 'true':
            invalidate_handle = response.get('invalidate_handle')
            if invalidate_handle is not None:
                self.store.removeAssociation(server_url, invalidate_handle)

            return True

        oidutil.log('Server responds that checkAuth call is not valid')
        return False

    def _getAssociation(self, server_url):
        if self.store.isDumb():
            return None

        assoc = self.store.getAssociation(server_url)

        if assoc is None or assoc.expiresIn < self.TOKEN_LIFETIME:
            proto = urlparse(server_url)[0]
            if proto == 'https':
                dh = None
            else:
                dh = DiffieHellman()

            args = self._createAssociateRequest(dh)
            try:
                response = self._makeKVPost(args, server_url)
            except fetchers.HTTPFetchingError, why:
                oidutil.log('openid.associate request failed: %s' %
                            (str(why),))
                assoc = None
            else:
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
            raise ValueError('Bad token length: %d' % len(token))

        sig, joined = token[:20], token[20:]
        if cryptutil.hmacSha1(self.store.getAuthKey(), joined) != sig:
            raise ValueError('Bad token signature')

        split = joined.split('\x00')
        if len(split) != 5:
            raise ValueError('Bad token contents (not enough fields)')

        try:
            ts = int(split[0])
        except ValueError:
            raise ValueError('Bad token contents (timestamp bad)')

        if ts + self.TOKEN_LIFETIME < time.time():
            raise ValueError('Token expired')

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

class OpenIDAuthRequest(object):
    def __init__(self, token, assoc, endpoint):
        """
        Creates a new OpenIDAuthRequest object.  This just stores each
        argument in an appropriately named field.

        Users of this library should not create instances of this
        class.  Instances of this class are created by the library
        when needed.
        """
        self.assoc = assoc
        self.endpoint = endpoint
        self.extra_args = {}
        self.token = token

    def addExtensionArg(self, namespace, key, value):
        arg_name = '.'.join('openid', namespace, key)
        self.extra_args[arg_name] = value

    def redirectURL(self, trust_root, return_to, immediate=False):
        if immediate:
            mode = 'checkid_immediate'
        else:
            mode = 'checkid_setup'

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

class OpenIDConsumerResponse(object):
    status = None

class SuccessResponse(OpenIDConsumerResponse):
    status = 'success'

    def __init__(self, identity_url, signed_args):
        self.identity_url = identity_url
        self.signed_args = signed_args

    def fromQuery(cls, identity_url, query, signed):
        signed_args = {}
        for field_name in signed.split(','):
            signed_args[field_name] = query.get(field_name, '')
        return cls(identity_url, signed_args)

    fromQuery = classmethod(fromQuery)

    def extensionResponse(self, prefix):
        response = {}
        prefix = 'openid.%s.' % (prefix,)
        prefix_len = len(prefix)
        for k, v in self.signed_args.iteritems():
            if k.startswith(prefix):
                response_key = k[prefix_len:]
                response[response_key] = v

        return response

class FailureResponse(OpenIDConsumerResponse):
    status = 'failure'

    def __init__(self, identity_url=None, message=None):
        self.identity_url = identity_url
        self.message = message

class CancelResponse(OpenIDConsumerResponse):
    status = 'cancelled'

    def __init__(self, identity_url=None):
        self.identity_url = identity_url

class SetupNeededResponse(OpenIDConsumerResponse):
    status = 'setup_needed'

    def __init__(self, identity_url=None, setup_url=None):
        self.identity_url = identity_url
        self.setup_url = setup_url
