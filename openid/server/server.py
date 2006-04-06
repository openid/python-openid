"""
Overview
========

    An OpenID server must perform three tasks:

        1. Examine the incoming request to determine its nature and validity.

        2. Make a decision about how to respond to this request.

        3. Format the response according to the protocol.

    The first and last of these tasks may performed by
    the L{decodeRequest<OpenIDServer.decodeRequest>} and
    L{encodeResponse<OpenIDServer.encodeResponse>} methods of the
    L{OpenIDServer} object.  Who gets to do the remaining task -- deciding how
    to respond to the request -- will depend on what type of request it is.

    If it's a request to authenticate a user (a X{C{checkid_setup}} or
    X{C{checkid_immediate}} request), you need to decide if you will assert
    that this user may claim the identity in question.  Exactly how you do
    that is a matter of application policy, but it generally involves making
    sure the user has an account with your system and is logged in, checking
    to see if that identity is hers to claim, and verifying with the user that
    she does consent to releasing that information to the party making the
    request.

    Examine the properties of the L{CheckIDRequest} object, and if and when
    you've come to a decision about their claim, form a response by calling
    L{CheckIDRequest.answer}.

    Other types of requests relate to establishing associations between client
    and server and verifing the authenticity of previous communications.
    L{OpenIDServer} contains all the logic and data necessary to respond to
    such requests; just pass it to L{OpenIDServer.handleRequest}.


OpenID Extensions
=================

    FIXME


Library Design
==============

    FIXME

        - Requests
        - Responses
        - WebResponse

        - Decoder
        - Encoder
        - Signatory

        - Server

Stores
======

    The OpenID server needs to maintain state between requests in order
    to function.  Its mechanism for doing this is called a store.  The
    store interface is defined in C{L{openid.store.interface.OpenIDStore}}.
    Additionally, several concrete store implementations are provided, so that
    most sites won't need to implement a custom store.  For a store backed
    by flat files on disk, see C{L{openid.store.filestore.FileOpenIDStore}}.
    For stores based on MySQL or SQLite, see the C{L{openid.store.sqlstore}}
    module.

@group Requests: OpenIDRequest, AssociateRequest, CheckIDRequest,
    CheckAuthRequest

@group Responses: OpenIDResponse, CheckIDResponse

@group HTTP Codes: HTTP_OK, HTTP_REDIRECT, HTTP_ERROR

@group Response Encodings: ENCODE_KVFORM, ENCODE_URL
"""

import time
from copy import deepcopy

from openid import cryptutil
from openid import kvform
from openid import oidutil
from openid.dh import DiffieHellman
from openid.server.trustroot import TrustRoot
from openid.association import Association

HTTP_OK = 200
HTTP_REDIRECT = 302
HTTP_ERROR = 400

BROWSER_REQUEST_MODES = ['checkid_setup', 'checkid_immediate']
OPENID_PREFIX = 'openid.'

ENCODE_KVFORM = ('kvform',)
ENCODE_URL = ('URL/redirect',)

class OpenIDRequest(object):
    """I represent an incoming OpenID request.

    @cvar mode: the C{X{openid.mode}} of this request.
    @type mode: str
    """
    mode = None

class CheckAuthRequest(OpenIDRequest):
    """
    @type assoc_handle: str
    @type sig: str
    @type signed: list of pairs
    @type invalidate_handle: str
    """
    mode = "check_authentication"
    invalidate_handle = None

    def __init__(self, assoc_handle, sig, signed, invalidate_handle=None):
        self.assoc_handle = assoc_handle
        self.sig = sig
        self.signed = signed
        if invalidate_handle is not None:
            self.invalidate_handle = invalidate_handle

    def fromQuery(klass, query):
        self = klass.__new__(klass)
        try:
            self.assoc_handle = query[OPENID_PREFIX + 'assoc_handle']
            self.sig = query[OPENID_PREFIX + 'sig']
            signed_list = query[OPENID_PREFIX + 'signed']
        except KeyError, e:
            raise ProtocolError(query,
                                text="%s request missing required parameter %s"
                                " from query %s" %
                                (self.mode, e.args[0], query))
        signed_list = signed_list.split(',')
        signed_pairs = []
        for field in signed_list:
            try:
                if field == 'mode':
                    # XXX KLUDGE HAX WEB PROTOCoL BR0KENNN
                    # openid.mode is currently check_authentication because
                    # that's the mode of this request.  But the signature
                    # was made on something with a different openid.mode.
                    value = "id_res"
                else:
                    value = query[OPENID_PREFIX + field]
            except KeyError, e:
                raise ProtocolError(
                    query,
                    text="Couldn't find signed field %r in query %s"
                    % (field, query))
            else:
                signed_pairs.append((field, value))

        self.signed = signed_pairs
        return self

    fromQuery = classmethod(fromQuery)

    def answer(self, signatory):
        is_valid = signatory.verify(self.assoc_handle, self.sig, self.signed)
        # Now invalidate that assoc_handle so it this checkAuth message cannot
        # be replayed.
        signatory.invalidate(self.assoc_handle, dumb=True)
        response = OpenIDResponse(self)
        response.fields['is_valid'] = (is_valid and "true") or "false"

        if self.invalidate_handle:
            assoc = signatory.getAssociation(self.invalidate_handle, dumb=False)
            if not assoc:
                response.fields['invalidate_handle'] = self.invalidate_handle
        return response

    def __str__(self):
        if self.invalidate_handle:
            ih = " invalidate? %r" % (self.invalidate_handle,)
        else:
            ih = ""
        s = "<%s handle: %r sig: %r: signed: %r%s>" % (
            self.__class__.__name__, self.assoc_handle,
            self.sig, self.signed, ih)
        return s

class AssociateRequest(OpenIDRequest):
    mode = "associate"
    session_type = 'plaintext'
    assoc_type = 'HMAC-SHA1'

    def fromQuery(klass, query):
        self = AssociateRequest()
        session_type = query.get(OPENID_PREFIX + 'session_type')
        if session_type:
            self.session_type = session_type
            if session_type == 'DH-SHA1':
                try:
                    self.pubkey = cryptutil.base64ToLong(
                        query[OPENID_PREFIX + 'dh_consumer_public'])
                except KeyError, e:
                    raise ProtocolError(
                        query,
                        text="Public key for DH-SHA1 session "
                        "not found in query %s" % (query,))
                # FIXME: Missing dh_modulus and dh_gen options.
        return self

    fromQuery = classmethod(fromQuery)

    def answer(self, assoc):
        response = OpenIDResponse(self)
        response.fields.update({
            'expires_in': '%d' % (assoc.getExpiresIn(),),
            'assoc_type': 'HMAC-SHA1',
            'assoc_handle': assoc.handle,
            })
        if self.session_type == 'DH-SHA1':
            # XXX - get dh_modulus and dh_gen
            dh = DiffieHellman()
            mac_key = dh.xorSecret(self.pubkey, assoc.secret)
            response.fields.update({
                'session_type': self.session_type,
                'dh_server_public': cryptutil.longToBase64(dh.public),
                'enc_mac_key': oidutil.toBase64(mac_key),
                })
        elif self.session_type == 'plaintext':
            response.fields['mac_key'] = oidutil.toBase64(assoc.secret)
        else:
            # XXX - kablooie
            pass
        return response

class CheckIDRequest(OpenIDRequest):
    """A CheckID Request.

    @type mode: str
    @type immediate: bool
    @type identity: str
    @type trust_root: str
    @type return_to: str
    @type assoc_handle: str
    """
    mode = "checkid_setup" or "checkid_immediate"

    immediate = False

    trust_root = None
    assoc_handle = None

    def __init__(self, identity, return_to, trust_root=None,
                 immediate=False):
        self.identity = identity
        self.return_to = return_to
        self.trust_root = trust_root
        if immediate:
            self.immediate = True
            self.mode = "checkid_immediate"
        else:
            self.immediate = False
            self.mode = "checkid_setup"

        if not TrustRoot.parse(self.return_to):
            raise MalformedReturnURL(None, self.return_to)


    def fromQuery(klass, query):
        self = klass.__new__(klass)
        mode = query[OPENID_PREFIX + 'mode']
        if mode == "checkid_immediate":
            self.immediate = True
            self.mode = "checkid_immediate"
        else:
            self.immediate = False
            self.mode = "checkid_setup"

        required = [
            'identity',
            'return_to',
            ]
        optional = [
            'trust_root',
            'assoc_handle',
            ]

        for field in required:
            value = query.get(OPENID_PREFIX + field)
            if not value:
                raise ProtocolError(
                    query,
                    text="Missing required field %s from %r"
                    % (field, query))
            setattr(self, field, value)

        for field in optional:
            value = query.get(OPENID_PREFIX + field)
            if value:
                setattr(self, field, value)

        if not TrustRoot.parse(self.return_to):
            raise MalformedReturnURL(query, self.return_to)

        return self

    fromQuery = classmethod(fromQuery)


    def trustRootValid(self):
        """Is my return_to under my trust_root?

        @returntype: bool
        """
        if not self.trust_root:
            return True
        tr = TrustRoot.parse(self.trust_root)
        if tr is None:
            raise MalformedTrustRoot(None, self.trust_root)
        return tr.validateURL(self.return_to)

    def answer(self, allow, setup_url=None):
        if allow or self.immediate:
            mode = 'id_res'
        else:
            mode = 'cancel'

        response = CheckIDResponse(self, mode)

        if allow:
            response.fields['identity'] = self.identity
            response.fields['return_to'] = self.return_to
            if not self.trustRootValid():
                raise UntrustedReturnURL(self.return_to, self.trust_root)
        else:
            response.signed[:] = []
            if self.immediate:
                if not setup_url:
                    raise ValueError("setup_url is required for allow=False "
                                     "in immediate mode.")
                response.fields['user_setup_url'] = setup_url

        return response


    def getCancelURL(self):
        """Get the URL to cancel this request.

        Useful for creating a "Cancel" button on a web form so that operation
        can be carried out directly without another trip through the server.

        @returntype: str
        @returns: The return_to URL with openid.mode = cancel.
        """
        if self.immediate:
            raise ValueError("Cancel is not an appropriate response to "
                             "immediate mode requests.")
        return oidutil.appendArgs(self.return_to, {OPENID_PREFIX + 'mode':
                                                   'cancel'})


    def __str__(self):
        return '<%s id:%r im:%s tr:%r ah:%r>' % (self.__class__.__name__,
                                                 self.identity,
                                                 self.immediate,
                                                 self.trust_root,
                                                 self.assoc_handle)

class OpenIDResponse(object):
    """
    @type request: L{OpenIDRequest}
    @type fields: dict
    """
    def __init__(self, request):
        self.request = request
        self.fields = {}

    def __str__(self):
        return "%s for %s: %s" % (
            self.__class__.__name__,
            self.request.__class__.__name__,
            self.fields)


    # implements IEncodable

    def whichEncoding(self):
        if self.request.mode in BROWSER_REQUEST_MODES:
            return ENCODE_URL
        else:
            return ENCODE_KVFORM


    def encodeToURL(self):
        """Encode a response as a URL for redirection.

        @param response: The response to encode.
        @type response: L{OpenIDResponse}

        @returns: A URL to direct the user agent back to.
        @returntype: str
        """
        fields = dict(
            [(OPENID_PREFIX + k, v) for k, v in self.fields.iteritems()])
        return oidutil.appendArgs(self.request.return_to, fields)


    def encodeToKVForm(self):
        """Encode a response as a kvform.

        @param response: The response to encode.
        @type response: L{OpenIDResponse}

        @returns: The response in kvform.
        @returntype: str
        """
        return kvform.dictToKV(self.fields)



class CheckIDResponse(OpenIDResponse):
    """
    @type signed: list
    """
    def __init__(self, request, mode='id_res'):
        super(CheckIDResponse, self).__init__(request)
        self.fields['mode'] = mode
        self.signed = []
        if mode == 'id_res':
            self.signed.extend(['mode', 'identity', 'return_to'])


    def addField(self, namespace, key, value, signed=True):
        key = '%s.%s' % (namespace, key)
        self.fields[key] = value
        if signed and key not in self.signed:
            self.signed.append(key)


    def addFields(self, namespace, fields, signed=True):
        for key, value in fields.iteritems():
            self.addField(namespace, key, value, signed)


    def update(self, namespace, other):
        namespaced_fields = dict([('%s.%s' % (namespace, k), v) for k, v
                                  in other.fields.iteritems()])
        self.fields.update(namespaced_fields)
        self.signed.extend(other.signed)


    def __str__(self):
        return "%s for %s: signed%s %s" % (
            self.__class__.__name__,
            self.request.__class__.__name__,
            self.signed, self.fields)


class WebResponse(object):
    code = HTTP_OK
    body = ""

    def __init__(self, code=None, headers=None, body=None):
        if code:
            self.code = code
        if headers is not None:
            self.headers = headers
        else:
            self.headers = {}
        if body is not None:
            self.body = body

class Signatory(object):
    SECRET_LIFETIME = 14 * 24 * 60 * 60 # 14 days, in seconds

    # keys have a bogus server URL in them because the filestore
    # really does expect that key to be a URL.  This seems a little
    # silly for the server store, since I expect there to be only one
    # server URL.
    normal_key = 'http://localhost/|normal'
    dumb_key = 'http://localhost/|dumb'

    def __init__(self, store):
        assert store is not None
        self.store = store

    def verify(self, assoc_handle, sig, signed_pairs):
        assoc = self.getAssociation(assoc_handle, dumb=True)
        if not assoc:
            oidutil.log("failed to get assoc with handle %r to verify sig %r"
                        % (assoc_handle, sig))
            return False

        expected_sig = oidutil.toBase64(assoc.sign(signed_pairs))

        return sig == expected_sig

    def sign(self, response):
        signed_response = deepcopy(response)
        assoc_handle = response.request.assoc_handle
        if assoc_handle:
            # normal mode
            assoc = self.getAssociation(assoc_handle, dumb=False)
            if not assoc:
                # fall back to dumb mode
                signed_response.fields['invalidate_handle'] = \
                                                                   assoc_handle
                assoc = self.createAssociation(dumb=True)
        else:
            # dumb mode.
            assoc = self.createAssociation(dumb=True)

        signed_response.fields['assoc_handle'] = assoc.handle
        assoc.addSignature(signed_response.signed, signed_response.fields,
                           prefix='')
        return signed_response

    def createAssociation(self, dumb=True, assoc_type='HMAC-SHA1'):
        secret = cryptutil.getBytes(20)
        uniq = oidutil.toBase64(cryptutil.getBytes(4))
        handle = '{%s}{%x}{%s}' % (assoc_type, int(time.time()), uniq)

        assoc = Association.fromExpiresIn(
            self.SECRET_LIFETIME, handle, secret, assoc_type)

        if dumb:
            key = self.dumb_key
        else:
            key = self.normal_key
        self.store.storeAssociation(key, assoc)
        return assoc

    def getAssociation(self, assoc_handle, dumb):
        if assoc_handle is None:
            raise ValueError("assoc_handle must not be None")

        if dumb:
            key = self.dumb_key
        else:
            key = self.normal_key
        assoc = self.store.getAssociation(key, assoc_handle)
        if assoc is not None and assoc.expiresIn <= 0:
            oidutil.log("requested %sdumb key %r is expired (by %s seconds)" %
                        ((not dumb) and 'not-' or '',
                         assoc_handle, assoc.expiresIn))
            self.store.removeAssociation(key, assoc_handle)
            assoc = None
        return assoc

    def invalidate(self, assoc_handle, dumb):
        if dumb:
            key = self.dumb_key
        else:
            key = self.normal_key
        self.store.removeAssociation(key, assoc_handle)



class Encoder(object):
    """I encode responses to L{WebResponse}s.

    If you don't like L{WebResponse}s, you can do your own handling of
    L{OpenIDResponse}s with L{responseIsKvform}, L{encodeToURL}, and
    L{encodeToKVForm}.
    """

    responseFactory = WebResponse


    def encode(self, response):
        """Encode a response to a L{WebResponse}.

        @raises: L{EncodingError}
        """
        encode_as = response.whichEncoding()
        if encode_as == ENCODE_KVFORM:
            wr = self.responseFactory(body=response.encodeToKVForm())
            if isinstance(response, Exception):
                wr.code = HTTP_ERROR
        elif encode_as == ENCODE_URL:
            location = response.encodeToURL()
            wr = self.responseFactory(code=HTTP_REDIRECT,
                                      headers={'location': location})
        else:
            # Can't encode this to a protocol message.  You should probably
            # render it to HTML and show it to the user.
            raise EncodingError(response)
        return wr



def needsSigning(response):
    """Does this response require signing?

    @returntype: bool
    """
    return (
        (response.request.mode in ['checkid_setup', 'checkid_immediate'])
        and response.signed
        )



class SigningEncoder(Encoder):
    """I encode responses to L{WebResponse}s, signing them when required.
    """
    def __init__(self, signatory):
        self.signatory = signatory

    def encode(self, response):
        # the isinstance is a bit of a kludge... it means there isn't really
        # an adapter to make the interfaces quite match.
        if (not isinstance(response, Exception)) and needsSigning(response):
            if not self.signatory:
                raise ValueError(
                    "Must have a store to sign this request: %s" %
                    (response,), response)
            if 'sig' in response.fields:
                raise AlreadySigned(response)
            response = self.signatory.sign(response)
        return super(SigningEncoder, self).encode(response)



class Decoder(object):
    prefix = OPENID_PREFIX

    handlers = {
        'checkid_setup': CheckIDRequest.fromQuery,
        'checkid_immediate': CheckIDRequest.fromQuery,
        'check_authentication': CheckAuthRequest.fromQuery,
        'associate': AssociateRequest.fromQuery,
        }

    def decode(self, query):
        if not query:
            return None
        myquery = dict(filter(lambda (k, v): k.startswith(self.prefix),
                              query.iteritems()))
        if not myquery:
            return None

        mode = myquery.get(self.prefix + 'mode')
        if not mode:
            raise ProtocolError(
                query,
                text="No %smode value in query %r" % (
                self.prefix, query))
        handler = self.handlers.get(mode, self.defaultDecoder)
        return handler(query)

    def defaultDecoder(self, query):
        mode = query[self.prefix + 'mode']
        raise ProtocolError(
            query,
            text="No decoder for mode %r" % (mode,))



class OpenIDServer(object):
    signatoryClass = Signatory
    encoderClass = SigningEncoder
    decoderClass = Decoder
    def __init__(self, store):
        self.store = store
        self.signatory = self.signatoryClass(self.store)
        self.encoder = self.encoderClass(self.signatory)
        self.decoder = self.decoderClass()

    def handleRequest(self, request):
        handler = getattr(self, 'openid_' + request.mode)
        return handler(request)

    def openid_check_authentication(self, request):
        return request.answer(self.signatory)

    def openid_associate(self, request):
        assoc = self.signatory.createAssociation(dumb=False)
        return request.answer(assoc)

    def encodeResponse(self, response):
        return self.encoder.encode(response)

    def decodeRequest(self, query):
        return self.decoder.decode(query)


class ProtocolError(Exception):
    def __init__(self, query=None, text=None):
        self.query = query
        Exception.__init__(self, text)

    def hasReturnTo(self):
        return (OPENID_PREFIX + 'return_to') in self.query

    # implements IEncodable

    def encodeToURL(self):
        return_to = self.query.get(OPENID_PREFIX + 'return_to')
        if not return_to:
            raise ValueError("I have no return_to URL.")
        return oidutil.appendArgs(return_to, {
            'openid.mode': 'error',
            'error': str(self),
            })

    def encodeToKVForm(self):
        return kvform.dictToKV({
            'mode': 'error',
            'error': str(self),
            })

    def whichEncoding(self):
        if self.hasReturnTo():
            return ENCODE_URL

        mode = self.query.get('openid.mode')
        if mode:
            if mode not in BROWSER_REQUEST_MODES:
                return ENCODE_KVFORM

        # According to the OpenID spec as of this writing, we are probably
        # supposed to switch on request type here (GET versus POST) to figure
        # out if we're supposed to print machine-readable or human-readable
        # content at this point.  GET/POST seems like a pretty lousy way of
        # making the distinction though, as it's just as possible that the
        # user agent could have mistakenly been directed to post to the
        # server URL.

        # Basically, if your request was so broken that you didn't manage to
        # include an openid.mode, I'm not going to worry too much about
        # returning you something you can't parse.
        return None



class EncodingError(Exception):
    """Could not encode this as a protocol message.

    You should probably render it and show it to the user.
    """

    def __init__(self, response):
        self.response = response

class AlreadySigned(EncodingError):
    """This response is already signed."""

class UntrustedReturnURL(ProtocolError):
    def __init__(self, return_to, trust_root):
        self.return_to = return_to
        self.trust_root = trust_root

    def __str__(self):
        return "return_to %r not under trust_root %r" % (self.return_to,
                                                         self.trust_root)
class MalformedReturnURL(ProtocolError):
    def __init__(self, query, return_to):
        self.return_to = return_to
        ProtocolError.__init__(self, query)

class MalformedTrustRoot(ProtocolError):
    pass


#class IEncodable: # Interface
#     def encodeToURL(return_to):
#         pass
#
#     def encodeToKvform():
#         pass
#
#     def whichEncoding():
#         """How should I be encoded?
#
#         @returns: one of ENCODE_URL, ENCODE_KVFORM, or None.  If None,
#             I cannot be encoded as a protocol message and should be
#             displayed to the user.
#         """
#         pass
