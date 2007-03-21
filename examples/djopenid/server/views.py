
import cgi

from djopenid import util

from django import http

from openid.server.server import Server, ProtocolError, CheckIDRequest, \
     EncodingError
from openid import sreg

def getOpenIDStore():
    """
    Return an OpenID store object fit for the currently-chosen
    database backend, if any.
    """
    return util.getOpenIDStore('/tmp/djopenid_s_store', 's_')

def getServerURL(request):
    """
    Get the OpenID endpoint URL for this application.
    """
    return util.getTrustRoot(request) + "server/endpoint/"

def getServer(request):
    """
    Get a Server object to perform OpenID authentication.
    """
    return Server(getOpenIDStore(), getServerURL(request))

def getUserURL(request, name='user'):
    """
    Return the URL of the OpenID that this application serves.
    """
    return util.getTrustRoot(request) + "server/%s/" % (name,)

def getIdpXRDSURL(request):
    """
    Return the URL to the server's XRDS URL.
    """
    return util.getTrustRoot(request) + "server/xrds/"

def setRequest(request, openid_request):
    """
    Store the openid request information in the session.
    """
    if openid_request:
        request.session['openid_request'] = openid_request
    else:
        request.session['openid_request'] = None

def getRequest(request):
    """
    Get an openid request from the session, if any.
    """
    return request.session.get('openid_request')

@util.sendResponse
def server(request):
    return 'server/index.html', {'user_url': getUserURL(request),
                                 'server_xrds_url': getIdpXRDSURL(request)}

@util.sendResponse
def idpXrds(request):
    body = util.renderTemplate(request, 'server/xrds.html',
                               {'server_url': getServerURL(request)})
    r = http.HttpResponse(body)
    r['Content-Type'] = 'application/xrds+xml'
    return r

@util.sendResponse
def idPage(request):
    return 'server/idPage.html', {'server_url': getServerURL(request)}

@util.sendResponse
def trustPage(request):
    return 'server/trust.html', {}

@util.sendResponse
def endpoint(request):
    s = getServer(request)

    query = util.normalDict(request.GET or request.POST)

    try:
        openid_request = s.decodeRequest(query)
    except ProtocolError, why:
        return 'server/endpoint.html', {'error': str(why)}

    if openid_request is None:
        # Display text indicating that this is an endpoint.
        return 'server/endpoint.html', {}

    if openid_request.mode in ["checkid_immediate", "checkid_setup"]:
        return handleCheckIDRequest(request, openid_request)
    else:
        response = s.handleRequest(openid_request)
        return displayResponse(request, response)

def handleCheckIDRequest(request, openid_request):
    if openid_request.immediate:
        # Always respond with 'cancel' to immediate mode requests
        # because we don't track information about a logged-in user.
        # If we did, then the answer would depend on whether that user
        # had trusted the request's trust root and whether the user is
        # even logged in.
        response = openid_request.answer(False)
        return displayResponse(request, response)
    else:
        setRequest(request, openid_request)
        return showDecidePage(request, openid_request)

def showDecidePage(request, openid_request):
    idSelect = openid_request.idSelect()
    identity = openid_request.identity
    trust_root = openid_request.trust_root

    return 'server/trust.html', {'idSelect': idSelect,
                                 'identity': identity,
                                 'trust_root': trust_root,}

@util.sendResponse
def processTrustResult(request):
    openid_request = getRequest(request)

    result = None
    response_identity = openid_request.identity

    if 'allow' in request.POST:
        result = True
    elif 'cancel' in request.POST:
        result = False

    if openid_request.idSelect():
        response_identity = getUserURL(request, name=request.POST['name'])

    response = openid_request.answer(result, identity=response_identity)

    return displayResponse(request, response)

def displayResponse(request, response):
    s = getServer(request)

    try:
        webresponse = s.encodeResponse(response)
    except EncodingError, why:
        text = why.response.encodeToKVForm()
        return 'server/endpoint.html', {'error': cgi.escape(text)}

    r = http.HttpResponse(webresponse.body)
    r.status_code = webresponse.code

    for header, value in webresponse.headers.iteritems():
        r[header] = value

    return r
