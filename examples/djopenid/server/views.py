
"""
This module implements an example server for the OpenID library.  Some
functionality has been omitted intentionally; this code is intended to
be instructive on the use of this library.  This server does not
perform actual user authentication and serves up only one OpenID URL,
with the exception of IDP-generated identifiers.

Some code conventions used here:

* 'request' is a Django request object.

* 'openid_request' is an OpenID library request object.

* 'openid_response' is an OpenID library response
"""

import cgi

from django import http
from django.shortcuts import render
from django.urls import reverse
from openid.consumer.discover import OPENID_IDP_2_0_TYPE
from openid.extensions import pape, sreg
from openid.fetchers import HTTPFetchingError
from openid.server.server import EncodingError, ProtocolError, Server
from openid.server.trustroot import verifyReturnTo
from openid.yadis.discover import DiscoveryFailure

from .. import util


def getOpenIDStore():
    """
    Return an OpenID store object fit for the currently-chosen
    database backend, if any.
    """
    return util.getOpenIDStore('/tmp/djopenid_s_store', 's_')


def getServer(request):
    """
    Get a Server object to perform OpenID authentication.
    """
    endpoint_url = request.build_absolute_uri(reverse('server:endpoint'))
    return Server(getOpenIDStore(), endpoint_url)


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


def server(request):
    """
    Respond to requests for the server's primary web page.
    """
    local_id = request.build_absolute_uri(reverse('server:local_id'))
    server_xrds_url = request.build_absolute_uri(reverse('server:xrds'))
    context = {'local_id': local_id, 'server_xrds_url': server_xrds_url}
    return render(request, 'server/index.html', context)


def idpXrds(request):
    """
    Respond to requests for the IDP's XRDS document, which is used in
    IDP-driven identifier selection.
    """
    endpoint_url = request.build_absolute_uri(reverse('server:endpoint'))
    return util.renderXRDS(request, [OPENID_IDP_2_0_TYPE], [endpoint_url])


def idPage(request):
    """
    Serve the identity page for OpenID URLs.
    """
    endpoint_url = request.build_absolute_uri(reverse('server:endpoint'))
    return render(request, 'server/idPage.html', {'endpoint_url': endpoint_url})


def endpoint(request):
    """
    Respond to low-level OpenID protocol messages.
    """
    s = getServer(request)

    query = util.normalDict(request.GET or request.POST)

    # First, decode the incoming request into something the OpenID
    # library can use.
    try:
        openid_request = s.decodeRequest(query)
    except ProtocolError as why:
        # This means the incoming request was invalid.
        return render(request, 'server/endpoint.html', {'error': str(why)})

    # If we did not get a request, display text indicating that this
    # is an endpoint.
    if openid_request is None:
        return render(request, 'server/endpoint.html')

    # We got a request; if the mode is checkid_*, we will handle it by
    # getting feedback from the user or by checking the session.
    if openid_request.mode in ["checkid_immediate", "checkid_setup"]:
        return handleCheckIDRequest(request, openid_request)
    else:
        # We got some other kind of OpenID request, so we let the
        # server handle this.
        openid_response = s.handleRequest(openid_request)
        return displayResponse(request, openid_response)


def handleCheckIDRequest(request, openid_request):
    """
    Handle checkid_* requests.  Get input from the user to find out
    whether she trusts the RP involved.  Possibly, get intput about
    what Simple Registration information, if any, to send in the
    response.
    """
    # If the request was an IDP-driven identifier selection request
    # (i.e., the IDP URL was entered at the RP), then return the
    # default identity URL for this server. In a full-featured
    # provider, there could be interaction with the user to determine
    # what URL should be sent.
    if not openid_request.idSelect():

        id_url = request.build_absolute_uri(reverse('server:local_id'))

        # Confirm that this server can actually vouch for that
        # identifier
        if id_url != openid_request.identity:
            # Return an error response
            error_response = ProtocolError(
                openid_request.message,
                "This server cannot verify the URL %r" %
                (openid_request.identity,))

            return displayResponse(request, error_response)

    if openid_request.immediate:
        # Always respond with 'cancel' to immediate mode requests
        # because we don't track information about a logged-in user.
        # If we did, then the answer would depend on whether that user
        # had trusted the request's trust root and whether the user is
        # even logged in.
        openid_response = openid_request.answer(False)
        return displayResponse(request, openid_response)
    else:
        # Store the incoming request object in the session so we can
        # get to it later.
        setRequest(request, openid_request)
        return showDecidePage(request, openid_request)


def showDecidePage(request, openid_request):
    """
    Render a page to the user so a trust decision can be made.

    @type openid_request: openid.server.server.CheckIDRequest
    """
    trust_root = openid_request.trust_root
    return_to = openid_request.return_to

    try:
        # Stringify because template's ifequal can only compare to strings.
        trust_root_valid = verifyReturnTo(trust_root, return_to) and "Valid" or "Invalid"
    except DiscoveryFailure:
        trust_root_valid = "DISCOVERY_FAILED"
    except HTTPFetchingError:
        trust_root_valid = "Unreachable"

    pape_request = pape.Request.fromOpenIDRequest(openid_request)

    context = {'trust_root': trust_root,
               'trust_root_valid': trust_root_valid,
               'pape_request': pape_request}
    return render(request, 'server/trust.html', context)


def processTrustResult(request):
    """
    Handle the result of a trust decision and respond to the RP
    accordingly.
    """
    # Get the request from the session so we can construct the
    # appropriate response.
    openid_request = getRequest(request)

    # The identifier that this server can vouch for
    response_identity = request.build_absolute_uri(reverse('server:local_id'))

    # If the decision was to allow the verification, respond
    # accordingly.
    allowed = 'allow' in request.POST

    # Generate a response with the appropriate answer.
    openid_response = openid_request.answer(allowed,
                                            identity=response_identity)

    # Send Simple Registration data in the response, if appropriate.
    if allowed:
        sreg_data = {
            'fullname': 'Example User',
            'nickname': 'example',
            'dob': '1970-01-01',
            'email': 'invalid@example.com',
            'gender': 'F',
            'postcode': '12345',
            'country': 'ES',
            'language': 'eu',
            'timezone': 'America/New_York',
        }

        sreg_req = sreg.SRegRequest.fromOpenIDRequest(openid_request)
        sreg_resp = sreg.SRegResponse.extractResponse(sreg_req, sreg_data)
        openid_response.addExtension(sreg_resp)

        pape_response = pape.Response()
        pape_response.setAuthLevel(pape.LEVELS_NIST, 0)
        openid_response.addExtension(pape_response)

    return displayResponse(request, openid_response)


def displayResponse(request, openid_response):
    """
    Display an OpenID response.  Errors will be displayed directly to
    the user; successful responses and other protocol-level messages
    will be sent using the proper mechanism (i.e., direct response,
    redirection, etc.).
    """
    s = getServer(request)

    # Encode the response into something that is renderable.
    try:
        webresponse = s.encodeResponse(openid_response)
    except EncodingError as why:
        # If it couldn't be encoded, display an error.
        text = why.response.encodeToKVForm()
        return render(request, 'server/endpoint.html', {'error': cgi.escape(text)})

    # Construct the appropriate django framework response.
    r = http.HttpResponse(webresponse.body)
    r.status_code = webresponse.code

    for header, value in webresponse.headers.iteritems():
        r[header] = value

    return r
