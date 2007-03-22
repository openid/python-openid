
from djopenid import util

from django import http
from django.http import HttpResponseRedirect

from openid.consumer import consumer
from openid.consumer.discover import DiscoveryFailure
from openid.fetchers import HTTPFetchingError
from openid import sreg

def getOpenIDStore():
    """
    Return an OpenID store object fit for the currently-chosen
    database backend, if any.
    """
    return util.getOpenIDStore('/tmp/djopenid_c_store', 'c_')

def getConsumer(request):
    """
    Get a Consumer object to perform OpenID authentication.
    """
    return consumer.Consumer(request.session, getOpenIDStore())

@util.sendResponse
def startOpenID(request):
    """
    Start the OpenID authentication process.  Renders an
    authentication form and accepts its POST.

    * Renders an error message if OpenID cannot be initiated

    * Requests some Simple Registration data using the OpenID
      library's Simple Registration machinery

    * Generates the appropriate trust root and return URL values for
      this application (tweak where appropriate)

    * Generates the appropriate redirect based on the OpenID protocol
      version.
    """
    if request.POST:
        # Start OpenID authentication.
        openid_url = request.POST['openid_url']
        c = getConsumer(request)
        error = None

        try:
            auth_request = c.begin(openid_url)
        except HTTPFetchingError, e:
            # A fetching error occurred (DNS resolution, etc.)
            error = "OpenID discovery error: not a valid OpenID"
        except DiscoveryFailure, e:
            # Some other protocol-level failure occurred.
            error = "OpenID discovery error: %s" % (str(e),)

        if error:
            # Render the page with an error.
            return 'consumer/index.html', {'error': error}

        # Add Simple Registration request information.  Some fields
        # are optional, some are required.  It's possible that the
        # server doesn't support sreg or won't return any of the
        # fields.
        sreg_request = sreg.SRegRequest(optional=['email', 'nickname'],
                                        required=['dob'])
        auth_request.addExtension(sreg_request)

        # Compute the trust root and return URL values to build the
        # redirect information.
        trust_root = util.getTrustRoot(request)
        return_to = trust_root + 'consumer/finish/'

        # Send the browser to the server either by sending a redirect
        # URL or by generating a POST form.
        if auth_request.shouldSendRedirect():
            url = auth_request.redirectURL(trust_root, return_to)
            return HttpResponseRedirect(url)
        else:
            # Beware: this renders a template whose content is a form
            # and some javascript to submit it upon page load.  Non-JS
            # users will have to click the form submit button to
            # initiate OpenID authentication.
            form_id = 'openid_message'
            form_html = auth_request.formMarkup(trust_root, return_to,
                                                False, {'id': form_id})
            return 'consumer/request_form.html', {'html': form_html}

    return 'consumer/index.html', {}

@util.sendResponse
def finishOpenID(request):
    """
    Finish the OpenID authentication process.  Invoke the OpenID
    library with the response from the OpenID server and render a page
    detailing the result.
    """
    result = {}

    if request.GET:
        c = getConsumer(request)

        # Because the object containing the query parameters is a
        # MultiValueDict and the OpenID library doesn't allow that,
        # we'll convert it to a normal dict.
        GET_data = util.normalDict(request.GET)

        # Get a response object indicating the result of the OpenID
        # protocol.
        response = c.complete(GET_data)

        # Get a Simple Registration response object if response
        # information was included in the OpenID response.
        sreg_response = {}
        if response.status == consumer.SUCCESS:
            sreg_response = sreg.SRegResponse.fromSuccessResponse(response)

        # Map different consumer status codes to template contexts.
        results = {
            consumer.CANCEL:
            {'message': 'OpenID authentication cancelled.'},

            consumer.FAILURE:
            {'error': 'OpenID authentication failed.'},

            consumer.SUCCESS:
            {'url': response.identity_url,
             'sreg': sreg_response.items(),},
            }

        result = results[response.status]

    return 'consumer/index.html', result
