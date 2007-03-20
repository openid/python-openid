
from djopenid import util

from django.views.decorators import http
from django.http import HttpResponseRedirect

from openid.consumer import consumer
from openid.consumer.discover import DiscoveryFailure
from openid.fetchers import HTTPFetchingError

def getOpenIDStore():
    return util.getOpenIDStore('/tmp/djopenid_c_store', 'c_')

def getConsumer(request):
    return consumer.Consumer(request.session, getOpenIDStore())

@util.sendResponse
def startOpenID(request):
    if request.POST:
        # Start OpenID authentication.

        openid_url = request.POST['openid_url']
        c = getConsumer(request)

        error = None

        try:
            auth_request = c.begin(openid_url)
        except HTTPFetchingError, e:
            error = "OpenID discovery error: not a valid OpenID"
        except DiscoveryFailure, e:
            error = "OpenID discovery error: %s" % (str(e),)

        if error:
            return 'consumer/index.html', {'error': error}

        trust_root = util.getTrustRoot(request)
        return_to = trust_root + 'consumer/finish/'

        if auth_request.shouldSendRedirect():
            url = auth_request.redirectURL(trust_root, return_to)
            response = HttpResponseRedirect(url)
        else:
            form_id = 'openid_message'
            form_html = auth_request.formMarkup(trust_root, return_to,
                                                False, {'id': form_id})
            response = http.HttpResponse(form_html)
            response['Content-Type'] = 'text/html'

        return response

    return 'consumer/index.html', {}

@util.sendResponse
def finishOpenID(request):

    result = {}

    if request.GET:
        c = getConsumer(request)

        # Because the object containing the query parameters is a
        # MultiValueDict and the OpenID library doesn't allow that,
        # we'll convert it to a normal dict.
        GET_data = util.normalDict(request.GET)

        response = c.complete(GET_data)

        results = {
            consumer.CANCEL:
            {'message': 'OpenID authentication cancelled.'},

            consumer.FAILURE:
            {'error': 'OpenID authentication failed.'},

            consumer.SUCCESS:
            {'url': response.identity_url,},
            }

        result = results[response.status]

    return 'consumer/index.html', result
