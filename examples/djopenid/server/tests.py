
from django.test.testcases import TestCase
from djopenid.server import views

from django.http import HttpRequest
from django.contrib.sessions.middleware import SessionWrapper

from openid.server.server import CheckIDRequest
from openid.message import Message

def dummyRequest():
    request = HttpRequest()
    request.session = SessionWrapper("test")
    request.META['HTTP_HOST'] = 'XXX'
    request.META['SERVER_PROTOCOL'] = 'HTTP'
    return request

class TestProcessTrustResult(TestCase):
    def test_allow(self):
        request = dummyRequest()

        # Set up the OpenID request we're responding to.
        op_endpoint = 'http://127.0.0.1:8080/endpoint'
        message = Message.fromPostArgs({
            'openid.mode': 'checkid_setup',
            'openid.identity': 'http://127.0.0.1:8080/id/bob',
            'openid.return_to': 'http://127.0.0.1/%s' % (self.id(),),
            'openid.sreg.required': 'postcode',
            })
        openid_request = CheckIDRequest.fromMessage(message, op_endpoint)

        views.setRequest(request, openid_request)

        # Testing the 'allow' response.
        request.POST['allow'] = 'Yes'

        response = views.processTrustResult(request)

        self.failUnlessEqual(response.status_code, 302)
        finalURL = response['location']
        self.failUnless('openid.mode=id_res' in finalURL, finalURL)
        self.failUnless('openid.identity=' in finalURL, finalURL)
        self.failUnless('openid.sreg.postcode=12345' in finalURL, finalURL)
