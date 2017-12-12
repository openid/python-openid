"""Server URLs."""
from django.conf.urls import url
from django.views.generic import TemplateView

from djopenid.server.views import endpoint, idPage, idpXrds, processTrustResult, server

urlpatterns = [
    url(r'^$', server, name='index'),
    url(r'^xrds/$', idpXrds, name='xrds'),
    url(r'^user/$', idPage, name='local_id'),
    url(r'^endpoint/$', endpoint, name='endpoint'),
    url(r'^trust/$', TemplateView.as_view(template_name='server/trust.html'), name='confirmation'),
    url(r'^processTrustResult/$', processTrustResult, name='process-confirmation'),
]
