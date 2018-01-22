"""Djopenid URLs."""
from django.conf.urls import include, url
from django.views.generic import TemplateView

urlpatterns = [
    url('^$', TemplateView.as_view(template_name='index.html'), name='index'),
    url('^consumer/', include(('djopenid.consumer.urls', 'consumer'))),
    url('^server/', include(('djopenid.server.urls', 'server'))),
]
