"""Consumer URLs."""
from django.conf.urls import url

from djopenid.consumer.views import finishOpenID, rpXRDS, startOpenID

urlpatterns = [
    url(r'^$', startOpenID, name='index'),
    url(r'^finish/$', finishOpenID, name='return_to'),
    url(r'^xrds/$', rpXRDS, name='xrds'),
]
