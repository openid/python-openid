from django.conf.urls.defaults import *

urlpatterns = patterns(
    '',
    ('^consumer/', include('djopenid.consumer.urls')),
    ('^server/', include('djopenid.server.urls')),
)
