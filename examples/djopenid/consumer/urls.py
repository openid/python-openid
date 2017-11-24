from django.conf.urls.defaults import patterns

urlpatterns = patterns(
    'djopenid.consumer.views',
    (r'^$', 'startOpenID'),
    (r'^finish/$', 'finishOpenID'),
    (r'^xrds/$', 'rpXRDS'),
)
