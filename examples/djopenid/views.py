
from djopenid import util

@util.sendResponse
def index(request):
    return 'index.html', {'consumer_url':util.getViewURL(request, 'djopenid.consumer.views.startOpenID'),
                          'server_url':util.getViewURL(request, 'djopenid.server.views.server'),
                          }
