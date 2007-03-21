
from djopenid import util

@util.sendResponse
def index(request):
    return 'index.html', {}
