"""
This package is an implementation of the OpenID specification in
Python.  It contains code for both server and consumer
implementations.  For information on implementing an OpenID consumer,
see the C{L{openid.consumer.consumer}} module.  For information on
implementing an OpenID server, see the C{L{openid.server.server}}
module.
"""

__version__ = '[library version:1.1.2-rc1]'[17:-1]

# Parse the version info
try:
    version_info = map(int, __version__.split('.'))
except ValueError:
    version_info = (None, None, None)
else:
    if len(version_info) != 3:
        version_info = (None, None, None)
    else:
        version_info = tuple(version_info)
