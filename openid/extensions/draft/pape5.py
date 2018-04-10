"""An implementation of the OpenID Provider Authentication Policy
Extension 1.0, Draft 5

@see: http://openid.net/developers/specs/

@since: 2.1.0
"""
import warnings

from openid.extensions.pape import (AUTH_MULTI_FACTOR, AUTH_MULTI_FACTOR_PHYSICAL, AUTH_PHISHING_RESISTANT, LEVELS_JISA,
                                    LEVELS_NIST, Request, Response, ns_uri)

__all__ = [
    'Request',
    'Response',
    'ns_uri',
    'AUTH_PHISHING_RESISTANT',
    'AUTH_MULTI_FACTOR',
    'AUTH_MULTI_FACTOR_PHYSICAL',
    'LEVELS_NIST',
    'LEVELS_JISA',
]

warnings.warn("Module 'openid.extensions.draft.pape5' is deprecated in favor of 'openid.extensions.pape'.",
              DeprecationWarning)
