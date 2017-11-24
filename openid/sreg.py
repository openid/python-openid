"""moved to L{openid.extensions.sreg}"""

import warnings

from openid.extensions.sreg import SRegRequest, SRegResponse, data_fields, ns_uri, ns_uri_1_0, ns_uri_1_1, supportsSReg

warnings.warn("openid.sreg has moved to openid.extensions.sreg",
              DeprecationWarning)

__all__ = ['SRegRequest', 'SRegResponse', 'data_fields', 'ns_uri', 'ns_uri_1_0', 'ns_uri_1_1', 'supportsSReg']
