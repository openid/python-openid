from __future__ import unicode_literals

import unittest
import warnings

from testfixtures import ShouldWarn

from openid.extensions import pape


class PapeImportTestCase(unittest.TestCase):
    def test_version(self):
        warning_msg = "Module 'openid.extensions.draft.pape5' is deprecated in favor of 'openid.extensions.pape'."
        with ShouldWarn(DeprecationWarning(warning_msg)):
            warnings.simplefilter('always')
            from openid.extensions.draft import pape5
        self.assertEqual(pape.Request, pape5.Request)
        self.assertEqual(pape.Response, pape5.Response)
