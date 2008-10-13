
from openid.extensions import pape

import unittest

class PapeImportTestCase(unittest.TestCase):
    def test_version(self):
        from openid.extensions.draft import pape5
        self.assertTrue(pape is pape5)
