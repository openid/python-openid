import unittest

from openid.extensions import pape


class PapeImportTestCase(unittest.TestCase):
    def test_version(self):
        from openid.extensions.draft import pape5
        self.assertEqual(pape.Request, pape5.Request)
        self.assertEqual(pape.Response, pape5.Response)
