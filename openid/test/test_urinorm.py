import os
import unittest

import openid.urinorm

with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'urinorm.txt')) as test_data_file:
    test_data = test_data_file.read()


class UrinormTest(unittest.TestCase):

    def runTest(self):
        for case in test_data.split('\n\n'):
            case = case.strip()
            if not case:
                continue

            desc, raw, expected = self.parse(case)
            try:
                actual = openid.urinorm.urinorm(raw)
            except ValueError as why:
                self.assertEqual(expected, 'fail', why)
            else:
                self.assertEqual(actual, expected, desc)

    def parse(self, full_case):
        desc, case, expected = full_case.split('\n')
        case = unicode(case, 'utf-8')

        return (desc, case, expected)
