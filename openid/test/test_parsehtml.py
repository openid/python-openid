import os.path
import unittest
from HTMLParser import HTMLParseError

from openid.yadis.parsehtml import ParseDone, YadisHTMLParser


class TestParseHTML(unittest.TestCase):
    reserved_values = ['None', 'EOF']

    def test(self):
        for expected, case in getCases():
            p = YadisHTMLParser()
            try:
                p.feed(case)
            except ParseDone as why:
                found = why[0]

                # make sure we protect outselves against accidental bogus
                # test cases
                assert found not in self.reserved_values

                # convert to a string
                if found is None:
                    found = 'None'

                msg = "%r != %r for case %s" % (found, expected, case)
                self.assertEqual(found, expected, msg)
            except HTMLParseError:
                self.assertEqual(expected, 'None', (case, expected))
            else:
                self.assertEqual(expected, 'EOF', (case, expected))


def parseCases(data):
    cases = []
    for chunk in data.split('\f\n'):
        expected, case = chunk.split('\n', 1)
        cases.append((expected, case))
    return cases


filenames = ['data/test1-parsehtml.txt']

default_test_files = []
base = os.path.dirname(__file__)
for filename in filenames:
    full_name = os.path.join(base, filename)
    default_test_files.append(full_name)


def getCases(test_files=default_test_files):
    cases = []
    for filename in test_files:
        data = file(filename).read()
        for expected, case in parseCases(data):
            cases.append((expected, case))
    return cases
