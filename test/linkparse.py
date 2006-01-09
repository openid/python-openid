from openid.consumer.parse import parseLinkAttrs
import os.path
import codecs
import unittest

def parseLink(line):
    parts = line.split()
    assert parts[0] == 'Link:'

    attrs = {}
    for attr in parts[1:]:
        k, v = attr.split('=', 1)
        attrs[k] = v

    return attrs

def parseCase(s):
    header, markup = s.split('\n\n', 1)
    lines = header.split('\n')
    name = lines.pop(0)
    assert name.startswith('Name: ')
    desc = name[6:]
    return desc, markup, map(parseLink, lines)

def parseTests(s):
    tests = []

    cases = s.split('\n\n\n')
    for case in cases[1:-1]:
        desc, markup, links = parseCase(case)
        tests.append((desc, markup, links, case))

    return tests

class _LinkTest(unittest.TestCase):
    def __init__(self, desc, case, expected, raw):
        unittest.TestCase.__init__(self)
        self.desc = desc
        self.case = case
        self.expected = expected
        self.raw = raw

    def shortDescription(self):
        return self.desc

    def runTest(self):
        actual = parseLinkAttrs(self.case)
        if self.expected != actual:
            print repr(self.raw)
        self.assertEqual(self.expected, actual)

def pyUnitTests():
    here = os.path.dirname(os.path.abspath(__file__))
    test_data_file_name = os.path.join(here, 'linkparse.txt')
    test_data_file = codecs.open(test_data_file_name, 'r', 'utf-8')
    test_data = test_data_file.read()
    test_data_file.close()

    tests = [_LinkTest(*case) for case in parseTests(test_data)]
    return unittest.TestSuite(tests)

if __name__ == '__main__':
    suite = pyUnitTests()
    runner = unittest.TextTestRunner()
    runner.run(suite)
