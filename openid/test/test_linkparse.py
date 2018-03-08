"""Test `openid.consumer.html_parse` module."""
import os.path
import unittest

from openid.consumer.html_parse import parseLinkAttrs


def parseLink(line):
    parts = line.split()
    optional = parts[0] == 'Link*:'
    assert optional or parts[0] == 'Link:'

    attrs = {}
    for attr in parts[1:]:
        k, v = attr.split('=', 1)
        if k[-1] == '*':
            attr_optional = 1
            k = k[:-1]
        else:
            attr_optional = 0

        attrs[k] = (attr_optional, v)

    return (optional, attrs)


def parseCase(s):
    header, markup = s.split('\n\n', 1)
    lines = header.split('\n')
    name = lines.pop(0)
    assert name.startswith('Name: ')
    desc = name[6:]
    return desc, markup, [parseLink(l) for l in lines]


def parseTests(s):
    tests = []

    cases = s.split('\n\n\n')
    header = cases.pop(0)
    tests_line, _ = header.split('\n', 1)
    k, v = tests_line.split(': ')
    assert k == 'Num Tests'
    num_tests = int(v)

    for case in cases[:-1]:
        desc, markup, links = parseCase(case)
        tests.append((desc, markup, links, case))

    assert len(tests) == num_tests, (len(tests), num_tests)
    return num_tests, tests


with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'linkparse.txt')) as link_test_data_file:
    link_test_data = link_test_data_file.read().decode('utf-8')


class LinkTest(unittest.TestCase):
    """Test `parseLinkAttrs` function."""

    def runTest(self):
        num_tests, test_cases = parseTests(link_test_data)

        for desc, case, expected, raw in test_cases:
            actual = parseLinkAttrs(case)
            i = 0
            for optional, exp_link in expected:
                if optional:
                    if i >= len(actual):
                        continue

                act_link = actual[i]
                for k, (o, v) in exp_link.items():
                    if o:
                        act_v = act_link.get(k)
                        if act_v is None:
                            continue
                    else:
                        act_v = act_link[k]

                    if optional and v != act_v:
                        break

                    self.assertEqual(v, act_v)
                else:
                    i += 1

            assert i == len(actual)
