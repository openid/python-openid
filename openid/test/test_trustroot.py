import os
import unittest

from openid.server.trustroot import TrustRoot

with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'trustroot.txt')) as test_data_file:
    trustroot_test_data = test_data_file.read()


class ParseTest(unittest.TestCase):

    def test(self):
        ph, pdat, mh, mdat = parseTests(trustroot_test_data)

        for sanity, desc, case in getTests(['bad', 'insane', 'sane'], ph, pdat):
            tr = TrustRoot.parse(case)
            if sanity == 'sane':
                assert tr.isSane(), case
            elif sanity == 'insane':
                assert not tr.isSane(), case
            else:
                assert tr is None, tr


class MatchTest(unittest.TestCase):

    def test(self):
        ph, pdat, mh, mdat = parseTests(trustroot_test_data)

        for expected_match, desc, line in getTests([1, 0], mh, mdat):
            tr, rt = line.split()
            tr = TrustRoot.parse(tr)
            self.assertIsNotNone(tr)

            match = tr.validateURL(rt)
            if expected_match:
                assert match
            else:
                assert not match


def getTests(grps, head, dat):
    tests = []
    top = head.strip()
    gdat = [i.strip() for i in dat.split('-' * 40 + '\n')]
    assert not gdat[0]
    assert len(gdat) == (len(grps) * 2 + 1), (gdat, grps)
    i = 1
    for x in grps:
        n, desc = gdat[i].split(': ')
        cases = gdat[i + 1].split('\n')
        assert len(cases) == int(n)
        for case in cases:
            tests.append((x, top + ' - ' + desc, case))
        i += 2
    return tests


def parseTests(data):
    parts = [i.strip() for i in data.split('=' * 40 + '\n')]
    assert not parts[0]
    _, ph, pdat, mh, mdat = parts
    return ph, pdat, mh, mdat
