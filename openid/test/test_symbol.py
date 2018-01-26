import unittest

from openid import oidutil


class SymbolTest(unittest.TestCase):
    def test_selfEquality(self):
        s = oidutil.Symbol('xxx')
        self.assertEqual(s, s)

    def test_otherEquality(self):
        x = oidutil.Symbol('xxx')
        y = oidutil.Symbol('xxx')
        self.assertEqual(x, y)

    def test_inequality(self):
        x = oidutil.Symbol('xxx')
        y = oidutil.Symbol('yyy')
        self.assertNotEqual(x, y)

    def test_selfInequality(self):
        x = oidutil.Symbol('xxx')
        self.assertFalse(x != x)

    def test_otherInequality(self):
        x = oidutil.Symbol('xxx')
        y = oidutil.Symbol('xxx')
        self.assertFalse(x != y)

    def test_ne_inequality(self):
        x = oidutil.Symbol('xxx')
        y = oidutil.Symbol('yyy')
        self.assertNotEqual(x, y)


if __name__ == '__main__':
    unittest.main()
