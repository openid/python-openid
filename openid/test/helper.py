import unittest
import sys
from os.path import dirname, join

data_dir = join(dirname(__file__), 'data')

def getTestDataFilename(rel_path):
    return join(data_dir, rel_path)

def getTestData(rel_path):
    filename = getTestDataFilename(rel_path)
    return file(filename).read()

def runModule(module):
    suite = getTestSuite(module)
    runner = unittest.TextTestRunner()
    result = runner.run(suite)
    if result.wasSuccessful():
        return 0
    else:
        return 1

def runAsMain(module=None):
    if module is None:
        import __main__
        module = __main__

    sys.exit(runModule(module))

def getTestSuite(module, *args, **kwargs):
    if hasattr(module, 'getTestSuite'):
        return module.getTestSuite(*args, **kwargs)
    elif hasattr(module, 'getTestCases'):
        cases = module.getTestCases(*args, **kwargs)
        return unittest.TestSuite(cases)
    else:
        return unittest.TestLoader().loadTestsFromModule(module)
