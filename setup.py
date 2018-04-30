# -*- coding: utf-8 -*-
import os
import sys

from setuptools import setup

if 'sdist' in sys.argv:
    os.system('./admin/makedoc')

# Import version from openid library itself
VERSION = __import__('openid').__version__
INSTALL_REQUIRES = [
    'lxml;platform_python_implementation=="CPython"',
    'lxml <4.0;platform_python_implementation=="PyPy"',
]
EXTRAS_REQUIRE = {
    'quality': ('flake8', 'isort'),
    'tests': ('mock', 'testfixtures', 'responses', 'coverage'),
    # Optional dependencies for fetchers
    'httplib2': ('httplib2', ),
    'pycurl': ('pycurl', ),
    'requests': ('requests', ),
    # Dependencies for Django example
    'djopenid': ('django<1.11.99', ),
}
LONG_DESCRIPTION = open('README.md').read() + '\n\n' + open('Changelog.md').read()
CLASSIFIERS = [
    'Development Status :: 5 - Production/Stable',
    'Environment :: Web Environment',
    'Intended Audience :: Developers',
    'License :: OSI Approved :: Apache Software License',
    'Operating System :: POSIX',
    'Programming Language :: Python',
    'Programming Language :: Python :: 2',
    'Programming Language :: Python :: 2.7',
    'Topic :: Internet :: WWW/HTTP',
    'Topic :: Internet :: WWW/HTTP :: Dynamic Content :: CGI Tools/Libraries',
    'Topic :: Software Development :: Libraries :: Python Modules',
    'Topic :: System :: Systems Administration :: Authentication/Directory',
]


setup(
    name='python-openid2',
    version=VERSION,
    description='Python OpenID library - OpenID support for servers and consumers.',
    long_description=LONG_DESCRIPTION,
    long_description_content_type='text/markdown',
    url='https://github.com/ziima/python-openid',
    packages=['openid',
              'openid.consumer',
              'openid.server',
              'openid.store',
              'openid.yadis',
              'openid.extensions',
              'openid.extensions.draft',
              ],
    python_requires='~=2.7',
    install_requires=INSTALL_REQUIRES,
    extras_require=EXTRAS_REQUIRE,
    # license specified by classifier.
    # license=getLicense(),
    author='Vlastimil Zíma',
    author_email='vlastimil.zima@gmail.com',
    classifiers=CLASSIFIERS,
)
