import os
import sys

from setuptools import setup

if 'sdist' in sys.argv:
    os.system('./admin/makedoc')

version = '[library version:2.2.5]'[17:-1]
INSTALL_REQUIRES = [
    'lxml;platform_python_implementation=="CPython"',
    'lxml <4.0;platform_python_implementation=="PyPy"',
]
EXTRAS_REQUIRE = {
    'quality': ('flake8', 'isort'),
    'tests': ('mock', 'testfixtures', 'coverage'),
    # Optional dependencies for fetchers
    'httplib2': ('httplib2', ),
    'pycurl': ('pycurl', ),
    # Dependencies for Django example
    'djopenid': ('django<1.11.99', ),
}

setup(
    name='python-openid',
    version=version,
    description='OpenID support for servers and consumers.',
    long_description='''This is a set of Python packages to support use of
the OpenID decentralized identity system in your application.  Want to enable
single sign-on for your web site?  Use the openid.consumer package.  Want to
run your own OpenID server? Check out openid.server.  Includes example code
and support for a variety of storage back-ends.''',
    url='http://github.com/openid/python-openid',
    packages=['openid',
              'openid.consumer',
              'openid.server',
              'openid.store',
              'openid.yadis',
              'openid.extensions',
              'openid.extensions.draft',
              ],
    install_requires=INSTALL_REQUIRES,
    extras_require=EXTRAS_REQUIRE,
    # license specified by classifier.
    # license=getLicense(),
    author='JanRain',
    author_email='openid@janrain.com',
    download_url='http://github.com/openid/python-openid/tarball/%s' % (version,),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: POSIX",
        "Programming Language :: Python",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content :: CGI Tools/Libraries",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Systems Administration :: Authentication/Directory",
    ],
)
