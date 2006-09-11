import sys
import os

from distutils.core import setup

if 'sdist' in sys.argv:
    os.system('./admin/makedoc')

def getLicense():
    f = open('COPYING', 'r')
    return f.read()

# patch distutils if it can't cope with the "classifiers" or
# "download_url" keywords
if sys.version < '2.2.3':
    from distutils.dist import DistributionMetadata
    DistributionMetadata.classifiers = None
    DistributionMetadata.download_url = None

version = '[library version:1.1.2-rc1]'[17:-1]

setup(
    name='python-openid',
    version=version,
    description='OpenID support for servers and consumers.',
    long_description='''This is a set of Python packages to support use of
the OpenID decentralized identity system in your application.  Want to enable
single sign-on for your web site?  Use the openid.consumer package.  Want to
run your own OpenID server? Check out openid.server.  Includes example code
and support for a variety of storage back-ends.''',
    url='http://www.openidenabled.com/openid/libraries/python/',
    packages=['openid',
              'openid.consumer',
              'openid.server',
              'openid.store',
              'openid.yadis',
              ],
    license=getLicense(),
    author='JanRain',
    author_email='openid@janrain.com',
    download_url="http://www.openidenabled.com/resources/downloads/python-openid/python-openid-%s.tar.gz" % (version,),
    classifiers=[
    "Development Status :: 5 - Production/Stable",
    "Environment :: Web Environment",
    "Intended Audience :: Developers",
    "License :: OSI Approved :: GNU Library or Lesser General Public License (LGPL)",
    "Operating System :: POSIX",
    "Programming Language :: Python",
    "Topic :: Internet :: WWW/HTTP",
    "Topic :: Internet :: WWW/HTTP :: Dynamic Content :: CGI Tools/Libraries",
    "Topic :: Software Development :: Libraries :: Python Modules",
    "Topic :: System :: Systems Administration :: Authentication/Directory",
    ],
    )
