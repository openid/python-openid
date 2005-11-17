import sys
import os

from distutils.core import setup

if 'sdist' in sys.argv:
    os.system('./makedoc')

try:
    f = open('COPYING', 'r')
    copying = f.read()
finally:
    f.close()

setup(
    name='python-openid',
    version='1.0-beta1',
    description='Python OpenID Library',
    url='http://openid.schtuff.com/',
    packages=['openid',
              'openid.consumer',
              'openid.server',
              'openid.store',
              ],
    license=copying,
    author='Janrain',
    author_email='openid@janrain.com',
    )

