import sys
import os

from distutils.core import setup

if 'sdist' in sys.argv:
    os.system('./makedoc')

def getLicense():
    f = open('COPYING', 'r')
    return f.read()

setup(
    name='python-openid',
    version='1.0.0-b1',
    description='Python OpenID Library',
    url='http://openid.schtuff.com/',
    packages=['openid',
              'openid.consumer',
              'openid.server',
              'openid.store',
              ],
    license=getLicense(),
    author='Janrain',
    author_email='openid@janrain.com',
    )

