from distutils.core import setup

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
              'openid.stores',
              ],
    license=copying,
    )

