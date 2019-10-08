# python-openid2 #

[![Build Status](https://travis-ci.org/ziima/python-openid.svg?branch=master)](https://travis-ci.org/ziima/python-openid)
[![codecov](https://codecov.io/gh/ziima/python-openid/branch/master/graph/badge.svg)](https://codecov.io/gh/ziima/python-openid)
[![PyPI](https://img.shields.io/pypi/v/python-openid2.svg)](https://pypi.org/pypi/python-openid2/)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/python-openid2.svg)](https://pypi.org/pypi/python-openid2/)

Python OpenID library - OpenID support for servers and consumers.

This is a set of Python packages to support use of the OpenID decentralized identity system in your application.
Want to enable single sign-on for your web site?
Use the `openid.consumer package`.
Want to run your own OpenID server?
Check out `openid.server`.
Includes example code and support for a variety of storage back-ends.

## REQUIREMENTS ##

 - Python 2.7, >=3.5
 - lxml
 - six
 - cryptography


## INSTALLATION ##

To install the base library, just run the following command:

    pip install python-openid2


## GETTING STARTED ##

The examples directory includes an example server and consumer
implementation.  See the README file in that directory for more
information on running the examples.

Library documentation is available in html form in the doc directory.


## LOGGING ##

This library offers a logging hook that will record unexpected
conditions that occur in library code. If a condition is recoverable,
the library will recover and issue a log message. If it is not
recoverable, the library will raise an exception. See the
documentation for the openid.oidutil module for more on the logging
hook.


## DOCUMENTATION ##

The documentation in this library is in Epydoc format, which is
detailed at:

  http://epydoc.sourceforge.net/


## CONTACT ##

Send bug reports, suggestions, comments, and questions to
https://github.com/ziima/python-openid/issues/new

If you have a bugfix or feature you'd like to contribute, don't
hesitate to send it to us on GitHub.
