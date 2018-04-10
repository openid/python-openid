# python-openid2 #

[![Build Status](https://travis-ci.org/ziima/python-openid.svg?branch=master)](https://travis-ci.org/ziima/python-openid)

This is the Python OpenID library.

## REQUIREMENTS ##

 - Python 2.7.
 - lxml


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
