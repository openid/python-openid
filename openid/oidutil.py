"""This module contains general utility code that is used throughout
the library.

For users of this library, the C{L{log}} function is probably the most
interesting.
"""
from __future__ import unicode_literals

import binascii
import logging
import warnings

import six
from six.moves.urllib.parse import urlencode

__all__ = ['log', 'appendArgs', 'toBase64', 'fromBase64', 'autoSubmitHTML']


def autoSubmitHTML(form, title='OpenID transaction in progress'):
    return """
<html>
<head>
  <title>%s</title>
</head>
<body onload="document.forms[0].submit();">
%s
<script>
var elements = document.forms[0].elements;
for (var i = 0; i < elements.length; i++) {
  elements[i].style.display = "none";
}
</script>
</body>
</html>
""" % (title, form)


def log(message, level=0):
    """Handle a log message from the OpenID library.

    This is a legacy function which redirects to logging.error.
    The logging module should be used instead of this

    @param message: A string containing a debugging message from the
        OpenID library
    @type message: six.text_type, six.binary_type is deprecated

    @param level: The severity of the log message. This parameter is
        currently unused, but in the future, the library may indicate
        more important information with a higher level value.
    @type level: int or None

    @returns: Nothing.
    """
    message = string_to_text(message, "Binary values for log are deprecated. Use text input instead.")

    logging.error("This is a legacy log message, please use the logging module. Message: %s", message)


def appendArgs(url, args):
    """Append query arguments to a HTTP(s) URL. If the URL already has
    query arguemtns, these arguments will be added, and the existing
    arguments will be preserved. Duplicate arguments will not be
    detected or collapsed (both will appear in the output).

    @param url: The url to which the arguments will be appended
    @type url: six.text_type, six.binary_type is deprecated

    @param args: The query arguments to add to the URL. If a
        dictionary is passed, the items will be sorted before
        appending them to the URL. If a sequence of pairs is passed,
        the order of the sequence will be preserved.
    @type args: Union[Dict[six.text_type, six.text_type], List[Tuple[six.text_type, six.text_type]]],
        six.binary_type is deprecated

    @returns: The URL with the parameters added
    @rtype: six.text_type
    """
    url = string_to_text(url, "Binary values for appendArgs are deprecated. Use text input instead.")

    if hasattr(args, 'items'):
        args = sorted(args.items())
    else:
        args = list(args)

    if len(args) == 0:
        return url

    if '?' in url:
        sep = '&'
    else:
        sep = '?'

    i = 0
    for k, v in args:
        k = string_to_text(k, "Binary values for appendArgs are deprecated. Use text input instead.")
        v = string_to_text(v, "Binary values for appendArgs are deprecated. Use text input instead.")
        args[i] = (k.encode('utf-8'), v.encode('utf-8'))
        i += 1

    encoded_args = urlencode(args)
    # `urlencode` returns `str` in both py27 and py3+. We need to convert it to six.text_type.
    if not isinstance(encoded_args, six.text_type):
        encoded_args = encoded_args.decode('utf-8')
    return '%s%s%s' % (url, sep, encoded_args)


def toBase64(s):
    """Return string s as base64, omitting newlines.

    @type s: six.binary_type
    @rtype six.text_type
    """
    return binascii.b2a_base64(s)[:-1].decode('utf-8')


def fromBase64(s):
    """Return binary data from base64 encoded string.

    @type s: six.text_type, six.binary_type deprecated.
    @rtype six.binary_type
    """
    s = string_to_text(s, "Binary values for s are deprecated. Use text input instead.")
    try:
        return binascii.a2b_base64(s)
    except binascii.Error as why:
        # Convert to a common exception type
        raise ValueError(six.text_type(why))


class Symbol(object):
    """This class implements an object that compares equal to others
    of the same type that have the same name. These are distict from
    string objects.
    """

    def __init__(self, name):
        self.name = name

    def __eq__(self, other):
        return type(self) == type(other) and self.name == other.name

    def __ne__(self, other):
        return not (self == other)

    def __hash__(self):
        return hash((self.__class__, self.name))

    def __repr__(self):
        return '<Symbol %s>' % (self.name,)


def string_to_text(value, deprecate_msg):
    """
    Return input string coverted to text string.

    If input is text, it is returned as is.
    If input is binary, it is decoded using UTF-8 to text.
    """
    assert isinstance(value, (six.text_type, six.binary_type))
    if isinstance(value, six.binary_type):
        warnings.warn(deprecate_msg, DeprecationWarning)
        value = value.decode('utf-8')
    return value


def force_text(value):
    """
    Return a text object representing value in UTF-8 encoding.
    """
    if isinstance(value, six.text_type):
        # It's already a text, just return it.
        return value
    elif isinstance(value, bytes):
        # It's a byte string, decode it.
        return value.decode('utf-8')
    else:
        # It's not a string, convert it.
        return six.text_type(value)
