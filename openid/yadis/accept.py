"""Functions for generating and parsing HTTP Accept: headers for supporting server-directed content negotiation."""
from __future__ import unicode_literals

from operator import itemgetter

import six

from openid.oidutil import string_to_text


def generateAcceptHeader(*elements):
    """Generate an accept header value

    [six.text_type or (six.text_type, float)] -> six.text_type
    """
    parts = []
    for element in elements:
        if isinstance(element, six.string_types):
            qs = "1.0"
            mtype = string_to_text(element,
                                   "Binary values for generateAcceptHeader are deprecated. Use text input instead.")
        else:
            mtype, q = element
            mtype = string_to_text(mtype,
                                   "Binary values for generateAcceptHeader are deprecated. Use text input instead.")
            q = float(q)
            if q > 1 or q <= 0:
                raise ValueError('Invalid preference factor: %r' % q)

            qs = '%0.1f' % (q,)

        parts.append((qs, mtype))

    parts.sort()
    chunks = []
    for q, mtype in parts:
        if q == '1.0':
            chunks.append(mtype)
        else:
            chunks.append('%s; q=%s' % (mtype, q))

    return ', '.join(chunks)


def parseAcceptHeader(value):
    """Parse an accept header, ignoring any accept-extensions

    returns a list of tuples containing main MIME type, MIME subtype,
    and quality markdown.

    six.text_type -> [(six.text_type, six.text_type, float)]
    """
    value = string_to_text(value, "Binary values for parseAcceptHeader are deprecated. Use text input instead.")
    chunks = [chunk.strip() for chunk in value.split(',')]
    accept = []
    for chunk in chunks:
        parts = [s.strip() for s in chunk.split(';')]

        mtype = parts.pop(0)
        if '/' not in mtype:
            # This is not a MIME type, so ignore the bad data
            continue

        main, sub = mtype.split('/', 1)

        for ext in parts:
            if '=' in ext:
                k, v = ext.split('=', 1)
                if k == 'q':
                    try:
                        q = float(v)
                        break
                    except ValueError:
                        # Ignore poorly formed q-values
                        pass
        else:
            q = 1.0

        accept.append((main, sub, q))

    # Sort in order q, main, sub
    return sorted(accept, key=itemgetter(2, 0, 1), reverse=True)


def matchTypes(accept_types, have_types):
    """Given the result of parsing an Accept: header, and the
    available MIME types, return the acceptable types with their
    quality markdowns.

    For example:

    >>> acceptable = parseAcceptHeader('text/html, text/plain; q=0.5')
    >>> matchTypes(acceptable, ['text/plain', 'text/html', 'image/jpeg'])
    [('text/html', 1.0), ('text/plain', 0.5)]


    Type signature: ([(six.text_type, six.text_type, float)], [six.text_type]) -> [(six.text_type, float)]
    """
    if not accept_types:
        # Accept all of them
        default = 1
    else:
        default = 0

    match_main = {}
    match_sub = {}
    for (main, sub, qvalue) in accept_types:
        main = string_to_text(main, "Binary values for matchTypes accept_types are deprecated. Use text input instead.")
        sub = string_to_text(sub, "Binary values for matchTypes accept_types are deprecated. Use text input instead.")
        if main == '*':
            default = max(default, qvalue)
            continue
        elif sub == '*':
            match_main[main] = max(match_main.get(main, 0), qvalue)
        else:
            match_sub[(main, sub)] = max(match_sub.get((main, sub), 0), qvalue)

    accepted_list = []
    order_maintainer = 0
    for mtype in have_types:
        mtype = string_to_text(mtype, "Binary values for matchTypes have_types are deprecated. Use text input instead.")
        main, sub = mtype.split('/')
        if (main, sub) in match_sub:
            quality = match_sub[(main, sub)]
        else:
            quality = match_main.get(main, default)

        if quality:
            accepted_list.append((1 - quality, order_maintainer, quality, mtype))
            order_maintainer += 1

    accepted_list.sort()
    return [(match, q) for (_, _, q, match) in accepted_list]


def getAcceptable(accept_header, have_types):
    """Parse the accept header and return a list of available types in
    preferred order. If a type is unacceptable, it will not be in the
    resulting list.

    This is a convenience wrapper around matchTypes and
    parseAcceptHeader.

    (six.text_type, [six.text_type]) -> [six.text_type]
    """
    accept_header = string_to_text(
        accept_header, "Binary values for getAcceptable accept_header are deprecated. Use text input instead.")
    accepted = parseAcceptHeader(accept_header)
    preferred = matchTypes(accepted, have_types)
    return [mtype for (mtype, _) in preferred]
