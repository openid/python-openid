# -*- test-case-name: openid.test.test_xri -*-
"""Utility functions for handling XRIs.

@see: XRI Syntax v2.0 at the
      U{OASIS XRI Technical Committee<http://www.oasis-open.org/committees/tc_home.php?wg_abbrev=xri>}
"""
from __future__ import unicode_literals

import re

from six.moves.urllib.parse import quote

from openid.oidutil import string_to_text
from openid.urinorm import GEN_DELIMS, PERCENT_ENCODING_CHARACTER, SUB_DELIMS

XRI_AUTHORITIES = ['!', '=', '@', '+', '$', '(']


def identifierScheme(identifier):
    """Determine if this identifier is an XRI or URI.

    @returns: C{"XRI"} or C{"URI"}
    """
    if identifier.startswith('xri://') or (identifier and identifier[0] in XRI_AUTHORITIES):
        return "XRI"
    else:
        return "URI"


def toIRINormal(xri):
    """Transform an XRI to IRI-normal form."""
    if not xri.startswith('xri://'):
        xri = 'xri://' + xri
    return escapeForIRI(xri)


_xref_re = re.compile(r'\((.*?)\)')


def _escape_xref(xref_match):
    """Escape things that need to be escaped if they're in a cross-reference.
    """
    xref = xref_match.group()
    xref = xref.replace('/', '%2F')
    xref = xref.replace('?', '%3F')
    xref = xref.replace('#', '%23')
    return xref


def escapeForIRI(xri):
    """Escape things that need to be escaped when transforming to an IRI."""
    xri = xri.replace('%', '%25')
    xri = _xref_re.sub(_escape_xref, xri)
    return xri


def toURINormal(xri):
    """Transform an XRI to URI normal form."""
    return iriToURI(toIRINormal(xri))


def iriToURI(iri):
    """Transform an IRI to a URI by escaping unicode.

    According to RFC 3987, section 3.1, "Mapping of IRIs to URIs"

    @type iri: six.text_type, six.binary_type deprecated.
    @rtype: six.text_type
    """
    iri = string_to_text(iri, "Binary input for iriToURI is deprecated. Use text input instead.")

    # This is hackish. `quote` requires `str` in both py27 and py3+.
    if isinstance(iri, str):
        # Python 3 branch
        return quote(iri, GEN_DELIMS + SUB_DELIMS + PERCENT_ENCODING_CHARACTER)
    else:
        # Python 2 branch
        return quote(iri.encode('utf-8'),
                     (GEN_DELIMS + SUB_DELIMS + PERCENT_ENCODING_CHARACTER).encode('utf-8')).decode('utf-8')


def providerIsAuthoritative(providerID, canonicalID):
    """Is this provider ID authoritative for this XRI?

    @returntype: bool
    """
    # XXX: can't use rsplit until we require python >= 2.4.
    lastbang = canonicalID.rindex('!')
    parent = canonicalID[:lastbang]
    return parent == providerID


def rootAuthority(xri):
    """Return the root authority for an XRI.

    Example::

        rootAuthority("xri://@example") == "xri://@"

    @type xri: six.text_type
    @returntype: six.text_type
    """
    if xri.startswith('xri://'):
        xri = xri[6:]
    authority = xri.split('/', 1)[0]
    if authority[0] == '(':
        # Cross-reference.
        # XXX: This is incorrect if someone nests cross-references so there
        #   is another close-paren in there.  Hopefully nobody does that
        #   before we have a real xriparse function.  Hopefully nobody does
        #   that *ever*.
        root = authority[:authority.index(')') + 1]
    elif authority[0] in XRI_AUTHORITIES:
        # Other XRI reference.
        root = authority[0]
    else:
        # IRI reference.  XXX: Can IRI authorities have segments?
        segments = authority.split('!')
        segments = [c for s in segments for c in s.split('*')]
        root = segments[0]

    return XRI(root)


def XRI(xri):
    """An XRI object allowing comparison of XRI.

    Ideally, this would do full normalization and provide comparsion
    operators as per XRI Syntax.  Right now, it just does a bit of
    canonicalization by ensuring the xri scheme is present.

    @param xri: an xri string
    @type xri: six.text_type
    """
    if not xri.startswith('xri://'):
        xri = 'xri://' + xri
    return xri
