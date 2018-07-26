"""Utilities to parse YADIS header from HTML."""
from __future__ import unicode_literals

from lxml import etree

from openid.yadis.constants import YADIS_HEADER_NAME

__all__ = ['findHTMLMeta', 'MetaNotFound']


class MetaNotFound(Exception):
    """Yadis meta tag not found in the HTML page."""


def xpath_lower_case(context, values):
    """Return lower cased values in XPath."""
    return [v.lower() for v in values]


def findHTMLMeta(stream):
    """Look for a meta http-equiv tag with the YADIS header name.

    @param stream: Source of the html text
    @type stream: Readable text I/O file object

    @return: The URI from which to fetch the XRDS document
    @rtype: six.text_type

    @raises MetaNotFound: raised with the content that was
        searched as the first parameter.
    """
    parser = etree.HTMLParser()
    try:
        html = etree.parse(stream, parser)
    except (ValueError, etree.XMLSyntaxError):
        raise MetaNotFound("Couldn't parse HTML page.")

    # Invalid input may return element with no content
    if html.getroot() is None:
        raise MetaNotFound("Couldn't parse HTML page.")

    # Create a XPath evaluator with a local function to lowercase values.
    xpath_evaluator = etree.XPathEvaluator(html, extensions={(None, 'lower-case'): xpath_lower_case})
    # Find YADIS meta tag, case insensitive to the header name.
    yadis_headers = xpath_evaluator('/html/head/meta[lower-case(@http-equiv)="{}"]'.format(YADIS_HEADER_NAME.lower()))
    if not yadis_headers:
        raise MetaNotFound('Yadis meta tag not found.')

    yadis_header = yadis_headers[0]
    yadis_url = yadis_header.get('content')
    if yadis_url is None:
        raise MetaNotFound('Attribute "content" missing in yadis meta tag.')
    return yadis_url
