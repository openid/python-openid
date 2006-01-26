from xml.sax.saxutils import escape
import urlparse
from cgi import parse_qs

def renderQuery(query):
    l = ['<table>',
        ]
    items = query.items()
    items.sort()
    for key, values in items:
        if len(values) > 1:
            rowspan = 'rowspan="%d"' % (len(values),)
            l.append('<tr>\n<td rowspan="%d">%s</td>' % (len(values),
                                                         escape(key)))
            for value in values:
                l.append('<td>%s</td>' % (escape(value),))
            l.append('</tr>')
        else:
            l.append('<tr><td>%s</td><td>%s</td></tr>' % (escape(key),
                                                          escape(values[0])))
    l.append('</table>\n')
    return '\n'.join(l)

def renderURLQuery(url):
    query_string = urlparse.urlparse(url)[4]
    query = parse_qs(query_string)
    return renderQuery(query)
