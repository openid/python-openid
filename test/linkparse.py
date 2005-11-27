from openid.consumer.parse import parseLinkAttrs

def test():
    failures = []
    exceptions = []

    def run(case, expected):
        try:
            actual = parseLinkAttrs(case)
        except KeyboardInterrupt:
            raise
        except:
            import traceback
            tb = traceback.format_exc()
            exceptions.append((case, expected, tb))
        else:
            if actual != expected:
                failures.append((case, expected, actual))

        run.ntests += 1

    run.ntests = 0

    no_match_cases_str = """
    <link>

    <html>
    <link>

    <head>
    <link>

    <html>
    <head>
    </head>
    <link>

    <html>
    <link>
    <head>

    <link>
    <html>
    <head>

    <html>
    <head>
    </head>
    </html>
    <link>

    <html>
    <head>
    <html>
    <link>

    <head>
    <html>
    <link>

    <html>
    <head>
    <body>
    <link>

    <html>
    <head>
    <head>
    <link>

    <html>
    <head>
    <script>
    <link>
    </script>

    <html>
    <head>
    <!--
    <link>
    -->

    <html>
    <head>
    <![CDATA[
    <link>
    ]]>

    <html>
    <head>
    <![cDaTa[
    <link>
    ]]>
    """

    cases = no_match_cases_str.strip().split('\n\n')
    for case in cases:
        run(case, [])

    empty_link_cases_str = """
    <html>
    <head>
    <link>

    <html><head><link>

    <html>
    <head>
    <link>
    </head>

    <html>
    <head>
    <link>
    </head>
    <link>

    <html>
    <head>
    <link>
    <body>
    <link>

    <html>
    <head>
    <link>
    </html>

    <html>
    <head>
    <link>
    </html>
    <link>

    <html>
    <delicata>
    <head>
    <title>
    <link>

    <HtMl>
    <hEaD>
    <LiNk>

    <butternut>
    <html>
    <summer>
    <head>
    <turban>
    <link>

    <html>
    <head>
    <script>
    <link>

    <html><head><script><link>

    <html>
    <head>
    <!--
    <link>

    <html>
    <head>
    <![CDATA[
    <link>

    <html>
    <head>
    <![ACORN[
    <link>
    ]]>

    <html>
    <head>
    <link>
    -->
    """

    cases = empty_link_cases_str.strip().split('\n\n')
    for case in cases:
        run(case, [{}])

    two_link_cases_str = """
    <html>
    <head>
    <link>
    <link>

    <html>
    <gold nugget>
    <head>
    <link>
    <link>

    <html>
    <head>
    <link>
    <LiNk>
    <body>
    <link>
    """

    cases = two_link_cases_str.strip().split('\n\n')
    expected = [{}, {}]
    for case in cases:
        run(case, expected)

    attr_cases_str = """
    <html><head><link rel=openid.server>

    <html><head><link rel=openid.server/>

    <html><head><link rel=openid.server />

    <html><head><link hubbard rel=openid.server>

    <html><head><link hubbard rel=openid.server/>

    <html><head><link hubbard rel=openid.server />

    <html><head><link / rel=openid.server>

    <html><head><link rel=\"openid.server\">

    <html><head><link rel='openid.server'>
    """

    cases = attr_cases_str.strip().split('\n\n')
    expected = [{'rel':'openid.server'}]
    for case in cases:
        run(case, expected)

    cases = [
        ('<html><head><link x=y><link a=b>',
         [{'x':'y'}, {'a': 'b'}]),
        ('<html><head><link x=&y>',
         [{'x':'&y'}]),
        ('<html><head><link x="&y">',
         [{'x': '&y'}]),
        ('<html><head><link x="&amp;">',
         [{'x': '&'}]),
        ('<html><head><link x="&#26;">',
         [{'x': '&#26;'}]),
        ('<html><head><link x="&lt;">',
         [{'x': '<'}]),
        ('<html><head><link x="&gt;">',
         [{'x': '>'}]),
        ('<html><head><link x="&quot;">',
         [{'x': '"'}]),
        ('<html><head><link x="&amp;&quot;">',
         [{'x': '&"'}]),
        ('<html><head><link x="&amp;&quot;&hellip;&gt;">',
         [{'x': '&"&hellip;>'}]),
        ('<html><head><link x="x&amp;&quot;&hellip;&gt;x">',
         [{'x': 'x&"&hellip;>x'}]),
        ('<html><head><link x=y<>',
         [{'x': 'y'}]),
        ('<html><head><link x=y<link x=y />',
         [{'x': 'y'}, {'x': 'y'}]),
        ('<html><head><link x=y y=><link x=y />',
         [{'x': 'y'}, {'x': 'y'}]),
        ('<html><head><link x=y',
         [{'x': 'y'}]),
        ('<html><head><link x="<">',
         [{'x': '<'}]),
        ('<html><head><link x=">">',
         [{'x': '>'}]),
        (u'<html><head><link x="\u1234">',
         [{u'x': u'\u1234'}]),
        (u'<html><head><link x="\u1234&amp;">',
         [{u'x': u'\u1234&'}]),
        ('<html><head><link x=z x=y>',
         [{'x': 'y'}]),
        ('<html><head><link x=y x=y>',
         [{'x': 'y'}]),
        ('<html><head><link x=y y=z>',
         [{'x': 'y', 'y': 'z'}]),

        # The important examples:
        # Well-formed link rel="openid.server"
        ('<html><head><link rel="openid.server" '
         'href="http://www.myopenid.com/server" />'
         '</head></html>',
         [{'rel': 'openid.server',
           'href': 'http://www.myopenid.com/server'}]),

        # Well-formed link rel="openid.server" and "openid.delegate"
        ('<html><head><link rel="openid.server" '
         'href="http://www.myopenid.com/server" />'
         '<link rel="openid.delegate" href="http://example.myopenid.com/" />'
         '</head></html>',
         [{'rel': 'openid.server',
           'href': 'http://www.myopenid.com/server'},
          {'rel': 'openid.delegate',
            'href': 'http://example.myopenid.com/'}]),

         # from brian's livejournal page
         ("""<!DOCTYPE html
          PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
                 "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
                 <html xmlns="http://www.w3.org/1999/xhtml">
                   <head>
                     <link rel="stylesheet" href="http://www.livejournal.com/~serotta/res/319998/stylesheet?1130478711" type="text/css" />
         <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
 <meta name="foaf:maker" content="foaf:mbox_sha1sum '12f8abdacb5b1a806711e23249da592c0d316260'" />
 <meta name="robots" content="noindex, nofollow, noarchive" />
 <meta name="googlebot" content="nosnippet" />
 <link rel="openid.server" href="http://www.livejournal.com/openid/server.bml" />
                   <title>Brian</title>
         </head>""",
          [{'rel':'stylesheet',
            'href':"http://www.livejournal.com/~serotta/res/319998/stylesheet?1130478711", 'type':'text/css'},
           {'rel':'openid.server',
            'href':'http://www.livejournal.com/openid/server.bml'},
         ])
        
        ]

    for html, expected in cases:
        run(html, expected)

    if failures or exceptions:
        for (case, expected, actual) in failures:
            print '=' * 50
            print 'FAILURE:'
            print 'Case:'
            print case
            print 'Expected:'
            print expected
            print 'Actual:'
            print actual
            print

        for case, expected, exception in exceptions:
            print '=' * 50
            print 'EXCEPTION:'
            print 'Case:'
            print case
            print 'Expected:'
            print expected
            print 'Exception:'
            print exception
            print

        print run.ntests, 'total tests'
        print len(failures), 'failures'
        print len(exceptions), 'exceptions'
    else:
        print run.ntests, 'tests passed'

if __name__ == '__main__':
    test()
