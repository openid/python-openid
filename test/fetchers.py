from openid.consumer import fetchers

def test_fetcher(fetcher, exc, server):
    def geturl(path):
        return 'http://%s:%s%s' % (server.server_name,
                                   server.socket.getsockname()[1],
                                   path)

    def plain(path, code):
        path = '/' + path
        return (path, (code, geturl(path), path))

    cases = [
        plain('success', 200),
        ('/301redirect', (200, geturl('/success'), '/success')),
        ('/302redirect', (200, geturl('/success'), '/success')),
        ('/303redirect', (200, geturl('/success'), '/success')),
        ('/307redirect', (200, geturl('/success'), '/success')),
        plain('notfound', 404),
        plain('badreq', 400),
        plain('forbidden', 403),
        plain('error', 500),
        plain('server_error', 503),
        ]

    for path, expected in cases:
        fetch_url = geturl(path)
        try:
            actual = fetcher.get(fetch_url)
        except (SystemExit, KeyboardInterrupt):
            pass
        except:
            print fetcher, fetch_url
            raise
        else:
            assert actual == expected, (fetcher, actual, expected)

    for err_url in [geturl('/closed'),
                    'http://invalid.janrain.com/',
                    'not:a/url',
                    'ftp://janrain.com/pub/']:
        try:
            result = fetcher.get(err_url)
        except (KeyboardInterrupt, SystemExit):
            raise
        except:
            if not exc:
                print fetcher
                raise
        else:
            assert result is None, (fetcher, result)

def run_fetcher_tests(server):
    exc_fetchers = [fetchers.UrllibFetcher(),]
    try:
        exc_fetchers.append(fetchers.ParanoidHTTPFetcher())
    except RuntimeError, why:
        if why[0] == 'Cannot find pycurl library':
            try:
                import pycurl
            except ImportError:
                pass
            else:
                assert False, 'curl present but not detected'
        else:
            raise

    non_exc_fetchers = []
    for f in exc_fetchers:
        non_exc_fetchers.append(fetchers.ExceptionCatchingFetcher(f))

    for f in exc_fetchers:
        test_fetcher(f, True, server)

    for f in non_exc_fetchers:
        test_fetcher(f, False, server)

from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer

class FetcherTestHandler(BaseHTTPRequestHandler):
    cases = {
        '/success':(200, None),
        '/301redirect':(301, '/success'),
        '/302redirect':(302, '/success'),
        '/303redirect':(303, '/success'),
        '/307redirect':(307, '/success'),
        '/notfound':(404, None),
        '/badreq':(400, None),
        '/forbidden':(403, None),
        '/error':(500, None),
        '/server_error':(503, None),
        }

    def log_request(self, *args):
        pass

    def do_GET(self):
        if self.path == '/closed':
            self.wfile.close()
        else:
            try:
                http_code, location = self.cases[self.path]
            except KeyError:
                self.errorResponse('Bad path')
            else:
                extra_headers = [('Content-type', 'text/plain')]
                if location is not None:
                    base = ('http://%s:%s' % self.server.server_address)
                    location = base + location
                    extra_headers.append(('Location', location))
                self._respond(http_code, extra_headers, self.path)

    def do_POST(self):
        try:
            http_code, extra_headers = self.cases[self.path]
        except KeyError:
            self.errorResponse('Bad path')
        else:
            if http_code in [301, 302, 303, 307]:
                self.errorResponse()
            else:
                content_type = self.headers.get('content-type', 'text/plain')
                extra_headers.append(('Content-type', content_type))
                content_length = int(self.headers.get('Content-length', '-1'))
                body = self.rfile.read(content_length)
                self._respond(http_code, extra_headers, body)

    def errorResponse(self, message=None):
        req = [
            ('HTTP method', self.command),
            ('path', self.path),
            ]
        if message:
            req.append(('message', message))

        body_parts = ['Bad request:\r\n']
        for k, v in req:
            body_parts.append(' %s: %s\r\n' % (k, v))
        body = ''.join(body_parts)
        self._respond(400, [('Content-type', 'text/plain')], body)

    def _respond(self, http_code, extra_headers, body):
        self.send_response(http_code)
        for k, v in extra_headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)
        self.wfile.close()

    def finish(self):
        if not self.wfile.closed:
            self.wfile.flush()
        self.wfile.close()
        self.rfile.close()

def test():
    host = 'localhost'
    # When I use port 0 here, it works for the first fetch and the
    # next one gets connection refused.  Bummer.  So instead, pick a
    # port that's *probably* not in use.
    import os
    port = (os.getpid() % 31000) + 1024

    server = HTTPServer((host, port), FetcherTestHandler)

    import threading
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.setDaemon(True)
    server_thread.start()

    run_fetcher_tests(server)

if __name__ == '__main__':
    test()
