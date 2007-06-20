"Test some examples."

import os.path, unittest, sys, time
from cStringIO import StringIO

import twill.commands, twill.parse, twill.unit

from openid.consumer.discover import \
     OpenIDServiceEndpoint, OPENID_1_1_TYPE
from openid.consumer.consumer import AuthRequest

class TwillTest(twill.unit.TestInfo):
    """Variant of twill.unit.TestInfo that runs scripts from strings,
    not filename."""
    def run_script(self):
        time.sleep(self.sleep)
        # twill.commands.go(self.get_url())
        self.script(self)
        

def runExampleServer(host, port, data_path):
    thisfile = os.path.abspath(sys.modules[__name__].__file__)
    topDir = thisfile.rsplit(os.sep, 3)[0]
    exampleDir = os.path.join(topDir, 'examples')
    serverExample = os.path.join(exampleDir, 'server.py')
    serverModule = {}
    execfile(serverExample, serverModule)
    serverMain = serverModule['main']

    serverMain(host, port, data_path)

# def scriptName(name):
#     return os.path.join(os.path.dirname(sys.modules[__name__].__file__),
#                         'twill', name)


class TestServer(unittest.TestCase):
    def setUp(self):
        import twill
        self.twillOutput = StringIO()
        self.twillErr = StringIO()
        twill.set_output(self.twillOutput)
        twill.set_errout(self.twillErr)
        self.server_port = 8080

        # We need something to feed the server as a realm, but it needn't
        # be reachable.  (Until we test realm verification.)
        self.realm = 'http://127.0.0.1/%s' % (self.id(),)
        self.return_to = self.realm + '/return_to'

        twill.commands.reset_browser()

    def runExampleServer(self):
        # FIXME - make sure sstore starts clean.
        runExampleServer('127.0.0.1', self.server_port, 'sstore')

    def v1endpoint(self, port):
        base = "http://127.0.0.1:%s" % (port,)
        ep = OpenIDServiceEndpoint()
        ep.claimed_id = base + "/id/bob"
        ep.server_url = base + "/openidserver"
        ep.type_uris = [OPENID_1_1_TYPE]
        return ep
        
    # TODO: test discovery

    def test_checkidv1(self):
        ti = TwillTest(self.twill_checkidv1, self.runExampleServer,
                       self.server_port, sleep=0.2)
        twill.unit.run_test(ti)
        
        if self.twillErr.getvalue():
            self.fail(self.twillErr.getvalue())

        # self.fail(self.twillOutput.getvalue())

    def twill_checkidv1(self, twillInfo):
        endpoint = self.v1endpoint(self.server_port)
        authreq = AuthRequest(endpoint, assoc=None)
        url = authreq.redirectURL(self.realm, self.return_to)

        c = twill.commands

        try:
            c.go(url)
            c.get_browser()._browser.set_handle_redirect(False)
            c.submit("yes")
            c.code(302)
            headers = c.get_browser()._browser.response().info()
            finalURL = headers['Location']
            self.failUnless('openid.mode=id_res' in finalURL, finalURL)
            self.failUnless('openid.identity=' in finalURL, finalURL)
        except twill.commands.TwillAssertionError, e:
            b = c.get_browser()
            msg = '%s\nFinal page:\n%s' % (
                str(e), b.get_html())
            self.fail(msg)

    def tearDown(self):
        twill.set_output(None)
        twill.set_errout(None)

unittest.main()
