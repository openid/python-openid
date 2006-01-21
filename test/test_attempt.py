
import unittest
from openid.tools import attempt, events

from tools import DummyRequest

class SuccessOrFailureAttempt(attempt.Attempt):
    def result(self):
        return self.code

class SuccessOrFailureRow(attempt.ResultRow):
    attemptClass = SuccessOrFailureAttempt

class TestAttempt(unittest.TestCase):
    def test_subscribe(self):
        eventlist = []
        def subscriber(event):
            eventlist.append(event)
        a = attempt.Attempt("zing")
        a.subscribe(subscriber)
        a.record(events.TextEvent("event1"))
        a.record(events.TextEvent("event2"))
        self.failUnlessEqual(len(eventlist), 2)

class TestResultRow(unittest.TestCase):
    def setUp(self):
        r = self.rrow = SuccessOrFailureRow(None, None)
        results = [
            attempt.Attempt.SUCCESS,
            attempt.Attempt.INCOMPLETE,
            attempt.Attempt.FAILURE,
            attempt.Attempt.SUCCESS,
            attempt.Attempt.INCOMPLETE,
            attempt.Attempt.FAILURE,
            attempt.Attempt.INCOMPLETE,
            attempt.Attempt.FAILURE,
            attempt.Attempt.INCOMPLETE,
            ]
        for result in results:
            a = r.newAttempt()
            a.code = result

    def test_getFailures(self):
        f = self.rrow.getFailures()
        self.failUnlessEqual(len(f), 3)

    def test_getSuccesses(self):
        s = self.rrow.getSuccesses()
        self.failUnlessEqual(len(s), 2)

    def test_getIncompletes(self):
        i = self.rrow.getIncompletes()
        self.failUnlessEqual(len(i), 4)


class TestResultRowWeb(unittest.TestCase):
    def setUp(self):
        class SomeTest(attempt.ResultRow):
            name = "Some Unit Test"
            tryCalled = False

            def request_try(self, req):
                self.tryCalled = True
        self.rrow = SomeTest(None, None)

    def test_getURL(self):
        u = self.rrow.getURL()
        self.failUnlessEqual(u, "SomeTest/?action=try")

    def test_handleRequest(self):
        req = DummyRequest()
        req.path_info = "SomeTest/"
        req._fields["action"] = ["try"]
        self.rrow.handleRequest(req)
        self.failUnless(self.rrow.tryCalled)


if __name__ == '__main__':
    unittest.main()
