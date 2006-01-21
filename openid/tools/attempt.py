import time
import urllib
from xml.sax.saxutils import quoteattr

class Attempt(object):
    parent = None

    t_attempt = '''<div class="attempt"><span class="name">%(name)s</span>
<ul>
%(event_rows)s
</ul>
</div>
'''

    # Sometimes an enum type would be nice.
    SUCCESS = ('success',)
    FAILURE = ('failure',)
    INCOMPLETE = ('incomplete',)

    def __init__(self, handle, parent=None):
        self.handle = handle
        self.when = time.time()
        self.event_log = []
        self.subscribers = []
        if parent is not None:
            self.parent = parent

    def subscribe(self, subscriber):
        self.subscribers.append(subscriber)

    def record(self, event):
        self.event_log.append(event)
        for subscriber in self.subscribers:
            subscriber(event)

    def result(self):
        raise NotImplementedError

    def to_html(self):
        def fmtEvent(event):
            return '<li>%s</li>\n' % (event.to_html(),)
        if self.parent is not None:
            name = self.parent.name
        else:
            name = self.__class__.__name__
        d = {
            'name': name,
            'event_rows': ''.join(map(fmtEvent, self.event_log)),
            }
        return self.t_attempt % d

    def __setstate__(self, state):
        self.__dict__.clear()
        self.__dict__.update(state)
        # super(Attempt, self).__setstate__(state)
        if not hasattr(self, 'subscribers'):
            self.subscribers = []

    def __getstate__(self, state=None):
        if state is None:
            state = self.__dict__.copy()
        if 'subscribers' in state:
            del state['subscribers']
        return state


class ResultRow:
    name = None
    handler = None
    attemptClass = Attempt

    def __init__(self, parent, identity_info):
        self._lastAttemptHandle = 0
        self.attempts = []
        self.shortname = self.__class__.__name__
        self.parent_table = parent
        self.identity_info = identity_info

    def getAttempt(self, handle):
        for a in self.attempts:
            if a.handle == handle:
                return a
        raise KeyError(handle)

    def getSuccesses(self):
        return [r for r in self.attempts if r.result() is Attempt.SUCCESS]

    def getFailures(self):
        return [r for r in self.attempts if r.result() is Attempt.FAILURE]

    def getIncompletes(self):
        return [r for r in self.attempts if r.result() is Attempt.INCOMPLETE]

    def newAttempt(self):
        self._lastAttemptHandle += 1
        a = self.attemptClass(str(self._lastAttemptHandle), parent=self)
        self.attempts.append(a)
        return a

    # Webby bits.

    def getURL(self, action="try"):
        return "%s/?action=%s" % (urllib.quote(self.shortname, safe=''),
                                  urllib.quote(action, safe=''))

    def handleRequest(self, req):
        action = req.fields.getfirst("action")
        if action:
            method = getattr(self, "request_" + action)
            if method:
                return method(req)
            else:
                # FIXME: return some status message about broken args
                return None

    def getConsumer(self):
        return self.parent_table.diagnostician.getConsumer()


    t_result_row = '''<tr class=%(rowClass)s>
    <th scope="row" class=%(statusClass)s>%(name)s</th>
    <td headers="success" %(hi_succ)s>%(succ)s</td>
    <td headers="failure" %(hi_fail)s>%(fail)s</td>
    <td headers="incomplete" %(hi_incl)s>%(incl)s</td>
    <td><a href=%(trylink)s rel="nofollow">Try again?</a></td>
</tr>\n'''

    t_empty_row = (
        '<tr class=%(rowClass)s><th scope="row">%(name)s</th><td colspan="4">'
        'Not yet attempted -- <a href=%(trylink)s rel="nofollow">try now</a>.'
        '</td></tr>'
        '\n')

    def to_html(self, rownum=0, highlight=None):
        if rownum % 2:
            rowclass = "odd"
        else:
            rowclass = "even"
        if self.attempts:
            template = self.t_result_row
            recent_result = self.attempts[-1].result()
            recent_status = {
                Attempt.FAILURE: 'failed',
                Attempt.SUCCESS: 'success',
                Attempt.INCOMPLETE: 'incomplete',
                }[recent_result]
        else:
            template = self.t_empty_row
            recent_status = ''

        cell_highlights = {'hi_succ': '',
                           'hi_fail': '',
                           'hi_incl': '',
                           }
        if highlight is not None:
            rowclass += ' highlight'
            cell = {Attempt.FAILURE: 'hi_fail',
                    Attempt.SUCCESS: 'hi_succ',
                    Attempt.INCOMPLETE: 'hi_incl',
                    }[highlight.result() ]
            cell_highlights[cell] = 'class=%s' % (quoteattr('highlight'),)

        values = {
            'rowClass': quoteattr(rowclass),
            'statusClass': quoteattr(recent_status),
            'name': self.name,
            'succ': len(self.getSuccesses()),
            'fail': len(self.getFailures()),
            'incl': len(self.getIncompletes()),
            'trylink': quoteattr(self.getURL()),
            }
        values.update(cell_highlights)
        return template % values


class ResultTable(object):

    def __init__(self, diagnostician, identity_info, rows):
        self.rows = []
        self.diagnostician = diagnostician
        self.identity_info = identity_info
        for rowclass in rows:
            self.rows.append(rowclass(self, identity_info))

    def getChild(self, key):
        for row in self.rows:
            if row.shortname == key:
                return row
        raise KeyError(key)

    def handleRequest(self, req, parts):
        child = self.getChild(parts[0])
        return child.handleRequest(req)

    def __getstate__(self, state=None):
        if state is None:
            state = self.__dict__.copy()
        if 'diagnostician' in state:
            del state['diagnostician']
        return state
