from openid.server import interface
from openid.trustroot import TrustRoot
from openid import oidUtil
from openid import cryptutil

_signed_fields = ['mode', 'identity', 'return_to']

class OpenIDServerImpl(object):
    def __init__(self, server_url, internal_store, external_store):
        self.url = server_url
        self.istore = internal_store
        self.estore = external_store

    def getAuthData(self, args):
        trust_root = args.get('openid.trust_root')
        identity = args.get('openid.identity')
        return identity, trust_root

    def processGet(self, authorized, args):
        identity = args.get('openid.identity')
        if identity is None:
            return self._getErr(args, 'No identity specified')

        trust_root = args.get('openid.trust_root')
        tr = TrustRoot.parse(trust_root)
        if tr is None:
            return self._getErr(args, 'Malformed trust_root: %s' % trust_root)

        return_to = args.get('openid.return_to')
        if return_to is None:
            return self._getErr(args, 'No return_to URL specified')

        if not tr.validateURL(return_to):
            return self._getErr(
                args, 'return_to(%s) not valid against trust_root(%s)' % (
                return_to, trust_root))

        assoc_handle = args.get('openid.assoc_handle')
        mode = args.get('openid.mode')

        if authorized:
            if mode == 'checkid_immediate':
                nargs = dict(args)
                nargs['openid.mode'] = 'checkid_setup'
                return interface.REDIRECT, oidUtil.appendArgs(self.url, nargs)

            elif mode == 'checkid_setup':
                ret = oidUtil.appendArgs(self.url, args)
                can = oidUtil.appendArgs(return_to, {'openid.mode': 'cancel'})

                return interface.DO_AUTH, (ret, can)

            else:
                return self._getErr(
                    args, 'open.mode (%r) not understood' % mode)

        reply = {
            'openid.mode': 'id_res',
            'openid.return_to': return_to,
            'openid.identity': identity,
            }

        if assoc_handle:
            assoc = self.estore.lookup(assoc_handle, 'HMAC-SHA1')

            # fall back to dumb mode if assoc_handle not found,
            # and send the consumer an invalidate_handle message
            if assoc is None or assoc.expires_in <= 0:
                if assoc is not None and assoc.expires_in <= 0:
                    self.estore.remove(assoc.handle)
                assoc = self.istore.get('HMAC-SHA1')
                reply['openid.invalidate_handle'] = assoc_handle
        else:
            assoc = self.istore.get('HMAC-SHA1')

        reply.update({
            'openid.assoc_handle': assoc.handle,
            })

        signed, sig = cryptutil.signReply(reply, assoc.secret, _signed_fields)

        reply.update({
            'openid.signed': signed,
            'openid.sig': sig,
            })

        return interface.REDIRECT, oidUtil.appendArgs(return_to, reply)

    def processPost(self, args):
        pass

    def _getErr(self, args, msg):
        return_to = args.get('openid.return_to')
        if return_to:
            err = {
                'openid.mode': 'error',
                'openid.error': msg
                }
            return interface.REDIRECT, oidUtil.appendArgs(return_to, err)
        else:
            return interface.ERROR, msg

    def _postErr(self, msg):
        return interface.ERROR, msg

