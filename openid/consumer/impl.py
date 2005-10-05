import urlparse
import urllib
import string

from openid.consumer.stores import ConsumerAssociation, OpenIDStore
from openid.consumer.parse import parseLinkAttrs
from openid import oidUtil
from openid.dh import DiffieHellman

class OpenIDConsumer(object):
    CHRS = string.letters + string.digits
    NONCE_LEN = 8

    def __init__(self, store, trust_root, fetcher, immediate, split):
        if store is None:
            self.store = DumbStore()
        else:
            self.store = store
        self.trust_root = trust_root
        self.fetcher = fetcher

        if immediate:
            self.mode = 'checkid_immediate'
        else:
            self.mode = 'checkid_setup'

        self.immediate = immediate
        self.split = split


    def constructRedirect(self, proxy):
        import sys
        sys.stderr.write('in constructRedirect')
        ret = self._findIdentityInfo(proxy.getUserInput())
        if ret is None:
            return None

        sys.stderr.write('Identity info found')
        consumer_id, server_id, server = ret
        nonce = oidUtil.randomString(self.NONCE_LEN, self.CHRS)
        self.store.storeNonce(nonce)

        token = self._genToken(nonce, consumer_id)
        return_to = proxy.getReturnTo(token)

        redir_args = {'openid.identity': server_id,
                      'openid.return_to': return_to,}

        if self.trust_root is not None:
            redir_args['openid.trust_root'] = self.trust_root

        redir_args['openid.mode'] = self.mode

        assoc_handle = self._getAssociation(server)

        if assoc_handle is not None:
            redir_args['openid.assoc_handle'] = assoc_handle

        return str(oidUtil.appendArgs(server, redir_args))


    def processServerResponse(self, proxy):
        mode = self._extract(proxy, 'mode')
        func = getattr(self, '_do_' + mode, None)
        if func is None:
            return proxy.loginError()

        return func(proxy)


    def checkAuth(self, proxy):
        blob = proxy.getCheckAuthParams()
        if blob is None:
            return proxy.loginError()

        return self._checkAuth(proxy, blob)

    def _checkAuth(self, proxy, blob):
        ret = self._splitCheckAuthBlob(blob)
        if ret is None:
            return proxy.loginError()

        nonce, consumer_id, post_data, server_url = ret

        ret = self.fetcher.post(server_url, post_data)
        if ret is None:
            return proxy.loginError()

        results = oidUtil.parsekv(ret[1])
        is_valid = results.get('is_valid', 'false')

        if is_valid == 'true':
            invalidate_handle = results.get('invalidate_handle')
            if invalidate_handle is not None:
                self.store.removeAssociation(server_url, invalidate_handle)

            return proxy.loginGood(consumer_id)

        error = results.get('error')
        if error is not None:
            return proxy.serverError(error)

        return proxy.loginError()

    def _do_id_res(self, proxy):
        return_to = self._extract(proxy, 'return_to')
        server_id = self._extract(proxy, 'identity')
        assoc_handle = self._extract(proxy, 'assoc_handle')

        if return_to is None or server_id is None or assoc_handle is None:
            return proxy.loginError()

        token = proxy.verifyReturnTo(return_to)
        if token is None:
            return proxy.loginError()

        ret = self._splitToken(token)
        if ret is None:
            return proxy.loginError()

        nonce, consumer_id = ret

        user_setup_url = self._extract(proxy, 'user_setup_url')
        if user_setup_url is not None:
            return proxy.setupNeeded(user_setup_url)

        cid, sid, server_url = self._findIdentityInfo(consumer_id)
        if cid != consumer_id or sid != server_id:
            return proxy.loginError()

        assoc = self.store.getAssociation(server_url)

        if (assoc is None or assoc.handle != assoc_handle or
            assoc.expires_in <= 0):
            # It's not an association we know about.  Dumb mode is our
            # only possible path for recovery.
            check_args = dict(proxy.getOpenIDParameters())
            check_args['openid.mode'] = 'check_authentication'
            post_data = urllib.urlencode(check_args)

            blob = self._genCheckAuthBlob(
                nonce, consumer_id, post_data, server_url)

            if self.split:
                return proxy.checkAuthRequired(blob)
            else:
                return self._checkAuth(proxy, blob)

        # Check the signature
        sig = self._extract(proxy, 'sig')
        signed = self._extract(proxy, 'signed')
        if sig is None or signed is None:
            return proxy.loginError()

        args = proxy.getOpenIDParameters()
        signed_list = signed.split(',')
        _signed, v_sig = oidUtil.signReply(args, assoc.secret, signed_list)

        if v_sig != sig:
            return proxy.loginError()

        if not self.store.useNonce(nonce):
            return proxy.loginError()

        return proxy.loginGood(consumer_id)


    def _do_cancel(self, proxy):
        return proxy.loginCancelled()

    def _do_error(self, proxy):
        error = self._extract(proxy, 'error')
        if error is None:
            proxy.serverError('Unspecified Server Error')
        else:
            proxy.serverError('Server Error: %r' % error)

    def _extract(self, proxy, param):
        return proxy.getOpenIDParameters().get('openid.' + param)

    def _getAssociation(self, server_url):
        assoc = self.store.getAssociation(server_url)

        if assoc is not None:
            return assoc

        return self._associate(server_url)

    def _genCheckAuthBlob(self, nonce, consumer_id, post_data, server_url):
        joined = '\x00'.join([nonce, consumer_id, post_data, server_url])
        sig = oidUtil.hmacSha1(self.store.getAuthKey(), joined)

        return '%s%s' % (sig, joined)

    def _splitCheckAuthBlob(self, blob):
        if len(blob) < 20:
            return None

        sig, joined = blob[:20], blob[20:]
        if oidUtil.hmacSha1(self.store.getAuthKey(), joined) != sig:
            return None

        split = joined.split('\x00')
        if len(split) != 4:
            return None

        return split

    def _genToken(self, nonce, consumer_id):
        joined = '%s%s' % (nonce, consumer_id)
        sig = oidUtil.hmacSha1(self.store.getAuthKey(), joined)

        return '%s%s' % (sig, joined)

    def _splitToken(self, token):
        if len(token) < 20:
            return None

        sig, res = token[:20], token[20:]
        if oidUtil.hmacSha1(self.store.getAuthKey(), res) != sig:
            return None

        return res[:self.NONCE_LEN], res[self.NONCE_LEN:]

    def _quoteMinimal(self, s):
        # Do not escape anything that is already 7-bit safe, so we do the
        # minimal transform on the identity URL
        res = []
        for c in s:
            if c >= u'\x80':
                for b in c.encode('utf8'):
                    res.append('%%%02X' % ord(b))
            else:
                res.append(c)
        return str(''.join(res))

    def _normalizeUrl(self, url):
        assert isinstance(url, basestring), type(url)

        url = url.strip()
        parsed = urlparse.urlparse(url)

        if parsed[0] == '':
            url = 'http://' + url
            parsed = urlparse.urlparse(url)

        authority = parsed[1].encode('idna')
        tail = map(self._quoteMinimal, parsed[2:])
        if tail[0] == '':
            tail[0] = '/'
        encoded = (str(parsed[0]), authority) + tuple(tail)
        url = urlparse.urlunparse(encoded)
        assert type(url) is str

        return url

    def _findIdentityInfo(self, identity_url):
        url = self._normalizeUrl(identity_url)
        ret = self.fetcher.get(url)
        if ret is None:
            return None

        consumer_id, data = ret

        server = None
        delegate = None
        link_attrs = parseLinkAttrs(data)
        for attrs in link_attrs:
            rel = attrs.get('rel')
            if rel == 'openid.server' and server is None:
                href = attrs.get('href')
                if href is not None:
                    server = href

            if rel == 'openid.delegate' and delegate is None:
                href = attrs.get('href')
                if href is not None:
                    delegate = href

        if server is None:
            return None

        if delegate is not None:
            server_id = delegate
        else:
            server_id = consumer_id

        return tuple(map(self._normalizeUrl, (consumer_id, server_id, server)))

    def _associate(self, server_url):
        dh = DiffieHellman()
        cpub = oidUtil.toBase64(oidUtil.longToStr(dh.createKeyExchange()))

        args = {
            'openid.mode': 'associate',
            'openid.assoc_type':'HMAC-SHA1',
            'openid.session_type':'DH-SHA1',
            'openid.dh_modulus': oidUtil.toBase64(oidUtil.longToStr(dh.p)),
            'openid.dh_gen': oidUtil.toBase64(oidUtil.longToStr(dh.g)),
            'openid.dh_consumer_public': cpub,
            }

        body = urllib.urlencode(args)

        url, data = self.fetcher.post(server_url, body)
        results = oidUtil.parsekv(data)

        try:
            assoc_type = results['assoc_type']
            if assoc_type != 'HMAC-SHA1':
                return None

            assoc_handle = results['assoc_handle']
            expires_in = results.get('expires_in', '0')

            session_type = results.get('session_type')
            if session_type is None:
                secret = oidUtil.fromBase64(results['mac_key'])
            else:
                if session_type != 'DH-SHA1':
                    return None

                spub = oidUtil.strToLong(
                    oidUtil.fromBase64(results['dh_server_public']))

                dh_shared = dh.decryptKeyExchange(spub)
                enc_mac_key = results['enc_mac_key']
                secret = oidUtil.strxor(
                    oidUtil.fromBase64(enc_mac_key),
                    oidUtil.sha1(oidUtil.longToStr(dh_shared)))

            return ConsumerAssociation.fromExpiresIn(
                expires_in, server_url, assoc_handle, secret)

        except KeyError:
            return None


class DumbStore(OpenIDStore):
    def __init__(self, auth_key='n08e7fgu4b981fhxifdu'):
        self.auth_key = auth_key

    def storeAssociation(self, unused_association):
        pass

    def getAssociation(self, unused_server_url):
        return None

    def removeAssociation(self, unused_server_url, unused_handle):
        return False

    def storeNonce(self, nonce):
        pass

    def useNonce(self, nonce):
        """In a system truly limited to dumb mode, nonces must all be
        accepted."""
        return True

    def getAuthKey(self):
        return self.auth_key
