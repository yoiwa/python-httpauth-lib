# Client-side implementation of HTTP Digest authentication (including SHA-256)
# A part of the DOORMEN controller.
# (c) 2018 National Institute of Advanced Industrial Science and Technology.

import collections
import os
import sys
import re
import binascii
import threading
from requests.exceptions import ContentDecodingError, RequestsWarning
from warnings import warn
from copy import copy

from .digest_auth_funcs import random_value, hash_algorithms, compute_digest, hash
from .auth_http_header import encode_http7615_header, parse_http7615_header, parse_http7615_authinfo, parse_csv_string
import requests
import requests.cookies

LastReq = collections.namedtuple('LastReq', ['nc', 'c_resp', 'qop', 'respauth'])

class DigestClientSession:
    __slots__ = ['algorithm', 'qop', 'realm', 'nonce', 'nc', 'cnonce', 'opaque', 'last_req']

    def __init__(self):
        pass

class DigestAuth2(requests.auth.AuthBase):
    # Logics for session resending and thread_local state management is
    # imported from requests/auth.py
    # it is the only available "documentation" for "requests"-library internals.

    # others are reimplemented here for
    #  - SHA256 support,
    #  - rspauth support.
    #  - support for "nextnonce" and "stale" flags.
    #  - more rigid rfc7615 header parsing,

    def __init__(self, username, password, qops=['auth'], realm=None, strict_auth=True):
        self.username = username
        self.password = password
        self.realm = realm
        self.qops = qops
        self.strict_auth = strict_auth
        self._tls = threading.local()
        self._initialize_tls()

    def choose_qop(self, qop_header):
        l = parse_csv_string(qop_header)
        for q in self.qops:
            if q in l:
                return q
        return None

    def _initialize_tls(self):
        pass

    def __call__(self, r):
        tls = self._tls
        url = r.url
        url = re.sub(r'^[a-z]+://[^/]+/', '/', url)

        if hasattr(tls, 'session'):
            session = tls.session
            #print("@@@ WE HAVE SESSION {}".format(session.nonce))

            session.nc += 1

            nc_str = "%08x" % session.nc

            if session.qop == 'auth-int':
                req_body = r.body or b''
            else:
                req_body = None

            c_resp, respauth = compute_digest(
                session.algorithm, username=self.username, realm=session.realm,
                password=self.password, method=r.method, url=url,
                nonce=session.nonce, nc=nc_str, cnonce=session.cnonce,
                qop=session.qop, req_body=req_body)
            h = encode_http7615_header(
                [('Digest',
                  { 'algorithm': session.algorithm,
                    'qop': session.qop,
                    'realm': session.realm,
                    'uri': url,
                    'username': self.username,
                    'nonce': session.nonce,
                    'nc': nc_str,
                    'cnonce': session.cnonce,
                    'opaque': session.opaque,
                    'response': c_resp,
            })])
            session.last_req = LastReq(nc = session.nc,
                                       c_resp = c_resp,
                                       qop = session.qop,
                                       respauth = respauth)
            #print("@@@ added  header Authorization: {}".format(h))
            r.headers['Authorization'] = h
        else:
            #print("@@@  WE DON'T HAVE SESSION")
            pass

        ### dirty tricks:
        try:
            self._tls.pos = r.body.tell()
        except AttributeError:
            self._tls.pos = None
        r.register_hook('response', self.response_hook)
        return r

    def response_hook(self, r, **kwargs):
        if r.status_code == 401:
            return self.process_401(r, **kwargs)
        elif r.status_code < 400:
            return self.process_200(r, **kwargs)
        return r

    def process_401(self, r, **kwargs):
        tls = self._tls

        #print("@@@ 401 HOOK CALLED")
        if 'www-authenticate' not in r.headers:
            print("@@@ no WWW-Authenticate header.", file=sys.stderr)
            return r
        try:
            auth_header = parse_http7615_header(r.headers['www-authenticate'])
        except:
            print("@@@ WWW-Authenticate parse failed.", file=sys.stderr)
            return r

        #print("@@@ WWW-Authenticate header: {!r}.".format(auth_header))

        challenge = None
        retry_ok = False

        if hasattr(tls, 'session'):
            sess = tls.session
            #print("@@@ WE HAVE SESSION {}. search for matching".format(sess.nonce))
            for (c, kv) in auth_header:
                if (c != 'Digest' or
                    kv.get('algorithm') != sess.algorithm or
                    kv.get('realm') != sess.realm):
                    continue
                #print("@@@ matched session seems to be {!r}".format(kv))
                challenge = kv
                if kv.get('stale') == '1':
                    # session expired. retrying.
                    challenge = kv
                    retry_ok = True
                else:
                    retry_ok = False
                break
            if not retry_ok:
                print("@@@ authentication is not retryable.".format(kv), file=sys.stderr)
                return r

        if not challenge:
            #print("@@@ looks for the best challenge")
            prec, challenge = (-1, None)
            for (c, kv) in auth_header:
                if c != 'Digest': continue
                algo = kv.get('algorithm', None)
                if not algo or algo not in hash_algorithms: continue
                if self.realm and kv.get('realm', None) != self.realm: continue
                (_h, _s, p) = hash_algorithms[algo]
                if p > prec:
                    prec, challenge = p, kv

        #print("@@@ best challenge to be {!r}".format(challenge))
        if not challenge:
            print("@@@ no matching authentication scheme found.".format(kv), file=sys.stderr)
            return r

        # now making a retry request.
        #   a lot of undocumented, dirty tricks here (marked ####)
        #   for requests-lib internals.
        #   It may require renovation for future requests-lib updates.

        #print("@@@ creaing new session from challenge {}".format(challenge))
        session = self.create_new_session(challenge=challenge)
        if not session:
            print("@@@ creaing new session from challenge {} FAILED! (possibly bad headers from server)".format(challenge), file=sys.stderr)
            return r

        tls.session = session

        #### very internal of requests-lib.
        if self._tls.pos is not None:
            r.request.body.seek(self._tls.pos)
        r.content
        r.close()
        p = r.request.copy()
        requests.cookies.extract_cookies_to_jar(p._cookies, r.request, r.raw)
        p.prepare_cookies(p._cookies)

        # print("@@@ preparing retry {!r}".format(p))
        self.__call__(p)
        # print("@@@ sending retry {!r}".format(p))
        _r = r.connection.send(p, **kwargs)
        # print("@@@ sending retry {!r} done".format(p))
        _r.history.append(r)
        _r.request = p
        #### end of dirty magics

        return _r

    def create_new_session(self, *, challenge=None, nextnonce=None, session=None):
        s = DigestClientSession()
        if challenge:
            try:
                s.algorithm = challenge['algorithm']
                s.qop = self.choose_qop(challenge['qop'])
                s.realm = challenge['realm']
                s.nonce = challenge['nonce']
                s.nc = 0
                s.cnonce = random_value(160)
                s.opaque = challenge['opaque']
                s.last_req = None
            except KeyError:
                return None
            else:
                if not s.qop: return None
                return s
        elif nextnonce and session:
            s = copy(session)
            s.nonce = nextnonce
            s.nc = 0
            s.last_req = None
            return s
        else:
            raise ValueError

    def process_200(self, r, **kwargs):
        if 'authentication-info' not in r.headers:
            return r
        try:
            auth_info = r.headers['authentication-info']
            auth_info = parse_http7615_authinfo(auth_info)
        except ValueError as e:
            print("@@@ parsing Authentication-Info: header failed: {}: {}.".format(auth_info, e), file=sys.stderr)
            return r

        assert(self._tls.session is not None)
        session = self._tls.session
        svr_rspauth = session.last_req.respauth
        if session.last_req.qop == 'auth':
            e1 = svr_rspauth(None).lower()
            e2 = auth_info.get('rspauth', "<none>").lower()
        else:
            body = r.content or b''
            h, _s, _p = hash_algorithms[session.algorithm]
            print("@@@ RESPONSEBODY = {}, hash={}".format(body, hash(h)(body)))
            e1 = svr_rspauth(hash(h)(body)).lower()
            e2 = auth_info.get('rspauth', "<none>").lower()
        if e1 != e2:
            msg = "Digest ressponse authentication failed: expected {}, returned {}".format(e1, e2)
            if self.strict_auth:
                raise ContentDecodingError(msg)
            else:
                warn(RequestsWarning(msg))
        else:
            print("@@@ checking response authentication OK: {}".format(e1), file=sys.stderr)

        nextnonce = auth_info.get('nextnonce')
        if nextnonce:
            print("@@@ Nonce renewal requested: {} -> {}".format(session.nonce, nextnonce), file=sys.stderr)
            self._tls.session = self.create_new_session(nextnonce=nextnonce,session=session)
        return r
