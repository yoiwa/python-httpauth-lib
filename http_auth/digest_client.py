# Client-side implementation of HTTP Digest authentication (including SHA-256)
# A part of httpauth_lib from the DOORMEN project.
# (c) 2018-2019 National Institute of Advanced Industrial Science and Technology.

from collections import namedtuple
#import sys
import re
import threading
from .multihop_client import MultihopAuthBase
from requests.exceptions import ContentDecodingError, RequestsWarning
from warnings import warn
from copy import copy

from .digest_auth_funcs import random_value, hash_algorithms, compute_digest
from .auth_http_header import encode_http7615_header, parse_http7615_header, parse_http7615_authinfo, parse_csv_string
from . import passive_datapool
import logging

LastReq = namedtuple('LastReq', ('nc', 'c_resp', 'qop', 'respauth'))

class DigestClientSession(passive_datapool.PooledDataBase):
    __slots__ = ('algorithm', 'qop', 'realm', 'nonce',
                 'nc', 'cnonce', 'opaque', 'last_req')

    def __init__(self):
        pass

class DigestAuth(MultihopAuthBase):
    # complete reimplementation of Digest authentication scheme with
    #  - SHA256 support,
    #  - rspauth support.
    #  - support for "nextnonce" and "stale" flags.
    #  - more rigid rfc7615 header parsing,

    def __init__(self, username, password, qops=('auth',), realm=None, strict_auth=True, logger=None):
        super().__init__()
        self.username = username
        self.password = password
        self.realm = realm
        self.qops = qops
        self.strict_auth = strict_auth
        self.logger = logger or logging.getLogger('httpauth')
        self.pool = passive_datapool.DataPool()

    def choose_qop(self, qop_header):
        l = parse_csv_string(qop_header)
        for q in self.qops:
            if q in l:
                return q
        return None

    def prepare_Authorization(self, r, counts):
        #print("@@@ PREPARE #{}".format(counts))
        url = r.url
        url = re.sub(r'^[a-z]+://[^/]+/', '/', url)

        session = None
        if counts >= 1: session = self.load_state()
        if not session: session = self.pool.get(r)

        if session:
            #print("@@@ WE HAVE SESSION {}".format(session.nonce))

            self.save_state(session)

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
                (('Digest',
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
                  }),))
            session.last_req = LastReq(nc = session.nc,
                                       c_resp = c_resp,
                                       qop = session.qop,
                                       respauth = respauth)
            return h
        else:
            #print("@@@  WE DON'T HAVE SESSION")
            return None

    def process_401(self, r, counts, **kwargs):
        #print("@@@ 401 HOOK CALLED")
        if 'www-authenticate' not in r.headers:
            self.logger.error("401 response with no WWW-Authenticate header.")
            return False
        try:
            auth_header = parse_http7615_header(r.headers['www-authenticate'])
        except:
            self.logger.error("cannot parse WWW-Authenticate header: {!r}.".format(r.headers['www-authenticate']))
            return False

        #print("@@@ WWW-Authenticate header: {!r}.".format(auth_header))

        challenge = None
        retry_ok = False

        session = self.load_state()
        self.save_state(None)

        if session:
            #print("@@@ WE HAD SESSION {}. search for matching".format(sess.nonce))
            for (c, kv) in auth_header:
                if (c != 'Digest' or
                    kv.get('algorithm') != session.algorithm or
                    kv.get('realm') != session.realm):
                    continue
                #print("@@@ matched session seems to be {!r}".format(kv))
                challenge = kv
                if kv.get('stale') == '1':
                    # session expired. retrying.
                    session.remove_from_pool()
                    session = None
                    challenge = kv
                    retry_ok = counts <= 1
                else:
                    retry_ok = False
                break
            if not retry_ok:
                self.logger.info("authentication is not retryable.")
                if session:
                    session.return_to_pool()
                return False

        if not challenge:
            #print("@@@ looks for the best challenge")
            prec, challenge = (-1, None)
            for (c, kv) in auth_header:
                if c != 'Digest': continue
                algoname = kv.get('algorithm', "").lower()
                if algoname not in hash_algorithms: continue
                if self.realm and kv.get('realm', None) != self.realm: continue
                algo = hash_algorithms[algoname]
                if algo.precedence > prec:
                    prec, challenge = algo.precedence, kv

        #print("@@@ best challenge to be {!r}".format(challenge))
        if not challenge:
            self.logger.error("no matching algorithm found.".format(kv))
            if session: session.return_to_pool()
            return False

        #print("@@@ creaing new session from challenge {}".format(challenge))
        if session: session.return_to_pool()

        session = self.create_new_session(challenge=challenge)
        if not session:
            self.logger.error("cannot create new session from challenge: bad header or parameter mismatch: {!r}".format(challenge))
            return False

        self.pool.put_and_use(session, r.request)
        self.save_state(session)

        return True

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

    def __authinfo_error(self, msg, *args):
        msg = msg.format(*args)
        self.logger.error(msg)
        if self.strict_auth == 'IGNORE':
            pass
        elif self.strict_auth:
            raise ContentDecodingError(msg)
        else:
            warn(RequestsWarning(msg))

    def process_200(self, r, counts, **kwargs):
        session = self.load_state()

        if session is None:
            # 200 is returned for initial request without challenge,
            # 401 expected.
            self.__authinfo_error('no Digest authentication ever requested by server')
            return

        self.save_state(None)

        try:
            if 'authentication-info' not in r.headers:
                self.__authinfo_error('no Authentication-Info header in response')
                return
            try:
                auth_info = r.headers['authentication-info']
                auth_info = parse_http7615_authinfo(auth_info)
            except ValueError as e:
                self.__authinfo_error("parsing Authentication-Info: header failed: {}: {}.", auth_info, e)
                return

            svr_rspauth = session.last_req.respauth
            if session.last_req.qop == 'auth':
                e1 = svr_rspauth(None)
                e2 = auth_info.get('rspauth', "<none>").lower()
            else:
                body = r.content or b''
                #print("@@@ RESPONSEBODY = {}, hash={}".format(body, hash(h)(body)))
                e1 = svr_rspauth(body)
                e2 = auth_info.get('rspauth', "<none>").lower()
            if e1 != e2:
                self.__authinfo_error("Digest ressponse authentication failed: expected {}, returned {}", e1, e2)
            else:
                pass
                #print("@@@ checking response authentication OK: {}".format(e1), file=sys.stderr)

            nextnonce = auth_info.get('nextnonce')
            if nextnonce:
                #print("@@@ Nonce renewal requested: {} -> {}".format(session.nonce, nextnonce), file=sys.stderr)
                session = session.replace_with(self.create_new_session(nextnonce=nextnonce,session=session))
            return
        finally:
            session.return_to_pool()
