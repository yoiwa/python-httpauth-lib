# Server-side implementation of HTTP Digest authentication
# A part of httpauth_lib from the DOORMEN project.
# (c) 2018 National Institute of Advanced Industrial Science and Technology.

import collections
import os
import hashlib
import binascii
import time

from .digest_auth_funcs import random_value, hash_algorithms, compute_digest
from .auth_core import BaseAuthenticator
from .auth_http_header import parse_csv_string

class NonceSession(collections.namedtuple(
        'NonceSession',
        ['nonce', 'algo', 'used_nc', 'nc_max', 'endtime'])):
    """a Digest-auth session represented by a nonce"""

    def near_last(self):
        return (self.nc_max - 2 <= len(self.used_nc)
                or self.endtime < time.time() + 10)

supported_qops = {'auth', 'auth-int'}

class NonceCache:
    """An LRU cache and generator for active nonces."""
    def __init__(self, params, algo=None):
        self.dic = collections.OrderedDict()
        self.maxentries = params.get('entries', 1024)
        self.timeout = params.get('timeout', 300)
        self.nc_max = params.get('nc_max', 128)
        self.algo = algo

    def get(self, nonce):
        sess = self.dic.get(nonce)
        if sess == None:
            return None
        if (sess.endtime < time.time() or
            len(sess.used_nc) >= self.nc_max):
            del self.dic[nonce]
            return None
        self.dic.move_to_end(nonce)
        return sess

    def new_nonce(self):
        nonce = random_value(128)
        session = NonceSession(nonce=nonce, algo=self.algo,
                               endtime=(time.time() + self.timeout), used_nc=set(),
                               nc_max = self.nc_max)
        #print ("@@@ nonce {} created".format(nonce))
        self.dic[nonce] = session
        if len(self.dic) > self.maxentries:
            k, v = self.dic.popitem(last=False)
            #print ("@@@ dropped {}".format(k))
        return session

    def __delitem__(self, k):
        del self.dic[k]

class RequestResponseState:
    __slots__ = ['session', 'rspauth', 'qop', 'cnonce', 'nc', 'stale']
    def __init__(self, session=None, rspauth=None, qop=None,
                 cnonce=None, nc=None, stale=False):
        self.session = session
        self.rspauth = rspauth
        self.qop = qop
        self.cnonce = cnonce
        self.nc = nc
        self.stale = stale

RequestResponseState.empty = RequestResponseState()

class DigestAuthenticator(BaseAuthenticator):
    """Authenticator for the HTTP Digest access authentication.

    It supports many features of new RFC 7616, including SHA-256
    and UTF-8.  It also fully supports *-sess style variant,
    proper nonce-checking for replay protection, and response
    authentication.

    It also supports qop=auth-int content body integrity checking,
    but it may suffer performances (because requset/response body
    must be fully available before processing.)

    """

    def __init__(self, algo, realm, checkerdic, idwrap=str, qops=['auth'], cache_params={}, **kw):
        """Prepare Digest authentication for server-side resources.

        Parameters:

         - algo: a string representing the hash algorithm to be used.
                 Valid values are MD5, SHA1, SHA-256, SHA-512, and
                 any of those suffixed with "-sess".

         - realm: a string representing an "authentication realm"
                  provided from the server.

         - checkerdic: a map from users to their passwords.  A dict or
                       any class instances implementing an equivalent
                       interface (accessed by []) will be accepted.

         - idwrap: default `str`, meaning do-nothihg. An optional
           function converting from user-names used by Digest
           authentication to any internally-used identifiers.

           One useful case is with CombinedAuthenticator in
           basic_handler.py, to internally distinguish IDs for
           different authtication schemes.

         - cache_params: An optional dict to control behavior of
           Internal nonce caches.  Used keys and default values are:

           - 'entries': a maximum number of retained active nonces.
                        Default: 1024.

           - 'timeout': a maximum duration (in seconds) to retain
                        unused, inactive nonces.  Default: 300 [sec].

           - 'nc_max': a maximum accepted value for `nc` field of
             Digest authentication, meaning how many requests can be
             sent using the same nonce.  Default: 128.

        """
        super().__init__('Digest', **kw)
        self.algoname_lower = algo.lower()
        self.algo = hash_algorithms.get(self.algoname_lower)
        if not self.algo:
            raise RuntimeError("no Digest algorithm {} defined".format(algo))
        self.dic = checkerdic
        self.realm = realm
        self.idwrap = idwrap
        self.qops = qops
        for qop in qops:
            if not qop in supported_qops:
                raise RuntimeError("no qop {} defined".format(qop))
        self.nonce_cache = NonceCache(cache_params, algo=self.algo)
        self.opaque = random_value(64)

    def check_auth(self, v, request):
        """
        Authenticate an HTTP request.

        Arguments:
         - v: a key-value dict of HTTP Authorization params.
         - request: a corresponding HTTP request.
        """
        # print ("@@@ STATES: {!r}".format(self.nonce_cache.dic))
        algo = self.algo

        if '' in v:
            return False
        
        try:
            username = v['username']
            realm = v['realm']
            qop = v['qop']
            nonce = v['nonce']
            nc = v['nc']
            cnonce = v['cnonce']
            opaque = v['opaque']
            response = v['response']
            r_uri = v['uri']
            algorithm = v['algorithm'].lower()
        except KeyError:
            return False

        if realm != self.realm:
            return False
        if algorithm != self.algoname_lower:
            return False

        session = self.nonce_cache.get(nonce)

        if not session:
            self.logger.debug("authentication failed: no corresponding nonce found")
            return False, RequestResponseState(stale=True)
        assert(session.nonce == nonce)

        if (opaque != self.opaque):
            self.logger.debug("authentication failed: opaque parameter mismatch")
            del self.nonce_cache[nonce]
            return False

        if (username not in self.dic): 
            self.logger.debug("authentication failed: user not found")
            del self.nonce_cache[nonce]
            return False
           
        if (not (request.full_path == r_uri or
                 (request.query_string == b'' and
                  r_uri + '?' == request.full_path))):
            del self.nonce_cache[nonce]
            self.logger.debug("authentication failed: url parameter mismatch")
            return False
        request_url = r_uri # see above check for correctness
        # Flask cannot distinguish ".../" and ".../?"

        if nc in session.used_nc:
            self.logger.debug("authentication failed: nc duplication detected")
            return False, RequestResponseState(stale=True)

        session.used_nc.add(nc)

        if (qop not in self.qops):
            self.logger.debug("authentication failed: qop mismatch")
            return False

        if qop == 'auth-int':
            body = request.data
        else:
            body = None
        #print ("@@@ body = {!r}".format(body))

        try:
            response_computed, rspauth = compute_digest(
                self.algo, username=username, realm=realm,
                password=self.dic[username],
                method=request.method, url=request_url,
                nonce=nonce, nc=nc, cnonce=cnonce,
                qop=qop, req_body=body)
        except ValueError:
            # decoding failure
            self.logger.debug("authentication failed: decoding error in hash checking")
            return False

        # print("AUTH: computed={}, given={}".format(response_computed, response))
        
        if response.lower() != response_computed:
            self.logger.debug("authentication failed: hash mismatch (wrong password?)")
            return False, RequestResponseState(session=session)

        sessk = RequestResponseState(
            session=session, rspauth=rspauth, qop=qop,
            cnonce=cnonce, nc=nc)

        self.logger.debug("authentication succeeded: username = {}".format(username))
        return (self.idwrap(username), sessk)

    def generate_challenge(self, sessk):
        sessk = sessk or RequestResponseState.empty
        if sessk.session:
            session = sessk.session
        else:
            session = self.nonce_cache.new_nonce()
        h = {'realm': self.realm,
             'qop': ", ".join(self.qops),
             'algorithm': session.algo.name,
             'nonce': session.nonce,
             'opaque': self.opaque,
             'charset': 'UTF-8'}
        if sessk.stale:
            h['stale'] = '1'
        # print("GENERATE_CHALLENGE: {!r}".format(h))
        return [('Digest', h)]

    # `rbody_f` is a function returning a iterative of
    # byte sequence for the body.
    # Not used if qop=auth.
    def generate_auth_info(self, sessk, rbody_f):
        # print("GENERATE_AUTHINFO: {!r}".format(sessk))

        if(sessk.qop == 'auth-int'):
            body_iter = rbody_f()
        else:
            body_iter = None

        h = {'rspauth': sessk.rspauth(body_iter),
             'qop': sessk.qop,
             'cnonce': sessk.cnonce,
             'nc': sessk.nc}

        if sessk.session.near_last():
            self.logger.debug("Digest: requesting nonce change")
            newsession = self.nonce_cache.new_nonce()
            h['nextnonce'] = newsession.nonce

        return h

"""
Use case without Flask nor Werkzeug:
- The request object must respond on
   - .full_path: a requested URI w/o host part, starting from "/".
   - .query_string: bytes for the query after '?'.
   - .method: a case-sensitive request method.
   - .data: a request body in bytes (used with qop=auth-int).

- The response object for generate_auth_info must respond,
  when using qop=auth-int, on
   - .make_sequence: a preparation before iter_encoded.
   - .iter_encoded: bytes of response body, or iterable returing that.
"""
