# Server-side implementation of HTTP Digest authentication
# A part of the DOORMEN controller.
# (c) 2018 National Institute of Advanced Industrial Science and Technology.

import collections
import os
import hashlib
import binascii
import time

from .digest_auth_funcs import random_value, hash_algorithms, compute_digest
from .auth_core import BaseAuthenticator
from .auth_http_header import parse_csv_string

NonceSession = collections.namedtuple('NonceSession',
                                      ['nonce', 'algo', 'used_nc', 'nc_max', 'endtime'])
NonceSession.near_last = (lambda self:
                          self.nc_max - 2 <= len(self.used_nc)
                          or self.endtime < time.time() + 10)

class NonceCache:
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
        session = NonceSession(nonce=nonce,algo=self.algo,
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

class DigestAuthenticator(BaseAuthenticator):
    def __init__(self, algo, realm, checkerdic, idwrap=str, qops=['auth'], cache_params={}):
        super().__init__('Digest')
        self.algo = algo.lower()
        self.dic = checkerdic
        self.realm = realm
        self.idwrap = idwrap
        self.qops = qops
        self.nonce_cache = NonceCache(cache_params, algo=self.algo)
        self.opaque = random_value(64)

    def check_auth(self, v, request):
#        print ("@@@ STATES: {!r}".format(self.nonce_cache.dic))
        h, sess_mode, _p = hash_algorithms[self.algo]
        
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
        if algorithm != self.algo:
            return False
        
        session = self.nonce_cache.get(nonce)
        sessk = {'session': session}
        if not session:
            return False, {'stale': True}
        assert(session.nonce == nonce)

        if (opaque != self.opaque):
            del self.nonce_cache[nonce]
            return False

        if (username not in self.dic): 
            del self.nonce_cache[nonce]
            return False
           
        if (not (request.full_path == r_uri or
                 (request.query_string == b'' and
                  r_uri + '?' == request.full_path))):
            del self.nonce_cache[nonce]
            return False
        request_url = r_uri # see above check for correctness
        # Flask cannot distinguish ".../" and ".../?"

        if nc in session.used_nc:
            return False, {'stale': True}

        session.used_nc.add(nc)

        if (qop not in self.qops):
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
            return False

        # print("AUTH: computed={}, given={}".format(response_computed, response))
        
        if response.lower() != response_computed:
            return False, sessk

        sessk['rspauth'] = rspauth
        sessk['qop'] = qop
        sessk['cnonce'] = cnonce
        sessk['nc'] = nc

        return (self.idwrap(username), sessk)

    def generate_challenge(self, sessk):
        sessk = sessk or {}
        stale = ('stale' in sessk)
        if 'session' in sessk:
            session = sessk['session']
        else:
            session = self.nonce_cache.new_nonce()
        h = {'realm': self.realm,
             'qop': ", ".join(self.qops),
             'algorithm': session.algo,
             'nonce': session.nonce,
             'opaque': self.opaque,
             'charset': 'UTF-8'}
        if stale:
            h['stale'] = '1'
#        print("GENERATE_CHALLENGE: {!r}".format(h))
        return [('Digest', h)]

    def generate_auth_info(self, sessk, response):
        h, sess_mode, _p = hash_algorithms[self.algo]
#        print("GENERATE_AUTHINFO: {!r}".format(sessk))

        if(sessk['qop'] == 'auth-int'):
            response.make_sequence()
            body_iter = response.iter_encoded()
            m = h()
            s = b''
            for b in body_iter:
                m.update(b)
                s += b
            # print ("@@@ RESPONSEBODY = {}".format(s))
            bodyhash = binascii.hexlify(m.digest())
        else:
            bodyhash = None

        h = {'rspauth': sessk['rspauth'](bodyhash),
             'qop': sessk['qop'],
             'cnonce': sessk['cnonce'],
             'nc': sessk['nc']}

        if sessk['session'].near_last():
            newsession = self.nonce_cache.new_nonce()
            h['nextnonce'] = newsession.nonce

        return h
