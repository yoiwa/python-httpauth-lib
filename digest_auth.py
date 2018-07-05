import collections
import os
import hashlib
import binascii
import time

def random_value(len=128):
    len = (len + 7) // 8;
    s = os.urandom(len)
    return binascii.hexlify(s).decode('ascii')

def http_encode(s):
    s.replace('\\', '\\\\').replace('"', '\\"')

from .auth_core import BaseAuthenticator

hash_algorithms = {
    'sha-256': hashlib.sha256,
    'md5': hashlib.md5
}

for h in list(hash_algorithms.keys()):
    a = hash_algorithms[h]
    hash_algorithms[h] = (a, False)
    hash_algorithms[h + '-sess'] = (a, True)

def hash(h):
    def f(b):
        if isinstance(b, str):
#            print("@@@ STR IS GIVEN")
            b = b.encode('utf-8')
        v = h(b).digest()
        v = binascii.hexlify(v)
#        print("@@@INPUT={!r} OUTPUT={!r}".format(b, v))
        return v
    return f

def kd(h, sec, dat):
#    print("KD: hash={!r} sec={!r} dat={!r}".format(h, sec, dat))
    return hash(h)(sec + b":" + dat)

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

class DigestAuthenticator(BaseAuthenticator):
    def __init__(self, algo, realm, checkerdic, idwrap=str, cache_params={}):
        super().__init__('Digest')
        self.algo = algo.lower()
        self.dic = checkerdic
        self.realm = realm
        self.idwrap = idwrap
        self.nonce_cache = NonceCache(cache_params, algo=self.algo)
        self.opaque = random_value(64)

    def check_auth(self, v, request):
#        print ("@@@ STATES: {!r}".format(self.nonce_cache.dic))
        h, sess_mode = hash_algorithms[self.algo]
        
        if '' in v:
            return False
        
        # how to pass stale?

        try:
            username = v['username']
            realm = v['realm']
            qop = v['qop']
            nonce = v['nonce']
            nc = v['nc']
            cnonce = v['cnonce']
            nc = v['nc']
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
        
        if (qop != 'auth'):
            return False, sessk  #flask.abort(400) # unimplemented

        a1 = "{}:{}:{}".format(username, realm, self.dic[username]).encode('utf-8')
        if sess_mode:
            a1 = "{}:{}:{}".format(hash(h)(a1), nonce, cnonce).encode('utf-8')
        a2 = "{}:{}".format(request.method, request_url).encode('utf-8')
        a2h = hash(h)(a2)
        a3p = "{}:{}:{}:{}:".format(nonce, nc, cnonce, qop).encode('utf-8')
        response_computed = kd(h, hash(h)(a1), a3p + a2h)
        response_computed = response_computed.decode('ascii')
#        print("AUTH: computed={}, given={}".format(response_computed, response))
        
        if response.lower() != response_computed:
            return False, sessk

        sessk['a1'] = a1
        sessk['a3p'] = a3p
        sessk['a2rp'] = ":{}".format(request_url).encode('utf-8')
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
             'qop': 'auth',
             'algorithm': session.algo,
             'nonce': session.nonce,
             'opaque': self.opaque,
             'charset': 'UTF-8'}
        if stale:
            h['stale'] = '1'
#        print("GENERATE_CHALLENGE: {!r}".format(h))
        return [('Digest', h)]

    def generate_auth_info(self, sessk):
        h, sess_mode = hash_algorithms[self.algo]
#        print("GENERATE_AUTHINFO: {!r}".format(sessk))
        
        response_computed = kd(h, hash(h)(sessk['a1']), sessk['a3p'] + sessk['a2rp'])

        h = {'rspauth': response_computed.decode('ascii'),
             'qop': 'auth',
             'cnonce': sessk['cnonce'],
             'nc': sessk['nc']}

        if sessk['session'].near_last():
            newsession = self.nonce_cache.new_nonce()
            h['nextnonce'] = newsession.nonce

        return h
