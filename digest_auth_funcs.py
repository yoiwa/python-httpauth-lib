# Functions for HTTP Digest authentication
# A part of the DOORMEN controller.
# (c) 2018 National Institute of Advanced Industrial Science and Technology.

import os
import hashlib
import binascii

def random_value(len=128):
    """hexadecimal random values in string."""
    len = (len + 7) // 8;
    s = os.urandom(len)
    return binascii.hexlify(s).decode('ascii')

hash_algorithms = {
    'md5': (hashlib.md5, 0),
    'sha1': (hashlib.sha1, 2),
    'sha-256': (hashlib.sha256, 4),
    'sha-512': (hashlib.sha512, 6)
}

for h in list(hash_algorithms.keys()):
    a , p = hash_algorithms[h]
    hash_algorithms[h] = (a, False, p)
    hash_algorithms[h + '-sess'] = (a, True, p + 1)

def hash(h):
    """hexadecimal hash of bytes in bytes."""
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
    """keyed digest of bytes in bytes."""
#    print("KD: hash={!r} sec={!r} dat={!r}".format(h, sec, dat))
    return hash(h)(sec + b":" + dat)

def compute_digest(algo, *, username=None, realm=None, password=None,
                   passhash=None, method=None, url=None,
                   nonce=None, nc=None, cnonce=None, qop=None,
                   req_body=None):

    if isinstance(algo, str):
        algo = hash_algorithms[algo]
    h, sess_mode, _p = algo

    if isinstance(username, str): username = username.encode('utf-8')
    if isinstance(realm, str):    realm = realm.encode('utf-8')
    if isinstance(password, str): password = password.encode('utf-8')
    if isinstance(passhash, str): passhash = passhash.encode('utf-8') # for error proof
    if isinstance(method, str):   method = method.encode('utf-8')
    if isinstance(url, str):      url = url.encode('utf-8')
    if isinstance(nonce, str):    nonce = nonce.encode('utf-8')
    if isinstance(nc, str):       nc = nc.encode('utf-8')
    if isinstance(cnonce, str):   cnonce = cnonce.encode('utf-8')
    if isinstance(qop, str):      qop = qop.encode('utf-8')

    if passhash == None:
        a1 = b"%s:%s:%s" % (username, realm, password)
        a1h = hash(h)(a1)
    else:
        a1h = passhash

    if sess_mode:
        a1 = b"%s:%s:%s" % (a1h, nonce, cnonce)
        a1h = hash(h)(a1)

    if qop == b'auth':
        a2 = b"%s:%s" % (method, url)
    elif qop == b'auth-int':
        if req_body == None:
            raise RuntimeError('no body provided with qop=auth-int')
        a2 = b"%s:%s:%s" % (method, url, hash(h)(req_body))
    else:
        raise RuntimeError('unknown qop: ' + str(qop, 'utf-8'))

    a2h = hash(h)(a2)

    a3p = b"%s:%s:%s:%s:" % (nonce, nc, cnonce, qop)

    response_computed = kd(h, a1h, a3p + a2h).decode('ascii')

    a2r = b":%s" % url

    if qop == b'auth':
        a2rh = hash(h)(a2r)
        rspauth = kd(h, a1h, a3p + a2rh).decode('ascii')
        rspauth = (lambda _r: (lambda b: _r))(rspauth)
    elif qop == b'auth-int':
        rspauth = (lambda _a1h, _a3p, _a2r:
                   (lambda bh:
                    kd(h, _a1h,
                       _a3p + hash(h)(_a2r + b":" + bh)
                      ).decode('ascii')))(a1h, a3p, a2r)
    else:
        raise RuntimeError('unknown qop: ' + str(qop, 'utf-8'))

    return (response_computed, rspauth)
