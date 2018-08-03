# Functions for HTTP Digest authentication
# A part of httpauth_lib from the DOORMEN project.
# (c) 2018 National Institute of Advanced Industrial Science and Technology.

import os
import hashlib
import binascii
import collections

def random_value(len=128):
    """hexadecimal random values in str."""
    len = (len + 7) // 8;
    s = os.urandom(len)
    return binascii.hexlify(s).decode('ascii')


DigestAlgorithm = collections.namedtuple(
    'DigestAlgorithm',
    ['name', 'h', 'sess_mode', 'precedence'])

def _make_hash(h):
    def hashfun(b):
        """hexadecimal hash vaule of input bytes.

        Input value can either be bytes or iteratives of bytes.

        The return value is in bytes."""
        m = h()
        if isinstance(b, (bytes, bytearray)):
            m.update(b)
        elif isinstance(b, str):
            raise ValueError("hash should receive bytes, not str")
            m.update(b.encode('utf-8'))
        elif hasattr(b, '__bytes__'):
            m.update(bytes(b))
        elif hasattr(b, '__iter__'):
            for e in b:
                m.update(e)
        else:
            m.update(b) # expecting b implements buffer protocol

        v = binascii.hexlify(m.digest())
#       print("@@@INPUT={!r} OUTPUT={!r}".format(b, v))
        return v
    return hashfun

hash_algorithms = {}

for name, v in {
        'MD5': (hashlib.md5, 0),
        'SHA1': (hashlib.sha1, 2),
        'SHA-256': (hashlib.sha256, 4),
        'SHA-512': (hashlib.sha512, 6) }.items():
    a, p = v
    hf = _make_hash(a)
    hash_algorithms[name.lower()] = \
        DigestAlgorithm(name=name, h=hf, sess_mode=False, precedence=p)
    hash_algorithms[name.lower() + '-sess'] = \
        DigestAlgorithm(name=name+'-sess',
                        h=hf, sess_mode=True, precedence=p+1)

def kd(h, sec, dat):
    """keyed digest of bytes in bytes."""
#    print("KD: hash={!r} sec={!r} dat={!r}".format(h, sec, dat))
    return h(sec + b":" + dat)

def compute_digest(algo, *, username=None, realm=None, password=None,
                   passhash=None, method=None, url=None,
                   nonce=None, nc=None, cnonce=None, qop=None,
                   req_body=None):
    """Compute expected response value of HTTP Digest access auth.

    arguments:
      Except ones described below, arguments are string
      (bytes or str; to be UTF-8 encoded) of the corresponding
      Digest authentication parameters.

      - algo: name of algorithm in str, or a DigestAlgorithm object.
      - password or passhash: one of these must be provided.
        - password: bare user password.
        - passhash: pre-computed hexadecimal value of the
          user authentication credential (A1)..
      - nc: must be 8-digit hexadecimal string, not just an int.
      - method: HTTP request method, case sensitive.
      - url: host-local absolute part of accessed URI, starting from '/'.
      - req_body: if qop='auth', it may be None.
                  if qio='auth-int', request body in bytes.

    return value: tuple of (response, rspauth).
      - response is in str type, hexadecimal, lower-cased.
      - rspauth is a function taking the response body,
        (as same requirements as req_body argument),
        returning a rspauth value (same format as response).
    """

    if isinstance(algo, str):
        algo = hash_algorithms[algo.lower()]
    H = algo.h

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
        a1h = H(a1)
    else:
        a1h = passhash

    if algo.sess_mode:
        a1 = b"%s:%s:%s" % (a1h, nonce, cnonce)
        a1h = H(a1)

    if qop == b'auth':
        a2 = b"%s:%s" % (method, url)
    elif qop == b'auth-int':
        if req_body == None:
            raise RuntimeError('no body provided with qop=auth-int')
        a2 = b"%s:%s:%s" % (method, url, H(req_body))
    else:
        raise RuntimeError('unknown qop: ' + str(qop, 'utf-8'))

    a2h = H(a2)

    a3p = b"%s:%s:%s:%s:" % (nonce, nc, cnonce, qop)

    response_computed = kd(H, a1h, a3p + a2h).decode('ascii')

    a2r = b":%s" % url

    if qop == b'auth':
        a2rh = H(a2r)
        rspauth = kd(H, a1h, a3p + a2rh).decode('ascii')
        rspauth = (lambda _r: (lambda b: _r))(rspauth)
    elif qop == b'auth-int':
        rspauth = (lambda _a1h, _a3p, _a2r, _H:
                   (lambda body:
                    kd(H, _a1h,
                       _a3p + H(_a2r + b":" + H(body))
                      ).decode('ascii')))(a1h, a3p, a2r, H)
    else:
        raise RuntimeError('unknown qop: ' + str(qop, 'utf-8'))

    return (response_computed, rspauth)
