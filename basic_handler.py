from . import auth_core
from .auth_core import BaseAuthenticator, BaseAuthorization
from binascii import b2a_base64, a2b_base64

class DictIdChecker:
    __slots__ = ['dic']

    def __init__(self, dic):
        self.dic = dic

    def __call__(self, id, pw):
        if id not in self.dic:
            return False
        return self.dic[id] == pw

class BasicAuthenticator(BaseAuthenticator):
    def __init__(self, realm, checker, idwrap=str):
        super().__init__('Basic')

        if not callable(checker):
            checker = DictIdChecker(checker)
        self.checker = checker
        self.realm = realm
        self.idwrap = idwrap

    def check_auth(self, v, _request):
        if '' not in v:
            return False
        try:
            v = a2b_base64(v['']).decode('utf-8')
        except ValueError:
            return False

        u, s, p = v.partition(":")
        if s != ":":
            return False
        if self.checker(u, p):
            return self.idwrap(u), None
        else:
            return False

    def generate_challenge(self, h):
        return [('Basic', {'realm': self.realm, 'charset': 'UTF-8'})]

class SimpleAuthorization(BaseAuthorization):
    def check_authz(self, resource, entity):
        return entity != None

class BearerAuthenticator(BaseAuthenticator):
    def __init__(self, scope, tokendic, idwrap=str):
        super().__init__('Bearer')
        self.scope = scope
        self.tokendic = tokendic
        self.idwrap = idwrap

    def check_auth(self, v, _request):
        if '' not in v:
            return False
        token = v['']
        id = self.tokendic.get(token)
        if not id:
            return False
        return self.idwrap(id), None

    def generate_challenge(self, h):
        return [('Bearer', {'scope': self.scope})]

class CombinedAuthenticator(BaseAuthenticator):
    def __init__(self, *authns):
        super().__init__('*')
        self.authns = authns

    def check_auth_full(self, scheme, v, request):
        h = []
        for authn in self.authns:
            if authn.scheme != scheme:
                h.append((authn, None))
                continue
            r = authn.check_auth(v, request)
            if not r:
                r = r, None
            usr, hdr = r
            if usr:
                return (usr, (authn, hdr))
            else:
                h.append(hdr)
        return False, (None, h)

    def generate_challenge(self, h):
        r = []
        if h == None:
            for authn in self.authns:
                r.extend(authn.generate_challenge(None))
        elif h[0] == None:
            assert(len(self.authns) == len(h[1]))
            for authn, hh in zip(self.authns, h[1]):
                r.extend(authn.generate_challenge(hh))
        else:
            r.extend(h[0].generate_challenge[h[1]])
        return r

    def generate_auth_info(self, hdr):
        if hdr:
            (authn, hdr) = hdr
            return authn.generate_auth_info(hdr)
        else:
            return {}
