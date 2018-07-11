# Basic handlers for HTTP Authentication.
# A part of httpauth_lib from the DOORMEN project.
# (c) 2018 National Institute of Advanced Industrial Science and Technology.

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
    """Authenticator for HTTP Basic authentication.
    It is based on RFC 7617, using UTF-8 encoding.
    """

    def __init__(self, realm, checker, idwrap=str):
        """Generates an authenticator for HTTP Basic.

        arguments:
          - realm: the realm string to be sent.
          - checker: either a callable (passed user-id and passwird)
                     or a dict of {user-name: password}.
          - idwrap (optional): convert HTTP username to any object
            representing an authenticated identity.
        """
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
    """Very simple authorizer accepting any authenticated entity."""
    def check_authz(self, resource, entity):
        return entity != None

class BearerAuthenticator(BaseAuthenticator):
    """Authenticator for HTTP Bearer authentication."""
    def __init__(self, scope, tokendic, idwrap=str):
        """Constructor.

        arguments:
          scope: the scope string sent to clients.
          tokendic: a dict from bearer token to identity.
                    It can be any object implementing a "get" method.

        """
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
    """Authenticator which combines several sub-authenticators
    passed to the constructor.

    Note: many HTTP clients confuses with RFC-valid multiple
    challanges sent from the Web servers.  For maximal
    interoperability, "Basic" authenticator should be the first
    authenticator.  Many "Digest"-scheme clients are simply
    buggy enough on parsing mis-support multiple challenges.

    """
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
                h.append((authn, hdr))
        return False, (Ellipsis, h)

    def generate_challenge(self, h):
        r = []
        if h == None:
            for authn in self.authns:
                r.extend(authn.generate_challenge(None))
        elif h[0] is Ellipsis:
            assert(len(self.authns) == len(h[1]))
            for authn, hh in h[1]:
                r.extend(authn.generate_challenge(hh))
        else:
            r.extend(h[0].generate_challenge[h[1]])
        return r

    def generate_auth_info(self, hdr, resp):
        if hdr:
            (authn, hdr) = hdr
            return authn.generate_auth_info(hdr, resp)
        else:
            return {}
