from werkzeug.exceptions import Unauthorized

from functools import wraps
from .auth_http_header import parse_http7615_header, encode_http7615_header, encode_http7615_authinfo
import flask
from flask import abort

class BaseAuthenticator:
    def __init__(self, scheme):
        self.scheme = scheme

    def check_auth_full(self, method, param, request):
        if method == self.scheme:
            return self.check_auth(param, request)
        else:
            return False

    def check_auth(self, *request):
        """
        First argument is representing HTTP credential as
        ("Method", {key: value, ...}).
        For bare "token68"-type challenge, key will be empty string ("").

        Second argument is the flask request object.

        If successfully authenticated, it should return pair of
        (authenticated_entity, authentication_info header).
        the value of authentication_info header, if not Null, will be passed
        to generate_auth_info().
        """
        return False

    def generate_challenge(self):
        """
        Must return authnorization challenge in form
        [("Method", {key: value, ...})].
        """
        return []

    def generate_auth_info(self, hdr, resp):
        """
        Passed the second return value of check_auth, return a hash
        representing 'Authentication-Info' header.
        """
        return {}

class BaseAuthorization:
    def __init__(self, authenticator):
        self.authenticator = authenticator

    def check_authz(self, resource, entity):
        """
        Check authorization on given resource for authenticated entity.
        For unauthenticated request, called with entity == None.
        """
        return False

    def wrap_response(rv, hdr):
        return rv

    def _return_401(self, hdr=None, r=None, status=None):
        chal = self.authenticator.generate_challenge(hdr)
        hdr = {"WWW-Authenticate": encode_http7615_header(chal)} if chal != "" else {}
        if r == None:
            r = Unauthorized()
        r = r.get_response()
        for k, v in hdr.items():
            r.headers[k] = v
        flask.abort(r)

    def authenticate(self, resource):
        auth_header = flask.request.headers.get('authorization')

        if auth_header == None:
            authz = self.check_authz(resource, None)
            hdr = None
        else:
            try:
                cred = parse_http7615_header(auth_header)
            except ValueError:
                abort(400)
            if len(cred) != 1:
                abort(400)

            met, kv = cred[0]
            authn = self.authenticator.check_auth_full(met, kv, flask.request)

            if not authn:
                authn = authn, None
            usr, hdr = authn
            if usr:
                authz = self.check_authz(resource, usr)
            else:
                authz = False

        if not authz:
            return self._return_401(hdr=hdr)

        flask.g.auth_value = usr
        return hdr

    def wrap_result(self, rv, hdr):
        if hdr:
            r = flask.make_response(rv)
            h = self.authenticator.generate_auth_info(hdr, r)
            if h != {}:
                r.headers['Authentication-Info'] = encode_http7615_authinfo(h)
            return r
        else:
            return rv

    def __call__(self, resource):
        def wrap(f):
            @wraps(f)
            def wrapped(*a, **k):
                h = self.authenticate(resource)
                try:
                    r = f(*a, **k)
                    return self.wrap_result(r, h)
                except Unauthorized as e:
                    if e.response == None:
                        self._return_401(hdr=h, r=e)
                    raise
            return wrapped
        return wrap
