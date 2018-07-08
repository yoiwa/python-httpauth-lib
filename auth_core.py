# Core handler for HTTP Authentication.
# A part of the DOORMEN controller.
# (c) 2018 National Institute of Advanced Industrial Science and Technology.

"""
HTTP Authentication framework for Flask applications.

How to use:
 1) Instanciate an Authenticator class.
 2) Set it to an Authorization class.
 3) Decorate application entry point by the authorization instance.

Authenticator is more or less portable.
Authorization is Flask-specific.

"""

from werkzeug.exceptions import Unauthorized
from functools import wraps
from .auth_http_header import parse_http7615_header, encode_http7615_header, encode_http7615_authinfo
import flask
from flask import abort

class BaseAuthenticator:
    def __init__(self, scheme):
        self.scheme = scheme

    def check_auth_full(self, method, param, request):
        """The same as check_auth(), but invoked for every requests
        regardless of the authentication scheme.

        Additional first argument is authentication-scheme,
        in a first-capital format.

        """
        if method == self.scheme:
            return self.check_auth(param, request)
        else:
            return False

    def check_auth(self, params, request):
        """[To be overridden]

        First argument is representing HTTP credential parameters as a dict.
        For bare "token68"-type challenge, key will be empty string ("").

        Second argument is the flask request object.

        If successfully authenticated, it should return pair of
        (authenticated_entity, authentication_info header).
        The value of authentication_info header, if not Null,
        will be passed to generate_auth_info().

        This method is only called if the authentication scheme
        of the request matches with this authenticator.
        If this is unhappy, override check_auth_full instead.
        """
        return False

    def generate_challenge(self):
        """[To be overridden]

        Generate a HTTP authorization challenge returned to clients.

        The returned value is in a form of [("Method", {key: value, ...})].
        (note the list and the tuple around it)

        """
        return []

    def generate_auth_info(self, hdr, resp):
        """
        Passed the second return value of check_auth, return a hash
        representing 'Authentication-Info' header.

        the second argument is the flask response object.
        """
        return {}

class BaseAuthorization:
    def __init__(self, authenticator):
        self.authenticator = authenticator

    def check_authz(self, resource, entity):
        """[To be overridden by subclasses]

        Check authorization on given resource for authenticated entity.

        For unauthenticated request, it will be called with entity == None.
        Otherwise, the result of the authenticator is passed to entity.

        """
        return False

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
