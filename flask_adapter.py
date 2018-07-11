# Flask adapter for HTTP Authentication.
# A part of httpauth_lib from the DOORMEN project.
# (c) 2018 National Institute of Advanced Industrial Science and Technology.

"""
HTTP Authentication framework for Flask applications.

How to use:
 1) Instanciate an Authenticator class.
 2) Set it to an Authorization class.
 3) Decorate application entry point by the authorization instance.
    FlaskAuthWrapper is automatically enabled when authorization is
    used for wrapping.
"""

from functools import wraps
global abort, Unauthorized
from werkzeug.exceptions import Unauthorized
import flask
from flask import abort
from .auth_http_header import parse_http7615_header, encode_http7615_header, encode_http7615_authinfo

class FlaskAuthWrapper:
    def __init__(self, authz):
        self.authz = authz

    def _return_401(self, hdr=None, r=None, status=None):
        chal = self.authz.generate_challenge(hdr)
        hdr = {"WWW-Authenticate": encode_http7615_header(chal)} if chal != "" else {}
        if r == None:
            r = Unauthorized()
        r = r.get_response()
        for k, v in hdr.items():
            r.headers[k] = v
        flask.abort(r)

    def authenticate(self, resource):
        auth_header = flask.request.headers.get('authorization')
        def abort(reason, hdr):
            if reason == 401:
                self._return_401(hdr=hdr)
            else:
                flask.abort(reason)

        usr, hdr = self.authz.authenticate(
            resource, flask.request,
            auth_header = auth_header,
            abort=abort)

        flask.g.auth_value = usr
        return hdr

    def wrap_result(self, rv, hdr):
        if hdr:
            r = flask.make_response(rv)
            h = self.authz.generate_auth_info(hdr, r)
            if h != {}:
                r.headers['Authentication-Info'] = encode_http7615_authinfo(h)
            return r
        else:
            return rv

    def _flask_wrap(self):
        return self

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

'''

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
'''
