# Core handler for HTTP Authentication.
# A part of httpauth_lib from the DOORMEN project.
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

from .auth_http_header import parse_http7615_header, encode_http7615_header, encode_http7615_authinfo
import logging

class BaseAuthenticator:
    def __init__(self, scheme, logger=None):
        self.scheme = scheme
        self.logger = logger or logging.getLogger('httpauth')

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
    def __init__(self, authenticator, logger=None):
        self.authenticator = authenticator
        self._wrap = None
        self.logger = logger or authenticator.logger

    def check_authz(self, resource, entity):
        """[To be overridden by subclasses]

        Check authorization on given resource for authenticated entity.

        For unauthenticated request, it will be called with entity == None.
        Otherwise, the result of the authenticator is passed to entity.

        """
        return False

    def abort(self, status, hdr):
        raise NotImplementedError()

    def generate_auth_info(self, *a, **kwargs):
        return self.authenticator.generate_auth_info(*a, **kwargs)
    def generate_challenge(self, *a, **kwargs):
        return self.authenticator.generate_challenge(*a, **kwargs)

    def authenticate(self, resource, request,
                     auth_header=None,
                     abort=None):
        if auth_header == None:
            usr = None
            authz = self.check_authz(resource, None)
            hdr = None
        else:
            try:
                cred = parse_http7615_header(auth_header)
            except ValueError:
                self.logger.debug("authentication failed: malformed Authorization header")
                abort(400, None)
            if len(cred) != 1:
                self.logger.debug("authentication failed: malformed Authorization header (multiple responses)")
                abort(400, None)

            met, kv = cred[0]
            authn = self.authenticator.check_auth_full(met, kv, request)

            if not authn:
                authn = authn, None
            usr, hdr = authn
            if usr:
                authz = self.check_authz(resource, usr)
            else:
                self.logger.debug("authentication failed")
                authz = False

        if not authz:
            if usr:
                self.logger.debug("authorization failed")
            return abort(401, hdr)

        return usr, hdr

    def _flask_wrap(self):
        if not self._wrap:
            from . import flask_adapter
            self._wrap = flask_adapter.FlaskAuthWrapper(self)
        return self._wrap

    def __call__(self, resource):
        return self._flask_wrap()(resource)
