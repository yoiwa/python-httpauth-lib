# Flask adapter for HTTP Authentication.
# A part of httpauth_lib from the DOORMEN project.
# (c) 2018 National Institute of Advanced Industrial Science and Technology.

"""HTTP Authentication framework for Flask applications.

How to use:

 1) Instanciate an Authenticator class.

 2) Set it to an Authorization class.

 3) Decorate application entry points by an authorization instance.
    FlaskAuthWrapper is automatically enabled when authorization
    instance is used as a function decorator.

 It would look like following:

      authn = digest_auth.DigestAuthenticator(...)
      authz = basic_handler.SimpleAuthorization(authn)
      # authz = flask_adapter.FlaskAuthWrapper(authz)

      @app.route("/")
      @authz("/")
      def service():
        ...

      app.run(...)

 With Flask adapter, `flask.abort(401)` can be used in the application
 to reject authorization of the current request from the client. An
 appropriate `WWW-Authenticate` header will be returned to the client.

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

    def _return_401(self, sessk=None, r=None, status=None):
        chal = self.authz.generate_challenge(sessk)
        header = {"WWW-Authenticate": encode_http7615_header(chal)} if chal != "" else {}
        if r == None:
            r = Unauthorized()
        r = r.get_response()
        for k, v in header.items():
            r.headers[k] = v
        flask.abort(r)

    def authenticate(self, resource):
        auth_header = flask.request.headers.get('authorization')
        def abort(reason, sessk):
            if reason == 401:
                self._return_401(sessk=sessk)
            else:
                flask.abort(reason)

        usr, sessk = self.authz.authenticate(
            resource, flask.request,
            auth_header = auth_header,
            abort=abort)

        flask.g.auth_value = usr
        return sessk

    def modify_response_header(self, r, sessk):
        request = flask.request
        # see werkzeug.wrappers.BaseRequest.get_app_iter()
        empty_response = (request.method == 'HEAD' or
                          r.status_code in (204, 304, 412))
        # NO CONTENT: data may be b'{}' for somewhat reason. override.
        if empty_response:
            rbody_f = (lambda: b'')
        else:
            def rbody_f():
                r.freeze()
                return r.response
        h = self.authz.generate_auth_info(sessk, rbody_f)
        if h != {}:
            r.headers['Authentication-Info'] = encode_http7615_authinfo(h)

    def wrap_result(self, rv, sessk):
        if sessk:
            r = flask.make_response(rv)
            self.modify_response_header(r, sessk)
            return r
        else:
            return rv

    def _flask_wrap(self):
        return self

    def __call__(self, resource):
        def wrap(f):
            @wraps(f)
            def wrapped(*a, **k):
                sessk = self.authenticate(resource)
                try:
                    r = f(*a, **k)
                    return self.wrap_result(r, sessk)
                except Unauthorized as e:
                    if e.response == None:
                        self._return_401(sessk=sessk, r=e)
                    raise
            return wrapped
        return wrap
