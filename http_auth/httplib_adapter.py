# HTTPLIB adapter for HTTP Authentication.
# A part of httpauth_lib from the DOORMEN project.
# (c) 2018 National Institute of Advanced Industrial Science and Technology.

"""HTTP Authentication adapter for httplib applications.

How to use:

 1) Instanciate an Authenticator class.

 2) Set it to an Authorization class.

 3) make Handlerclass inherited from AuthnHTTPRequestHandler, or put
    AuthHTTPMixin in the "top of" superclass list.

 4) call `authenticate()` at the front of actions.

 5) If authentication has been succeeded, `authenticate()` will return
    an authenticated entity (usually a user name).

    If it has returned a false value, authentication has been failed.
    Simply return from the action then; a 401-status error is already
    sent to the client.

 Steps 1--2) would look like following:

        authn = digest_auth.DigestAuthenticator(...)
        authz = basic_handler.SimpleAuthorization(authn)

 Steps 4--5) look like following:
 
        usr = self.authenticate(authz)
        if not usr:
            return

"""

from http.server import BaseHTTPRequestHandler
from .auth_http_header import *
import sys, types, urllib.parse
def d(f, *a):
    pass #print(f.format(*a), file=sys.stderr)

class AuthHTTPMixin:
    class abort(BaseException):
        def __init__(self, reason, hdr):
            self._reason = reason
            self._hdr = hdr

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.__auth_add_headers = {}

    def authenticate(self, authz, resource):
        self.__auth_add_headers = {}

        auth_header = self.headers.get('Authorization')
        request = types.SimpleNamespace()
        parse = urllib.parse.urlparse(self.path)
        request.query_string = parse.query.encode('iso-8859-1','replace')
        request.full_path = parse.path + '?' + parse.query
        # see workaround for excess '?' in digest_auth.py
        request.method = self.command
        def abort(reason, hdr):
            raise AuthHTTPMixin.abort(reason, hdr)
        try:
            usr, hdr = authz.authenticate(
                resource, request,
                auth_header=auth_header,
                abort=abort)

            h = authz.generate_auth_info(hdr, None)
            if h != {}:
                self.__auth_add_headers['Authentication-Info'] = encode_http7615_authinfo(h)
            return usr
        except AuthHTTPMixin.abort as a:
            if a._reason == 401:
                d("hdr={!r}", a._hdr)
                chal = authz.generate_challenge(a._hdr)
                self.__auth_add_headers = {'WWW-Authenticate':
                                           encode_http7615_header(chal)} if chal != "" else {}
            self.send_error(a._reason)

    def end_headers(self):
        d ("@@@END_HEADERS")
        for k, v in self.__auth_add_headers.items():
            self.send_header(k, v)
        super().end_headers()

    def handle_one_request(self):
        self.__auth_add_headers = {}
        super().handle_one_request()

class AuthnHTTPRequestHandler(AuthHTTPMixin, BaseHTTPRequestHandler):
    pass
