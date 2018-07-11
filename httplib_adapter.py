# HTTPLIB adapter for HTTP Authentication.
# A part of httpauth_lib from the DOORMEN project.
# (c) 2018 National Institute of Advanced Industrial Science and Technology.

"""
HTTP Authentication adapter for httplib applications.

How to use:
 1) Instanciate an Authenticator class.
 2) make Handlerclass inherited from AuthnHTTPRequestHandler,
    or put AuthHTTPMixin in the "top of" superclass list.
 3) call authenticate at the front of actions.
 4) if it returned any false value,
    simply return from the action.

Steps 3-4 looks like following:
        usr = self.authenticate(authn)
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
        def __init__(self, reason):
            self._reason = reason

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.__auth_add_headers = {}

    def authenticate(self, authn):
        self.__auth_add_headers = {}
        hdr = None
        auth_header = self.headers.get('Authorization')
        d('authheader={}', auth_header)
        try:
            if auth_header == None:
                raise AuthHTTPMixin.abort(401)
            else:
                try:
                    cred = parse_http7615_header(auth_header)
                except ValueError:
                    AuthHTTPMixin.abort(400)
                if len(cred) != 1:
                    AuthHTTPMixin.abort(400)

                request = types.SimpleNamespace()
                parse = urllib.parse.urlparse(self.path)
                request.query_string = parse.query.encode('iso-8859-1','replace')
                request.full_path = parse.path + '?' + parse.query
                # see workaround for excess '?' in digest_auth.py
                request.method = self.command

                met, kv = cred[0]
                a_ret = authn.check_auth_full(met, kv, request)
                d("a_ret={!r}", a_ret)
                if not a_ret:
                    a_ret = a_ret, None
                usr, hdr = a_ret
                if usr:
                    h = authn.generate_auth_info(hdr, None)
                    if h != {}:
                        self.__auth_add_headers['Authentication-Info'] = encode_http7615_authinfo(h)
                    return usr
                else:
                    raise AuthHTTPMixin.abort(401)
        except AuthHTTPMixin.abort as a:
            if a._reason == 401:
                d("hdr={!r}", hdr)
                chal = authn.generate_challenge(hdr)
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
