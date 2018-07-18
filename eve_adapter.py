# Eve adapter for HTTP Authentication.
# A part of httpauth_lib from the DOORMEN project.
# (c) 2018 National Institute of Advanced Industrial Science and Technology.

"""HTTP Authentication wrappe for Eve applications.

How to use:
 1) Instanciate an Authenticator class.
 2) Set it to an Authorization class.
 3) Wrap the authorization object with EveAuthentication.
 4) pass it to Eve's "auth=" parameter.
 5) call setup_hooks with the eve-app as an argument.

 It would look like following:

      authn = digest_auth.DigestAuthenticator(...)
      authz = basic_handler.SimpleAuthorization(authn)

      eve_auth = EveAuthentication(authz)
      app = Eve(..., auth=eve_auth)
      eve_auth.setup_hooks(app)

      app.run(...)

"""

from eve.auth import BasicAuth, request, Response, app, g, abort

class EveAuthentication(BasicAuth):
    def __init__(self, authz):
        self.authz = authz._flask_wrap()

    def authorized(self, allowed_roles, resource, method):
        hdr = self.authz.authenticate(resource)
        g._hdr_for_authentication_info = hdr
        self.set_user_or_token(g.auth_value)
        return True

    def authenticate(self):
        self.authz._return_401(g.get('_hdr_for_authentication_info'))

    def post_hook(self, resource, request, response):
        hdr = g.get('_hdr_for_authentication_info')
        if hdr:
            self.authz.modify_response_header(response, hdr)

    def setup_hooks(self, app):
        app.on_post_GET += self.post_hook
        app.on_post_POST += self.post_hook
        app.on_post_PATCH += self.post_hook
        app.on_post_PUT += self.post_hook
        app.on_post_DELETE += self.post_hook
        
