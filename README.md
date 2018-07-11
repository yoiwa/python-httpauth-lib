# DOORMEN httpauth-lib for python

This is a fresh implementation of HTTP Digest and other authentication
schemes.

This library supports various advanced features of HTTP authentication
which many existing libraries do not support.

 - Handling multiple challenges in RFC 7235.
 - SHA-256 and SHA-256-sess algorithm (RFC 7616)
 - support for both qop=auth and qop=auth-int (RFC 7616)
 - Multilingual headers (RFC 5987, required in RFC 7616).

The support for server-side Flask and Eve framework, as well as
client-side requests library is included.  Adaptations to other
frameworks should be easy, provided that such framework can properly
handle multi-hop HTTP authentication flow.

This library is a part of DOORMEN project, derived (subtree-split)
from the DOORMEN network controller.
