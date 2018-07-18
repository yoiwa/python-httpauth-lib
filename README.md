# DOORMEN httpauth-lib for python

This is a fresh implementation of HTTP Digest and other authentication
schemes.  This library supports various advanced features of HTTP
authentication which many existing libraries do not support:

 - Handling multiple challenges in RFC 7235.
 - Support for Basic authentication with UTF-8 support.
 - Advanced support for Digest authentication scheme:
   - SHA-256 and SHA-256-sess algorithm (RFC 7616).
   - support for both qop=auth and qop=auth-int (RFC 7616).
   - Multilingual headers for UTF-8 support (RFC 5987, required in RFC
     7616).

The library includes support adapters for server-side Flask and Eve
framework, as well as that for http.server standard library in Python.
Client-side support of Digest authentication for the "requests"
library is also included.  Adaptations to other frameworks should be
easy, provided that such framework can properly handle multi-hop HTTP
authentication flow.

## Licensing

Please refer LICENSE file for details.  In short, it is Apache-license
based.

## Acknowledgment

This library is developed as a part of DOORMEN project, derived
(subtree-split) as a generic library from the DOORMEN network
controller implementation.  The DOORMEN project is supported by the
NEDO research funding for "Orchestrated Security Infrastructure for
Industrial IoT Network" under the "Project to develop cross-sectoral
technologies for IoT promotion".

