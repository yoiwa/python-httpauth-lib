# httpauth-lib for Python

This is a fresh implementation of HTTP Digest and other authentication
schemes for both server-side and client-side.  This library supports
various advanced features of HTTP authentication for which many
existing libraries do not support:

 - Multiple challenges as defined in RFC 7235.
 - Basic authentication scheme with UTF-8 support.
 - Digest authentication scheme with advanced features:
   - SHA-256 and SHA-256-sess algorithm (RFC 7616).
   - support for both qop=auth and qop=auth-int (RFC 7616).
   - UTF-8 support with proper multilingual header format (RFC 5987,
     required in RFC 7616).

The library includes server-side support adapters for Flask and Eve
frameworks, as well as that for `http.server` standard library in
Python.  Client-side support of Digest authentication for the
`requests` library is also included.  Adapting to other frameworks
should be easy, provided that such framework can properly handle
multi-hop HTTP authentication message flow.

## Copyright and license

(c) 2018-2019 National Institute of Advanced Industrial Science and Technology.

Please refer to LICENSE file for license details.  In shoft, the
license is based on Apache Public License version 2.0.

    [AIST program registration #H30PRO-2234]

## Acknowledgment

This library is developed as a part of DOORMEN project, derived
(subtree-split) as a generic library from the DOORMEN network
controller implementation.  The DOORMEN project is supported by the
NEDO research funding for "Orchestrated Security Infrastructure for
Industrial IoT Network" under the "Project to develop cross-sectoral
technologies for IoT promotion".

