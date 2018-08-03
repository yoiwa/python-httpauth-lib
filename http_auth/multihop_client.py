# extension to requests.auth for multi-hop authentication schemes
# A part of httpauth_lib from the DOORMEN project.
# (c) 2018 National Institute of Advanced Industrial Science and Technology.

import threading
from copy import copy

import requests
import requests.cookies

class MultihopAuthBase(requests.auth.AuthBase):
    # Logics for session resending and thread_local state management are
    # imported from requests/auth.py
    # It is the only available "documentation" for "requests"-library internals.

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__tls = threading.local()

    ## APIs for subclasses:

    def save_state(self, s):
        """save state objects to thread-local memory.

        The object can be retrieved by load_state().
        """
        self.__tls.state = s

    def load_state(self):
        """load state objects stored by save_state()."""
        if hasattr(self.__tls, 'state'):
            return self.__tls.state
        else:
            return None

    def prepare_Authorization(r, counts):
        # [must be overridden]
        """Prepare the authentication response for Authorization header.

        counts: number of requests to be retried."""
        raise NotImplementedError
        return None

    def process_401(r, counts, **kwargs):
        # [must be overridden]
        """Called upon reception of 401 Authorization Required response.

        If it returns True, the request will be retried, with
        a new call to prepare_Authorization."""
        raise NotImplementedError
        return False

    def process_200(r, counts, **kwargs):
        # [may be overridden]
        """Called upon reception of successful (200-399) response.

        May raise some exception to flag server authentication failure."""
        return

    ## API entry points from superclass

    def __call__(self, r, *, counts=0):
        self.__tls.counts = counts
        self.__tls.rid = id(r)
        # for sanity check, ignorable possibility of false negatives.
        # keeping r will cause memory-leak of whole request objects
        # upon request failures (resulted in exceptions).

        h = self.prepare_Authorization(r, counts=counts)
        if h:
            r.headers['Authorization'] = h

        ### dirty trick (1):
        try:
            self.__tls.pos = r.body.tell()
        except AttributeError:
            self.__tls.pos = None
        r.register_hook('response', self.__response_hook)
        return r

    def __response_hook(self, r, **kwargs):
        counts = self.__tls.counts
        assert(id(r.request) == self.__tls.rid)
        del self.__tls.rid
        del self.__tls.counts
        if r.status_code == 401:
            retry = self.process_401(r, counts=counts, **kwargs)
            if retry:
                #### touching very internal of requests-lib.
                if self.__tls.pos is not None:
                    r.request.body.seek(self.__tls.pos)
                r.content
                r.close()
                p = r.request.copy()
                requests.cookies.extract_cookies_to_jar(p._cookies, r.request, r.raw)
                p.prepare_cookies(p._cookies)

                self.__call__(p, counts=(counts + 1))
                _r = r.connection.send(p, **kwargs)
                _r.history.append(r)
                _r.request = p
                #### end of magics
                return _r
            else:
                return r
        elif r.status_code < 400:
            self.process_200(r, counts=counts, **kwargs)
            return r
        else:
            return r

