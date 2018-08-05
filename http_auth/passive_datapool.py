# Data pool with passive reclaim
# A part of the httpauth-lib derived from DOORMEN controller.
# (c) 2018 National Institute of Advanced Industrial Science and Technology.

import weakref
import threading
import collections
import types
wr = weakref.ref
wr_None = lambda: None # pseudo weak reference to None or an expired object
c_true = lambda x: True

__all__ = ['DataPool', 'PooledDataMixin']

class DataPool:
    def __init__(self, factory=None):
        self.queue = collections.deque()
        self.lock = threading.RLock()
        self.factory = factory

    def get(self, ref, pred=c_true, factory=None):
        """Retrieve one of stored data from pool.

        The parameter `pred` can be used to choose data which meets
        specific condition.

        If the object `ref` is destroyed, the data will be
        automatically returned to the pool.  The data can also be
        returned back to pool by calling `DataPool.finished(data)`.

        """

        with self.lock:
            d = None
            n = len(self.queue)
            for _ in range(n):
                d = self.queue.popleft()
                if pred(d):
                    break
                self.queue.append(d)
            else:
                d = None
            if factory and not d:
                d = factory(key)
            if d:
                self._setup(d, ref)
            return d

    def _setup(self, d, ref):
        refback_obj = [d]
        d.__watch_target = wr(ref)
        d.__datapool = wr(self)
        d.__alive = True
        d.__refback = refback_obj
        f = weakref.finalize(ref, DataPool._reclaim, refback_obj)
        f.atexit = False
        d.__finalizer = f

    def put(self, data):
        """Store a new data to pool.

        The data must be an object having `__dict__`, or
        having `__slots__` of `DataPool.required_slot_names`."""

        self._check_cleanness(data)
        self.queue.append(data)

    def put_and_use(self, data, ref):
        """Register data to be used with the pool.

        It is mostly equivalent to put - get pair, but
        it is ensured that data is always returned.

        The data has the same restriction as put."""

        self._check_cleanness(data)
        self._setup(data, ref)
        return data

    def _check_cleanness(self, d):
        try:
            if (d.__watch_target != None):
                raise ValueError("put data is currently in-use")
        except AttributeError:
            d.__watch_target = None

        try:
            if not (d.__datapool == None or d.__datapool() is self):
                raise ValueError("put data belongs to another pool")
        except AttributeError: d.__datapool = wr(self)

        try:
            if (not d.__alive):
                raise ValueError("put data is no more active")
        except AttributeError:
            d.__alive = True

    @staticmethod
    def replace_data(old, new):
        """Replace the data `old`, associated to some DataPool, with
        the `new` data.  `new` will be returned to pool instead of `old`
        when old should have been expired.
        """

        if not old.__alive:
            raise ValueError("old data is not active")
        pool = old.__datapool()
        if pool == None:
            # no pool to return: ensure future replace_data will not fail
            new.__datapool = old.__datapool
            return new
        with pool.lock:
            new.__watch_target = old.__watch_target
            new.__alive = True
            old.__watch_target = None
            old.__alive = False

            new.__datapool = old.__datapool

            old_refback = old.__refback
            old_refback[0] = new
            new.__refback = old_refback
            old.__refback = None

            new.__finalizer = old.__finalizer
            old.__finalizer = None

        return new

    @staticmethod
    def finished(d):
        """Return the data `d` immediately to the associated DataPool.
        """

        pool = d.__datapool()
        if pool == None:
            if d.__finalizer:
                d.__finalizer.detach()
            return
        with pool.lock:
            d.__refback = None
            # ensure finalizer will not behave bad
            d.__watch_target = None
            if d.__finalizer:
                d.__finalizer.detach()
                d.__finalizer = None
            if not d.__alive:
                return
            pool._check_cleanness(d)
            pool.put(d)

    def kill(d):
        """Declare `d` should not be returned to pool.

        the data d must not be returned to pool already."""

        if not d.__alive:
            raise ValueError("data is already inactive")
        pool = d.__datapool()
        if pool == None:
            d.__alive == False
            if d.__finalizer:
                d.__finalizer.detach()
            return
        with pool.lock:
            d.__alive == False
            d.__refback[0] = None # cut circular dependency here
            d.__datapool = wr_None
            # ensure finalizer will not behave bad
            d.__watch_target = None
            d.__finalizer.detach()
            d.__finalizer = None

    @staticmethod
    def _reclaim(refback):
        # called from finalizer
        d = refback[0]
        if not d: return
        pool = d.__datapool()
        if pool == None:
            return
        with pool.lock:
            if refback[0] is not d: return
            if not d.__alive:
                return
            d.__refback = None
            assert(d.__watch_target() == None)
            d.__watch_target = None
            d.__finalizer = None
            pool.put(d)

    @classmethod
    def _get_names(self):
        d = types.SimpleNamespace()
        d.__watch_target = None
        d.__datapool = None
        d.__alive = None
        d.__refback = None
        d.__finalizer = None
        return ['__weakref__'] + list(d.__dict__.keys())

required_slot_names = DataPool._get_names()

class PooledDataMixin:
    def replace_with(self, new):
        return DataPool.replace_data(self, new)
    def return_to_pool(self):
        DataPool.finished(self)
    def remove_from_pool(self):
        DataPool.kill(self)

