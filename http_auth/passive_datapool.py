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

IN_POOL = [True]
DEAD = [False]

class _Handle:
    __slots__ = ['watch_target', 'datapool', 'refback', 'finalizer']
    def __init__(self, watch_target, datapool, refback, finalizer):
        self.watch_target = watch_target
        self.datapool = datapool
        self.refback = refback
        self.finalizer = finalizer

class DataPool:
    """A data pool which will reclaim unused data in a passive manner.

    One of more data can be put to pool, and leased out one-by-one
    using `get()`.

    Each leased data is internally associated to a referent object
    `ref`, provided as an argument to `get`.  If the referent `ref` is
    destroyed, the data will be automatically recraimed and returned
    to the pool.  The data can also be returned to pool by calling
    `DataPool.return_to_pool(data)`.

    The referent object `ref` must be alive during the data is used.
    Other methods in this class must not be called on the data when
    the corresponding referent is lost.  It is OK to lose both ref and
    data at the same time, however.

    This pool is useful when some resource is used with callbacks for
    some another library, and the usual `with` or `try-finally`
    pattern cannot be used to reclaim a resource in case of abnormal
    exits.

    Methods regarding managed data is static methods: these are called
    like `DataPool.method(data, ...)`.

    The pool is thread safe, and the managed data is also safe with
    background GC behavior.  However, Explicit methods for a single
    data must not be called concurrently, else the behavior is
    undefined.

    Note: the resource data is better not having a strong reference to
    the referent, if possible: circular dependency may postpone
    reclaiming data to next full-scanning GC.

    """

    def __init__(self, *, factory=None):
        """Create a data pool."""
        self._queue = collections.deque()
        self._lock = threading.Lock()
        self._factory = factory

    # Public APIs

    def get(self, ref, pred=c_true, factory=None):
        """Retrieve one of stored data from pool.

        parameters:

          `ref`: the referent object to be tracked.  It must be
                 weak-referencible.  If `ref` object vanishes, the
                 retrieved data will automatically be returned to this
                 pool.

          `pred`: optional function to choose data to be retrieved.

          `factory`: optional function returning new data when data is
                     not available.  new data. If it is not supplied,
                     `get()` will return None.  See `put()` for
                     requirements on the data returned from factory.

        """

        factory = factory or self._factory
        with self._lock:
            d = None
            n = len(self._queue)
            for _ in range(n):
                d = self._queue.popleft()
                if pred(d):
                    break
                self._queue.append(d)
            else:
                d = None

            if factory and not d:
                d = factory()
            if d:
                self._setup_lease(d, ref)
            return d

    def put(self, data):
        """Store a new data to pool.

        The data must be an object having `__dict__`, or
        having `__slots__` of `DataPool.required_slot_names`."""

        self._check_cleanness(data)
        self._append_to_queue(data)

    def put_and_use(self, data, ref):
        """Register data to be used with the pool.
        The data is already `leased out`: it can be used
        in the current context.

        It is mostly equivalent to put-get pair, but
        it is ensured that the same data is always returned.

        The data has the same restriction as put."""

        self._check_cleanness(data)
        self._setup_lease(data, ref)
        return data

    @staticmethod
    def replace_data(old, new):
        """Replace the data `old`, associated to some DataPool, with
        the `new` data.

        The old data must be retrieved from some pool.  The data `new`
        will be returned to pool instead of `old` in future.

        It is almost equivalent to `remove_from_pool(old)` followed by
        `put_and_use(new, ...)`, but inheriting associated pool and
        referent object from `old`.

        """

        handle, ref, pool = DataPool._check_alive_leased_data(old)
        # inhibit finalizer

        assert(ref)
        assert(handle.refback[0] is old)

        # holding ref alive is important!
        # BEGIN CRITICAL SECTION regarding to finalizer
        old.__handle = DEAD
        handle.refback[0] = new
        new.__handle = handle
        # END CRITICAL SECTION
        
        if not ref or not old:
            raise AssertionError(str(ref)+str(old))
            # for doubly sure ref is not optimized out in any way in future

        return new

    @staticmethod
    def return_to_pool(d):
        """Return the data `d` immediately to the associated DataPool.
        """

        handle, ref, pool = DataPool._check_alive_leased_data(d)
        # inhibit finalizer

        DataPool._clear_handle_content(handle)
        d.__handle = IN_POOL

        if pool:
            pool._append_to_queue(d)

    finished = return_to_pool

    @staticmethod
    def remove_from_pool(d):
        """Declare `d` should not be returned to pool.

        the data d must not be returned to pool already."""

        handle, ref, pool = DataPool._check_alive_leased_data(d)
        # inhibit finalizer

        DataPool._clear_handle_content(handle)
        d.__handle = DEAD

    kill = remove_from_pool

    # internal methods

    @staticmethod
    def _reclaim(refback):
        # called as finalizer
        d = refback[0]
        if not d: return
        handle = d.__handle
        if type(handle) is not _Handle:
            return
        assert(d.__handle.watch_target() == None)

        pool = handle.datapool()
        DataPool._clear_handle_content(handle, finalizer_detach=False)
        d.__handle = IN_POOL

        if pool:
            pool._append_to_queue(d)

    @staticmethod
    def _check_cleanness(d):
        try:
            h = d.__handle
            raise ValueError("data is already managed by DataPool")
        except AttributeError:
            d.__handle = IN_POOL

    def _setup_lease(self, d, ref):
        assert(d.__handle == IN_POOL)
        refback_obj = [d]
        f = weakref.finalize(ref, DataPool._reclaim, refback_obj)
        f.atexit = False
        d.__handle = _Handle(
            watch_target = wr(ref),
            datapool = wr(self),
            refback = refback_obj,
            finalizer = f)

    def _append_to_queue(self, d):
        assert(d.__handle is IN_POOL)
        with self._lock:
            self._queue.append(d)

    @staticmethod
    def _check_alive_leased_data(d):
        handle = d.__handle
        if type(handle) is not _Handle:
            raise ValueError("data is not leased")

        ref = handle.watch_target()
        # inhibit finalizer here.
        if not ref:
            raise RuntimeError("pool-managed data is dangling; referent lost.")
        # here, finalizer is not running

        # state may be changed: need recheck.
        handle = d.__handle
        if type(handle) is not _Handle:
            raise RuntimeError("pool-managed data is dead during processing; referent lost.")

        pool = handle.datapool()

        assert(handle.watch_target() is ref)
        return (handle, ref, pool)

    @staticmethod
    def _clear_handle_content(handle, finalizer_detach=True):
        handle.refback[0] = None # cut circular dependency
        handle.refback = None
        if finalizer_detach:
            handle.finalizer.detach()
        handle.finalizer = None
        handle.watch_target = None

    @classmethod
    def _get_names(self):
        class _NAMES: pass
        d = _NAMES()
        d.__handle = None
        r = wr(d)
        return list(d.__dict__.keys())

required_slot_names_mixin = DataPool._get_names()
required_slot_names = DataPool._get_names() + ['__weakref__']

class PooledDataMixin:
    """Method mixin for data managed by DataPool.

    Provides instance methods for managed data.
    """
    def replace_with(self, new):
        return DataPool.replace_data(self, new)
    def return_to_pool(self):
        DataPool.finished(self)
    def remove_from_pool(self):
        DataPool.kill(self)

"""
# Internal states:

0: data not registered:
  __handle not defined

  Allowed_action:
    put
    put_and_use

1: data in pool:
  __handle = IN_POOL

  contained in pool.queue

  Allowed_action:
    lease to r -> state 2

1L: data in dead pool:
  __handle = IN_POOL

  container pool garbage-collected

  Allowed_action:
    nothing

1D: data killed:
  __handle = DEAD

  NOT contained in pool.queue

  Allowed_action:
    nothing

2: data leased to r:
  __handle = [watch_target = wr(r)
              datapool = wr(pool)
              refback = [d]
              finalizer = final(__refback)]

  Events:
    - r lost -> finalizer_called
    - pool lost -> state 3
  Allowed_action:
    - return_to_pool
    - replace_with
    - kill

3: pool lost:
  __handle = [watch_target = wr(r)
              datapool = wr(None)
              refback = [d]
              finalizer = final(__refback)]

  Events:
    - r lost -> finalizer_called
  Allowed_action:
    - return_to_pool
    - replace_with
    - kill

Mutual exclusion:
  Each actions and finalizers must not run in parallel.
  ._check_alive_leased_data() will carefully check
  that finalizer is not already running, and that
  finalizer will not run during the actions.


Actions and Events:

  finalizer_called:

    SYNCHRONIZE check state:
    - from state 1/1L/1D: no op (should not happen, no error reports in finalizer)
    - from state 2: __handle.datapool = wr(pool)
      clear __handle's content
      __handle = IN_POOL
      putback to pool.queue
      [ now state 1 ]

    - from state 3: __handle.datapool = wr(None)
      clear __handle's content
      __handle = IN_POOL
      not returned to pool
      [ now state 1L ]

  Action return_to_pool:
    SYNCHRONIZE check_state
    - from state 1, 1L, 1D: Error
    - deactivate finalizer
    - from state 2:  __handle.datapool = wr(pool)
      clear __handle's content
      __handle = IN_POOL
      putback to pool.queue
      [ now state 1 ]

    - from state 3: __handle.datapool = wr(None)
      clear __handle's content
      __handle = IN_POOL
      not returned to pool
      [ now state 1L ]

  Action replace_with:
    SYNCHRONIZE check_state
    - from state 0/1/1L: error
    - from state 2/3:
      old.__handle = DEAD
      [old is state DEAD, new is state 0, refback points to old.
       finalizer will not be called here, because we have ref in SYNCHRONIZE.]
      handle.refback <- [new]
      [old is state DEAD, new is state 0, refback points to new.
       finalizer will not be called here, because we have ref in SYNCHRONIZE.]
      new.__handle = old.handle
      [old is state 1D, new is state 2/3.]
      [now finalizer may be activated.]

  Action return_to_pool:
    SYNCHRONIZE check_state
    - from state 0, 1, 1L: Error
    - from state 2/3:
    - deactivate finalizer
      clear __handle's content
      __handle = DEAD
      [ now state 1D ]


"""

""
