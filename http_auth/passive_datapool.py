# Data pool with passive reclaim
# A part of the httpauth-lib derived from DOORMEN controller.
# (c) 2018 National Institute of Advanced Industrial Science and Technology.

import weakref
import threading
import collections
import types
import sys

wr = weakref.ref
wr_None = lambda: None # pseudo weak reference to None or an expired object
c_true = lambda x: True

__all__ = ('DataPool', 'PooledDataMixin', 'PooledDataBase')

IN_POOL = [True]
DEAD = [False]

DEBUG = False

class _Handle:
    __slots__ = ('watch_target', 'datapool', 'refback', 'finalizer')
    def __init__(self, watch_target, datapool, refback, finalizer):
        self.watch_target = watch_target
        self.datapool = datapool
        self.refback = refback
        self.finalizer = finalizer

class _Rref(wr):
    __slots__ = ('o', '__weakref__')
    self_wr = None
    def __new__(klass, ref, o):
        def _cb(arg):
            self = self_wr()
            if self and self.o:
                o = self.o
                self.o = None
                DataPool._reclaim(o)
        self = weakref.ref.__new__(klass, ref, _cb)
        self_wr = weakref.ref(self)
        return self
    def __init__(self, ref, o):
        super().__init__(ref)
        self.o = o
    def __del__(self):
        if self.o:
            o = self.o
            self.o = None
            DataPool._reclaim_dead(o)
    def detach(self):
        # intentionally coincide name with weakref.finalize
        self.o = None

_identity = lambda x: x
_ignore = lambda x: None

class DataPool:
    """A data pool which will reclaim unused data in a passive manner.

    One of more data can be put to pool, and leased out one-by-one
    using `get()`.

    Each leased data is internally associated to a referent object
    `ref`, provided as an argument to `get`.  If the referent is
    discarded from memory, the data will be automatically recraimed
    and returned to the pool.  The data can also be returned to pool
    by calling `DataPool.return_to_pool(data)`.

    The referent object `ref` must be alive during the data is used.
    Other methods in this class must not be called on the data when
    the corresponding referent is lost.  It is OK to lose both ref and
    data at the same time, however.

    This class is useful when some resource is used with callbacks for
    some another library, and the usual `with` or `try-finally`
    pattern cannot be used to reclaim a resource in case of abnormal
    exits.

    Methods regarding managed data are static methods: these are
    called like `DataPool.method(data, ...)`.

    The leased data MUST NOT have a permanent strong reference to the
    referent: circular dependency will eliminate possibility of
    returning object to pool, and cause memory leaks (such garbage
    cannot be collected by cycle-detecting GC.)  Having a weak
    reference is fine, or DataPool.get_referent(data) will serve as a
    replacement.

    Alternative approach (with a side effect) can be enabled with the
    `gc_recovery` hook parameter.  See more description in the bottom
    of the source code for more details and possible workarounds.

    The pool is thread safe, and the leased data is also safe with
    background GC behavior.  However, methods working on a leased data
    must not be called concurrently on a single data, otherwise the
    behavior is undefined.

    """

    def __init__(self, *, factory=None, type=None, gc_recovery=None):
        """Create a data pool.

        Optional Parameters:

           `factory`: generator function for new data, used when the
                      pool cannot serve request by existing data.

           `type`: limit pooled data to subtype of the given type.

           `gc_recovery`: hook for rescue from cyclic data condition.
                See documentation in the bottom of the source code for
                details.

        """
        self._queue = collections.deque()
        self._lock = threading.Lock()
        self._factory = factory
        self._type = type
        self._gc_recovery = (_identity if gc_recovery == True else
                             _ignore if gc_recovery == False else
                             gc_recovery)
        self._reclaimed = []

    # Public APIs

    def get(self, ref, pred=c_true, factory=None):
        """Retrieve one of stored data from pool.

        Parameters:

          `ref` (mandatory): the referent object to be tracked.  It
                 must be weak-referencible.  If `ref` object vanishes,
                 the retrieved data will automatically be returned to
                 this pool.

          `pred` (optional): predicate function to choose data to be
                  retrieved.

          `factory` (optional): function returning new data when
                  existing data is not available. If it is not
                  supplied for both `get()` and `DataPool()`, `get()`
                  will return None.  See `put()` for requirements on
                  the data returned from factory.

        """

        factory = factory or self._factory

        if len(self._reclaimed) > 0:
            while True:
                # intentionally racing with producer _reclaim_dead():
                # Both list.append and list.pop are atomic.
                # Use of self._lock will cause deadlock inside GC.
                l = []
                try:
                    l.append(self._reclaimed.pop())
                except IndexError:
                    break

                for i in reversed(l):
                    self._append_to_queue(i)

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
        if DEBUG:
            print("data {} leased from pool {}".format(d, self))
        return d

    def put(self, data):
        """Store a new data to pool.

        If stored data have slots restriction, it must either inherit
        from `PooledDataBase` or have slots shown in
        `DataPool.required_slot_names`.

        """

        if (self._type and not isinstance(data, self._type)):
            raise ValueError("Datapool accepts only {!s} but put {!s}".
                             format(self._type, type(data)))
        self._check_cleanness(data)
        self._append_to_queue(data)
        if DEBUG:
            print("data {} put to pool {}".format(d, self))

    def put_and_use(self, data, ref):
        """Register data to be used with the given pool.

        The data is already `leased out`: it can be used in the
        current context.

        It is mostly equivalent to put-get pair, but `put_and_use`
        ensures that the same data is always returned.

        The data has the same restriction as put.

        """

        if (self._type and not isinstance(data, self._type)):
            raise ValueError("Datapool accepts only {} but put {}".
                             format(self._type, type(data)))
        self._check_cleanness(data)
        self._setup_lease(data, ref)
        if DEBUG:
            print("data {} put_and_use for pool {}".format(data, self))
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
    def update_referent(d, ref):
        """Update referent object of d to ref.

        Both old and new referents must be alive at this moment.
        """
        handle, old_ref, pool = DataPool._check_alive_leased_data(d)
        # inhibit old finalizer

        assert(old_ref)
        assert(ref)
        assert(handle.watch_target() == old_ref)
        handle.finalizer.detach()
        pool._setup_lease(d, ref, forced=True)
        DataPool._clear_handle_content(handle, finalizer_detach=False)

    @staticmethod
    def return_to_pool(d):
        """Return the data `d` immediately to the associated DataPool.
        """

        handle, ref, pool = DataPool._check_alive_leased_data(d)
        # inhibit finalizer

        if DEBUG:
            print("data {} returned to pool {}".format(d, pool))
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

    @staticmethod
    def get_referent(d):
        """Get a (strong) referece to the referent object
        currently associated to the argument.
        """

        handle, ref, pool = DataPool._check_alive_leased_data(d)
        return ref

    # debug method

    def __len__(self):
        return len(self._queue) + len(self._reclaimed)

    def __bool__(self):
        return True

    def _dump(self):
        l = [*iter(self._queue), *iter(self._reclaimed)]
        return("DataPool({!r})".format(l))

    def _debug_peeklist(self):
        l = [*iter(self._queue), *iter(self._reclaimed)]
        return l

    # internal methods

    @staticmethod
    def _reclaim(refback):
        # called either from finalizer or as weakref callback
        if sys.is_finalizing():
            # meaningless to return objects to pools upon exit
            return
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
    def _reclaim_dead(refback):
        # be careful: data is dead and we're in GC!
        if sys.is_finalizing():
            return
        d = refback[0]
        if not d: return
        handle = d.__handle
        if type(handle) is not _Handle: return

        #assert(d.__handle.watch_target() == None)

        # d is dead: if watch_target is live, it have lost a reference to d.
        # It means that d is safe to be returned to pool.

        pool = handle.datapool()
        DataPool._clear_handle_content(handle, finalizer_detach=False)
        d.__handle = IN_POOL

        if not pool:
            return

        if pool._gc_recovery:
            new_d = pool._gc_recovery(d)
            if new_d:
                pool._check_cleanness(new_d, in_pool_ok=True)
                pool._reclaimed.append(new_d)
            # We're inside GC!
            # pool._append_to_queue is not useful because
            # deque.append causes deadlock
        else:
            warnings.warn(UserWarning("DataPool: an object collected during cyclic garbage collection; discarded"))
            # data is discarded

    @staticmethod
    def _check_cleanness(d, in_pool_ok=False):
        try:
            h = d.__handle
            if not in_pool_ok or h is not IN_POOL:
                raise ValueError("data is already managed by DataPool")
        except AttributeError:
            d.__handle = IN_POOL

    def _setup_lease(self, d, ref, forced=False):
        if not forced:
            if not (d.__handle == IN_POOL):
                raise ValueError("data was not in DataPool")
        refback_obj = [d]

        if self._gc_recovery is None:
            # we have recovery clue from dead zombie: use strict finalizer
            r = wr(ref)
            f = weakref.finalize(ref, DataPool._reclaim, refback_obj)
        else:
            # we have a recovery clue from dead zombie: use closed graph method
            r = f = _Rref(ref, refback_obj)

        d.__handle = _Handle(
            watch_target = r,
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
        return tuple(d.__dict__.keys())

DataPool.required_slot_names = DataPool._get_names() + ('__weakref__',)
# may be used if __weakref__ already exists
DataPool.required_slot_names_direct = DataPool._get_names()

del DataPool._get_names

class PooledDataMixin:
    """Mixin object for data managed by DataPool.

    Provides instance methods for managed data.
    Classes importing this mixin must provide slot names
    given in `DataPool.required_slot_names`.
    """

    __slots__ = ()
    def replace_with(self, new):
        return DataPool.replace_data(self, new)
    def return_to_pool(self):
        return DataPool.return_to_pool(self)
    def remove_from_pool(self):
        return DataPool.kill(self)
    def update_referent(self, new):
        return DataPool.update_referent(self, new)
    def get_referent(self):
        return DataPool.get_referent(self)

class PooledDataBase(PooledDataMixin):
    """Base object for data managed by DataPool.

    Using this class as a single base, required slots are
    automatically maintained.
    """
    __slots__ = DataPool.required_slot_names

"""# Internal states:

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

Reference graph:

       _________________(expected)---------------
      |                                          |
      |         pool                             |
      |           ^                              |
      |           :                              |
      v           :                              |
     obj ----> handle ----> (weakref) .....> referent
      ^           |         /                  ^ |
      |           |        /(*A)           (*B): (virtually)
      |           |       |                    : |
       \          v       v       (*B)         : v
        -------- refback_obj <-------------- finalizer <- (weakref module)

  Solid lines represent strong references, and
  Dotted lines represent weak references.
  References marked with (*A) exist when gc_recovery is enabled.
  Those with (*B) exist when gc_recovery is not used.

  - The refback_obj is referenced strongly from finalizer or weakref.
    It will keep obj alive when referent is dying.  The callbacks will
    reclaim the obj into pool before it is trashed.

  - No strong reference to the referent: referent is expected to be
    collected by reference-counting GC.

  - There is a cycles around the obj.  It will be usually eliminated
    during object reclaim by clearing refback_obj -> obj and obj ->
    handle links.

  - Having a finalizer is virtually equivalent to having a strong
    reference from referent to the finalizer.

    So, when gc_recovery is not used, if there is a strong reference
    from obj to referent, there causes a virtual circular dependency
    around obj: obj -> referent -> finalizer -> refback_obj -> obj.
    Because obj is strongly kept alive by the finalizer for
    reclaiming, referent cannot be collected by both reference
    counting and mark-sweep GCs, resulting in memory leak.

    Also, if there is other data to the same referent, those will also
    be considered a part of cyclic objects (because it is internally
    referenced from the referent).

Use of `gc_recovery` hook parameter

    When gc_recovery hook is enabled, such leased data with dependency
    cycles can be collected by GC.  To enable that, the reference
    structure is modified so that refback_obj is directly pointed from
    the weak reference, not using the finalizer indirection.

    When the whole cycle is collected by the mark-sweep GC, all
    objects are instantly considered dead; an object finalizer
    (__del__) associated to the weakref will be kicked and it will
    resurrect obj to return the data to pools.  However, at this
    moment, the object is already marked dead by GC.

    Such marked-dead objects have some tricky behaviors: its
    finalizers will not be called again, existing weakrefs to those
    objects are eliminated, etc.  Such objects might be safe or unsafe
    to be reused, depending on the situation.  It is the reason that
    this hook is not enabled by default.

    The `gc_recovery` hook is responsible to make such a dead object
    useful again; the hook will receive a dead object, and assumed to
    return a "clean" copy of it.  If non-null object is returned, it
    will be returned back to the associated pool.  If the hook returns
    None, the object is not resurrected.

    Either `copy.copy` or `copy.deepcopy` can be used as `gc_recovery`
    hook, depending on a situation.  Alternatively, if the data's
    internal liveness does not cause any issues, `True` can be passed
    to reuse the dead object as is.  `False` will silently discard the
    dead.

    It also have another side effect; if the referent has dropped all
    strong references to the pooled-managed object before itself is
    unreferenced, and the caller also lose the reference to the pooled
    object (to be used for `return_to_pool`), the object will become
    dead and collected by the GC, before the referent is collected.
    The object have to be returned to pool via the tricky
    `gc_recovery` path, instead of safer finalizer-based path.  This
    is another reason that the pool uses the finalizer-based approach
    by default.

"""

""
