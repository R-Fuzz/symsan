from logging import getLogger
from collections import defaultdict
from xxhash import xxh64

from . import TerminationConditionBase

logger = getLogger(__name__)

F_CHECK_POINTER = 0x8
F_SWITCH_CASE = 0x10
class Branch(TerminationConditionBase):
    def __init__(self, manager, target=[], always_true=False, path_sensitive=False) -> None:
        self._manager = manager
        self.branches = defaultdict(dict)
        self._context = xxh64()
        self._skip = False
        self._check_pointers = set()
        self._target = target if target else []
        self._always_true = always_true
        self._path_sensitive = path_sensitive
        self._visited = set()
        self._last_id = 0
        self._last_check_ret = False
        self._has_trace_bb = False
        self._loop_checker = None

    def _loop_signature(self):
        # Distinguish a branch by the trip counts of the loops executed so far
        # on this path.  This covers both:
        #   * in-loop exits (e.g. `if (head->v > 40) return`) -- keyed by the
        #     current iteration, and
        #   * post-loop branches (e.g. `sum > 200`) whose satisfiability
        #     depends on how many times the loop ran -- keyed by the trip count
        #     even though the loop has already exited.
        # Each counter is bounded by the loop threshold, so the key space is
        # finite (no full path sensitivity).  Counters reset to 0 between
        # executions, so outside any loop the signature is empty (no change).
        mgr = self._manager
        if self._loop_checker is None and mgr is not None:
            for c in getattr(mgr, "checkers", []):
                if hasattr(c, "_nest"):
                    self._loop_checker = c
                    break
        if self._loop_checker is None:
            return ()
        counters = self._loop_checker._nest.counters
        return tuple(sorted(
            (c._id, c._context, c._depth, c._current)
            for c in counters.values() if c._current > 0
        ))

    def check(self, flags, addr, context, id, result) -> bool:
        if self._skip: # skip if certain condition is met
            self._skip = False
            logger.debug(f"\033[93m[Branch@0x{id:x}] skip because of certain condition\033[0m")
            return False
        if flags & 0x6 != 0: # loop related branch, let loop handle it
            logger.debug(f"\033[93m[Branch@0x{id:x}] loop related branch, let loop handle it\033[0m")
            if not self._has_trace_bb:
                self._context.update(addr.to_bytes(8, "little") + context.to_bytes(8, "little") + id.to_bytes(8, "little") + result.to_bytes(8, "little"))
            return False
        if flags & F_CHECK_POINTER:
            ret = id not in self._check_pointers
            if ret:
                self._check_pointers.add(id)
                if not self._has_trace_bb:
                    self._context.update(addr.to_bytes(8, "little") + context.to_bytes(8, "little") + id.to_bytes(8, "little"))
                logger.debug(f"\033[93m[Branch(check pointer)@0x{id:x}] ask for flip to {'NT' if result else 'T'} ({id})\033[0m ")
            return ret
        if id not in self._visited:
            logger.critical(f"\033[91mNew branch reached: 0x{id:x}\033[0m")
            # input()
            self._visited.add(id)
        if flags & F_SWITCH_CASE:
            if self._last_id == id:
                # same switch, reuse the result
                return self._last_check_ret
            else:
                # set result to 0
                result = 0
        self._last_id = id
        if id in self._target:
            logger.critical(f"\033[91mTarget branch reached: 0x{id:x}\033[0m")
            # input()
        # else:
            # logger.critical(f"\033[91mBranch CID: 0x{id:x}\033[0m")
        
        if self._always_true:
            return True

        if not self._has_trace_bb:
            self._context.update(addr.to_bytes(8, "little") + context.to_bytes(8, "little") + id.to_bytes(8, "little") + result.to_bytes(8, "little"))
        if self._path_sensitive:
            bid = (id, addr)
            h = self._context.intdigest()
            key = (h, result)
            target_key = (h, 0 if result else 1)
        else:
            # Key in-loop branches by loop iteration (bounded by threshold) so
            # each iteration's exit is explored, without full path sensitivity.
            bid = (id, addr, self._loop_signature())
            h = 0
            key = result
            target_key = 0 if result else 1
        # Keep asking for a flip until the *target* (opposite) direction has
        # actually been executed, not merely until we've observed this
        # direction once.  A branch whose other side is still unvisited stays
        # solvable, so e.g. `sum > 200` keeps being solved on longer paths
        # until a satisfying one is found.  This stays path-insensitive
        # (<=2 keys per branch) so it still terminates.  Switch branches keep
        # the seen-this-case keying since "opposite" is not binary there.
        if flags & F_SWITCH_CASE:
            ret = key not in self.branches[bid]
        else:
            ret = target_key not in self.branches[bid]
        logger.debug(f"\033[96m[Branch@0x{id:x}] hash={h:016x}, result={result}, seen_before={not ret}, num_seen={len(self.branches[bid])}, path_sensitive={self._path_sensitive}, addr=0x{addr:x}, context={context}\033[0m")
        self.branches[bid][key] = (addr, context, id, result)
        if flags & F_SWITCH_CASE:
            self._last_check_ret = ret
        if ret:
            logger.debug(f"\033[93m[Branch@0x{id:x}] ask for flip to {'NT' if result else 'T'} ({id})\033[0m ")

        return ret
    
    def trace(self, flags, addr, context, id, result):
        # The branch is guarded by a loop header
        # self._skip = True
        pass

    def trace_bb(self, function_index, bb_index):
        self._has_trace_bb = True
        self._context.update(bb_index.to_bytes(8, "little"))

    def reset(self):
        logger.debug(f"\033[95m[Branch] Context reset - starting new seed (total branches tracked: {sum(len(v) for v in self.branches.values())})\033[0m")
        self._context = xxh64()
        pass
        # self.branches.clear()