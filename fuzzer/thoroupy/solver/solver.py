import os

import symsan

# UCSan's unit inputs: a solution keeps every input byte the constraints do not
# make change at its seed value (z3-ts.cpp keep_seed_values).  Without it a
# byte only a test's assumption mentions came back as anything the assumption
# allows, and a later precondition rejected the run.  Read at the first solve;
# SYMSAN_KEEP_SEED_VALUES=0 in the environment turns it off.
os.environ.setdefault("SYMSAN_KEEP_SEED_VALUES", "1")


class OpType:
    """Operation types for seed mutation."""
    SET = 0
    INSERT = 1
    DELETE = 2


class Z3Solver:
    """Z3 solver using symsan Python extension."""

    def __init__(self) -> None:
        self._initialized = False

    def initialize(self, shm_name: str, size: int, pipe_name: str = ''):
        """Initialize solver with shared memory.

        Note: pipe_name is ignored - new API returns results directly.
        """
        symsan.init_parser(shm_name, size)
        self._initialized = True

    def reset_input(self, inputs: list, origins: list = None) -> None:
        """Reset parser with new input data (list of bytes objects), and each
        object's origin (Seed.origins(); None means 0 for all)."""
        symsan.reset_input(inputs, origins)

    def update_input(self, inputs: list, origins: list = None) -> None:
        """Update input cache without clearing deps (for late-arriving GV data)."""
        symsan.update_input(inputs, origins)

    def parse_cond(self, label: int, result: int, add_nested: bool) -> list:
        """Parse condition, return list of task IDs to solve."""
        flags = 0x1 if add_nested else 0x0
        return symsan.parse_cond(label, result, flags)

    def parse_gep(self, ptr_label: int, ptr: int, index_label: int, index: int,
                  num_elems: int, elem_size: int, current_offset: int,
                  enum_index: bool = True) -> list:
        """Parse GEP, return list of task IDs."""
        return symsan.parse_gep(ptr_label, ptr, index_label, index,
                                num_elems, elem_size, current_offset, enum_index)

    def add_constraint(self, label: int, value: int, hard: bool = False) -> None:
        """Add explicit constraint (for trace_cond).  hard: an assumption the
        program states (AssumedConstraint), kept by every later solve."""
        symsan.add_constraint(label, value, hard)

    def record_memcmp(self, label: int, data: bytes) -> None:
        """Record memcmp concrete data."""
        symsan.record_memcmp(label, data)

    def record_table(self, ptr: int, data: bytes) -> None:
        """Record a read-only lookup table's contents, keyed on its base address."""
        symsan.record_table(ptr, data)

    def record_minimize(self, label: int, allow_zero: bool = False) -> None:
        """Record a label to minimize during solving (e.g., malloc size).

        allow_zero defaults to False to match the runtime's
        allow_zero_size_alloc flag (also False by default): minimizing a
        symbolic allocation size must not collapse it to malloc(0), which
        returns null and steers exploration away from the intended heap
        object (e.g. the OOB memcpy in memcpy.c).
        """
        symsan.record_minimize(label, allow_zero)

    def solve_task(self, task_id: int, timeout: int = 5000) -> tuple:
        """Solve task, return (status, solutions).

        solutions is list of dicts with keys:
          - op: OpType (SET=0, INSERT=1, DELETE=2)
          - id: input object ID
          - offset: byte offset
          - val: byte value (for SET)
          - data: bytes (for INSERT)
          - len: count (for DELETE)
        """
        return symsan.solve_task(task_id, timeout)

    def discard_task(self, task_id: int) -> None:
        """Drop a parsed task without solving it."""
        symsan.discard_task(task_id)

    def export_task_smt2(self, task_id: int, filename: str) -> None:
        """Export a task's constraints as SMT-LIB v2 to a file."""
        symsan.export_task_smt2(task_id, filename)

    def ResetCache(self) -> None:
        """Reset caches between seeds."""
        pass  # Reset happens via reset_input()

    def destroy(self) -> None:
        """Clean up solver resources."""
        symsan.destroy()
        self._initialized = False


if __name__ == "__main__":
    z3 = Z3Solver()
    import code
    z3.initialize("psm_636625e7", 0, "/tmp/manual_pipe")
    code.interact(local=locals())
