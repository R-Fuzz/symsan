# SymSan Python Binding

Python binding to launch SymSan-instrumented binaries, receive events, parse constraints, and solve constraints.

## Usage

```python
import sys
sys.path.insert(0, 'symsan_python_path')
import symsan

# Or set PYTHONPATH
# PYTHONPATH=symsan_python_path python3 your_script.py
```

## API Reference

### Initialization & Configuration

#### `symsan.init(program_path, [shm_size], [init_solver])`
Initialize SymSan target with the instrumented binary.

**Parameters:**
- `program_path` (str): Path to the instrumented binary
- `shm_size` (int, optional): Size of union table (default: from defs.h)
- `init_solver` (bool, optional): Build the parser/solver too (default: True).
  Pass `0` to trace without solving -- the event stream still works, but
  `parse_cond`, `parse_gep` and `solve_task` are unavailable.

**Returns:** Capsule containing dfsan_label_info pointer

#### `symsan.config(input_file, args=[], debug=0, bounds=0, undefined=0, forkserver=0)`
Configure SymSan runtime options.

**Parameters:**
- `input_file` (str): Path to input file, "stdin", or "protocol@host:port"
- `args` (list[str], optional): Command-line arguments for target, including argv[0]
- `debug` (int, optional): Enable debug output (0 or 1)
- `bounds` (int, optional): Enable bounds checking (0 or 1)
- `undefined` (int, optional): Enable undefined behavior solving (0 or 1)
- `forkserver` (int, optional): Ask the target to serve runs from a fork server
  (0 or 1). A request, not a promise -- `forkserver_active()` says what happened.

Everything here reaches the target through the environment it is spawned with,
so **once a fork server is up none of it can change**. `config()` raises
`RuntimeError` if you try; re-stating the identical configuration is a no-op.
To feed a running server a second input, rewrite the contents of the one path
it was configured with (truncating, or a short input reads its predecessor's
tail).

### Execution

#### `symsan.run([stdin_file])`
Run the instrumented target.

**Parameters:**
- `stdin_file` (str, optional): File to use as stdin

#### `symsan.read_event(buffer_size, [timeout])`
Read a symbolic execution event from the target.

**Parameters:**
- `buffer_size` (int): Size of buffer to read
- `timeout` (int, optional): Timeout in milliseconds (default: 0 = no timeout)

**Returns:** bytes containing the event data

Events are a byte stream, not a message stream: ask for exactly the number of
bytes the record you are reading occupies. Several event types are followed by
a variable-length payload (memcmp content, table contents) that **must be read
even if you do not use it** -- leaving it on the stream misaligns every event
after it, and the run still ends normally. `test.py` is the worked example.

#### `symsan.forkserver_active()`
Whether a fork server is up and serving runs.

**Returns:** bool. False before the first `run()`, and after one if the target
had no fork server to talk to.

#### `symsan.terminate()`
End the current run. Keeps a fork server alive for the next `run()`; use
`destroy()` to tear it down.

**Returns:** Tuple of (exit_status, is_killed)

#### `symsan.destroy()`
Clean up and destroy SymSan instance.

### Constraint Solving

#### `symsan.reset_input(input_list)`
Reset the symbolic expression parser with new input(s).

**Parameters:**
- `input_list` (list[bytes]): List of input byte arrays

#### `symsan.parse_cond(label, result, flags)`
Parse a conditional branch event into solving tasks.

**Parameters:**
- `label` (int): DFSan label ID
- `result` (int): Branch result value
- `flags` (int): Event flags

**Returns:** List of task IDs (int)

#### `symsan.parse_gep(ptr_label, ptr, index_label, index, num_elems, elem_size, offset, enum_index)`
Parse a GEP (GetElementPtr) event into solving tasks.

**Parameters:**
- `ptr_label` (int): DFSan label for pointer
- `ptr` (int): Pointer value
- `index_label` (int): DFSan label for index
- `index` (int): Index value
- `num_elems` (int): Number of elements in array
- `elem_size` (int): Size of each element
- `offset` (int): Current offset
- `enum_index` (bool): Whether to enumerate index values

**Returns:** List of task IDs (int)

#### `symsan.record_memcmp(label, content)`
Record a memcmp operation for constraint solving.

**Parameters:**
- `label` (int): DFSan label ID
- `content` (bytes): Concrete content being compared

#### `symsan.record_table(ptr, content)`
Record the contents of a read-only lookup table, keyed on its base address.

**Parameters:**
- `ptr` (int): Base address of the table in the traced process
- `content` (bytes): The table's bytes

#### `symsan.record_minimize(label)`
Record a label to minimize during solving (e.g. an allocation size).

**Parameters:**
- `label` (int): DFSan label ID

#### `symsan.add_constraint(label, val)`
Add an explicit constraint.

**Parameters:**
- `label` (int): DFSan label ID
- `val` (int): Constraint value

#### `symsan.solve_task(task_id, [timeout])`
Solve a constraint task and return solutions.

**Parameters:**
- `task_id` (int): Task ID from parse_cond or parse_gep
- `timeout` (int, optional): Timeout in milliseconds (default: 5000)

**Returns:** Tuple of (status, solutions)
- `status` (int): Solving status code
- `solutions` (list[dict]): List of solution dictionaries

#### `symsan.export_task_smt2(task_id, path)`
Write a task out as SMT-LIB v2, for solving or inspecting outside the binding.

#### `symsan.init_parser(name_or_address)` / `symsan.update_input(input_list)`
Attach a parser to a union table someone else owns, and refresh the input cache
without clearing the dependency sets. For drivers that share a table across
processes; `init()` plus `reset_input()` is what a standalone script wants.

**Status Codes:**
- `1` - invalid_task
- `2` - opt_sat (optimized satisfiable)
- `3` - opt_unsat (optimized unsatisfiable)
- `4` - opt_timeout (optimized timeout)
- `5` - nested_sat (nested satisfiable)
- `6` - opt_sat_nested_unsat
- `7` - opt_sat_nested_timeout

## Solution Format

Solutions are returned as dictionaries with different fields depending on the operation type.

### OpType Enum

The `symsan.OpType` enum defines three operation types:

```python
symsan.OpType.SET     # 0 - Set a byte value
symsan.OpType.INSERT  # 1 - Insert bytes
symsan.OpType.DELETE  # 2 - Delete bytes
```

### Solution Dictionary Fields

**Common fields (all operations):**
- `op` (int): Operation type (OpType.SET, OpType.INSERT, or OpType.DELETE)
- `id` (int): Input ID (which input file this applies to)
- `offset` (int): Byte offset in the input

**Operation-specific fields:**

**SET operation** - Set a single byte:
```python
{
    'op': symsan.OpType.SET,
    'id': 0,
    'offset': 10,
    'val': 0x41  # Byte value to set
}
```

**INSERT operation** - Insert bytes at position:
```python
{
    'op': symsan.OpType.INSERT,
    'id': 0,
    'offset': 5,
    'data': b'hello'  # Bytes to insert
}
```

**DELETE operation** - Delete bytes:
```python
{
    'op': symsan.OpType.DELETE,
    'id': 0,
    'offset': 20,
    'len': 3  # Number of bytes to delete
}
```

## Example Usage

`test.py` is `driver/fgtest.cpp` written against this binding: same command
line, same `TAINT_OPTIONS`, same generated-input names, and
`tests/symsan/python_fgtest.c` asserts the two write byte-identical outputs.
So it is both the worked example -- the event loop there is the whole
protocol, payload draining included -- and the coverage: anything the C driver
can do and it cannot is a gap in the wrapper.

```
PYTHONPATH=symsan_python_path \
TAINT_OPTIONS="taint_file=seed:output_dir=out" python3 test.py ./target seed...
```

`test_forkserver.py` is the smaller one: it traces a corpus with and without
`config(forkserver=1)` and checks the two event streams agree.

## Notes

- Currently only Z3 solver is supported
- The binding uses Python 3.7+ (uses f-strings in examples, but core module works with 3.6+)
- Solutions are automatically sorted by offset when applying multiple operations
- INSERT and DELETE operations are designed for string constraint solving (strchr, strstr, etc.)
- SET operations are most common and used for integer/byte-level constraints
