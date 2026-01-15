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

#### `symsan.init(program_path, [uniontable_size])`
Initialize SymSan target with the instrumented binary.

**Parameters:**
- `program_path` (str): Path to the instrumented binary
- `uniontable_size` (int, optional): Size of union table (default: from defs.h)

**Returns:** Capsule containing dfsan_label_info pointer

#### `symsan.config(input_file, args=[], debug=0, bounds=0, undefined=0)`
Configure SymSan runtime options.

**Parameters:**
- `input_file` (str): Path to input file or "stdin"
- `args` (list[str], optional): Command-line arguments for target
- `debug` (int, optional): Enable debug output (0 or 1)
- `bounds` (int, optional): Enable bounds checking (0 or 1)
- `undefined` (int, optional): Enable undefined behavior solving (0 or 1)

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

#### `symsan.terminate()`
Terminate the target process.

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

See `test.py`

## Notes

- Currently only Z3 solver is supported
- The binding uses Python 3.7+ (uses f-strings in examples, but core module works with 3.6+)
- Solutions are automatically sorted by offset when applying multiple operations
- INSERT and DELETE operations are designed for string constraint solving (strchr, strstr, etc.)
- SET operations are most common and used for integer/byte-level constraints
