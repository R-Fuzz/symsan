"""
Seed-to-Unit-Test Synthesis

Given a seed (with typed UObjects) and a type table JSON, generate a
compilable C unit test that initializes program objects with concrete
values from the seed and calls the entry function.
"""

import json
import logging
import struct
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class TypeTable:
    def __init__(self, path: str) -> None:
        with open(path, 'r') as f:
            data = json.load(f)
        self.entry_function: str = data.get('entry_function', '')
        self.args: list = data.get('args', [])
        self.types: Dict[int, dict] = {}
        for tid_str, desc in data.get('types', {}).items():
            self.types[int(tid_str)] = desc

    def get(self, type_id: int) -> Optional[dict]:
        return self.types.get(type_id)

    def size(self, type_id: int) -> int:
        t = self.types.get(type_id)
        return t.get('size', 0) if t else 0

    def pointee(self, type_id: int) -> int:
        t = self.types.get(type_id)
        if t and t.get('kind') == 'pointer':
            return t.get('pointee_type_id', 0)
        return 0


def _obj_bytes(obj) -> bytes:
    """Get the raw bytes of a UObject (value portion only, positive offsets)."""
    return b"".join(obj.value) if obj.value else b""


def _read_int(data: bytes, offset: int, size: int) -> int:
    """Read a little-endian integer from data at offset."""
    chunk = data[offset:offset + size]
    if len(chunk) < size:
        chunk = chunk + b'\x00' * (size - len(chunk))
    if size == 1:
        return struct.unpack('<B', chunk)[0]
    elif size == 2:
        return struct.unpack('<H', chunk)[0]
    elif size == 4:
        return struct.unpack('<I', chunk)[0]
    elif size == 8:
        return struct.unpack('<Q', chunk)[0]
    return int.from_bytes(chunk, 'little')


def _c_type_name(tt: TypeTable, type_id: int) -> str:
    """Get C type name from type table entry."""
    t = tt.get(type_id)
    if not t:
        return f"unknown_type_{type_id}"
    kind = t.get('kind', '')
    name = t.get('name', '')
    if kind == 'primitive':
        mapping = {'i8': 'char', 'i16': 'short', 'i32': 'int',
                   'i64': 'long long', 'i1': '_Bool'}
        return mapping.get(name, name)
    elif kind == 'struct':
        return name.replace('struct.', 'struct ')
    elif kind == 'pointer':
        pointee_tid = t.get('pointee_type_id', 0)
        return _c_type_name(tt, pointee_tid) + ' *'
    return name


def _c_field_type_name(tt: TypeTable, type_id: int) -> str:
    """Get C type name for a struct field (unsigned for integer types)."""
    t = tt.get(type_id)
    if not t:
        return f"unknown_type_{type_id}"
    kind = t.get('kind', '')
    name = t.get('name', '')
    if kind == 'primitive':
        mapping = {'i8': 'unsigned char', 'i16': 'unsigned short',
                   'i32': 'unsigned int', 'i64': 'unsigned long long',
                   'i1': '_Bool'}
        return mapping.get(name, name)
    return _c_type_name(tt, type_id)


def _emit_typedefs(tt: TypeTable) -> List[str]:
    """Emit struct typedefs and forward declarations from the type table."""
    lines = []
    # Collect all struct types
    structs = [(tid, t) for tid, t in tt.types.items() if t.get('kind') == 'struct']
    if not structs:
        return lines

    # Forward declarations
    for tid, t in structs:
        sname = t.get('name', '').replace('struct.', 'struct ')
        lines.append(f'{sname};')
    lines.append('')

    # Full definitions
    for tid, t in structs:
        sname = t.get('name', '').replace('struct.', 'struct ')
        lines.append(f'{sname} {{')
        for field in t.get('fields', []):
            fname = field['name']
            ftid = field['type_id']
            lines.append(f'    {_c_field_type_name(tt, ftid)} {fname};')
        lines.append('};')
        lines.append('')

    return lines


def _emit_entry_decl(tt: TypeTable) -> str:
    """Emit forward declaration for the entry function."""
    arg_parts = []
    for arg in tt.args:
        arg_tid = arg['type_id']
        arg_name = arg.get('name', '')
        type_name = _c_type_name(tt, arg_tid)
        if arg_name:
            arg_parts.append(f'{type_name} {arg_name}')
        else:
            arg_parts.append(type_name)
    args_str = ', '.join(arg_parts) if arg_parts else 'void'
    return f'int {tt.entry_function}({args_str});'


def _find_child_object(seed, parent_id: int, offset: int) -> Optional[int]:
    """Find a child object created from (parent_id, offset)."""
    for idx, obj in enumerate(seed.objects):
        if idx == 0:
            continue
        m = obj.metadata
        if m.from_object == parent_id and m.from_offset == offset:
            return idx
    return None


def synthesize(seed, tt: TypeTable) -> str:
    """
    Generate a C unit test from a seed and type table.

    Args:
        seed: Seed object with typed UObjects
        tt: TypeTable loaded from .types.json

    Returns:
        C source code as a string
    """
    lines = []

    # Headers
    lines.append('#include <string.h>')
    lines.append('#include <stdlib.h>')
    lines.append('')

    # Emit struct typedefs from type table
    lines.extend(_emit_typedefs(tt))

    # Emit entry function declaration
    lines.append(_emit_entry_decl(tt))
    lines.append('')

    # Walk the object tree and emit declarations bottom-up
    # First, figure out which objects exist and their types
    obj_decls = []  # (obj_index, type_id, pointee_type_id, var_name)
    obj_type_map = {}  # obj_index -> type_id (pointee type for pointer-created objects)

    for idx, obj in enumerate(seed.objects):
        if idx == 0:
            continue  # super object handled via args
        tid = obj.metadata.type_id
        if tid:
            # type_id from EVENT_TYPE_BIND is the pointer type used at check_pointer
            ptid = tt.pointee(tid)
            obj_type_map[idx] = ptid if ptid else tid

    # Topological sort: emit leaf objects first
    # Build dependency graph: object -> list of child object indices
    children = {}  # obj_index -> [(field_offset, child_obj_index)]
    for idx, obj in enumerate(seed.objects):
        if idx == 0:
            continue
        parent = obj.metadata.from_object
        offset = obj.metadata.from_offset
        if parent not in children:
            children[parent] = []
        children[parent].append((offset, idx))

    # DFS order (post-order = leaves first)
    visited = set()
    emit_order = []

    def dfs(obj_idx):
        if obj_idx in visited or obj_idx == 0:
            return
        visited.add(obj_idx)
        for _, child_idx in children.get(obj_idx, []):
            dfs(child_idx)
        emit_order.append(obj_idx)

    # Start DFS from all non-zero objects
    for idx in range(1, len(seed.objects)):
        dfs(idx)

    # Emit object declarations
    for idx in emit_order:
        obj = seed.objects[idx]
        data = _obj_bytes(obj)
        tid = obj_type_map.get(idx, 0)
        t = tt.get(tid) if tid else None

        var_name = f"obj_{idx}"

        if t and t.get('kind') == 'struct':
            struct_name = _c_type_name(tt, tid)
            lines.append(f'// Object {idx}: {struct_name}')
            lines.append(f'//   from Object {obj.metadata.from_object} offset {obj.metadata.from_offset}')
            lines.append(f'static {struct_name} {var_name} = {{')

            for field in t.get('fields', []):
                fname = field['name']
                foffset = field['offset']
                fsize = field['size']
                ftid = field['type_id']
                ft = tt.get(ftid)

                # Check if this field is a pointer that has a child object
                child_idx = _find_child_object(seed, idx, foffset)
                if child_idx is not None:
                    lines.append(f'    .{fname} = &obj_{child_idx},')
                elif ft and ft.get('kind') == 'pointer':
                    lines.append(f'    .{fname} = NULL,')
                else:
                    # Read concrete value
                    val = _read_int(data, foffset, fsize) if foffset + fsize <= len(data) else 0
                    if fsize <= 4:
                        lines.append(f'    .{fname} = {val},')
                    else:
                        lines.append(f'    .{fname} = {val}ULL,')

            lines.append('};')
            lines.append('')
        else:
            # Unknown type or primitive - emit as raw byte array
            lines.append(f'// Object {idx}: type_id={tid} (raw bytes)')
            hex_bytes = ', '.join(f'0x{b:02x}' for b in data) if data else '0'
            lines.append(f'static unsigned char {var_name}[{max(len(data), 1)}] = {{{hex_bytes}}};')
            lines.append('')

    # Emit main()
    lines.append('int main(void) {')

    # Build entry function call arguments
    arg_offset = 0
    super_data = _obj_bytes(seed.objects[0]) if seed.objects else b""
    call_args = []

    for arg_info in tt.args:
        arg_name = arg_info['name']
        arg_tid = arg_info['type_id']
        arg_size = tt.size(arg_tid)
        arg_t = tt.get(arg_tid)

        if arg_t and arg_t.get('kind') == 'pointer':
            # Find the child object created from super object at this offset
            child_idx = _find_child_object(seed, 0, arg_offset)
            if child_idx is not None:
                call_args.append(f'&obj_{child_idx}')
            else:
                call_args.append('NULL')
        else:
            # Read concrete value from super object
            val = _read_int(super_data, arg_offset, arg_size) if arg_offset + arg_size <= len(super_data) else 0
            call_args.append(str(val))

        arg_offset += arg_size

    args_str = ', '.join(call_args)
    lines.append(f'    {tt.entry_function}({args_str});')
    lines.append('    return 0;')
    lines.append('}')
    lines.append('')

    return '\n'.join(lines)
