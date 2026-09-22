import json
import logging
import os

from control.message.enums import PIPE_EVENT_TYPE

from ..handler import HandlerBase

import typing
if typing.TYPE_CHECKING:
    from manager import UcsanManager

logger = logging.getLogger(__name__)

class TypeTable:
    def __init__(self, path: str) -> None:
        with open(path, 'r') as f:
            data = json.load(f)
        self.entry_function = data.get('entry_function', '')
        self.args = data.get('args', [])
        self.types = {}
        for tid_str, desc in data.get('types', {}).items():
            self.types[int(tid_str)] = desc

    def get_type(self, type_id: int) -> dict:
        return self.types.get(type_id, {})

    def get_size(self, type_id: int) -> int:
        t = self.types.get(type_id)
        if t:
            return t.get('size', 0)
        return 0

    def get_pointee_type_id(self, type_id: int) -> int:
        t = self.types.get(type_id)
        if t and t.get('kind') == 'pointer':
            return t.get('pointee_type_id', 0)
        return 0


class ObjectTracer(HandlerBase):
    SUB=[PIPE_EVENT_TYPE.EVENT_LAZY_INIT,
         PIPE_EVENT_TYPE.EVENT_USAGE_CITE,
         PIPE_EVENT_TYPE.EVENT_EXTENSION,
         PIPE_EVENT_TYPE.EVENT_TYPE_BIND,
         PIPE_EVENT_TYPE.EVENT_COPY_OVERFLOW,
        ]

    def __init__(self, manager: "UcsanManager") -> None:
        super().__init__(manager)
        self.type_table = None
        type_table_path = manager.config.get('type_table', None)
        if type_table_path and os.path.exists(type_table_path):
            self.type_table = TypeTable(type_table_path)
            logger.info(f"Loaded type table from {type_table_path} ({len(self.type_table.types)} types)")

    def handle(self, msg):
        match msg.context:
            case PIPE_EVENT_TYPE.EVENT_LAZY_INIT:
                # UCSan sends object metadata directly in the pipe message
                # msg.result = packed: object_id (lower 32 bits) | parent_obj_id (upper 32 bits)
                # msg.id = offset_in_parent
                object_id = msg.result & 0xFFFFFFFF
                parent_obj_id = (msg.result >> 32) & 0xFFFFFFFF
                offset_in_parent = msg.id
                logger.info(f"Lazy initialization @{msg.addr:#x} <Object {object_id}> from <Object {parent_obj_id}~{offset_in_parent}>")
                metatdata = self._manager._current[object_id].metadata
                metatdata.object_id = object_id
                metatdata.from_object = parent_obj_id
                metatdata.from_offset = offset_in_parent
                metatdata.addr = msg.addr
            case PIPE_EVENT_TYPE.EVENT_USAGE_CITE:
                # UCSan sends object metadata directly in the pipe message
                # msg.id = offset within object (non-zero for global variables)
                offset = msg.id
                if offset != 0:
                    # Global variable: msg.result = type_id, object is always super (0)
                    object_id = 0
                    type_id = msg.result
                    size = self.type_table.get_size(type_id) if self.type_table and type_id else 0
                else:
                    # Child object: msg.result = packed: object_id (lower 32 bits) | size (upper 32 bits)
                    object_id = msg.result & 0xFFFFFFFF
                    size = (msg.result >> 32) & 0xFFFFFFFF
                metatdata = self._manager._current[object_id].metadata
                logger.info(f"Usage cite @{msg.addr:#x} <Object {object_id}> from {offset}+{size}>")
                metatdata.cite(msg.addr, offset, size)
            case PIPE_EVENT_TYPE.EVENT_TYPE_BIND:
                # msg.result = object_id (lower 32) | size (upper 32)
                # msg.id = type_id from compile-time type table (0 = typeless)
                object_id = msg.result & 0xFFFFFFFF
                raw_size = (msg.result >> 32) & 0xFFFFFFFF
                type_id = msg.id
                if object_id < len(self._manager._current):
                    metadata = self._manager._current[object_id].metadata
                    metadata.type_id = type_id
                    size = raw_size
                    # If type_id is set, verify size matches type table
                    if type_id != 0 and self.type_table:
                        pointee_tid = self.type_table.get_pointee_type_id(type_id)
                        tt_size = self.type_table.get_size(pointee_tid) if pointee_tid else self.type_table.get_size(type_id)
                        if tt_size > 0 and tt_size != raw_size:
                            logger.warning(f"Type bind <Object {object_id}> size mismatch: raw_size={raw_size}, type_table_size={tt_size}, type_id={type_id}")
                        if tt_size > 0:
                            size = tt_size
                    if size > 0:
                        obj = self._manager._current[object_id]
                        if len(obj.value) < size:
                            obj.value.extend([b"\x00"] * (size - len(obj.value)))
                        logger.info(f"Type bind <Object {object_id}> -> type_id={type_id}, size={size}")
                    else:
                        logger.info(f"Type bind <Object {object_id}> -> type_id={type_id}, size=unknown")
            case PIPE_EVENT_TYPE.EVENT_EXTENSION:
                object_id = msg.result
                if object_id < len(self._manager._current):
                    new_lower = -msg.id
                    self._manager._current[object_id][new_lower] = b'\x00'
                    logger.info(f"Extending lower bound for <Object {object_id}> of current seed to {new_lower}")
            case PIPE_EVENT_TYPE.EVENT_COPY_OVERFLOW:
                # msg.result = src_object_id
                # msg.id = dst_bound (alloca size)
                src_object_id = msg.result
                dst_bound = msg.id
                target_size = dst_bound + 1
                if src_object_id < len(self._manager._current):
                    src_obj = self._manager._current[src_object_id]
                    if len(src_obj) < target_size:
                        seed = self._manager._current.clone()
                        obj = seed[src_object_id]
                        # Pad so strlen(src) == dst_bound, overflowing the dest.
                        # dst_bound non-null bytes + '\0' terminator
                        while len(obj) < target_size:
                            obj[len(obj)] = b"A"
                        obj[target_size - 1] = b"\x00"
                        self._manager.scheduler.append(seed)
                        logger.info(f"Copy overflow: enlarged <Object {src_object_id}> "
                                    f"from {len(src_obj)} to {target_size} "
                                    f"(dst_bound={dst_bound}) @{msg.addr:#x}")