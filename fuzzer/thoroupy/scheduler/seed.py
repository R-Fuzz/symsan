import struct
from typing import List
from control import UcsanTicket, ModelDescriber # type: ignore
import logging
from hashlib import sha256

logger = logging.getLogger(__name__)

OBJ_LIMIT = 100000
SIZE_LIMIT = 1000000000

class UObject:
    def __init__(self) -> None:
        self.value = []
        self.lvalue = []
        self.metadata = UObjectMetadata()

    def __setitem__(self, index: int, value: bytes) -> None:
        if index >= 0 and index < OBJ_LIMIT:
            if index >= len(self.value):
                self.value.extend([b"\x00"] * (index - len(self.value) + 1))
            self.value[index] = value
        elif index < 0 and (-index - 1) < OBJ_LIMIT:
            lindex = -index - 1
            if lindex >= len(self.lvalue):
                self.lvalue.extend([b"\x00"] * (lindex - len(self.lvalue) + 1))
            self.lvalue[lindex] = value
        else:
            logger.warning(f"Index {index} out of bounds for UObject, value: {value.hex() if isinstance(value, bytes) else value}")

    def __bytes__(self) -> bytes:
        return b"".join(self.lvalue[::-1]) + b"".join(self.value)

    def __repr__(self) -> str:
        return self._compress_hex(self.lvalue[::-1]) + '|' + self._compress_hex(self.value)

    @staticmethod
    def _compress_hex(byte_list) -> str:
        if not byte_list:
            return ""
        data = b"".join(byte_list)
        parts = []
        i = 0
        while i < len(data):
            if data[i] == 0:
                j = i
                while j < len(data) and data[j] == 0:
                    j += 1
                n = j - i
                parts.append(f"0x{n}" if n > 2 else "00" * n)
                i = j
            else:
                j = i
                while j < len(data) and data[j] != 0:
                    j += 1
                parts.append(data[i:j].hex())
                i = j
        return "".join(parts)

    def __len__(self) -> int:
        return len(self.lvalue) + len(self.value)

    def pack_len(self) -> bytes:
        return struct.pack("<Q", len(self))

    def pack_index(self) -> bytes:
        return struct.pack("<L", len(self.lvalue))

class UObjectMetadata:
    _elf = None  # shared ELF instance, set by UcsanManager

    class Usage:
        def __init__(self, addr=0, offset=0, size=0) -> None:
            self.addr = addr
            self.offset = offset
            self.size = size

        @property
        def loc(self):
            if UObjectMetadata._elf:
                return UObjectMetadata._elf.get_loc(self.addr - 1)
            return (None, None, None)

    def __init__(self, object_id = 0, from_object = 0, from_offset = 0, addr = 0) -> None:
        self.object_id = object_id
        self.from_object = from_object
        self.from_offset = from_offset
        self.target_offset = 0  # offset within this object the pointer points to
        self.addr = addr
        self.type_id = 0
        self.citations:List[UObjectMetadata.Usage] = []

    @property
    def loc(self):
        if self._elf and self.addr:
            return self._elf.get_loc(self.addr - 1)
        return (None, None, None)

    def __bytes__(self) -> bytes:
        return struct.pack("<QQQ", self.from_object, self.from_offset, self.target_offset)

    def unpack(self, data:bytes):
        if len(data) >= 24:
            obj, offset, target = struct.unpack("<QQQ", data[:24])
            self.target_offset = target
        else:
            obj, offset = struct.unpack("<QQ", data[:16])
            self.target_offset = 0
        self.from_object = obj
        self.from_offset = offset

    def cite(self, addr, offset, size):
        self.citations.append(UObjectMetadata.Usage(addr, offset, size))

class Seed:
    def __init__(self) -> None:
        self.objects: List[UObject] = []
        self.traces = []
        self.flip_meta = None  # auto-debug: {bid, context, original_result, original_seed}

    def from_msg(self, data: bytes) -> None:
        """
        Parse seed from message (message via the pipe)
        """
        # logger.debug(data, len(data), ModelDescriber.size)
        for i in range(len(data) // ModelDescriber.size):
            offset = i * ModelDescriber.size
            model_describer = ModelDescriber(data[offset:offset+ModelDescriber.size])
            if model_describer.object_id >= OBJ_LIMIT or model_describer.offset >= SIZE_LIMIT:
                logger.error(f"Model describer exceed: {model_describer}")
                continue
            logger.debug(f"Model describer obj_id: {model_describer.object_id}, offset: {model_describer.offset}, value: {model_describer.value}")
            self[model_describer.object_id][model_describer.offset] = model_describer.value.to_bytes(1, 'little')

    def from_bytes(self, data: bytes) -> None:
        """
        Parse seed from raw bytes (data stored in the disk)
        """
        # print(data)
        size = struct.unpack("<Q", data[:8])[0]
        # print(size)
        offset = 8
        indexes = []
        for _ in range(size):
            obj_size = struct.unpack("<Q", data[offset:offset+4])[0]
            offset += 4
            indexes.append(obj_size)
        sizes = []
        for _ in range(size):
            obj_size = struct.unpack("<Q", data[offset:offset+8])[0]
            offset += 8
            sizes.append(obj_size)
        for obj_index, obj_size in zip(indexes, sizes):
            obj = UObject()
            obj.lvalue = [data[offset+i:offset+i+1] for i in range(obj_index)]
            obj.value = [data[offset+i:offset+i+1] for i in range(obj_index, obj_size)]
            offset += obj_size
            self.objects.append(obj)

        if len(data) <= offset:
            return

        # Determine metadata size: 3 u64s (new) or 2 u64s (old)
        remaining = len(data) - offset
        meta_size = 8 * 3 if remaining >= size * 8 * 3 else 8 * 2
        for index in range(size):
            self.objects[index].metadata.unpack(data[offset:offset + meta_size])
            offset += meta_size

    def __len__(self) -> int:
        return len(self.objects)

    def __getitem__(self, index: int) -> UObject:
        if index >= len(self.objects):
            for _ in range(index - len(self.objects) + 1):
                self.objects.append(UObject())
        return self.objects[index]

    def __bytes__(self) -> bytes:
        return struct.pack("<Q", len(self.objects)) + \
                b"".join(obj.pack_index() for obj in self.objects) + \
                b"".join(obj.pack_len() for obj in self.objects) + \
                b"".join(bytes(obj) for obj in self.objects) + \
                b"".join(bytes(obj.metadata) for obj in self.objects)

    def to_ticket(self, instance_id = 0, session_id = 0) -> bytes:
        ticket = UcsanTicket()
        payload = bytes(self)
        ticket.payload_size = len(payload)
        ticket.instance_id = instance_id
        ticket.session_id = session_id
        ticket.msg_type = 2
        return bytes(ticket) + payload

    def clone(self) -> "Seed":
        s = Seed()
        s.objects = [UObject() for _ in self.objects]
        for i, obj in enumerate(self.objects):
            s[i].value = obj.value[:]
            s[i].lvalue = obj.lvalue[:]
            # Copy metadata
            s[i].metadata.object_id = obj.metadata.object_id
            s[i].metadata.from_object = obj.metadata.from_object
            s[i].metadata.from_offset = obj.metadata.from_offset
            s[i].metadata.target_offset = obj.metadata.target_offset
            s[i].metadata.addr = obj.metadata.addr
            s[i].metadata.type_id = obj.metadata.type_id
            s[i].metadata.citations = obj.metadata.citations[:]
        s.flip_meta = self.flip_meta
        return s

    def set_byte(self, obj_id: int, offset: int, value: int) -> None:
        """Set single byte at offset."""
        self[obj_id][offset] = bytes([value])

    def insert_bytes(self, obj_id: int, offset: int, data: bytes) -> None:
        """Insert bytes at offset, shifting existing bytes right."""
        obj = self[obj_id]
        # Convert list of single-byte bytes to a single bytes object
        current = b"".join(obj.value)
        # Insert data at offset
        new_value = current[:offset] + data + current[offset:]
        # Convert back to list of single-byte bytes
        obj.value = [new_value[i:i+1] for i in range(len(new_value))]

    def delete_bytes(self, obj_id: int, offset: int, length: int) -> None:
        """Delete bytes at offset, shifting existing bytes left."""
        obj = self[obj_id]
        # Convert list of single-byte bytes to a single bytes object
        current = b"".join(obj.value)
        # Delete length bytes at offset
        new_value = current[:offset] + current[offset + length:]
        # Convert back to list of single-byte bytes
        obj.value = [new_value[i:i+1] for i in range(len(new_value))]

    def to_bytes(self) -> bytes:
        """Return seed as single bytes object."""
        # Concatenate all input objects
        return b''.join(bytes(obj) for obj in self.objects)

    def to_bytes_list(self) -> list:
        """Return list of bytes, one per object (for solver reset)."""
        return [bytes(obj) for obj in self.objects]

    def to_dict(self) -> "list[dict]":
        for obj in self.objects:
            from_object = obj.metadata.from_object
            from_offset = obj.metadata.from_offset
            print(from_object, from_offset)
            if from_object < OBJ_LIMIT:
                if from_object >= len(self.objects):
                    self.objects.extend([UObject() for _ in range(from_object - len(self.objects) + 1)])
                if from_offset >= len(self.objects[from_object].value):
                    self.objects[from_object].value.extend([b"\x00"] * (from_offset - len(self.objects[from_object].value) + 1 + 8))
                if from_offset < 0 and -from_offset - 1 >= len(self.objects[from_object].lvalue):
                    self.objects[from_object].lvalue.extend([b"\x00"] * (-from_offset - 1 - len(self.objects[from_object].lvalue) + 1))
            for cite in obj.metadata.citations:
                quoted = cite.offset + cite.size
                if quoted >= 0 and quoted > len(self.objects[from_object].value):
                    self.objects[from_object].value.extend([b"\x00"] * (quoted - len(self.objects[from_object].value) + 1))
                elif cite.offset < 0 and -cite.offset - 1 > len(self.objects[from_object].lvalue):
                    self.objects[from_object].lvalue.extend([b"\x00"] * (-cite.offset - 1 - len(self.objects[from_object].lvalue) + 1))

        return [{
            "value": b"".join(obj.value).hex(),
            "lvalue": b"".join(obj.lvalue).hex(),
            "metadata": {
                "object_id": obj.metadata.object_id,
                "from_object": obj.metadata.from_object,
                "from_offset": obj.metadata.from_offset,
                "loc": obj.metadata.loc,
                "addr": obj.metadata.addr,
                "citations": [{ "loc": citation.loc, "offset": citation.offset, "size": citation.size} for citation in obj.metadata.citations]
            },
            **({"traces": self.traces if hasattr(self, "traces") else []} if idx == 0 else {})
        } for idx, obj in enumerate(self.objects)]

    def __repr__(self) -> str:
        objs = ', '.join([f"{idx:02}@" + repr(obj) for idx, obj in enumerate(self.objects)])
        if logger.getEffectiveLevel() > logging.DEBUG:
            objs = objs[:20] + "..." + objs[-10:]
        return f"Seed< {objs} >"

    def digest(self):
        return sha256(bytes(self))

if __name__ == "__main__":
    s = UObject()
    s[10] = b"\x01"
    print(bytes(s))
    s = Seed()
    b = open("/tmp/seed", 'rb').read()
    s.from_bytes(b)
    d = bytes(s)
    print(d == b, d, b)
