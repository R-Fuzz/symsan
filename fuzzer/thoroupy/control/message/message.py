STURCT_FOLDER = "struct"
import os
from abc import ABC
from typing import Optional
from .struct_parser import StructParser

class MessageBase(ABC, bytes):
    from ctypes import Structure
    Struct: Structure = None # type: ignore
    size: int = 0
    def __init__(self, payload: Optional[bytes] = None) -> None:
        if payload is not None:
            self._msg = self.Struct.from_buffer_copy(payload)
        else:
            self._msg = self.Struct.from_buffer_copy(bytes(self.size))

    def __bytes__(self) -> bytes:
        return bytes(self._msg)

    def __getattr__(self, __name: str):
        return getattr(self._msg, __name)

    def __setattr__(self, __name: str, __value) -> None:
        if __name == "_msg":
            super().__setattr__(__name, __value)
        else:
            setattr(self._msg, __name, __value)
    
    def __repr__(self) -> str:
        res = f"{self.__class__.__name__}("
        for k, v in self._msg._fields_:
            res += f"{k}={getattr(self._msg, k)}, "
        return res[:-2] + ")"

                
for file in os.listdir(os.path.join(os.path.dirname(__file__), STURCT_FOLDER)):
    if file.endswith('.h'):
        sp = StructParser(os.path.join(os.path.dirname(__file__), STURCT_FOLDER, file), MessageBase)
        # print(sp.types)
        locals().update(sp.types)


# """
# struct pipe_msg {
#   u16 msg_type;
#   u16 flags;
#   u32 instance_id;
#   uptr addr;
#   u32 context;
#   u32 label;
#   u64 result;
# } __attribute__((packed));
# """
# class PipeMessage(MessageBase):
#     class Struct(Structure):
#         _pack_ = 1
#         _fields_ = [
#             ("msg_type", c_uint16),
#             ("flags", c_uint16),
#             ("instance_id", c_uint32),
#             ("addr", c_uint64),
#             ("context", c_uint32),
#             ("label", c_uint32),
#             ("result", c_uint64)
#         ]

#     def __init__(self, bytes: bytes) -> "PipeMessage":
#         self._msg = self.Struct.from_buffer_copy(bytes)
    
#     def __bytes__(self) -> bytes:
#         return bytes(self._msg)

#     def __getattr__(self, __name: str) -> Any:
#         return getattr(self._msg, __name)
    
#     def __setattr__(self, __name: str, __value: Any) -> None:
#         if __name == "_msg":
#             super().__setattr__(__name, __value)
#         else:
#             setattr(self._msg, __name, __value)

