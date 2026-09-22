from os import pipe, read, write, close, system, open, O_RDWR
from typing import Optional, TypeVar, Generic, Type
from .message import MessageBase
from uuid import uuid4
import logging

TMessageBase = TypeVar('TMessageBase', bound=bytes)
logger = logging.getLogger(__name__)

class Pipe(Generic[TMessageBase]):
    def __init__(self, flag="control_pipe_name", T: Type[TMessageBase] = MessageBase,  open_flag=0) -> None:
        self.pipe_file = f"/tmp/pipe_{uuid4()}"
        system(f"mkfifo {self.pipe_file}")
        self.fd = open(self.pipe_file, O_RDWR | open_flag)
        self.T = T
        self.flag = flag

    def __call__(self, env, args):
        env[self.flag] = self.pipe_file

    def __iter__(self):
        return self

    def __next__(self, T:Optional[Type[TMessageBase]]=None) -> TMessageBase:
        try:
            if isinstance(T, MessageBase):
                T = T.__class__
            size = T.size if T is not None and issubclass(T, MessageBase) else self.T.size # type: ignore
            recv = read(self.fd, size)  # type: ignore
            logger.debug(f"recv: {recv}")
        except EOFError:
            raise StopIteration()
        return T(recv) if T is not None else self.T(recv)

    def send(self, msg: TMessageBase) -> None:
        write(self.fd, bytes(msg))

    def close(self):
        close(self.fd)
        system(f"rm {self.pipe_file}")

    def __del__(self):
        self.close()

    def get_name(self):
        return self.pipe_file

    def get(self, T:Optional[Type[TMessageBase]]=None) -> TMessageBase:
        return self.__next__(T)

    def read_raw(self, size = 0x100000):
        return read(self.fd, size)