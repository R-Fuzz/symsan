from os import pipe, read, write, close, system, open, O_RDWR, mkfifo, unlink, getpid
from typing import Optional, TypeVar, Generic, Type
from .message import MessageBase
from uuid import uuid4
import tempfile
import os.path
import logging

TMessageBase = TypeVar('TMessageBase', bound=bytes)
logger = logging.getLogger(__name__)

class Pipe(Generic[TMessageBase]):
    def __init__(self, flag="control_pipe_name", T: Type[TMessageBase] = MessageBase,  open_flag=0) -> None:
        # The FIFO's name is unlinked as soon as it is open: the target opens
        # it through /proc/<pid>/fd/<fd>, a link to this open pipe, not to a
        # name in a directory.  So none is left behind however this process
        # ends -- the runners leave with os._exit, which skips __del__, and a
        # killed one never gets there (thousands of leaked /tmp/pipe_* FIFOs).
        self.fd = None
        fifo = os.path.join(tempfile.gettempdir(), f"pipe_{uuid4()}")
        mkfifo(fifo)
        try:
            self.fd = open(fifo, O_RDWR | open_flag)
        finally:
            unlink(fifo)
        self.pipe_file = f"/proc/{getpid()}/fd/{self.fd}"
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
        if self.fd is not None:
            close(self.fd)
            self.fd = None

    def __del__(self):
        self.close()

    def get_name(self):
        return self.pipe_file

    def get(self, T:Optional[Type[TMessageBase]]=None) -> TMessageBase:
        return self.__next__(T)

    def read_raw(self, size = 0x100000):
        return read(self.fd, size)