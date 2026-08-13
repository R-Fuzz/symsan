from multiprocessing import shared_memory
from typing import Callable, Dict, Optional, List
import mmap
import ctypes
import logging

logger = logging.getLogger(__name__)

class SharedMemory:
    def __init__(self, shm_id=None, size=0xC000000, create=True) -> None:
        self._size = size
        self._shm = shared_memory.SharedMemory(name=shm_id, create=create, size=size)
        logger.debug(msg=f"shm_id: {self._shm.name}, size: {self._size}")

    def __call__(self, env: Dict[str, str] , args: List) -> None:
        env['shm_name'] = self._shm.name
        env['shm_size'] = str(self._size)
        env.pop('shm_id', '')

    def close(self) -> None:
        self._shm.close()
        self._shm.unlink()

    def __getattr__(self, name):
        return getattr(self._shm, name)
    
    def get_address(self):
        import code
        code.interact(local=locals())
        ret = ctypes.c_void_p(self._shm.buf) # type: ignore
        return ret

    def get_name(self):
        return self._shm.name


if __name__ == "__main__":
    s = SharedMemory()
    print(s.get_address())
    input()