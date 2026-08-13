import ctypes
import mmap
import os
import select
import struct
from typing import Optional, Type, TypeVar

import symsan

from .message import MessageBase
from .pipe import Pipe

TMessageBase = TypeVar('TMessageBase', bound=bytes)

# Byte offsets into struct symsan_ring_hdr (include/symsan_ring.h): uint32
# magic, uint32 version, uint64 capacity, then head and tail each pinned to
# their own cacheline. Fixed by the C layout and mirrored here as constants
# rather than recomputed, since reproducing a C compiler's alignment rules in
# Python is exactly the kind of thing that goes silently wrong.
_HEAD_OFFSET = 64
_TAIL_OFFSET = 128


class RingChannel:
    """
    Event channel backed by a shared-memory ring (include/symsan_ring.h),
    read here and written by the target's __taint_emit() (see
    backend/solver_common.cpp, used by backend/thoroupy.cpp). A drop-in
    replacement for the `Pipe(flag="pipe_name", T=PipeMsg)` this project used
    before -- same __iter__/__next__/get/read_raw surface -- except the pipe
    itself no longer carries payloads, just the wake-up doorbell byte the
    producer sends when this side was found waiting (ring_wake_consumer() in
    backend/solver_common.cpp). That pipe is still required: thoroupy drives
    its target with a plain fork+exec (control/process.py's Process.spawn()),
    so flags().forksrv is always false on the target, and the producer's wake
    path for that case is the doorbell, not a futex -- see
    driver/launcher/launch.c's ring_read_event(), which this mirrors on the
    read side.

    Only the head cursor's WAITING bit needs a real atomic RMW, racing the
    producer's atomic advance of the same word -- that goes through
    symsan.ring_arm_head()/ring_disarm_head(), the two bits of native code
    this needs that Python cannot do safely on its own. Advancing tail is
    this process's alone to write, so it is a plain store; see _take()'s
    docstring for why a lost WAITING bit there cannot cause a missed wakeup.
    """

    # Spin this many times before arming and blocking -- matches
    # driver/launcher/launch.c's RING_SPINS. A commit on the producer side is
    # a memcpy and a store, so a live producer is a few hundred nanoseconds
    # away and any syscall to wait for it costs more than the wait.
    _SPINS = 64

    def __init__(self, doorbell_pipe: Pipe, T: Type[TMessageBase] = MessageBase,
                capacity: Optional[int] = None) -> None:
        self.T = T
        self._doorbell = doorbell_pipe
        self._capacity = capacity or symsan.RING_DEFAULT_CAPACITY
        if self._capacity < 4096 or (self._capacity & (self._capacity - 1)) != 0:
            raise ValueError("capacity must be a power of two >= 4096")

        total = symsan.ring_total_size(self._capacity)
        # memfd: anonymous and effectively pre-unlinked, so a crash leaves
        # nothing behind in /dev/shm for the next run to trip over.
        self._fd = os.memfd_create("thoroupy-event-ring")
        os.ftruncate(self._fd, total)
        os.set_inheritable(self._fd, True)  # survive fork()+execve()
        self._mm = mmap.mmap(self._fd, total)
        self._addr = ctypes.addressof((ctypes.c_char * total).from_buffer(self._mm))
        symsan.ring_init(self._addr, self._capacity)

        self._tail = 0  # local byte count; this process is the sole writer

    def __call__(self, env, args) -> None:
        self._doorbell(env, args)  # still registers pipe_name for the doorbell
        env['ring_fd'] = str(self._fd)
        env['ring_size'] = str(self._capacity)

    def __iter__(self):
        return self

    def _head_bytes(self) -> int:
        # Plain load: a naturally-aligned 8-byte read cannot tear on x86-64 or
        # aarch64, which is the property __atomic_load_n(..., ACQUIRE) rests
        # on too -- there is no weaker-ordered CPU underneath either target
        # for a single aligned word.
        head = struct.unpack_from('<Q', self._mm, _HEAD_OFFSET)[0]
        return head >> symsan.RING_SHIFT

    def _take(self, size: int) -> Optional[bytes]:
        """Copy `size` bytes out if the ring already has them; else None.

        Advancing tail here is a plain store, not the atomic RMW the producer
        uses for head -- and that is safe *because* this process is the only
        writer of tail's byte count. The producer may concurrently OR its own
        WAITING bit onto tail (if it is blocked for room), and this store can
        clobber that bit. But the producer only ever waits on tail with
        FUTEX_WAIT(word, expected=<the value it just armed>), and the kernel
        sleeps only if memory still equals `expected` at that instant -- so a
        clobber here either lands before the producer arms (its own read then
        folds this update in) or after (the compare fails and it retries
        immediately, no different from any other spurious wake). See
        include/symsan_ring.h's packing note for why the futex ABI makes
        exactly this race safe.
        """
        used = self._head_bytes() - self._tail
        if used < size:
            return None
        mask = self._capacity - 1
        off = self._tail & mask
        base = symsan.RING_HDR_SIZE
        first = self._capacity - off
        if first >= size:
            data = bytes(self._mm[base + off: base + off + size])
        else:
            data = bytes(self._mm[base + off: base + self._capacity])
            data += bytes(self._mm[base: base + (size - first)])
        self._tail += size
        struct.pack_into('<Q', self._mm, _TAIL_OFFSET, self._tail << symsan.RING_SHIFT)
        return data

    def _read_exact(self, size: int) -> bytes:
        while True:
            for _ in range(self._SPINS):
                data = self._take(size)
                if data is not None:
                    return data

            word = symsan.ring_arm_head(self._addr)
            if (word >> symsan.RING_SHIFT) - self._tail >= size:
                symsan.ring_disarm_head(self._addr)
                continue  # arrived while arming; the next spin pass takes it

            # Block for a doorbell. No timeout: matches Pipe's own os.read(),
            # which has always just blocked here.
            select.select([self._doorbell.fd], [], [])
            symsan.ring_disarm_head(self._addr)

            drained = os.read(self._doorbell.fd, 256)
            if len(drained) == 0:
                # Pipe closed with nothing left to wake us for: take whatever
                # landed right before teardown, if anything.
                data = self._take(size)
                if data is not None:
                    return data
                raise EOFError("event ring closed with a partial record pending")
            # else: doorbell drained, payload (if any) is in the ring --
            # loop back to the spin pass to take it.

    def __next__(self, T: Optional[Type[TMessageBase]] = None) -> TMessageBase:
        if isinstance(T, MessageBase):
            T = T.__class__
        size = T.size if T is not None and issubclass(T, MessageBase) else self.T.size
        data = self._read_exact(size)
        return T(data) if T is not None else self.T(data)

    def get(self, T: Optional[Type[TMessageBase]] = None) -> TMessageBase:
        return self.__next__(T)

    def read_raw(self, size: int = 0x100000) -> bytes:
        return self._read_exact(size)

    def get_name(self) -> str:
        return self._doorbell.get_name()

    def close(self) -> None:
        self._mm.close()
        os.close(self._fd)
