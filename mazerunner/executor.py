import os
import sys
from multiprocessing import shared_memory
import subprocess
import ctypes
import logging

from defs import *
from backend_solver import Solver

class Executor:
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(self.__class__.__qualname__)
        self.logger.setLevel(config.logging_level)
        # resources
        self.pipefds = self.shm = self.proc = None
        self.solver = None

    def tear_down(self):
        if self.pipefds:
            try:
                os.close(self.pipefds[0])
                os.close(self.pipefds[1])
            except OSError:
                pass
        if self.proc and not self.proc.poll():
            self.proc.kill()
            self.proc.wait()
        if self.shm:
            self.shm.close()
            self.shm.unlink()

    def setup(self, input_file):
        self.input_file = input_file
        # Create and map shared memory
        try:
            self.shm = shared_memory.SharedMemory(create=True, size=self.config.union_table_size)
        except:
            self.logger.critical(f"setup: Failed to map shm({self.shm._fd}), size(shm.size)")
            sys.exit(1)
        # pipefds[0] for read, pipefds[1] for write
        self.pipefds = os.pipe()
        self.solver = Solver(self.config, self.shm, self.input_file)

    def run(self):
        # create and execute the child symsan process
        logging_level = 1 if self.config.logging_level == logging.DEBUG else 0
        self.options = f"taint_file={self.input_file}:shm_fd={self.shm._fd}:pipe_fd={self.pipefds[1]}:debug={logging_level}"
        try:
            self.proc = subprocess.Popen([self.config.program, self.input_file], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, env={"TAINT_OPTIONS": self.options}, pass_fds=(self.shm._fd, self.pipefds[1]))
        except:
            self.logger.critical(f"run: Failed to execute subprocess, input_file: {self.input_file}")
            self.tear_down()
            sys.exit(1)
        os.close(self.pipefds[1])

    def process_request(self):
        while not self.proc.poll():
            msg_data = os.read(self.pipefds[0], ctypes.sizeof(pipe_msg))
            if not msg_data:
                break
            msg = pipe_msg.from_buffer_copy(msg_data)
            if msg.msg_type == MsgType.cond_type.value:
                self.solver.handle_cond(msg, self.pipefds[0])
            elif msg.msg_type == MsgType.gep_type.value:
                gep_data = os.read(self.pipefds[0], ctypes.sizeof(gep_msg))
                gmsg = gep_msg.from_buffer_copy(gep_data)
                if msg.label != gmsg.index_label: # Double check
                    self.logger.error(f"process_request: Incorrect gep msg: {msg.label} vs {gmsg.index_label}")
                    continue
                if self.config.gep_solving: self.solver.handle_gep(gmsg, msg.addr)
            elif msg.msg_type == MsgType.memcmp_type.value:
                self.solver.handle_memcmp(msg, self.pipefds[0])
            elif msg.msg_type == MsgType.loop_type.value:
                self.solver.handle_loop_enter(msg.id, msg.addr)
            elif msg.msg_type == MsgType.fsize_type.value:
                pass
            else:
                self.logger.error(f"process_request: Unknown message type: {msg.msg_type}", file=sys.stderr)
