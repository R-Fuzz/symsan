from enum import Enum
import os
import sys
from multiprocessing import shared_memory
import subprocess
import ctypes
import logging
import time

from backend_solver import Z3Solver, ConditionUnsat
from defs import *
import utils
from agent import ExploitAgent, ReplayAgent, RecordAgent

# TODO: automatically infer this
UNION_TABLE_SIZE = 0xc00000000

class MsgType(Enum):
    cond_type = 0
    gep_type = 1
    memcmp_type = 2
    fsize_type = 3
    loop_type = 4

class ExecutorResult:
    def __init__(self, total_time, solving_time, dist, returncode, out, err, testcases):
        self.returncode = returncode
        self.total_time = total_time
        self.solving_time = solving_time
        self.distance = dist
        self.generated_testcases = testcases
        self.stdout = out.read() if out else "Output not available"
        self.stderr = err.read() if err else "Unknown error"

    @property
    def emulation_time(self):
        return self.total_time - self.solving_time
    
    def update_time(self, total_time, solving_time):
        self.total_time = total_time
        self.solving_time = solving_time

class SymSanExecutor:
    class InvalidGEPMessage(Exception):
        pass
    
    class Timer:
        def __init__(self):
            self.proc_start_time = 0
            self.proc_end_time = 0
            self.solving_time = 0
        
        def reset(self):
            self.proc_start_time = 0
            self.proc_end_time = 0
            self.solving_time = 0

    def __init__(self, config, agent, output_dir):
        self.config = config
        self.cmd = config.cmd
        self.agent = agent
        self.timer = SymSanExecutor.Timer()
        self.logger = logging.getLogger(self.__class__.__qualname__)
        self.logging_level = config.logging_level
        # resources
        self.pipefds = self.shm = self.proc = None
        self.solver = None
        # options
        self.testcase_dir = output_dir
        self.record_replay_mode_enabled = True if (type(agent) is ReplayAgent or type(agent) is RecordAgent) else False
        self.onetime_solving_enabled = True if (type(agent) is ExploitAgent) else False
        assert not (self.record_replay_mode_enabled and self.onetime_solving_enabled)
        self.gep_solver_enabled = config.gep_solver_enabled

    @property
    def has_terminated(self):
        if not self.proc:
            return True
        if self.proc.poll() is not None:
            return True
        return False

    def tear_down(self):
        if self.pipefds:
            try:
                os.close(self.pipefds[0])
                os.close(self.pipefds[1])
            except OSError:
                pass
            self.pipefds = None
        if self.proc and self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()
            self.timer.proc_end_time = int(time.time() * 1000)
        if self.shm:
            self.shm.close()
            self.shm.unlink()
            self.shm = None

    def get_result(self):
        # TODO: implement stream reader thread in case the subprocess closes
            return ExecutorResult(self.timer.proc_end_time - self.timer.proc_start_time, 
                                  self.timer.solving_time, self.agent.min_distance, 
                                  self.proc.returncode, self.proc.stdin,
                                  self.proc.stderr, self.solver.generated_files)

    def setup(self, input_file, session_id=0):
        self.input_file = input_file
        # Create and map shared memory
        try:
            self.shm = shared_memory.SharedMemory(create=True, size=UNION_TABLE_SIZE)
        except:
            self.logger.critical(f"setup: Failed to map shm({self.shm._fd}), size(shm.size)")
            sys.exit(1)
        # pipefds[0] for read, pipefds[1] for write
        self.pipefds = os.pipe()
        self.solver = Z3Solver(self.config, self.shm, self.input_file, 
                               self.testcase_dir, 0, session_id)
        self.agent.reset()
        self.timer.reset()

    def process_request(self):
        self.timer.solving_time = 0
        should_terminate = False
        while not should_terminate and self.proc.poll() is None:
            msg_data = os.read(self.pipefds[0], ctypes.sizeof(pipe_msg))
            if not msg_data: break
            start_time = int(time.time() * 1000)
            msg = pipe_msg.from_buffer_copy(msg_data)
            if msg.msg_type == MsgType.cond_type.value:
                if self.__process_cond_request(msg) and self.onetime_solving_enabled:
                    should_terminate = True
            elif msg.msg_type == MsgType.gep_type.value:
                self.__process_gep_request(msg)
            elif msg.msg_type == MsgType.memcmp_type.value:
                self.solver.handle_memcmp(msg, self.pipefds[0])
            elif msg.msg_type == MsgType.loop_type.value:
                self.logger.debug(f"handle_loop_enter: id={msg.id}, loop_header={hex(msg.addr)}")
            elif msg.msg_type == MsgType.fsize_type.value:
                pass
            else:
                self.logger.error(f"process_request: Unknown message type: {msg.msg_type}",
                                  file=sys.stderr)
            end_time = int(time.time() * 1000)
            self.timer.solving_time += end_time - start_time
        self.timer.proc_end_time = int(time.time() * 1000)

    def run(self, timeout=None):
        # create and execute the child symsan process
        logging_level = 1 if self.logging_level == logging.DEBUG else 0
        options = (f"taint_file={self.input_file}"
        f":shm_fd={self.shm._fd}"
        f":pipe_fd={self.pipefds[1]}"
        f":debug={logging_level}")
        cmd, stdin = utils.fix_at_file(self.cmd, self.input_file)
        if timeout:
            cmd = ["timeout", "-k", str(5), str(timeout)] + cmd
        try:
            self.logger.debug("Executing %s" % ' '.join(cmd))
            self.timer.proc_start_time = int(time.time() * 1000)
            if stdin:
                # the symsan proc reads the input from stdin
                self.proc = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                             env={"TAINT_OPTIONS": options},
                                             pass_fds=(self.shm._fd, self.pipefds[1]))
                self.proc.stdin.write(stdin.encode())
                self.proc.stdin.flush()
            else:
                # the symsan proc reads the input from file stream
                self.proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL,
                                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                             env={"TAINT_OPTIONS": options},
                                             pass_fds=(self.shm._fd, self.pipefds[1]))
        except:
            self.logger.critical(f"run: Failed to execute subprocess, "
                                 f"input: {self.input_file}, cmd: {' '.join(cmd)}")
            self.tear_down()
            sys.exit(1)
        os.close(self.pipefds[1])

    def __process_cond_request(self, msg):
        is_interesting = False
        if msg.label:
            state_data = os.read(self.pipefds[0], ctypes.sizeof(mazerunner_msg))
            state_msg = mazerunner_msg.from_buffer_copy(state_data)
            self.agent.handle_new_state(state_msg, msg.result)
            is_interesting = self.agent.is_interesting_branch()
            if not self.record_replay_mode_enabled:
                try:
                    self.solver.handle_cond(msg, is_interesting)
                except ConditionUnsat:
                    self.agent.handle_unsat_condition()
                    return False
        if (msg.flags & TaintFlag.F_LOOP_EXIT) and (msg.flags & TaintFlag.F_LOOP_LATCH):
            self.logger.debug(f"Loop handle_loop_exit: id={msg.id}, target={hex(msg.addr)}")
        return is_interesting

    def __process_gep_request(self, msg):
        gep_data = os.read(self.pipefds[0], ctypes.sizeof(gep_msg))
        gmsg = gep_msg.from_buffer_copy(gep_data)
        if msg.label != gmsg.index_label: # Double check
            self.logger.error(f"process_request: Incorrect gep msg: {msg.label} "
                              f"vs {gmsg.index_label}")
            raise SymSanExecutor.InvalidGEPMessage()
        if self.gep_solver_enabled: self.solver.handle_gep(gmsg, msg.addr)
