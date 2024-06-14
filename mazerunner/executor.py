import select
import sys
import os
import fcntl
import subprocess
import ctypes
import logging
import threading
import time
from multiprocessing import shared_memory

from builtin_solver import Z3Solver
from defs import *
import utils
from agent import ExploitAgent, ExploreAgent

UNION_TABLE_SIZE = 0xc00000000
PIPE_CAPACITY = 4 * 1024 * 1024

class ConcolicExecutor:
    
    class InvalidGEPMessage(Exception):
        pass
    
    class Timer:
        def reset(self):
            self.proc_start_time = (time.time() * utils.MILLION_SECONDS_SCALE)
            self.proc_end_time = self.proc_start_time
            self.solving_time = 0

        def execution_timeout(self, timeout):
            curr_time = (time.time() * utils.MILLION_SECONDS_SCALE)
            total_time = curr_time - self.proc_start_time
            return total_time >= timeout * utils.MILLION_SECONDS_SCALE
        
    class SubprocessIOReader:
        def __init__(self, io):
            self.stream = io
            self.data = ''
            self.should_stop = False
            if self.is_io_valid:
                self._set_non_blocking()
        
        @property
        def is_io_valid(self):
            if not self.stream:
                return False
            if self.stream.closed:
                return False
            return True

        def _set_non_blocking(self):
            fd = self.stream.fileno()
            fl = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

        def read(self):
            while not self.should_stop:
                try:
                    if not self.is_io_valid:
                        break
                    line = self.stream.readline()
                    if not line:
                        continue
                    self.data += line.decode('utf-8')
                except BlockingIOError:
                    time.sleep(0.1)
                except Exception:
                    logging.error(f"SubprocessIOReader: Failed to read output")
                    break

    def __init__(self, config, agent, output_dir):
        self.config = config
        self.cmd = config.cmd
        self.agent = agent
        self.timer = ConcolicExecutor.Timer()
        self.logger = logging.getLogger(self.__class__.__qualname__)
        self.logging_level = config.logging_level
        # resources
        self.pipefds = self.shm = self.proc = None
        self.solver = None
        # Create and map shared memory
        try:
            self.shm = shared_memory.SharedMemory(create=True, size=UNION_TABLE_SIZE)
        except:
            self.logger.critical(f"setup: Failed to map shm({self.shm._fd}), size(shm.size)")
            sys.exit(1)
        # options
        self.testcase_dir = output_dir
        self._onetime_solving_enabled = True if (type(agent) is ExploitAgent) else False
        self._save_seed_info = True if (type(agent) is ExploreAgent or type(agent) is ExploitAgent) else False
        self._should_increase_pipe_capacity = True
        self._setup_pipe()
        utils.disable_core_dump()

    @property
    def has_terminated(self):
        if self.proc is None:
            return True
        if self.proc.poll() is not None:
            return True
        return False

    def tear_down(self, deep_clean=True):
        if self.pipefds:
            self._close_pipe()
        self.kill_proc()
        if deep_clean:
            try:
                self.shm.close()
                self.shm.unlink()
            except:
                pass

    def kill_proc(self):
        self.stdout_reader.should_stop = True
        self.stderr_reader.should_stop = True
        if not self.has_terminated:
            if self.proc.stdout: self.proc.stdout.close()
            if self.proc.stderr: self.proc.stderr.close()
            self.proc.kill()
            self.proc.wait()
        self.timer.proc_end_time = int(time.time() * utils.MILLION_SECONDS_SCALE)

    def get_result(self):
        ret_code = self.proc.returncode if self.proc.returncode >= 0 else -self.proc.returncode
        return ExecutorResult(self.timer.proc_end_time - self.timer.proc_start_time, 
                            self.timer.solving_time, int(self.agent.min_distance), 
                            ret_code, self.msg_num, 
                            self.solver.generated_files, self.stdout_reader.data, self.stderr_reader.data)

    def setup(self, input_file, session_id=0):
        self.input_file = input_file
        self.msg_num = 0
        self._setup_pipe()
        self.solver = Z3Solver(self.config, self.shm, self.input_file, 
                               self.testcase_dir, 0, session_id)
        self.agent.reset()
        self.timer.reset()

    def run(self, timeout=None):
        # create and execute the child symsan process
        logging_level = 1 if self.logging_level == logging.DEBUG else 0
        subprocess_io = subprocess.PIPE if self.logging_level == 1 else subprocess.DEVNULL
        cmd, stdin, _ = utils.fix_at_file(self.cmd, self.input_file)
        taint_file = "stdin" if stdin else self.input_file
        options = (f"taint_file=\"{taint_file}\""
        f":shm_fd={self.shm._fd}"
        f":pipe_fd={self.pipefds[1]}"
        f":debug={logging_level}")
        current_env = os.environ.copy()
        current_env["TAINT_OPTIONS"] = options
        if timeout:
            cmd = ["timeout", "-k", str(1), str(int(timeout))] + cmd
        try:
            self.logger.debug("Executing %s" % ' '.join(cmd))
            if stdin:
                # the symsan proc reads the input from stdin
                self.proc = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                                             stdout=subprocess_io, stderr=subprocess_io,
                                             env=current_env,
                                             pass_fds=(self.shm._fd, self.pipefds[1]))
                self.proc.stdin.write(stdin)
                self.proc.stdin.flush()
                self.proc.stdin.close()
            else:
                # the symsan proc reads the input from file stream
                self.proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL,
                                             stdout=subprocess_io, stderr=subprocess_io,
                                             env=current_env,
                                             pass_fds=(self.shm._fd, self.pipefds[1]))
        except Exception as e:
            self.logger.critical(f"Failed to execute subprocess, error: \n{e}\n"
                                 f"Input: {self.input_file}\n"
                                 f"CMD: {' '.join(cmd)}")
            self.tear_down(deep_clean=False)
            sys.exit(1)
        self.stdout_reader = ConcolicExecutor.SubprocessIOReader(self.proc.stdout)
        self.stderr_reader = ConcolicExecutor.SubprocessIOReader(self.proc.stderr)
        self.stdout_thread = threading.Thread(target=self.stdout_reader.read)
        self.stderr_thread = threading.Thread(target=self.stderr_reader.read)
        self.stdout_thread.start()
        self.stderr_thread.start()
        os.close(self.pipefds[1])
        self.pipefds[1] = None

    def process_request(self):
        self.timer.solving_time = 0
        should_handle = True
        self.msg_num = 0
        # we don't need to check self.has_terminated here
        # because the pipe might still be readable even if the child process has terminated
        while should_handle:
            readable, _, _ = select.select([self.pipefds[0]], [], [], 3)
            if not readable:
                self.logger.info("process_request: pipe is broken, stop processing.")
                break
            msg_data = os.read(self.pipefds[0], ctypes.sizeof(pipe_msg))
            if len(msg_data) < ctypes.sizeof(pipe_msg):
                break
            start_time = int(time.time() * utils.MILLION_SECONDS_SCALE)
            msg = pipe_msg.from_buffer_copy(msg_data)
            self.logger.debug(
                "process_request: received msg. "
                "msg_type=%s, flags=%s, instance_id=%s, addr=%s, context=%s, "
                "id=%s, label=%s, result=%s",
                msg.msg_type, msg.flags, msg.instance_id, hex(msg.addr),
                msg.context, msg.id, msg.label, msg.result
            )
            if msg.msg_type == MsgType.cond_type.value:
                solving_status = self._process_cond_request(msg)
                if ((solving_status == SolvingStatus.SOLVED_NESTED or solving_status == SolvingStatus.SOLVED_OPT_NESTED_TIMEOUT) 
                    and self._onetime_solving_enabled):
                    should_handle = False
                if (solving_status == SolvingStatus.UNSOLVED_UNKNOWN
                    or solving_status == SolvingStatus.UNSOLVED_INVALID_EXPR):
                    self.logger.error(f"process_request: slover panic, stop processing. "
                                      f"solving_status={solving_status}")
                    should_handle = False
            elif msg.msg_type == MsgType.gep_type.value:
                self._process_gep_request(msg)
            elif msg.msg_type == MsgType.memcmp_type.value:
                self.solver.handle_memcmp(msg, self.pipefds[0])
            elif msg.msg_type == MsgType.fsize_type.value:
                pass
            elif msg.msg_type == MsgType.fini_type.value:
                self.agent.min_distance = min(msg.result, self.agent.min_distance)
            else:
                self.logger.error(f"process_request: Unknown message type: {msg.msg_type}")
            end_time = int(time.time() * utils.MILLION_SECONDS_SCALE)
            self.timer.solving_time += end_time - start_time
            self.msg_num += 1

    def _process_cond_request(self, msg):
        state_data = os.read(self.pipefds[0], ctypes.sizeof(mazerunner_msg))
        if len(state_data) < ctypes.sizeof(mazerunner_msg):
            self.logger.error(f"__process_cond_request: mazerunner_msg too small: {len(state_data)}")
            return SolvingStatus.UNSOLVED_INVALID_MSG
        state_msg = mazerunner_msg.from_buffer_copy(state_data)
        self.agent.handle_new_state(state_msg, msg.result, msg.label)
        if not msg.label:
            return SolvingStatus.UNSOLVED_INVALID_MSG
        is_interesting = self.agent.is_interesting_branch()
        seed_info = ''
        if self._save_seed_info:
            reversed_sa = str(self.agent.curr_state.reversed_sa) if is_interesting else ''
            score = self.agent.compute_branch_score() if is_interesting else ''
            seed_info = f"{score}:{reversed_sa}"
        solving_status = self.solver.handle_cond(msg, is_interesting, self.agent.curr_state, seed_info)
        if not is_interesting:
            return SolvingStatus.UNSOLVED_UNINTERESTING_COND
        if solving_status == SolvingStatus.UNSOLVED_OPT_UNSAT:
            self.agent.handle_unsat_condition(solving_status)
        if solving_status == SolvingStatus.UNSOLVED_TIMEOUT:
            self.agent.handle_unsat_condition(solving_status)
        if solving_status == SolvingStatus.SOLVED_OPT_NESTED_UNSAT:
            self.agent.handle_nested_unsat_condition()
        if solving_status == SolvingStatus.SOLVED_OPT_NESTED_TIMEOUT:
            self.agent.handle_nested_unsat_condition()
        return solving_status

    def _process_gep_request(self, msg):
        gep_data = os.read(self.pipefds[0], ctypes.sizeof(gep_msg))
        if len(gep_data) < ctypes.sizeof(gep_msg):
            self.logger.error(f"__process_gep_request: GEP message too small: {len(gep_data)}")
            return SolvingStatus.UNSOLVED_INVALID_MSG
        gmsg = gep_msg.from_buffer_copy(gep_data)
        if msg.label != gmsg.index_label: # Double check
            self.logger.error(f"__process_gep_request: Incorrect gep msg: {msg.label} "
                              f"vs {gmsg.index_label}")
            raise ConcolicExecutor.InvalidGEPMessage()
        if self.config.gep_solver_enabled:
            return self.solver.handle_gep(gmsg, msg.addr)

    def _close_pipe(self):
        if self.pipefds[0] is not None:
            try:
                os.close(self.pipefds[0])
            except OSError:
                self.logger.warning("Failed to close pipefds[0] for read")
            finally:
                self.pipefds[0] = None
        if self.pipefds[1] is not None:
            try:
                os.close(self.pipefds[1])
            except OSError:
                self.logger.warning("Failed to close pipefds[1] for write")
            finally:
                self.pipefds[1] = None
        self.pipefds = None

    def _setup_pipe(self):
        if self.pipefds:
            self._close_pipe()
        # pipefds[0] for read, pipefds[1] for write
        self.pipefds = list(os.pipe())
        if not self._should_increase_pipe_capacity:
            return
        if not hasattr(fcntl, 'F_GETPIPE_SZ'):
            return
        pipe_capacity = fcntl.fcntl(self.pipefds[0], fcntl.F_GETPIPE_SZ)
        if pipe_capacity >= PIPE_CAPACITY:
            return
        try:
            fcntl.fcntl(self.pipefds[0], fcntl.F_SETPIPE_SZ, PIPE_CAPACITY)
            fcntl.fcntl(self.pipefds[1], fcntl.F_SETPIPE_SZ, PIPE_CAPACITY)
        except PermissionError:
            self._should_increase_pipe_capacity = False
            self.logger.warning(f"Failed to increase pipe capacity. Need higher privilege. \n"
                                f"Please try to set it manually by running: "
                                f"'echo {PIPE_CAPACITY} | sudo tee /proc/sys/fs/pipe-max-size' ")
