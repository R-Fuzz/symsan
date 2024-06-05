import copy
import symsan
import os
import ctypes
import logging
import time

from defs import *
import utils
from agent import ExploitAgent, RecordAgent, ExploreAgent

class ConcolicExecutor:
    
    class Timer:
        def reset(self):
            self.proc_start_time = (time.time() * utils.MILLION_SECONDS_SCALE)
            self.proc_end_time = self.proc_start_time
            self.solving_time = 0

        def execution_timeout(self, timeout):
            curr_time = (time.time() * utils.MILLION_SECONDS_SCALE)
            total_time = curr_time - self.proc_start_time
            return total_time >= timeout * utils.MILLION_SECONDS_SCALE

    def __init__(self, config, agent, output_dir):
        self.config = config
        self.cmd = config.cmd
        self.agent = agent
        self.timer = ConcolicExecutor.Timer()
        self.logger = logging.getLogger(self.__class__.__qualname__)
        self.logging_level = config.logging_level
        self.generated_files = []
        # symsan lib instance
        symsan.init(self.cmd[0])
        self.symsan_tasks = []
        self._recipe = {}
        # options
        self.config.defferred_solving_enabled = True if (type(agent) is ExploreAgent) else False
        self._testcase_dir = output_dir
        self._onetime_solving_enabled = True if (type(agent) is ExploitAgent) else False
        self._save_seed_info = True if (type(agent) is ExploreAgent or type(agent) is ExploitAgent) else False
        utils.disable_core_dump()

    def tear_down(self, need_cleanup=False):
        self.proc_returncode, is_killed = symsan.terminate()
        if is_killed:
            self.proc_returncode = 9
        if need_cleanup:
            symsan.destroy()
        self.timer.proc_end_time = (time.time() * utils.MILLION_SECONDS_SCALE)

    def get_result(self):
        assert self.proc_returncode is not None
        if self.config.defferred_solving_enabled:
            assert not self.generated_files
        return ExecutorResult(self.timer.proc_end_time - self.timer.proc_start_time, 
                                self.timer.solving_time, int(self.agent.min_distance),
                                self.proc_returncode, self.msg_num, 
                                self.generated_files, None, None)

    def setup(self, input_file, session_id=0):
        # subprocess status
        self.proc_returncode = None
        self.msg_num = 0
        self._session_id = session_id
        self._input_fp = input_file
        self._input_fn = os.path.basename(input_file)
        self._input_dir = os.path.dirname(input_file)
        self.symsan_tasks.clear()
        self.generated_files.clear()
        self.agent.reset()
        self.timer.reset()

    def run(self, timeout=None):
        # create and execute the child symsan process
        logging_level = 1 if self.logging_level == logging.DEBUG else 0
        cmd, stdin, self.input_content = utils.fix_at_file(self.cmd, self._input_fp)
        self.logger.debug("Executing %s" % ' '.join(cmd))
        
        if stdin:
            symsan.config("stdin", args=cmd, debug=logging_level, bounds=0)
            symsan.run(stdin=self._input_fp)
        else:
            symsan.config(self._input_fp, args=cmd, debug=logging_level, bounds=0)
            symsan.run()
        symsan.reset_input([self.input_content])

    def process_request(self):
        self.timer.solving_time = 0
        should_handle = True
        self.msg_num = 0
        # we don't need to check self.has_terminated here
        # because the pipe might still be readable even if the child process has terminated
        while should_handle:
            e = symsan.read_event(ctypes.sizeof(pipe_msg))
            if len(e) < ctypes.sizeof(pipe_msg):
                break
            start_time = (time.time() * utils.MILLION_SECONDS_SCALE)
            msg = pipe_msg.from_buffer_copy(e)
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
            # msg.flags == 1 means there is additional data need to be processed
            elif msg.msg_type == MsgType.memcmp_type.value and msg.flags == 1:
                has_error = self._process_memcmp_request(msg)
                if has_error: should_handle = False
            elif msg.msg_type == MsgType.fsize_type.value:
                pass
            elif msg.msg_type == MsgType.fini_type.value:
                self.agent.min_distance = min(msg.result, self.agent.min_distance)
            else:
                self.logger.error(f"process_request: Unknown message type: {msg.msg_type}")
            end_time = (time.time() * utils.MILLION_SECONDS_SCALE)
            self.timer.solving_time += end_time - start_time
            self.msg_num += 1

    def generate_testcase(self, target_sa, seed_map):
        if target_sa not in self._recipe:
            self.logger.warning(f"generate_testcase: target_sa not in recipe: {target_sa}")
            return None, None
        tasks, seed_id = self._recipe[target_sa]
        assert seed_id in seed_map
        solution, status = self._solve_tasks(tasks)
        solving_status = self._finalize_solving(status, solution, seed_map, seed_id)
        if solving_status not in solved_statuses:
            self.logger.debug(f"generate_testcase: failed to solve target_sa: {target_sa}")
            return None, seed_map[seed_id]
        return self.generated_files[-1], seed_map[seed_id]

    def _solve_tasks(self, tasks):
        solution = []
        status = []
        for task in tasks:
            r, sol = symsan.solve_task(task)
            s = self._parse_solving_status(r)
            solution += sol
            status.append(s)
        return solution, status

    def _finalize_solving(self, status, solution, seed_map=None, seed_id=None):
        seed_info = ''
        if self._save_seed_info:
            reversed_sa = str(self.agent.curr_state.reversed_sa)
            score = self.agent.compute_branch_score()
            seed_info = f"{score}:{reversed_sa}"
        solving_status = self._handle_solving_status(status)
        if solving_status in solved_statuses:
            input_buf = self._prepare_input_buffer(seed_map, seed_id)
            self._generate_testcase(solution, seed_info, input_buf)
        return solving_status

    def _prepare_input_buffer(self, seed_map, seed_id):
        if seed_map and seed_id:
            src_testcase = os.path.join(self._input_dir, seed_map[seed_id])
            with open(src_testcase, "rb") as f:
                return bytearray(f.read())
        return copy.copy(bytearray(self.input_content))

    def _process_cond_request(self, msg):
        state_data = symsan.read_event(ctypes.sizeof(mazerunner_msg))
        if len(state_data) < ctypes.sizeof(mazerunner_msg):
            self.logger.error(f"__process_cond_request: mazerunner_msg too small: {len(state_data)}")
            return SolvingStatus.UNSOLVED_INVALID_MSG

        state_msg = mazerunner_msg.from_buffer_copy(state_data)
        self.agent.handle_new_state(state_msg, msg.result, msg.label)
        
        if not msg.label:
            return SolvingStatus.UNSOLVED_INVALID_MSG
        
        tasks = symsan.parse_cond(msg.label, msg.result, msg.flags)
        if not self.agent.is_interesting_branch():
            return SolvingStatus.UNSOLVED_UNINTERESTING_COND

        if self.config.defferred_solving_enabled:
            reversed_sa = self.agent.curr_state.reversed_sa
            input_id = utils.get_id_from_fn(self._input_fn)
            self._recipe[reversed_sa] = (tasks, input_id)
            return SolvingStatus.UNSOLVED_DEFERRED

        solution, status = self._solve_tasks(tasks)
        solving_status = self._finalize_solving(status, solution)
        return solving_status

    def _process_gep_request(self, msg):
        #TODO: implemnet gep solver
        pass
    
    def _process_memcmp_request(self, msg):
        label = msg.label
        size = msg.result
        m = symsan.read_event(ctypes.sizeof(memcmp_msg) + size)
        if len(m) < ctypes.sizeof(memcmp_msg) + size:
            self.logger.error("error reading memcmp msg")
            return True
        buf = memcmp_msg.from_buffer_copy(m)
        if buf.label != label:
            self.logger.error("error reading memcmp msg")
            return True
        buf.content = m[ctypes.sizeof(memcmp_msg):]
        self.logger.debug(f"memcmp content: {buf.content.hex()}")
        symsan.record_memcmp(label, buf.content)     
        return False

    def _generate_testcase(self, solution, seed_info, input_buf):
        changed_index = set()
        for (_, i, v) in solution:
            assert i < len(input_buf)
            assert i not in changed_index
            input_buf[i] = v
            changed_index.add(i)
        fname = f"id-0-{self._session_id}-{len(self.generated_files)}"
        if seed_info:
            fname += "," + seed_info
        path = os.path.join(self._testcase_dir, fname)
        with open(path, "wb") as f:
            f.write(input_buf)
        self.generated_files.append(fname)
    
    def _handle_solving_status(self, status):
        nested_solved = True
        for s in status:
            if s == SolvingStatus.UNSOLVED_UNINTERESTING_SAT:
                return SolvingStatus.UNSOLVED_UNINTERESTING_SAT
            if s == SolvingStatus.UNSOLVED_PRE_UNSAT:
                return SolvingStatus.UNSOLVED_PRE_UNSAT
            if s == SolvingStatus.UNSOLVED_OPT_UNSAT:
                self.agent.handle_unsat_condition(SolvingStatus.UNSOLVED_OPT_UNSAT)
                return SolvingStatus.UNSOLVED_OPT_UNSAT
            if s == SolvingStatus.UNSOLVED_TIMEOUT:
                self.agent.handle_unsat_condition(SolvingStatus.UNSOLVED_TIMEOUT)
                return SolvingStatus.UNSOLVED_TIMEOUT
            if s == SolvingStatus.UNSOLVED_INVALID_EXPR:
                return SolvingStatus.UNSOLVED_INVALID_EXPR
            if s == SolvingStatus.UNSOLVED_INVALID_MSG:
                return SolvingStatus.UNSOLVED_INVALID_MSG
            if s == SolvingStatus.UNSOLVED_UNINTERESTING_COND:
                return SolvingStatus.UNSOLVED_UNINTERESTING_COND
            if s == SolvingStatus.UNSOLVED_UNKNOWN:
                return SolvingStatus.UNSOLVED_UNKNOWN
            if s == SolvingStatus.SOLVED_OPT_NESTED_UNSAT:
                self.agent.handle_nested_unsat_condition()
                return SolvingStatus.SOLVED_OPT_NESTED_UNSAT
            if s == SolvingStatus.SOLVED_OPT_NESTED_TIMEOUT:
                self.agent.handle_nested_unsat_condition()
                return SolvingStatus.SOLVED_OPT_NESTED_TIMEOUT
            if s != SolvingStatus.SOLVED_NESTED:
                nested_solved = False
        
        if nested_solved:
            return SolvingStatus.SOLVED_NESTED
        assert False, "Unkown solving status"
    
    def _parse_solving_status(self, r):
        status_map = {
            1: SolvingStatus.UNSOLVED_INVALID_MSG,
            2: SolvingStatus.UNSOLVED_UNKNOWN,
            3: SolvingStatus.UNSOLVED_OPT_UNSAT,
            4: SolvingStatus.UNSOLVED_TIMEOUT,
            5: SolvingStatus.SOLVED_NESTED,
            6: SolvingStatus.SOLVED_OPT_NESTED_UNSAT,
            7: SolvingStatus.SOLVED_OPT_NESTED_TIMEOUT,
            8: SolvingStatus.UNSOLVED_UNKNOWN,
        }
        return status_map.get(r, SolvingStatus.UNSOLVED_UNKNOWN)
