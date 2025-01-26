import collections
import copy
import shutil
import symsan
import os
import ctypes
import logging
import time

from defs import *
import utils
from agent import ExploitAgent, ExploreAgent

NEGATIVE_ONE = (1 << 32) - 1

class ConcolicExecutor:
    
    class InvalidGEPMessage(Exception):
        pass
    
    class Timer:
        def reset(self, ts):
            self.proc_start_time = (time.time() * utils.MILLI_SECONDS_SCALE)
            self.proc_end_time = self.proc_start_time
            self.solving_time = 0
            self.timeout = ts

        @property
        def has_execution_timeout(self):
            curr_time = (time.time() * utils.MILLI_SECONDS_SCALE)
            total_time = curr_time - self.proc_start_time
            return total_time >= self.timeout * utils.MILLI_SECONDS_SCALE

    def __init__(self, config, agent, output_dir):
        self.config = config
        self.cmd = config.cmd
        self.agent = agent
        self.timer = ConcolicExecutor.Timer()
        self.logger = logging.getLogger(self.__class__.__qualname__)
        self.logging_level = config.logging_level
        self.generated_files = []
        self.proc_returncode = None
        self.proc_exit_status = None
        # symsan lib instance
        symsan.init(self.cmd[0])
        self._critical_branches_fp = os.path.join(self.config.static_result_folder, "critical_branches.txt")
        if config.initial_policy:
            utils.make_critical_branches_file(config.initial_policy, self._critical_branches_fp)
        self._recipe = collections.defaultdict(list)
        self._processed = set()
        # options
        self.config.defferred_solving_enabled = True if (type(agent) is ExploreAgent) else False
        self._testcase_dir = output_dir
        self._onetime_solving_enabled = True if (type(agent) is ExploitAgent) else False
        self._save_seed_info = True if (type(agent) is ExploreAgent or type(agent) is ExploitAgent) else False
        utils.disable_core_dump()

    @property
    def cur_input(self):
        return os.path.join(self._testcase_dir, ".cur")

    def tear_down(self, deep_clean=False):
        self.proc_exit_status, is_killed = symsan.terminate()
        # TODO: enable this once symsan lib can detect process hang
        # if os.WIFEXITED(self.proc_exit_status):
        #     self.proc_returncode = os.WEXITSTATUS(self.proc_exit_status)
        # if is_killed:
        #     self.proc_returncode = 9
        if deep_clean:
            symsan.destroy()
            if os.path.exists(self._critical_branches_fp):
                os.unlink(self._critical_branches_fp)
        self.timer.proc_end_time = (time.time() * utils.MILLI_SECONDS_SCALE)

    def get_result(self):
        if self.config.defferred_solving_enabled:
            assert not self.generated_files
        if self.timer.has_execution_timeout:
            self.proc_returncode = 9
        return ExecutorResult(self.timer.proc_end_time - self.timer.proc_start_time, 
                                self.timer.solving_time, int(self.agent.min_distance),
                                self.proc_returncode, self.proc_exit_status,self.msg_num, 
                                self.generated_files, None, None)

    def setup(self, input_file, session_id=0):
        self._input_fp = input_file
        self._input_fn = os.path.basename(input_file)
        self._input_dir = os.path.dirname(input_file)
        shutil.copy2(self._input_fp, self.cur_input)
        self.proc_returncode = None
        self.proc_exit_status = None
        self.msg_num = 0
        self._session_id = session_id
        self.generated_files.clear()
        self.agent.reset()
        self.timer.reset(self.config.timeout)

    def run(self, timeout=None):
        self.timer.timeout = timeout if timeout else self.config.timeout
        # create and execute the child symsan process
        logging_level = 1 if self.logging_level == logging.DEBUG else 0
        shoud_trace_bounds = 1 if self.config.gep_solver_enabled else 0
        cmd, stdin, self.input_content = utils.fix_at_file(self.cmd, self.cur_input)
        self.logger.debug(f"Executing {' '.join(cmd)}, "
                          f"stdin={stdin}, "
                          f"input={self.cur_input}, "
                          f"logging_level={logging_level}, "
                          f"bounds={shoud_trace_bounds}")
        if stdin:
            symsan.config("stdin", args=cmd, debug=logging_level, bounds=shoud_trace_bounds)
            symsan.reset_input([self.input_content])
            symsan.run(stdin=self.cur_input)
        else:
            symsan.config(self.cur_input, args=cmd, debug=logging_level, bounds=shoud_trace_bounds)
            symsan.reset_input([self.input_content])
            symsan.run()

    def process_request(self):
        self.timer.solving_time = 0
        should_handle = True
        self.msg_num = 0
        # we don't need to check self.has_terminated here
        # because the pipe might still be readable even if the child process has terminated
        while should_handle and not self.timer.has_execution_timeout:
            try:
                e = symsan.read_event(ctypes.sizeof(pipe_msg), self.config.pipe_timeout)
            except OSError:
                self.logger.info("process_request: pipe reading timeout, stop processing.")
                break
            if len(e) < ctypes.sizeof(pipe_msg):
                self.logger.info("process_request: pipe is broken, stop processing.")
                break
            start_time = (time.time() * utils.MILLI_SECONDS_SCALE)
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
                self._process_memcmp_request(msg)
            elif msg.msg_type == MsgType.fsize_type.value:
                pass
            elif msg.msg_type == MsgType.fini_type.value:
                self.agent.min_distance = min(msg.result, self.agent.min_distance)
            elif msg.msg_type == MsgType.memerr_type.value:
                # indicate seg fault
                self.proc_returncode = 128 + 11
            else:
                self.logger.error(f"process_request: Unknown message type: {msg.msg_type}")
            end_time = (time.time() * utils.MILLI_SECONDS_SCALE)
            self.timer.solving_time += end_time - start_time
            self.msg_num += 1

    def make_testcase(self, target_sa, seed_map):
        self.generated_files.clear()
        if len(self._recipe) == 0:
            return None, None, SolvingStatus.UNSOLVED_RECIPE_LOST
        self._remove_stall_recipe(target_sa)
        if not self._recipe[target_sa]:
            return None, None, SolvingStatus.UNSOLVED_RECIPE_MISS
        tasks, seed_id = self._recipe[target_sa].pop()
        assert seed_id in seed_map
        solution, solving_status = self._solve_cond_tasks(tasks)
        self._finalize_solving(solving_status, solution, target_sa, seed_map[seed_id])
        self._processed.add(tasks)
        if solving_status not in solved_statuses:
            self.logger.debug(f"make_testcase: failed to solve target_sa: {target_sa}")
            return None, seed_map[seed_id], solving_status
        assert len(self.generated_files) == 1
        return self.generated_files[-1], seed_map[seed_id], solving_status

    def _remove_stall_recipe(self, target_sa):
        while self._recipe[target_sa]:
            tasks, _ = self._recipe[target_sa][-1]
            if tasks not in self._processed:
                break
            self._recipe[target_sa].pop()

    def _solve_cond_tasks(self, tasks):
        for task in tasks:
            r, sol = symsan.solve_task(task)
            s = self._parse_solving_status(r)
            if s in solved_statuses:
                # only need one solution
                break
        return sol, s
    
    def _solve_gep_tasks(self, tasks):
        res = []
        for task in tasks:
            r, sol = symsan.solve_task(task)
            s = self._parse_solving_status(r)
            if s in solved_statuses:
                res.append((sol, s))
        return res

    def _finalize_solving(self, status, solution, target_sa, src_seed=None):
        seed_info = ''
        if self._save_seed_info:
            score = self.agent.compute_branch_score()
            seed_info = f"{score}:{target_sa}"
        self._handle_solving_status(status, target_sa)
        if status in solved_statuses:
            input_buf = self._prepare_input_buffer(src_seed)
            self._generate_testcase(solution, seed_info, input_buf)

    def _prepare_input_buffer(self, src_seed):
        if src_seed is not None:
            src_testcase = os.path.join(self._input_dir, src_seed)
            with open(src_testcase, "rb") as f:
                return bytearray(f.read())
        return copy.copy(bytearray(self.input_content))

    def _process_cond_request(self, msg):
        try:
            state_data = symsan.read_event(ctypes.sizeof(mazerunner_msg), self.config.pipe_timeout)
        except OSError:
            self.logger.info("_process_cond_request: pipe reading timeout, skipping.")
            return SolvingStatus.UNSOLVED_TIMEOUT

        if len(state_data) < ctypes.sizeof(mazerunner_msg):
            self.logger.error(f"_process_cond_request: mazerunner_msg too small: {len(state_data)}")
            return SolvingStatus.UNSOLVED_INVALID_MSG

        state_msg = mazerunner_msg.from_buffer_copy(state_data)
        self.agent.handle_new_state(state_msg, msg.result, msg.label)
        reversed_sa = self.agent.curr_state.reversed_sa

        if not msg.label or msg.label in {-1, NEGATIVE_ONE}:
            return SolvingStatus.UNSOLVED_INVALID_MSG

        if not self.agent.is_interesting_branch():
            try:
                symsan.add_constraint(msg.label, msg.result)
            except RuntimeError as e:
                self.logger.error(f"_process_cond_request: failed to add constraint for label {msg.label}. Error log:\n{e}")
                return SolvingStatus.UNSOLVED_INVALID_MSG
            return SolvingStatus.UNSOLVED_UNINTERESTING_COND

        if self.config.defferred_solving_enabled:
            self._remove_stall_recipe(reversed_sa)
            # found one recipe that not been processed,
            # return without constructing a new recipe
            # TODO: bring it back if solver is reliable
            # if self._recipe[reversed_sa]:
            #     try:
            #         symsan.add_constraint(msg.label, msg.result)
            #     except RuntimeError as e:
            #         self.logger.error(f"_process_cond_request: failed to add constraint for label {msg.label}. Error log:\n{e}")
            #         return SolvingStatus.UNSOLVED_INVALID_MSG
            #     return SolvingStatus.UNSOLVED_DEFERRED

        try:
            tasks = tuple(symsan.parse_cond(msg.label, msg.result, msg.flags))
        except RuntimeError as e:
            self.logger.error(f"_process_cond_request: failed to parse cond for label {msg.label}. Error log:\n{e}")
            return SolvingStatus.UNSOLVED_INVALID_MSG

        if self.config.defferred_solving_enabled:
            input_id = utils.get_id_from_fn(self._input_fn)
            self._recipe[reversed_sa].append((tasks, input_id))
            for state in self.agent.episode:
                self._recipe[state.sa].append((tasks, input_id))
            self.logger.debug(f"_process_cond_request: deferred solve protential sa={reversed_sa}")
            return SolvingStatus.UNSOLVED_DEFERRED

        solution, status = self._solve_cond_tasks(tasks)
        self._finalize_solving(status, solution, reversed_sa)
        self._processed.add(tasks)
        self.logger.debug(f"_process_cond_request: label={msg.label}, result={msg.result}, addr={hex(msg.addr)}, solving_status={status}")
        return status

    def _process_gep_request(self, msg):
        try:
            gep_data = symsan.read_event(ctypes.sizeof(gep_msg), self.config.pipe_timeout)
        except OSError:
            self.logger.info("_process_gep_request: pipe reading timeout, skipping.")
            return SolvingStatus.UNSOLVED_TIMEOUT
        if len(gep_data) < ctypes.sizeof(gep_msg):
            self.logger.error(f"__process_gep_request: GEP message too small: {len(gep_data)}")
            return SolvingStatus.UNSOLVED_INVALID_MSG
        
        if msg.label == -1 or msg.label == NEGATIVE_ONE:
            return SolvingStatus.UNSOLVED_INVALID_MSG
        
        gmsg = gep_msg.from_buffer_copy(gep_data)
        if msg.label != gmsg.index_label: # Double check
            self.logger.error(f"__process_gep_request: Incorrect gep msg: {msg.label} "
                              f"vs {gmsg.index_label}")
            raise ConcolicExecutor.InvalidGEPMessage()
        
        if self.config.gep_solver_enabled:
            tasks = tuple(symsan.parse_gep(gmsg.ptr_label, 
                             gmsg.ptr, 
                             gmsg.index_label, 
                             gmsg.index, 
                             gmsg.num_elems, 
                             gmsg.elem_size, 
                             gmsg.current_offset,
                             False))
            gep_res = self._solve_gep_tasks(tasks)
            # we don't have a target_sa for GEP requests, use (0,0,0,0)
            for (solution, status) in gep_res:
                self._finalize_solving(status, solution, (0,0,0,0))
            self._processed.add(tasks)
    
    def _process_memcmp_request(self, msg):
        label = msg.label
        size = msg.result
        try:
            m = symsan.read_event(ctypes.sizeof(memcmp_msg) + size, self.config.pipe_timeout)
        except OSError:
            self.logger.info("_process_memcmp_request: pipe reading timeout, skipping.")
            return
        if len(m) < ctypes.sizeof(memcmp_msg) + size:
            self.logger.error("error reading memcmp msg")
            return
        buf = memcmp_msg.from_buffer_copy(m)
        if buf.label != label:
            self.logger.error("error reading memcmp msg")
            return
        buf.content = m[ctypes.sizeof(memcmp_msg):]
        self.logger.debug(f"memcmp content: {buf.content.hex()}")
        symsan.record_memcmp(label, buf.content)     

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
    
    def _handle_solving_status(self, status, target_sa):
        reversed_action = 1 if target_sa[3] == 0 else 0
        self.agent.create_curr_state(sa=(target_sa[0], target_sa[1], target_sa[2], reversed_action))
        if status == SolvingStatus.UNSOLVED_OPT_UNSAT:
            self.agent.handle_unsat_condition(SolvingStatus.UNSOLVED_OPT_UNSAT)
        if status == SolvingStatus.UNSOLVED_TIMEOUT:
            self.agent.handle_unsat_condition(SolvingStatus.UNSOLVED_TIMEOUT)
        if status == SolvingStatus.SOLVED_OPT_NESTED_UNSAT:
            self.agent.handle_nested_unsat_condition()
        if status == SolvingStatus.SOLVED_OPT_NESTED_TIMEOUT:
            self.agent.handle_nested_unsat_condition()
    
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
