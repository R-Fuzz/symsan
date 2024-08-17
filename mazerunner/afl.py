import ast
import copy
import logging
import functools
import math
import os
import pickle
import random
import re
import shutil
import sys
import time

import utils
import minimizer
import executor
import executor_symsan_lib
from agent import Agent, ExploreAgent, ExploitAgent, LazyAgent
from seed_scheduler import FILOScheduler, PrioritySamplingScheduler, RealTimePriorityScheduler
from defs import SolvingStatus

WAITING_INTERVAL = 5

def get_score(testcase):
    # New coverage is the best
    score1 = testcase.endswith("+cov")
    # NOTE: seed files are not marked with "+cov"
    # even though it contains new coverage
    score2 = "orig:" in testcase
    # Smaller size is better
    score3 = -os.path.getsize(testcase)
    # Since name contains id, so later generated one will be chosen earlier
    score4 = testcase
    return (score1, score2, score3, score4)

def testcase_compare(a, b, seed_dir):
    a_score = get_score(os.path.join(seed_dir, a))
    b_score = get_score(os.path.join(seed_dir, b))
    return 1 if a_score > b_score else -1

def get_afl_cmd(fuzzer_stats):
    while not os.path.exists(fuzzer_stats):
        time.sleep(1)
    with open(fuzzer_stats) as f:
        for l in f:
            if l.startswith("command_line"):
                # format is "command_line: [cmd]"
                return l.partition(':')[-1].strip().split()

class MazerunnerState:
    def __init__(self, timeout):
        self.timeout = timeout
        self.start_ts = time.time()
        self.end_ts = None
        self.ce_time = 0
        self.synced = set()
        self.hang = set()
        self.processed = {}
        self.target_triggered = False
        self.testscases_md5 = set()
        self.index = 0
        self.execs = 0
        self.num_crash_reports = 0
        self.seed_queue = []
        self.state_seed_mapping = {}
        self._best_seed_info = [None, float("inf"), False] # filename, distance, is_new
        self.bitmap = []

    def __setstate__(self, dict):
        self.__dict__ = dict

    def __getstate__(self):
        return self.__dict__

    @property
    def curr_ts(self):
        return int(time.time() * utils.MILLI_SECONDS_SCALE - self.start_ts * utils.MILLI_SECONDS_SCALE)
    
    @property
    def best_seed(self):
        return self._best_seed_info[0]

    @property
    def min_distance(self):
        return self._best_seed_info[1]
    
    @property
    def target_reached(self):
        return self._best_seed_info[0] is not None and self._best_seed_info[1] == 0

    def update_best_seed(self, filename, distance):
        self._best_seed_info[0] = filename
        self._best_seed_info[1] = int(distance)
    
    def read_bitmap(self, bitmap):
        self.bitmap = bitmap
    
    def create_bitmap(self, size):
        self.bitmap = [0] * size

    def increase_timeout(self, logger, max_timeout):
        old_timeout = self.timeout
        if self.timeout < max_timeout:
            t = self.timeout * 2
            self.timeout = t if t < max_timeout else max_timeout
            logger.info("Increase timeout %d -> %d" % (old_timeout, self.timeout))
            return True
        else:
            logger.warn("Hit the maximum timeout")
            return False

    def tick(self):
        old_index = self.index
        self.index += 1
        return old_index

class Mazerunner:
    def __init__(self, config, shared_state=None, seed_scheduler=None):
        self.config = config
        self.cmd = config.cmd
        self.output = config.output_dir
        self.my_dir = config.mazerunner_dir
        self._make_dirs()
        # Concolic Executors
        self.directed_ce = None
        self.exploit_ce = None

        if shared_state:
            self.state = shared_state
        else:
            self._import_state()
        if seed_scheduler:
            self.seed_scheduler = seed_scheduler
        else:
            self.seed_scheduler = FILOScheduler(self.state.seed_queue)
        self.logger = logging.getLogger(self.__class__.__qualname__)
        self.afl = config.afl_dir
        if self.afl:
            self.afl_cmd, afl_path, qemu_mode = self._parse_fuzzer_stats()
            self.minimizer = minimizer.TestcaseMinimizer(
                self.afl_cmd, afl_path, self.afl_dir, qemu_mode, self.state)
        else:
            self.minimizer = minimizer.TestcaseMinimizer(
                None, None, self.afl_dir, None, self.state)

    @property
    def afl_dir(self):
        if not self.afl:
            return ''
        return os.path.join(self.output, self.afl)

    @property
    def afl_queue(self):
        if not self.afl_dir:
            return ''
        return os.path.join(self.afl_dir, "queue")

    @property
    def my_queue(self):
        return os.path.join(self.my_dir, "seeds")

    @property
    def my_sync_queue(self):
        return os.path.join(self.my_dir, "queue")

    @property
    def my_hangs(self):
        return os.path.join(self.my_dir, "hangs")

    @property
    def my_errors(self):
        return os.path.join(self.my_dir, "crashes")

    @property
    def my_generations(self):
        return os.path.join(self.my_dir, "generated_inputs")

    @property
    def metadata(self):
        return os.path.join(self.my_dir, ".metadata")

    @property
    def bitmap(self):
        return os.path.join(self.my_dir, "bitmap")

    @property
    def dictionary(self):
        return os.path.join(self.my_dir, "dictionary")

    def run(self):
        self._run()

    def run_file(self, fn):
        self.state.execs += 1
        fp = os.path.join(self.my_queue, fn)
        self.logger.info("Run input: %s" % fn)
        symsan_res = self.run_target(fp)
        fp = self.update_seed_info(fp, symsan_res)
        self.handle_return_status(symsan_res, fp)
        self.update_timmer(symsan_res)
        self.sync_seed_queue(fp, symsan_res)
        # CVE might be reproduced before reaching the target
        distance_threshold = symsan_res.distance <= self.config.bug_trigger_distance
        execution_threshold = self.state.execs > 1000
        is_distance_zero = symsan_res.distance == 0
        shoud_trigger_crash = (distance_threshold and execution_threshold) or is_distance_zero
        if shoud_trigger_crash:
            self.trigger_crash(fp)
        return fp

    def run_target(self, testcase):
        self.directed_ce.setup(testcase, len(self.state.processed))
        self.directed_ce.run(self.state.timeout)
        try:
            self.directed_ce.process_request()
        finally:
            self.directed_ce.tear_down(deep_clean=False)
        symsan_res = self.directed_ce.get_result()
        self.logger.info(
            f"Total={symsan_res.total_time:.3f}ms, "
            f"Emulation={symsan_res.emulation_time:.3f}ms, "
            f"Solver={symsan_res.solving_time:.3f}ms, "
            f"Return={symsan_res.returncode}, "
            f"Distance={symsan_res.distance}, "
            f"Episode_length={len(self.agent.episode)}, "
            f"Msg_count={symsan_res.symsan_msg_num}. "
        )
        return symsan_res
    
    def trigger_crash(self, protential_seed):
        if self.exploit_ce is None:
            return
        self.logger.info(f"Try to trigger crash from {os.path.basename(protential_seed)}")
        # rerun the testcase with GEP solver
        self.exploit_ce.config.gep_solver_enabled = True
        self.exploit_ce.setup(protential_seed)
        self.exploit_ce.run(self.state.timeout)
        try:
            self.exploit_ce.process_request()
        finally:
            self.exploit_ce.tear_down(deep_clean=False)
        self.exploit_ce.config.gep_solver_enabled = False
        # find crashing input in the generation directory
        res = self.exploit_ce.get_result()
        for t in res.generated_testcases:
            testcase = os.path.join(self.my_generations, t)
            if not self.minimizer.is_new_file(testcase):
                os.unlink(testcase)
                continue
            # TODO: For performance reasons, instead of concolic execution, 
            # run ASAN, UBSAN or other sanitizer instrumented binary to confirm the crash
            self.exploit_ce.setup(testcase)
            self.exploit_ce.run(self.state.timeout)
            try:
                self.exploit_ce.process_request()
            finally:
                self.exploit_ce.tear_down(deep_clean=False)
            r = self.exploit_ce.get_result()
            # move testcase to the queue directory
            index = self.state.tick()
            src_id = utils.get_id_from_fn(os.path.basename(protential_seed))
            t_fn = f"id:{index:06},src:{src_id:06},ts:{self.state.curr_ts},execs:{self.state.execs}"
            q_fp = os.path.join(self.my_queue, t_fn)
            shutil.move(testcase, q_fp)
            fp = self.update_seed_info(q_fp, r)
            self.determine_crash(r, fp)
    
    def sync_seed_queue(self, fp, res):
        self._sync_seed_queue(fp, res)

    def update_seed_info(self, fp, res):
        new_fp = fp
        fn = os.path.basename(fp)
        if 'dis:' not in fn:
            new_fp = fp + f",dis:{res.distance}"
        if 'time:' in fn and 'ts:' not in fn:
            new_fp = new_fp.replace('time:', 'ts:')
        if new_fp != fp:
            shutil.move(fp, new_fp)
        sync_fp = os.path.join(self.my_sync_queue, os.path.basename(new_fp))
        try:
            os.link(new_fp, sync_fp)
        except FileExistsError:
            os.unlink(sync_fp)
            os.link(new_fp, sync_fp)
        except FileNotFoundError:
            pass
        except:
            shutil.copy2(new_fp, sync_fp)
        return new_fp

    def update_timmer(self, res):
        try:
            self.state.ce_time += res.total_time / utils.MILLI_SECONDS_SCALE
        except AttributeError:
            self.state.ce_time = res.total_time / utils.MILLI_SECONDS_SCALE

    def sync_from_afl(self, reversed_order=True, need_sort=False):
        files = []
        for name in os.listdir(self.afl_queue):
            path = os.path.join(self.afl_queue, name)
            if os.path.isfile(path) and not name in self.state.synced:
                index = self.state.tick()
                src_id = utils.get_id_from_fn(name)
                new_name = f"id:{index:06},src:{src_id:06},sync:{self.afl},ts:{self.state.curr_ts}"
                shutil.copy2(path, os.path.join(self.my_queue, new_name))
                files.append(new_name)
                self.state.synced.add(name)
        if need_sort:
            return sorted(files,
                        key=functools.cmp_to_key(
                            (lambda a, b: testcase_compare(a, b, self.afl_queue))),
                        reverse=reversed_order)
        return files

    def sync_from_seeds_dir(self):
        files = []
        for name in os.listdir(self.config.initial_seed_dir):
            path = os.path.join(self.config.initial_seed_dir, name)
            if os.path.isfile(path) and not name in self.state.synced:
                index = self.state.tick()
                new_name = f"id:{index:06},src:{name},sync:seed_dir,ts:{self.state.curr_ts}"
                shutil.copy2(path, os.path.join(self.my_queue, new_name))
                files.append(new_name)
                self.state.synced.add(name)
        return files

    def sync_from_either(self, need_sort=False):
        if self.afl_queue and os.path.exists(self.afl_queue):
            return self.sync_from_afl(need_sort)
        else:
            return self.sync_from_seeds_dir()

    def handle_return_status(self, result, fp):
        msg_count = result.symsan_msg_num
        if msg_count == 0:
            self.logger.warning("No message is received from the symsan process")
        trace_len = len(self.agent.episode)
        if trace_len == 0:
            self.logger.warning("No episode infomation during the execution")
        # check hangs
        fn = os.path.basename(fp)
        if result.returncode in [124, 9]: # killed
            shutil.copy2(fp, os.path.join(self.my_hangs, fn))
            self.state.hang.add(fn)

        self.determine_crash(result, fp)

    def handle_hang_files(self):
        if len(self.state.hang) > self.config.min_hang_files:
            if self.state.increase_timeout(self.logger, self.config.max_timeout):
                for fn in self.state.hang:
                    self.logger.info(f"Adding hang file {fn} back to queue")
                    d = utils.get_distance_from_fn(fn)
                    d = self.config.max_distance if d is None else d
                    self.seed_scheduler.put(fn, (d, ''), from_fuzzer=True)
                    seed_id = int(utils.get_id_from_fn(fn))
                    if seed_id in self.state.processed: del self.state.processed[seed_id]
                self.state.hang.clear()

    '''    
    Did we crash? The following are coming from AFL++'s doc.
    In a normal case, (abort or segfault) WIFSIGNALED(retcode) will be set.
    However, MSAN and LSAN use a special exit code.
    On top, a user may specify a custom AFL_CRASH_EXITCODE.
    '''
    # TODO: handle MSAN, LSAN and custom exit codes
    def determine_crash(self, result, testcase):
        ret_code = result.returncode
        exit_status = result.exit_status
        sig_terminated = exit_status and os.WIFSIGNALED(exit_status)
        if (sig_terminated and ret_code != 9) or (ret_code in {128 + 11, 11, 128 + 6, 6}):
            fn = os.path.basename(testcase)
            self.logger.info(f"crash triggered at {fn}, ret_code={ret_code}")
            shutil.copy2(testcase, os.path.join(self.my_errors, fn))
            self.state.num_crash_reports += 1
            if result.distance == 0:
                io = result.stderr
                self._report_crash(testcase, io)

    def cleanup(self):
        self.minimizer.cleanup()
        if not self.directed_ce is None:
            self.directed_ce.tear_down(deep_clean=True)
        if not self.exploit_ce is None:
            self.exploit_ce.tear_down(deep_clean=True)

    def export_state(self):
        self.state.end_ts = time.time()
        with open(self.metadata, "wb") as fp:
            pickle.dump(self.state, fp, protocol=pickle.HIGHEST_PROTOCOL)
        self.agent.save_model()

    def _make_dirs(self):
        utils.mkdir(self.my_queue)
        utils.mkdir(self.my_sync_queue)
        utils.mkdir(self.my_hangs)
        utils.mkdir(self.my_errors)
        utils.mkdir(self.my_generations)

    # Returns afl's cmd, afl_path, qemu_mode, cmd will be used in minimizer
    def _parse_fuzzer_stats(self):
        cmd = get_afl_cmd(os.path.join(self.afl_dir, "fuzzer_stats"))
        assert cmd is not None
        index = cmd.index("--")
        return cmd[index+1:], os.path.dirname(cmd[0]), '-Q' in cmd

    def _import_state(self):
        if os.path.exists(self.metadata):
            with open(self.metadata, "rb") as f:
                self.state = pickle.load(f)
        else:
            self.state = MazerunnerState(self.config.timeout)

    def _report_crash(self, fp, log):
        self.state.target_triggered = True
        # TODO: email the crash report

class SymSanExecutor(Mazerunner):
    def __init__(self, config, shared_state=None, seed_scheduler=None, model=None):
        super().__init__(config, shared_state, seed_scheduler)
        self.agent = Agent(config, model)
        if config.use_builtin_solver:
            self.directed_ce = executor.ConcolicExecutor(config, self.agent, self.my_generations)
        else:
            self.directed_ce = executor_symsan_lib.ConcolicExecutor(config, self.agent, self.my_generations)

    def _sync_seed_queue(self, fp, res):
        old_idx = self.state.index
        fn = os.path.basename(fp)
        num_testcase = 0
        for t in res.generated_testcases:
            num_testcase += 1
            testcase = os.path.join(self.my_generations, t)
            if not self.minimizer.is_new_file(testcase):
                os.unlink(testcase)
                continue
            index = self.state.tick()
            src_id = utils.get_id_from_fn(fn)
            q_fn = f"id:{index:06},src:{src_id:06},ts:{self.state.curr_ts}"
            q_fp = os.path.join(self.my_queue, q_fn)
            shutil.move(testcase, q_fp)
        self.logger.info("Generated %d testcases" % num_testcase)
        self.logger.info("%d testcases are new" % (self.state.index - old_idx))

    def _run(self):
        files = self.sync_from_either(need_sort=True)
        if not files:
            self.logger.info("Sleeping for getting seeds from Fuzzer")
            time.sleep(WAITING_INTERVAL)
            return
        for fn in files:
            self.run_file(fn)

class ExploreExecutor(Mazerunner):
    def __init__(self, config, shared_state=None, seed_scheduler=None, model=None):
        super().__init__(config, shared_state, seed_scheduler)
        self.agent = ExploreAgent(config, model)
        crash_config = copy.copy(config)
        lazy_agent = LazyAgent(crash_config)
        if config.use_builtin_solver:
            self.directed_ce = executor.ConcolicExecutor(config, self.agent, self.my_generations)
            self.exploit_ce = executor.ConcolicExecutor(crash_config, lazy_agent, self.my_generations)
        else:
            self.directed_ce = executor_symsan_lib.ConcolicExecutor(config, self.agent, self.my_generations)
            self.exploit_ce = executor_symsan_lib.ConcolicExecutor(crash_config, lazy_agent, self.my_generations)

    def _sync_seed_queue(self, fp, res):
        fn = os.path.basename(fp)
        if self.minimizer.has_closer_distance(res.distance, fn):
            self.logger.info(f"Explore agent found closer distance={res.distance}")
        self.agent.save_trace(fn)
        
        if self.config.defferred_solving_enabled:
            for s in self.agent.episode:
                self.seed_scheduler.put(fn, (res.distance, s.sa))
            return
        
        self.logger.info("Generated %d testcases" % len(res.generated_testcases))
        for t in res.generated_testcases:
            self._triage_testcase(t, fn, save_queue=True)
    
    def _triage_testcase(self, t, src_fn, save_queue):
        if t is None:
            return None
        testcase = os.path.join(self.my_generations, t)
        if not self.minimizer.is_new_file(testcase):
            os.unlink(testcase)
            return None
        
        index = self.state.tick()
        src_id = utils.get_id_from_fn(src_fn)
        t_fn = f"id:{index:06},src:{src_id:06},ts:{self.state.curr_ts},execs:{self.state.execs}"
        q_fp = os.path.join(self.my_queue, t_fn)
        shutil.move(testcase, q_fp)
        info = t.partition(',')[-1].strip().split(':')
        t_d = int(info[0]) if info and info[0] else self.config.max_distance
        t_sa = info[1] if info and info[1] else ''
        t_sa = ast.literal_eval(t_sa)
        if save_queue:
            self.seed_scheduler.put(t_fn, (t_d, t_sa))
        return t_fn

    def _get_tc_from_sa(self, target_sa):
        if target_sa is None:
            return None
        
        t, src, status = self.directed_ce.make_testcase(target_sa, self.state.processed)
        if status == SolvingStatus.UNSOLVED_RECIPE_MISS:
            self.logger.info(f"No valid recipe for {target_sa}. Skip...")
            return None
        if status == SolvingStatus.UNSOLVED_RECIPE_LOST:
            self.logger.warning(f"Recipe lost when trying to solve {target_sa}. "
                                f"Reset scheduler and processed seeds.")
            self.state.processed.clear()
            self.agent.model.rebuild_targets(target_sa)
            return None
        
        if t is None:
            self.logger.info(f"Cannot solve target_sa={target_sa}, status={status}. Skip...")
            return None
        
        next_seed = self._triage_testcase(t, src, save_queue=False)
        if not next_seed is None:
            seed_id = int(utils.get_id_from_fn(next_seed))
            assert seed_id not in self.state.processed
            self.logger.debug(f"Generated {next_seed} for {target_sa}, status={status}.")
        return next_seed

    def _run_seed(self, next_seed):
        fp = self.run_file(next_seed)
        self.agent.train()
        seed_id = int(utils.get_id_from_fn(next_seed))
        self.state.processed[seed_id] = os.path.basename(fp)

    def _run_defferred_gen(self):
        while True:
            fuzzer_sync_seed, target_sa = self.seed_scheduler.pop()
            if fuzzer_sync_seed is not None and target_sa is None:
                next_seed = fuzzer_sync_seed
                break
            
            if target_sa is None:
                if self.state.hang:
                    self.handle_hang_files()
                    continue
                self.logger.info("Sleeping for getting seeds from Fuzzer")
                time.sleep(WAITING_INTERVAL)
                return
            
            new_seed = self._get_tc_from_sa(target_sa)
            if new_seed is not None:
                next_seed = new_seed
                break

        self._run_seed(next_seed)

    def _run_realtime_gen(self):
        while True:
            next_seed, _ = self.seed_scheduler.pop()
            # Nothing in the queue
            if next_seed is None:
                if self.state.hang:
                    self.handle_hang_files()
                    continue
                self.logger.info("Sleeping for getting seeds from Fuzzer")
                time.sleep(WAITING_INTERVAL)
                return
            seed_id = int(utils.get_id_from_fn(next_seed))
            if seed_id in self.state.processed:
                self.logger.debug(f"Skip. {self.state.processed[seed_id]} already processed")
                continue
            break
        
        self._run_seed(next_seed)

    def _run(self):
        if self.config.defferred_solving_enabled:
            self._run_defferred_gen()
        else:
            self._run_realtime_gen()

class ExploitExecutor(Mazerunner):
    def __init__(self, config, shared_state=None, seed_scheduler=None, model=None):
        super().__init__(config, shared_state, seed_scheduler)
        self.agent = ExploitAgent(config, model)
        self._cur_input = os.path.join(self.my_generations, ".cur_input")
        crash_config = copy.copy(config)
        lazy_agent = LazyAgent(crash_config)
        if config.use_builtin_solver:
            self.directed_ce = executor.ConcolicExecutor(config, self.agent, self.my_generations)
            self.exploit_ce = executor.ConcolicExecutor(crash_config, lazy_agent, self.my_generations)
        else:
            self.directed_ce = executor_symsan_lib.ConcolicExecutor(config, self.agent, self.my_generations)
            self.exploit_ce = executor_symsan_lib.ConcolicExecutor(crash_config, lazy_agent, self.my_generations)
        
    def run_target(self, testcase) -> executor.ExecutorResult:
        shutil.copy2(testcase, self._cur_input)
        total_time = emulation_time = solving_time = 0
        has_reached_max_flip_num = lambda: len(self.agent.all_targets) >= self.config.max_flip_num
        while not has_reached_max_flip_num():
            try:
                self.directed_ce.setup(self._cur_input, len(self.state.processed))
                self.directed_ce.run(self.state.timeout)
                self.directed_ce.process_request()
                # (1) symsan proc has nomarlly terminated and cur_input is on policy
                # (2) the solver is not able to solve the branch condition
                if len(self.directed_ce.solver.generated_files) == 0:
                    break
                assert len(self.directed_ce.solver.generated_files) == 1
                fp = os.path.join(self.my_generations, self.directed_ce.solver.generated_files[0])
                shutil.move(fp, self._cur_input)
            finally:
                self.directed_ce.tear_down(deep_clean=False)
                symsan_res = self.directed_ce.get_result()
                total_time += symsan_res.total_time
                emulation_time += symsan_res.emulation_time
                solving_time += symsan_res.solving_time
        symsan_res.update_time(total_time, solving_time)
        symsan_res.flipped_times = len(self.agent.all_targets)
        self.logger.info(
            f"Total={total_time:.3f}ms, "
            f"Emulation={emulation_time:.3f}ms, "
            f"Solver={solving_time:.3f}ms, "
            f"Return={symsan_res.returncode}, "
            f"Distance={symsan_res.distance}, "
            f"Episode_length={len(self.agent.episode)}, "
            f"Msg_count={symsan_res.symsan_msg_num}, "
            f"flipped={symsan_res.flipped_times} times. "
        )
        # target might still be reachable due to hitting max_flip_num
        if self.agent.target[0] and not has_reached_max_flip_num():
            self.logger.debug(f"Did not reach the target {self.agent.target[0]}")
        self.agent.clear_targets()
        return symsan_res

    def _sync_seed_queue(self, fp, res):
        if res.flipped_times == 0:
            return
        if not self.minimizer.is_new_file(self._cur_input):
            return
        index = self.state.tick()
        target = utils.get_id_from_fn(os.path.basename(fp))
        dst_fn = f"id:{index:06},src:{target:06},execs:{self.state.execs},ts:{self.state.curr_ts},dis:{res.distance}"
        self.logger.debug(f"save testcase: {dst_fn}")
        dst_fp = os.path.join(self.my_queue, dst_fn)
        shutil.copy2(self._cur_input, dst_fp)
        self.agent.save_trace(dst_fn)
        self.state.processed[index] = dst_fn
        is_closer = self.minimizer.has_closer_distance(res.distance, dst_fn)
        if is_closer:
            self.seed_scheduler.put(dst_fn, (res.distance, ''))
            self.logger.info(f"Exploit agent found closer distance={res.distance}, ts={self.state.curr_ts}")

    def _run(self):
        next_seed = self.seed_scheduler.pop()
        if next_seed is not None:
            self.run_file(next_seed)
            self.agent.train()
        else:
            self.logger.info("Sleeping for getting seeds from Fuzzer")
            time.sleep(WAITING_INTERVAL)

class RecordExecutor(Mazerunner):
    def __init__(self, config, shared_state=None, record_enabled=True, seed_scheduler=None, model=None):
        super().__init__(config, shared_state, seed_scheduler)
        self.is_hybrid_mode = shared_state is not None
        self.record_enabled = record_enabled
        if self.record_enabled:
            self.agent = LazyAgent(config)
            if config.use_builtin_solver:
                self.directed_ce = executor.ConcolicExecutor(config, self.agent, self.my_generations)
            else:
                self.directed_ce = executor_symsan_lib.ConcolicExecutor(config, self.agent, self.my_generations)

    def _sync_seed_queue(self, fp, res):
        fn = os.path.basename(fp)
        if self.minimizer.has_closer_distance(res.distance, fn):
            self.logger.info(f"Fuzzer found closer distance={res.distance}")
        self.agent.save_trace(fn)

    def update_seed_queue(self, fn):
        d = utils.get_distance_from_fn(fn)
        d = 0 if d is None else d
        self.seed_scheduler.put(fn, [d, ''], from_fuzzer=True)

    def _run(self):
        files = self.sync_from_either()
        if self.is_hybrid_mode and not files and not self.state.seed_queue:
            self.handle_hang_files()
        for fn in files:
            if self.record_enabled:
                fp = self.run_file(fn)
                fn = os.path.basename(fp)
            if self.is_hybrid_mode:
                self.update_seed_queue(fn)

class ReplayExecutor(Mazerunner):
    def __init__(self, config, shared_state=None, seed_scheduler=None, model=None):
        super().__init__(config, shared_state) # replay does not need seed_scheduler
        self.agent = Agent(config, model)

    def _sync_seed_queue(self, fn, res):
        pass

    def offline_learning(self):
        iteration_num = 1
        files = os.listdir(self.agent.my_traces)
        if not files:
            return
        if len(files) > 10:
            iteration_num = int(len(files) / 10)
        for _ in range(iteration_num):
            picked_fp = os.path.join(self.agent.my_traces, random.choice(files))
            self.agent.replay_log(picked_fp)

    def _run(self):
        files = os.listdir(self.agent.my_traces)
        round_num = self.state.tick()
        self.logger.info(f"{round_num}th round(s) of offline learning")
        for fn in files:
            fp = os.path.join(self.agent.my_traces, fn)
            self.agent.replay_log(fp)
            self.state.execs += 1
            if self.state.execs % self.config.save_frequency == 0:
                self.export_state()

class RLExecutor():
    def __init__(self, config, agent_type):
        self.config = config
        self.logger = logging.getLogger(self.__class__.__qualname__)
        self.my_dir = config.mazerunner_dir
        self.memory_termination_event = None
        self.disk_termination_event = None
        # All executors share the same state and All agents share the same model
        self._import_state()
        self.replayer = ReplayExecutor(config, self.state)
        if agent_type == "explore":
            self.config.use_ordered_dict = True
        self.model = Agent.create_model(self.config)
        if agent_type == "exploit":
            self.seed_scheduler = PrioritySamplingScheduler(self.state.seed_queue)
            self.concolic_executor = ExploitExecutor(
                config,
                shared_state=self.state,
                seed_scheduler=self.seed_scheduler,
                model=self.model
            )
            self.synchronizer = RecordExecutor(
                config,
                shared_state=self.state,
                record_enabled=True,
                seed_scheduler=self.seed_scheduler,
                model=self.model
            )
        elif agent_type == "explore":
            self.seed_scheduler = RealTimePriorityScheduler(
                self.state.state_seed_mapping,
                self.model.q_table
            )
            self.concolic_executor = ExploreExecutor(
                config,
                shared_state=self.state,
                seed_scheduler=self.seed_scheduler,
                model=self.model
            )
            self.synchronizer = RecordExecutor(
                config,
                shared_state=self.state,
                record_enabled=False,
                seed_scheduler=self.seed_scheduler,
                model=self.model
            )
        else:
            raise NotImplementedError()

    @property
    def metadata(self):
        return os.path.join(self.my_dir, ".metadata")

    @property
    def reached_resource_limit(self):
        if self.memory_termination_event and self.disk_termination_event:
            return self.memory_termination_event.is_set() or self.disk_termination_event.is_set()
        return False

    def run(self):
        while True:
            if self.reached_resource_limit:    
                self.logger.error("Reached resource limit, exiting...")
                break
            if self.state.target_triggered and self.config.target_triggered_exit:
                self.logger.info("Target triggered, exiting...")
                break
            if self.state.target_reached and self.config.target_reached_exit:
                self.logger.info("Target reached, exiting...")
                break
            
            if self.config.save_frequency > 0:
                if self.state.execs % math.ceil(self.config.save_frequency) == 0:
                    self._export_state()

            if self.config.sync_frequency > 0:
                if (self.seed_scheduler.is_empty() or 
                    self.state.execs % math.ceil(self.config.sync_frequency) == 0):
                    self.synchronizer.run()

            if self.config.replay_frequency > 0:
                if (self.state.execs > 0 and 
                    self.state.execs % math.ceil(self.config.replay_frequency) == 0):
                    repetition = math.ceil(1 / self.config.replay_frequency)
                    for _ in range(repetition):
                        self.replayer.offline_learning()
            self.concolic_executor.run()

    def cleanup(self):
        self._export_state()
        self.replayer.cleanup()
        self.concolic_executor.cleanup()
        self.synchronizer.cleanup()

    def _import_state(self):
        if os.path.exists(self.metadata):
            with open(self.metadata, "rb") as f:
                self.state = pickle.load(f)
        else:
            self.state = MazerunnerState(self.config.timeout)

    def _export_state(self):
        self.state.end_ts = time.time()
        with open(self.metadata, "wb") as fp:
            pickle.dump(self.state, fp, protocol=pickle.HIGHEST_PROTOCOL)
        self.model.save()
