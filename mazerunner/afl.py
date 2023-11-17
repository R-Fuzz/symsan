import atexit
import logging
import functools
import os
import pickle
import random
import re
import shutil
import time
import heapq
import numpy as np

from agent import Agent, ExploreAgent, ExploitAgent, RecordAgent
from executor import SymSanExecutor
from model import RLModel
import minimizer
import utils

WAITING_INTERVAL = 5

class SeedScheduler:
    def __init__(self, q):
        self._seed_queue = q
        self._max = float('-inf')
        self._weights_need_update = True

    def _update_weights(self):
        if not self._seed_queue:
            self._weights = []
            return
        min_priority = self._seed_queue[0][0]
        max_priority = self._max
        mid_val = (min_priority + max_priority) / 2
        self._weights = [self._logistic_function(priority, 1, mid_val) for priority, _ in self._seed_queue]
        self._weights /= np.sum(self._weights)
        self._weights_need_update = False

    def _logistic_function(self, x, k, mid):
        return 1 / (1 + np.exp(k * (x - mid)))

    def put(self, fn, p):
        if not fn:
            raise ValueError("Invalid seed")
        priority = int(p/1000)
        heapq.heappush(self._seed_queue, (priority, fn))
        self._max = max(self._max, priority)
        self._weights_need_update = True

    def pop(self):
        if not self._seed_queue:
            return None
        p_to_remove, removed_seed = heapq.heappop(self._seed_queue)
        if p_to_remove == self._max and self._seed_queue:
            self._max = max(self._seed_queue, key=lambda x: x[0])[0]
        self._weights_need_update = True
        return removed_seed

    def remove(self, fn):
        if not self._seed_queue:
            return
        index_to_remove = None
        p_to_remove = float('-inf')
        for i, (p, seed_fn) in enumerate(self._seed_queue):
            if seed_fn == fn:
                index_to_remove = i
                p_to_remove = p
                break
        if index_to_remove is not None:
            self._seed_queue.pop(index_to_remove)
            heapq.heapify(self._seed_queue)
            if self._seed_queue and self._max == p_to_remove:
                self._max = max(self._seed_queue, key=lambda x: x[0])[0]
            if not self._seed_queue:
                self._max = float('-inf')
            self._weights_need_update = True

    def pick(self):
        if not self._seed_queue:
            return None
        if len(self._seed_queue) == 1:
            return self._seed_queue[0][1]
        if self._weights_need_update:
            self._update_weights()
        chosen_index = np.random.choice(range(len(self._seed_queue)), p=self._weights)
        return self._seed_queue[chosen_index][1]

# 'id:xxxx,src:yyyyy' -> 'id:xxxx'
# 'id-xxx-xxxxxx-xx,src:yy-yyyyyy-yy' -> 'id-xxx-xxxxxx-xx'
# 'idxxxxxxxx' -> 'idxxxxxxxx'
def get_id_from_fn(s):
    s_with_removed_sync = re.sub(r'(,?sync:[^,]*)', '', s)
    s_with_removed_dis = re.sub(r'(,?dis:[^,]*)', '', s_with_removed_sync)
    match = re.compile(r'id[^,]*').findall(s_with_removed_dis)
    if not match:
        return s_with_removed_dis
    if 'id:' in match[0] and len(match[0]) >= len("id:......"):
        return match[0][len("id:"):len("id:......")]
    return match[0]

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
                return l.lstrip('command_line:').strip().split()

class MazerunnerState:
    def __init__(self, timeout):
        self.timeout = timeout
        self.start_ts = time.time()
        self.end_ts = None
        self.synced = set()
        self.hang = set()
        self.processed = set()
        self.crashes = set()
        self.testscases_md5 = set()
        self.index = 0
        self.execs = 0
        self.num_error_reports = 0
        self.num_crash_reports = 0
        self.seed_queue = []
        self._best_seed_info = [None, float("inf"), False] # filename, distance, is_new

    def __setstate__(self, dict):
        self.__dict__ = dict

    def __getstate__(self):
        return self.__dict__

    @property
    def processed_num(self):
        return len(self.processed)

    @property
    def best_seed(self):
        return self._best_seed_info[0]

    @property
    def min_distance(self):
        return self._best_seed_info[1]

    def update_best_seed(self, filename, distance):
        self._best_seed_info[0] = filename
        self._best_seed_info[1] = int(distance)

    def increase_timeout(self, logger, max_timeout):
        old_timeout = self.timeout
        if self.timeout < max_timeout:
            t = self.timeout * 2
            self.timeout = t if t < max_timeout else max_timeout
            logger.info("Increase timeout %d -> %d" % (old_timeout, self.timeout))
            self.processed = self.processed - self.hang
            return True
        else:
            logger.warn("Hit the maximum timeout")
            return False

    def tick(self):
        old_index = self.index
        self.index += 1
        return old_index

class Mazerunner:
    def __init__(self, config, shared_state=None):
        self.config = config
        # check_resource_limit returns a flag that controlled by another monitor thread
        self.check_resource_limit = lambda: False
        self.cmd = config.cmd
        self.output = config.output_dir
        self.my_dir = config.mazerunner_dir
        self.filename = ".cur_input"
        self._make_dirs()
        if shared_state:
            self.state = shared_state
        else:
            self._import_state()
            self.seed_scheduler = SeedScheduler(self.state.seed_queue)
        self._setup_logger(config.logging_level)
        self.afl = config.afl_dir
        if self.afl:
            self.afl_cmd, afl_path, qemu_mode = self._parse_fuzzer_stats()
            self.minimizer = minimizer.TestcaseMinimizer(
                self.afl_cmd, afl_path, self.output, qemu_mode, self.state)
        else:
            self.minimizer = minimizer.TestcaseMinimizer(
                None, None, self.output, None, self.state)

    @property
    def reached_resource_limit(self):
        return self.check_resource_limit()

    @property
    def cur_input(self):
        return os.path.realpath(os.path.join(self.my_dir, self.filename))

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
        return os.path.join(self.my_dir, "queue")

    @property
    def my_hangs(self):
        return os.path.join(self.my_dir, "hangs")

    @property
    def my_errors(self):
        return os.path.join(self.my_dir, "errors")

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

    def run(self, run_once=False):
        while not self.reached_resource_limit:
            self._run()
            if run_once:
                break
            if self.state.execs % self.config.save_frequency == 0:
                self.export_state()
        if not run_once:
            self.logger.error("Reached resource limit, exiting...")

    def run_file(self, fn):
        self.state.execs += 1
        # copy the test case
        fp = os.path.join(self.my_generations, fn)
        shutil.copy2(fp, self.cur_input)
        self.logger.info("Run input: %s" % fn)
        symsan_res = self.run_target()
        fp = self.update_seed_info(fp, symsan_res)
        self.handle_return_status(symsan_res, fp)
        self.update_timmer(symsan_res)
        self.sync_back_if_interesting(fp, symsan_res)
        return fp

    def run_target(self):
        self.symsan.setup(self.cur_input, self.state.processed_num)
        timeout = self.state.timeout
        if self.symsan.record_mode_enabled:
            timeout = int(self.config.timeout / 10)
        self.symsan.run(timeout)
        try:
            self.symsan.process_request()
        finally:
            self.symsan.tear_down()
        symsan_res = self.symsan.get_result()
        self.logger.info(
            f"Total={symsan_res.total_time}ms, "
            f"Emulation={symsan_res.emulation_time}ms, "
            f"Solver={symsan_res.solving_time}ms, "
            f"Timeout={timeout}s, "
            f"Return={symsan_res.returncode}, "
            f"Distance={symsan_res.distance}, "
            f"Episode_length={len(self.agent.episode)}, "
            f"Msg_count={symsan_res.symsan_msg_num}. "
        )
        return symsan_res

    def update_seed_info(self, fp, res):
        new_fp = fp
        fn = os.path.basename(fp)
        if 'dis:' not in fn:
            new_fp = fp + f",dis:{res.distance:06}"
        if 'time:' in fn and 'ts:' not in fn:
            new_fp = new_fp.replace('time:', 'ts:')
        if new_fp != fp:
            shutil.move(fp, new_fp)
        return new_fp

    def update_timmer(self, res):
        pass

    def sync_from_afl(self, reversed_order=True, need_sort=False):
        files = []
        if self.afl_queue and os.path.exists(self.afl_queue):
            for name in os.listdir(self.afl_queue):
                path = os.path.join(self.afl_queue, name)
                new_name = "id:" + get_id_from_fn(name) + f',sync:{self.afl}'
                if os.path.isfile(path) and not new_name in self.state.synced:
                    shutil.copy2(path, os.path.join(self.my_generations, new_name))
                    files.append(new_name)
                    self.state.synced.add(new_name)
        if need_sort:
            return sorted(files,
                        key=functools.cmp_to_key(
                            (lambda a, b: testcase_compare(a, b, self.afl_queue))),
                        reverse=reversed_order)
        return files

    def sync_from_initial_seeds(self):
        files = []
        for name in os.listdir(self.config.initial_seed_dir):
            path = os.path.join(self.config.initial_seed_dir, name)
            if os.path.isfile(path) and not name in self.state.processed:
                shutil.copy2(path, os.path.join(self.my_generations, name))
                files.append(name)
                self.state.synced.add(name)
        return files

    def sync_from_either(self):
        files = self.sync_from_afl()
        if not files and not self.afl_queue:
            files = self.sync_from_initial_seeds()
        return files

    def handle_return_status(self, result, fp):
        msg_count = result.symsan_msg_num
        if msg_count == 0:
            self.logger.warning("No message is received from the symsan process")
        trace_len = len(self.agent.episode)
        if trace_len == 0:
            self.logger.warning("No episode infomation during the execution")
        
        retcode = result.returncode
        fn = os.path.basename(fp)
        if retcode in [124, -9]: # killed
            shutil.copy2(fp, os.path.join(self.my_hangs, fn))
            self.state.hang.add(fn)

        # segfault or abort
        if (retcode in [128 + 11, -11, 128 + 6, -6]):
            shutil.copy2(fp, os.path.join(self.my_errors, fn))
            self._report_error(fp, result.stderr)

    def handle_hang_files(self):
        if len(self.state.hang) > self.config.min_hang_files:
            if self.state.increase_timeout(self.logger, self.config.max_timeout):
                for fn in self.state.hang:
                    d = utils.get_distance_from_fn(fn)
                    d = self.config.max_distance if d is None else d
                    self.seed_scheduler.put(fn, d)
                self.state.hang.clear()

    def check_crashes(self):
        for fuzzer in os.listdir(self.output):
            crash_dir = os.path.join(self.output, fuzzer, "crashes")
            if not os.path.exists(crash_dir):
                continue
            # initialize if it's first time to see the fuzzer
            if not fuzzer in self.state.crashes:
                self.state.crashes[fuzzer] = -1
            for name in sorted(os.listdir(crash_dir)):
                # skip readme
                if "id:" not in name:
                    continue
                # read id from the format "id:000000..."
                num = int(name[3:9])
                if num > self.state.crashes[fuzzer]:
                    self.state.crashes[fuzzer] = num

    def cleanup(self):
        self.minimizer.cleanup()

    def export_state(self):
        self.state.end_ts = time.time()
        with open(self.metadata, "wb") as fp:
            pickle.dump(self.state, fp, protocol=pickle.HIGHEST_PROTOCOL)
        self.agent.save_model()

    def _make_dirs(self):
        utils.mkdir(self.my_queue)
        utils.mkdir(self.my_hangs)
        utils.mkdir(self.my_errors)
        utils.mkdir(self.my_generations)

    def _setup_logger(self, logging_level):
        self.logger = logging.getLogger(self.__class__.__qualname__)
        logging.basicConfig(level=logging_level)

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
        atexit.register(self.export_state)

    def _report_error(self, fp, log):
        self.logger.warn("Symsan process error: %s\nLog:%s" % (fp, log))

class QSYMExecutor(Mazerunner):
    def __init__(self, config, shared_state=None):
        super().__init__(config, shared_state)
        self.agent = ExploreAgent(self.config)
        self.symsan = SymSanExecutor(self.config, self.agent, self.my_generations)

    def sync_back_if_interesting(self, fp, res):
        old_idx = self.state.index
        fn = os.path.basename(fp)
        num_testcase = 0
        for testcase in res.generated_testcases():
            num_testcase += 1
            if not self.minimizer.has_new_cov(testcase):
                # Remove if it's not interesting testcases
                os.unlink(testcase)
                continue
            index = self.state.tick()
            filename = os.path.join(
                    self.my_queue,
                    "id:%06d,src:%s" % (index, get_id_from_fn(fn)))
            shutil.copy2(testcase, filename)
            self.logger.info("Sync back: %s" % filename)
        self.logger.info("Generated %d testcases" % num_testcase)
        self.logger.info("%d testcases are new" % (self.state.index - old_idx))

    def _run(self):
        files = self.sync_from_afl(need_sort=True)
        if not files:
            self.handle_hang_files()
            time.sleep(WAITING_INTERVAL)
            return
        for fn in files:
            fp = self.run_file(fn)
            fn = os.path.basename(fp)
            self.state.processed.add(fn)
            self.check_crashes()
            break

class ExploreExecutor(Mazerunner):
    def __init__(self, config, shared_state=None):
        super().__init__(config, shared_state)
        self.agent = ExploreAgent(self.config)
        self.symsan = SymSanExecutor(self.config, self.agent, self.my_generations)


    def update_timmer(self, res):
        try:
            self.state.explore_time += res.total_time / utils.MILLION_SECONDS_SCALE
        except AttributeError:
            self.state.explore_time = res.total_time / utils.MILLION_SECONDS_SCALE
    
    def sync_back_if_interesting(self, fp, res):
        fn = os.path.basename(fp)
        ts = int(time.time() * utils.MILLION_SECONDS_SCALE - self.state.start_ts * utils.MILLION_SECONDS_SCALE)
        self.agent.save_trace(fn)
        # rename or delete generated testcases from fp
        self.logger.info("Generated %d testcases" % len(res.generated_testcases))
        for t in res.generated_testcases:
            testcase = os.path.join(self.my_generations, t)
            if not self.minimizer.is_new_file(testcase):
                os.unlink(testcase)
                continue
            index = self.state.tick()
            filename = f"id:{index:06},src:{get_id_from_fn(fn)},ts:{ts},execs:{self.state.execs}"
            shutil.move(testcase, os.path.join(self.my_generations, filename))
            t_d = int(t.split(',')[-1].strip())
            self.seed_scheduler.put(filename, t_d)
        # syn back to AFL queue if it's interesting
        is_interesting = self.minimizer.has_closer_distance(res.distance, fn)
        if is_interesting and 'sync' not in fn:
            self.logger.info(f"Explore agent found closer distance={res.distance}, ts: {ts}")
            self.logger.info("Sync back: %s" % fn)
            dst_fp = os.path.join(self.my_queue, fn)
            shutil.copy2(fp, dst_fp)

    def _run(self):
        next_seed = self.seed_scheduler.pop()
        if not next_seed is None and next_seed not in self.state.processed:
            fp = self.run_file(next_seed)
            next_seed = os.path.basename(fp)
            # start RL training after symsan executor finishes
            self.agent.train(self.agent.episode)
            self.state.processed.add(next_seed)
        else:
            self.logger.info("Sleeping for getting seeds from AFL")
            time.sleep(WAITING_INTERVAL)


class ExploitExecutor(Mazerunner):
    def __init__(self, config, shared_state=None):
        super().__init__(config, shared_state)
        self.agent = ExploitAgent(self.config)
        self.symsan = SymSanExecutor(self.config, self.agent, self.my_generations)

    def run_target(self):
        total_time = emulation_time = solving_time = 0
        has_reached_max_flip_num = lambda: len(self.agent.all_targets) >= self.config.max_flip_num
        while not has_reached_max_flip_num():
            try:
                self.symsan.setup(self.cur_input, self.state.processed_num)
                self.symsan.run(self.state.timeout)
                self.symsan.process_request()
                # (1) symsan proc has nomarlly terminated and self.cur_input is on policy
                # (2) the solver is not able to solve the branch condition
                if len(self.symsan.solver.generated_files) == 0:
                    break
                assert len(self.symsan.solver.generated_files) == 1
                fp = os.path.join(self.my_generations, self.symsan.solver.generated_files[0])
                shutil.move(fp, self.cur_input)
            finally:
                self.symsan.tear_down()
                symsan_res = self.symsan.get_result()
                total_time += symsan_res.total_time
                emulation_time += symsan_res.emulation_time
                solving_time += symsan_res.solving_time
        symsan_res.update_time(total_time, solving_time)
        symsan_res.flipped_times = len(self.agent.all_targets)
        self.logger.info(
            f"Total={total_time}ms, "
            f"Emulation={emulation_time}ms, "
            f"Solver={solving_time}ms, "
            f"Return={symsan_res.returncode}, "
            f"Distance={symsan_res.distance}, "
            f"Episode_length={len(self.agent.episode)}, "
            f"Msg_count={symsan_res.symsan_msg_num}, "
            f"flipped={symsan_res.flipped_times} times. "
        )
        # target might still be reachable due to hitting max_flip_num
        if self.agent.target[0] and not has_reached_max_flip_num():
            self.agent.handle_unsat_condition()
        self.agent.all_targets.clear()
        return symsan_res

    def update_timmer(self, res):
        try:
            self.state.exploit_time += res.total_time / utils.MILLION_SECONDS_SCALE
        except AttributeError:
            self.state.exploit_time = res.total_time / utils.MILLION_SECONDS_SCALE

    def sync_back_if_interesting(self, fp, res):
        fn = os.path.basename(fp)
        if res.flipped_times == 0:
            self.seed_scheduler.remove(os.path.basename(fn))
        if not self.minimizer.is_new_file(self.cur_input):
            return
        index = self.state.tick()
        target = get_id_from_fn(fn)
        ts = int(time.time() * utils.MILLION_SECONDS_SCALE - self.state.start_ts * utils.MILLION_SECONDS_SCALE)
        dst_fn = f"id:{index:06},src:{target},ts:{ts},dis:{res.distance:06},execs:{self.state.execs}"
        dst_fp = os.path.join(self.my_generations, dst_fn)
        shutil.copy2(self.cur_input, dst_fp)
        self.agent.save_trace(dst_fn)
        is_closer = self.minimizer.has_closer_distance(res.distance, dst_fn)
        if is_closer:
            self.seed_scheduler.put(dst_fn, res.distance)
            self.logger.info(f"Exploit agent found closer distance={res.distance}, ts: {ts}")
            self.logger.info("Sync back: %s" % fn)
            dst_fp = os.path.join(self.my_queue, dst_fn)
            shutil.copy2(self.cur_input, dst_fp)

    def _run(self):
        next_seed = self.seed_scheduler.pick()
        if next_seed:
            self.run_file(next_seed)
            self.agent.train(self.agent.episode)
        else:
            self.logger.info("Sleeping for getting seeds from AFL")
            time.sleep(WAITING_INTERVAL)

class RecordExecutor(Mazerunner):
    def __init__(self, config, shared_state=None, record_enabled=True):
        super().__init__(config, shared_state)
        self.is_hybrid_mode = shared_state is not None
        self.record_enabled = record_enabled
        if self.record_enabled:
            self.agent = RecordAgent(config)
            self.symsan = SymSanExecutor(self.config, self.agent, self.my_generations)

    def sync_back_if_interesting(self, fp, res):
        fn = os.path.basename(fp)
        d = utils.get_distance_from_fn(fn)
        if self.minimizer.has_closer_distance(d, fn):
            self.logger.info(f"Fuzzer found closer distance={res.distance}")
        self.agent.save_trace(fn)

    def update_timmer(self, res):
        try:
            self.state.record_time += res.total_time / utils.MILLION_SECONDS_SCALE
        except AttributeError:
            self.state.record_time = res.total_time / utils.MILLION_SECONDS_SCALE

    def update_seed_queue(self, fn):
        d = utils.get_distance_from_fn(fn)
        d = -self.config.max_distance if d is None else d
        self.seed_scheduler.put(fn, d)

    def _run(self):
        files = self.sync_from_either()
        if self.is_hybrid_mode and not files and not self.state.seed_queue:
            self.handle_hang_files()
        for fn in files:
            if self.record_enabled:
                fp = self.run_file(fn)
                fn = os.path.basename(fp)
                self.state.processed.add(fn)
            if self.is_hybrid_mode:
                self.update_seed_queue(fn)

class ReplayExecutor(Mazerunner):
    def __init__(self, config, shared_state=None):
        super().__init__(config, shared_state)
        self.agent = Agent(config)

    def offline_learning(self):
        iteration_num = 1
        files = os.listdir(self.agent.my_traces)
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
        self.state.execs = 0

class HybridExecutor():
    def __init__(self, config, agent_type):
        self.config = config
        # check_resource_limit returns a flag that controlled by another monitor thread
        self.my_dir = config.mazerunner_dir
        self.check_resource_limit = lambda: False
        # All executors share the same state and All agents share the same model
        self._import_state()
        self.replayer = ReplayExecutor(config, self.state)
        self.model = Agent.create_model(self.config)
        self.seed_scheduler = SeedScheduler(self.state.seed_queue)
        if agent_type == "exploit":
            self.concolic_executor = ExploitExecutor(config, self.state)
            self.synchronizer = RecordExecutor(config, shared_state=self.state, record_enabled=True)
            self.synchronizer.agent.model = self.model
        elif agent_type == "explore":
            self.concolic_executor = ExploreExecutor(config, self.state)
            self.synchronizer = RecordExecutor(config, shared_state=self.state, record_enabled=False)
        else:
            raise NotImplementedError()
        self.replayer.agent.model = self.model
        self.concolic_executor.agent.model = self.model
        self.concolic_executor.seed_scheduler = self.seed_scheduler
        self.synchronizer.seed_scheduler = self.seed_scheduler
        self.replayer.seed_scheduler = self.seed_scheduler

    @property
    def metadata(self):
        return os.path.join(self.my_dir, ".metadata")

    @property
    def reached_resource_limit(self):
        return self.check_resource_limit()

    def run(self):
        while not self.reached_resource_limit:
            if self.state.execs % self.config.save_frequency == 0:
                self._export_state()
            if self.state.execs % self.config.sync_frequency == 0:
                self.synchronizer.run(run_once=True)
            self.concolic_executor.run(run_once=True)
            self.replayer.offline_learning()
        logging.getLogger(self.__class__.__qualname__).error("Reached resource limit, exiting...")

    def cleanup(self):
        self._export_state()

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
