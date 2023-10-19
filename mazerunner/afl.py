import atexit
import copy
import logging
import functools
import os
import pickle
import random
import re
import shutil
import subprocess
import time
import heapq

from agent import Agent, ExploreAgent, ExploitAgent, RecordAgent
from executor import SymSanExecutor
from model import RLModel
import minimizer
import utils

CONVERGING_THRESHOLD = 10
WAITING_INTERVAL = 5

# 'id:xxxx,src:yyyyy' -> 'id:xxxx'
# 'id-xxx-xxxxxx-xx,src:yy-yyyyyy-yy' -> 'id-xxx-xxxxxx-xx'
# 'idxxxxxxxx' -> 'idxxxxxxxx'
def get_id_from_fn(s):
    match = re.compile(r'id[^,]*').findall(s)
    if not match:
        return s
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
        self.exploit_ce_time = 0
        self.explore_ce_time = 0
        self.synced = set()
        self.hang = set()
        self.processed = set()
        self.crashes = set()
        self.testscases_md5 = set()
        self.index = 0
        self.execs = 0
        self.num_error_reports = 0
        self.num_crash_reports = 0
        self._seed_queue = []
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
        self._best_seed_info[2] = True

    @property
    def discovered_closer_seed(self):
        return self._best_seed_info[2]
    @discovered_closer_seed.setter
    def discovered_closer_seed(self, value):
        self._best_seed_info[2] = value
    
    def is_queue_empty(self):
        return len(self._seed_queue) == 0

    def put_seed(self, fn, priority):
        if not fn or priority < 0:
            raise ValueError("Invalid seed")
        heapq.heappush(self._seed_queue, (priority, fn))

    def get_seed(self):
        if self.is_queue_empty():
            return None
        return heapq.heappop(self._seed_queue)[1]

    def clear(self):
        self.processed = self.processed - self.hang

    def increase_timeout(self, logger, max_timeout):
        old_timeout = self.timeout
        if self.timeout < max_timeout:
            t = self.timeout * 2
            self.timeout = t if t < max_timeout else max_timeout
            logger.info("Increase timeout %d -> %d"
                         % (old_timeout, self.timeout))
        else:
            logger.info("Hit the maximum timeout")
        # clear state for retesting seeds that needs more time
        self.clear()

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
        self._setup_logger(config.logging_level)
        self.afl = ''
        if config.afl_dir:
            self.afl = config.afl_dir
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

    def run_file(self, fn):
        self.state.execs += 1
        # copy the test case
        fp = os.path.join(self.my_generations, fn)
        shutil.copy2(fp, self.cur_input)
        self.logger.info("Run: input=%s" % fp)
        symsan_res = self.run_target()
        self.handle_return_status(symsan_res, fp)
        self.update_timmer(symsan_res)
        self.sync_back_if_interesting(fp, symsan_res)

    def run_target(self):
        self.symsan.setup(self.cur_input, self.state.processed_num)
        self.symsan.run(self.state.timeout)
        try:
            self.symsan.process_request()
        finally:
            self.symsan.tear_down()
        symsan_res = self.symsan.get_result()
        self.logger.info(
            f"Total={symsan_res.total_time}ms, "
            f"Emulation={symsan_res.emulation_time}ms, "
            f"Solver={symsan_res.solving_time}ms, "
            f"Return={symsan_res.returncode}, "
            f"Distance={symsan_res.distance}, "
            f"Episode_length={len(self.agent.episode)}, "
            f"Msg_count={symsan_res.symsan_msg_num}. "
        )
        return symsan_res

    def update_timmer(self, res):
        pass

    def sync_from_afl(self, reversed_order=True, need_sort=False):
        files = []
        if self.afl_queue and os.path.exists(self.afl_queue):
            for name in os.listdir(self.afl_queue):
                path = os.path.join(self.afl_queue, name)
                if os.path.isfile(path) and not name in self.state.synced:
                    shutil.copy2(path, os.path.join(self.my_generations, name))
                    files.append(name)
                    self.state.synced.add(name)
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

    def sync_from_fuzzer(self):
        if self.state.execs % self.config.sync_frequency == 0:
            files = self.sync_from_either()
            for fn in files:
                d = utils.get_distance_from_fn(fn)
                d = self.config.max_distance if d is None else d
                self.state.put_seed(fn, d)
            if self.state.is_queue_empty():
                self.handle_hang_files()

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
            self.state.increase_timeout(self.logger, self.config.max_timeout)
            for fn in self.state.hang:
                d = utils.get_distance_from_fn(fn)
                d = self.config.max_distance if d is None else d
                self.state.put_seed(fn, d)
            self.state.hang.clear()
        # TODO: offline learning, replay from past experience

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
                    self._report_crash(os.path.join(crash_dir, name))
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

    def _send_mail(self, subject, info, attach=None):
        if attach is None:
            attach = []
        cmd = ["mail"]
        for path in attach:
            cmd += ["-A", path]
        cmd += ["-s", "[mazerunner-report] %s" % subject]
        cmd.append(self.config.mail)
        info = copy.copy(info)
        info["CMD"] = " ".join(self.cmd)
        text = "\n" # skip cc
        for k, v in info.items():
            text += "%s\n" % k
            text += "-" * 30 + "\n"
            text += "%s" % v + "\n" * 3
        try:
            proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, 
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            proc.communicate(text.encode())
        except OSError:
            pass

    def _report_error(self, fp, log):
        self.logger.debug("Error is occurred: %s\nLog:%s" % (fp, log))
        # if no mail, then stop
        if self.config.mail is None:
            return
        # don't do too much
        if self.state.num_error_reports >= self.config.max_error_reports:
            return
        self.state.num_error_reports += 1
        self._send_mail("Error found", {"LOG": log}, [fp])

    def _report_crash(self, fp):
        self.logger.debug("Crash is found: %s" % fp)
        # if no mail, then stop
        if self.config.mail is None:
            return
        # don't do too much
        if self.state.num_crash_reports >= self.config.max_error_reports:
            return
        self.state.num_crash_reports += 1
        info = {}
        stdout, stderr = utils.run_command(["timeout", "-k", "5", "5"] + self.afl_cmd, fp)
        info["STDOUT"] = stdout
        info["STDERR"] = stderr
        self._send_mail("Crash found", info, [fp])

class QSYMExecutor(Mazerunner):
    def __init__(self, config, shared_state=None):
        super().__init__(config, shared_state)
        self.agent = ExploreAgent(self.config)
        self.symsan = SymSanExecutor(self.config, self.agent, self.my_generations)

    def sync_back_if_interesting(self, fp, res):
        old_idx = self.state.index
        fn = os.path.basename(fp)
        target = fn[len("id:"):len("id:......")] if len(fn) >= len("id:......") else fn
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
                    "id:%06d,src:%s" % (index, target))
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
            self.run_file(fn)
            self.state.processed.add(fn)
            self.check_crashes()
            break

class ExploreExecutor(Mazerunner):
    def __init__(self, config, shared_state=None):
        super().__init__(config, shared_state)
        self.agent = ExploreAgent(self.config)
        self.symsan = SymSanExecutor(self.config, self.agent, self.my_generations)

    def dry_run(self):
        files = self.sync_from_either()
        for seed in files:
            self._run_single_file(seed)

    def update_timmer(self, res):
        self.state.explore_ce_time += res.total_time/1000
    
    def sync_back_if_interesting(self, fp, res):
        fn = os.path.basename(fp)
        ts = int(time.time() * utils.MILLION_SECONDS_SCALE - self.state.start_ts * utils.MILLION_SECONDS_SCALE)
        # rename or delete generated testcases from fp
        for t in res.generated_testcases:
            testcase = os.path.join(self.my_generations, t)
            if not self.minimizer.is_new_file(testcase):
                os.unlink(testcase)
                continue
            index = self.state.tick()
            target = fn[len("id:"):len("id:......")] if len(fn) >= len("id:......") else fn
            filename = f"id:{index:06},src:{target},ts:{ts},dis:{res.distance:06},execs:{self.state.execs},explore"
            shutil.move(testcase, os.path.join(self.my_generations, filename))
            self.state.put_seed(filename, res.distance)
        # syn back to AFL queue if it's interesting
        is_closer = self.minimizer.has_closer_distance(res.distance, fn)
        if is_closer:
            self.logger.info(f"Explore agent found closer seed. "
                         f"fn: {fn}, distance: {res.distance}, ts: {ts}")
        is_interesting = fn not in self.state.synced and (is_closer 
                          or self.minimizer.has_new_sa(len(self.agent.model.visited_sa)))
        if self.afl_queue and is_interesting:
            self.logger.info("Sync back: %s" % fn)
            dst_fp = os.path.join(self.my_queue, fn)
            shutil.copy2(fp, dst_fp)
        self.logger.info("Generated %d testcases" % len(res.generated_testcases))

    def _run(self):
        if self.config.agent_type == "explore":
            self.sync_from_fuzzer()
        next_seed = self.state.get_seed()
        if not next_seed is None:
            if next_seed not in self.state.processed:
                self._run_single_file(next_seed)
        else:
            self.logger.info("Sleeping for getting seeds from AFL")
            time.sleep(WAITING_INTERVAL)

    def _run_single_file(self, fn):
        self.run_file(fn)
        # start RL training after symsan executor finishes
        self.agent.replay_trace(self.agent.episode)
        self.state.processed.add(fn)

class ExploitExecutor(Mazerunner):
    def __init__(self, config, shared_state=None):
        super().__init__(config, shared_state)
        self.agent = ExploitAgent(self.config)
        self.symsan = SymSanExecutor(self.config, self.agent, self.my_generations)
        self.no_progress_count = 0

    @property
    def has_converged(self):
        return self.no_progress_count > CONVERGING_THRESHOLD

    def run_target(self):
        total_time = emulation_time = solving_time = 0
        has_reached_max_flip_num = lambda: len(self.agent.all_targets) >= self.config.max_flip_num
        while not has_reached_max_flip_num():
            try:
                self.symsan.setup(self.cur_input, self.state.processed_num)
                self.symsan.run(self.state.timeout)
                self.symsan.process_request()
                if self.symsan.has_terminated and len(self.symsan.solver.generated_files) == 0:
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
        self.logger.info(
            f"Total={total_time}ms, "
            f"Emulation={emulation_time}ms, "
            f"Solver={solving_time}ms, "
            f"Return={symsan_res.returncode}, "
            f"Distance={symsan_res.distance}, "
            f"Episode_length={len(self.agent.episode)}, "
            f"Msg_count={symsan_res.symsan_msg_num}, "
            f"flipped={len(self.agent.all_targets)} times. "
        )
        # target might still be reachable due to hitting max_flip_num
        if self.agent.target[0] and not has_reached_max_flip_num():
            self.agent.handle_unsat_condition()
        # check if it's stuck
        if self.agent.all_targets == self.agent.last_targets or has_reached_max_flip_num():
            self.no_progress_count += 1
        else:
            self.no_progress_count = 0
        self.agent.last_targets = self.agent.all_targets
        self.agent.all_targets = []
        return symsan_res

    def update_timmer(self, res):
        self.state.exploit_ce_time += res.total_time/1000

    def sync_back_if_interesting(self, fp, res):
        if not self.minimizer.is_new_file(self.cur_input):
            return
        fn = os.path.basename(fp)
        index = self.state.tick()
        target = get_id_from_fn(fn)
        ts = int(time.time() * utils.MILLION_SECONDS_SCALE - self.state.start_ts * utils.MILLION_SECONDS_SCALE)
        dst_fn = f"id:{index:06},src:{target},ts:{ts},dis:{res.distance:06},execs:{self.state.execs},exploit"
        dst_fp = os.path.join(self.my_generations, dst_fn)
        shutil.copy2(self.cur_input, dst_fp)
        is_closer = self.minimizer.has_closer_distance(res.distance, dst_fn)
        if is_closer:
            self.logger.info(f"Exploit agent found closer seed. "
                            f"fn: {fn}, distance: {res.distance}, ts: {ts}")
        is_interesting = is_closer or self.minimizer.has_new_sa(len(self.agent.model.visited_sa))
        if is_interesting:
            self.state.put_seed(dst_fn, res.distance)
        if self.afl_queue and is_interesting:
            self.logger.info("Sync back: %s" % fn)
            dst_fp = os.path.join(self.my_queue, dst_fn)
            shutil.copy2(self.cur_input, dst_fp)

    def _run(self):
        if self.config.agent_type == "exploit":
            self.sync_from_fuzzer()
        next_seed = None
        if self.has_converged or not self.state.best_seed:
            next_seed = self.state.get_seed()
        if next_seed is None:
            next_seed = self.state.best_seed
            if self.state.discovered_closer_seed:
                self.state.discovered_closer_seed = False
                self.no_progress_count = 0
        if next_seed:
            self.run_file(next_seed)
            self.agent.replay_trace(self.agent.episode)
        else:
            self.logger.info("Sleeping for getting seeds from AFL")
            time.sleep(WAITING_INTERVAL)

class RecordExecutor(Mazerunner):
    def __init__(self, config, shared_state=None):
        super().__init__(config, shared_state)
        self.agent = RecordAgent(config)
        self.symsan = SymSanExecutor(self.config, self.agent, self.my_generations)

    def sync_back_if_interesting(self, fp, res):
        pass

    def _run(self):
        files = self.sync_from_either()
        if not files:
            self.handle_hang_files()
            time.sleep(WAITING_INTERVAL)
            return
        for fn in files:
            self.state.timeout = self.config.timeout / 10
            self.run_file(fn)
            self.state.processed.add(fn)
            self.agent.save_trace(fn)

class ReplayExecutor(Mazerunner):
    def __init__(self, config, shared_state=None):
        super().__init__(config, shared_state)
        self.agent = Agent(config)
        self.symsan = SymSanExecutor(self.config, self.agent, self.my_generations)

    def sync_back_if_interesting(self, fp, res):
        pass

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
    def __init__(self, config):
        self.config = config
        # check_resource_limit returns a flag that controlled by another monitor thread
        self.my_dir = config.mazerunner_dir
        self.check_resource_limit = lambda: False
        # Two agents share the same state
        self._import_state()
        self.explore_executor = ExploreExecutor(config, self.state)
        self.exploit_executor = ExploitExecutor(config, self.state)
        # Two agents share the same model
        self.model = Agent.create_model(self.config)
        self.explore_executor.agent.model = self.model
        self.exploit_executor.agent.model = self.model

    @property
    def metadata(self):
        return os.path.join(self.my_dir, ".metadata")

    @property
    def reached_resource_limit(self):
        return self.check_resource_limit()

    def run(self):
        self.explore_executor.dry_run()
        while not self.reached_resource_limit:
            if self.state.execs % self.config.save_frequency == 0:
                self._export_state()
            if (self.state.discovered_closer_seed 
                or not self.exploit_executor.has_converged):
                self.exploit_executor.run(run_once=True)
                continue
            self.explore_executor.sync_from_fuzzer()
            self.explore_executor.run(run_once=True)

    def cleanup(self):
        self._export_state()
        self.explore_executor.cleanup()
        self.exploit_executor.cleanup()

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
