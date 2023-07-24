import collections
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

from agent import ExploreAgent, ExploitAgent, RecordAgent, ReplayAgent
from backend_solver import Z3Solver
from defs import OperationUnsupportedError
from executor import SymSanExecutor
import minimizer
import utils

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

def testcase_compare(a, b):
    a_score = get_score(a)
    b_score = get_score(b)
    return 1 if a_score > b_score else -1

def get_afl_cmd(fuzzer_stats):
    with open(fuzzer_stats) as f:
        for l in f:
            if l.startswith("command_line"):
                # format is "command_line: [cmd]"
                return l.lstrip('command_line:').strip().split()

# 'id:xxxx,src:yyyyy' -> 'id:xxxx'
# 'id-xxx-xxxxxx-xx,src:yy-yyyyyy-yy' -> 'id-xxx-xxxxxx-xx'
# 'idxxxxxxxx' -> 'idxxxxxxxx'
get_id_from_fn = lambda s: re.compile(r'id[^,]*').findall(s)

class MazerunnerState:
    def __init__(self, timeout):
        self.synced = set()
        self.hang = set()
        self.processed = set()
        self.timeout = timeout
        self.crashes = set()
        self.testscases_md5 = set()
        self.index = 0
        self.num_error_reports = 0
        self.num_crash_reports = 0
        self.best_seed = ("", float("inf"))

    def __setstate__(self, dict):
        self.__dict__ = dict

    def __getstate__(self):
        return self.__dict__

    def clear(self):
        self.processed = self.processed - self.hang
        self.hang = set()

    def increase_timeout(self, logger, max_timeout):
        old_timeout = self.timeout
        if self.timeout < max_timeout:
            self.timeout *= 2
            logger.debug("Increase timeout %d -> %d"
                         % (old_timeout, self.timeout))
        else:
            # Something bad happened, but wait until AFL resolves it
            logger.debug("Hit the maximum timeout")
            # Back to default timeout not to slow down fuzzing
            self.timeout = self.timeout
        # sleep for a minutes to wait until AFL resolves it
        time.sleep(60)
        # clear state for retesting seeds that needs more time
        self.clear()

    def tick(self):
        old_index = self.index
        self.index += 1
        return old_index

    def get_num_processed(self):
        return len(self.processed)

class Mazerunner:
    def __init__(self, config):
        self.config = config
        self.timeout = config.timeout
        self.max_timeout = config.max_timeout
        self.max_error_reports = config.max_error_reports
        self.max_crash_reports = config.max_error_reports
        self.max_flip_num = config.max_flip_num
        self.min_hang_files = config.min_hang_files
        self.cmd = config.cmd
        self.output = config.output_dir
        self.name = config.mazerunner_dir
        self.mail = config.mail
        self.initial_seed_dir = config.initial_seed_dir
        self.filename = ".cur_input"
        self.my_dir = os.path.join(self.output, self.name)
        self.config.mazerunner_dir = self.my_dir
        self._make_dirs()
        self._import_state()
        self._setup_logger(config.logging_level, config.log_file)
        self.afl = None
        if config.afl_dir:
            self.afl = config.afl_dir
            self.afl_cmd, afl_path, qemu_mode = self._parse_fuzzer_stats()
            self.minimizer = minimizer.TestcaseMinimizer(
                self.afl_cmd, afl_path, self.output, qemu_mode, self.state)
        else:
            self.minimizer = minimizer.TestcaseMinimizer(
                None, None, self.output, None, self.state)

    @property
    def cur_input(self):
        return os.path.realpath(os.path.join(self.my_dir, self.filename))

    @property
    def afl_dir(self):
        if not self.afl:
            return None
        return os.path.join(self.output, self.afl)

    @property
    def afl_queue(self):
        if not self.afl_dir:
            return None
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
        return os.path.join(self.my_dir, "metadata")

    @property
    def bitmap(self):
        return os.path.join(self.my_dir, "bitmap")

    @property
    def dictionary(self):
        return os.path.join(self.my_dir, "dictionary")

    def cleanup(self):
        self._export_state()

    def run_file(self, fn):
        # copy the test case
        fp = os.path.join(self.my_generations, fn)
        shutil.copy2(fp, self.cur_input)
        self.logger.info("Run: input=%s" % fp)
        symsan_res = self.run_target()
        self.handle_return_status(symsan_res.returncode, symsan_res.stderr, fp)
        self.sync_back_if_interesting(fp, symsan_res)
        self.state.processed.add(fn)

    def run_target(self):
        symsan = SymSanExecutor(self.config, self.agent, self.my_generations)
        symsan.setup(self.cur_input, len(self.state.processed))
        symsan.run()
        try:
            symsan.process_request()
        finally:
            symsan.tear_down()
        symsan_res = symsan.get_result()
        self.logger.info("Total=%dms, Emulation=%dms, Solver=%dms, Return=%d"
                     % (symsan_res.total_time,
                        symsan_res.emulation_time,
                        symsan_res.solving_time,
                        symsan_res.returncode))
        return symsan_res

    def sync_back_if_interesting(self, fp, res):
        pass

    def sync_from_afl(self, reversed_order=True):
        files = []
        if self.afl_queue and os.path.exists(self.afl_queue):
            for name in os.listdir(self.afl_queue):
                path = os.path.join(self.afl_queue, name)
                if os.path.isfile(path) and not name in self.state.synced:
                    shutil.copy2(path, os.path.join(self.my_generations, name))
                    files.append(name)
                    self.state.synced.add(name)
        return sorted(files,
                      key=functools.cmp_to_key(testcase_compare),
                      reverse=reversed_order)

    def sync_from_initial_seeds(self):
        files = []
        for name in os.listdir(self.initial_seed_dir):
            path = os.path.join(self.initial_seed_dir, name)
            if os.path.isfile(path):
                shutil.copy2(path, os.path.join(self.my_generations, name))
                files.append(name)
        return files

    def handle_return_status(self, retcode, log, fp):
        fn = os.path.basename(fp)
        if retcode in [124, -9]: # killed
            shutil.copy2(fp, os.path.join(self.my_hangs, fn))
            self.state.hang.add(fn)

        # segfault or abort
        if (retcode in [128 + 11, -11, 128 + 6, -6]):
            shutil.copy2(fp, os.path.join(self.my_errors, fn))
            self.report_error(fp, log)

    def handle_empty_files(self):
        if len(self.state.hang) > self.min_hang_files:
            self.state.increase_timeout(self.logger, self.max_timeout)
        else:
            # TODO: implement RL thinking: replay from the past
            self.logger.info("Sleep for getting files from AFL seed queue")
            time.sleep(5)

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

    def _make_dirs(self):
        utils.mkdir(self.my_queue)
        utils.mkdir(self.my_hangs)
        utils.mkdir(self.my_errors)
        utils.mkdir(self.my_generations)

    def _setup_logger(self, logging_level, logfile):
        self.logger = logging.getLogger(self.__class__.__qualname__)
        if logfile:
            log_path = os.path.join(self.my_dir, logfile)
            logging.basicConfig(filename=log_path, level=logging_level)
        else:
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
            self.state = MazerunnerState(self.timeout)

    def _send_mail(self, subject, info, attach=None):
        if attach is None:
            attach = []
        cmd = ["mail"]
        for path in attach:
            cmd += ["-A", path]
        cmd += ["-s", "[mazerunner-report] %s" % subject]
        cmd.append(self.mail)
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
        if self.mail is None:
            return
        # don't do too much
        if self.state.num_error_reports >= self.max_error_reports:
            return
        self.state.num_error_reports += 1
        self._send_mail("Error found", {"LOG": log}, [fp])

    def _report_crash(self, fp):
        self.logger.debug("Crash is found: %s" % fp)
        # if no mail, then stop
        if self.mail is None:
            return
        # don't do too much
        if self.state.num_crash_reports >= self.max_error_reports:
            return
        self.state.num_crash_reports += 1
        info = {}
        stdout, stderr = utils.run_command(["timeout", "-k", "5", "5"] + self.afl_cmd, fp)
        info["STDOUT"] = stdout
        info["STDERR"] = stderr
        self._send_mail("Crash found", info, [fp])

    def _export_state(self):
        with open(self.metadata, "wb") as fp:
            pickle.dump(self.state, fp, protocol=pickle.HIGHEST_PROTOCOL)

class QSYMExecutor(Mazerunner):
    def __init__(self, config):
        super().__init__(config)
        self.agent = ExploreAgent(self.config)

    def run(self):
        while True:
            files = self.sync_from_afl()
            if not files:
                self.handle_empty_files()
                continue
            for fp in files:
                self.run_file(fp)
                self.check_crashes()
                break

    def sync_back_if_interesting(self, fp, res):
        old_idx = self.state.index
        target = os.path.basename(fp)[:len("id:......")]
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
            self.logger.debug("Sync back: %s" % filename)
        self.logger.debug("Generated %d testcases" % num_testcase)
        self.logger.debug("%d testcases are new" % (self.state.index - old_idx))

class ExploreExecutor(Mazerunner):
    def __init__(self, config):
        super().__init__(config)
        self.agent = ExploreAgent(self.config)
        self.sync_frequency = self.config.sync_frequency
        self.state.explore_queue = collections.deque()

    def run(self):
        if not self.state.explore_queue:
            files = self.sync_from_afl()
            if not files:
                files = self.sync_from_initial_seeds()
            self.state.explore_queue.extend(files)
        while True:
            if (not self.state.explore_queue
                or len(self.state.processed) % self.sync_frequency == 0):
                files = self.sync_from_afl(False)
                self.state.explore_queue.extendleft(files)
            if not self.state.explore_queue:
                self.handle_empty_files()
                continue
            next_seed = self.state.explore_queue.popleft()
            if not next_seed in self.state.processed:
                self.run_file(next_seed)

    def sync_back_if_interesting(self, fp, res):
        num_testcase = 0
        for t in res.generated_testcases:
            testcase = os.path.join(self.my_generations, t)
            num_testcase += 1
            if not self.minimizer.is_new_file(testcase):
                os.unlink(testcase)
                continue
            self.state.explore_queue.append(t)
        fn = os.path.basename(fp)
        is_closer = self.minimizer.has_closer_distance(res.distance, fn)
        if self.afl_queue and (is_closer or self.minimizer.has_new_cov(fp)):
            self.logger.info("Sync back: %s" % fn)
            # TODO: try to infer the source of fp, check naming pattern of qsym
            filename = os.path.join(self.my_queue, fn)
            shutil.copy2(fp, filename)
        self.logger.info("Generated %d testcases" % num_testcase)

class ExploitExecutor(Mazerunner):
    def __init__(self, config):
        super().__init__(config)
        self.agent = ExploitAgent(self.config)

    def run(self):
        while True:
            next_seed = self.state.best_seed[0]
            if not next_seed:
                files = self.sync_from_afl()
                if not files:
                    files = self.sync_from_initial_seeds()
                next_seed = random.choice(files)
            self.run_file(next_seed)

    def run_target(self):
        total_time = emulation_time = solving_time = 0
        symsan = SymSanExecutor(self.config, self.agent, self.my_generations)
        flip_num = 0
        while flip_num < self.max_flip_num:
            try:
                symsan.setup(self.cur_input, len(self.state.processed))
                symsan.run()
                symsan.process_request()
                break
            # TODO: return a status from process_request() instead of catching exception
            except Z3Solver.AbortConcolicExecution:
                self.agent.target_sa = self.agent.curr_state.compute_reversed_sa()
                assert len(symsan.solver.generated_files) == 1
                fp = os.path.join(self.my_generations, symsan.solver.generated_files[0])
                shutil.move(fp, self.cur_input)
                self.logger.debug(f"Abort and restart. Target SA: {self.agent.target_sa}")
                flip_num += 1
                continue
            finally:
                symsan.tear_down()
                symsan_res = symsan.get_result()
                assert len(symsan_res.generated_testcases) <= 1
                total_time += symsan_res.total_time
                emulation_time += symsan_res.emulation_time
                solving_time += symsan_res.solving_time
        assert not symsan_res.generated_testcases
        self.agent.replay_trace(self.agent.episode)
        if self.agent.target_sa and flip_num < self.max_flip_num:
            self.agent.mark_sa_unreachable(self.agent.target_sa)
            self.agent.target_sa = None
        self.logger.info("Total=%dms, Emulation=%dms, Solver=%dms, Return=%d, flipped=%d times"
                     % (total_time, emulation_time, solving_time, symsan_res.returncode, flip_num))
        return symsan_res

    def sync_back_if_interesting(self, fp, res):
        fn = os.path.basename(fp)
        index = self.state.tick()
        names = get_id_from_fn(fn)
        target = names[0] if names else fn
        dst_fn = "id:%06d,src:%s" % (index, target)
        dst_fp = os.path.join(self.my_generations, dst_fn)
        shutil.copy2(self.cur_input, dst_fp)
        is_closer = self.minimizer.has_closer_distance(res.distance, fn)
        if self.afl_queue and (is_closer or self.minimizer.has_new_cov(fp)):
            self.logger.info("Sync back: %s" % fn)
            dst_fp = os.path.join(self.my_queue, dst_fn)
            shutil.copy2(self.cur_input, dst_fp)

class RecordExecutor(Mazerunner):
    def __init__(self, config):
        super().__init__(config)
        self.agent = RecordAgent(config)

    def run(self):
        while True:
            files = self.sync_from_afl()
            if not files:
                files = self.sync_from_initial_seeds()
            if not files:
                self.handle_empty_files()
                continue
            for fp in files:
                self.run_file(fp)
                self.agent.save_trace(os.path.basename(fp))
                break

class ReplayExecutor(Mazerunner):
    def __init__(self, config):
        super().__init__(config)
        self.agent = ReplayAgent(config)

    def run(self):
        files = os.listdir(self.agent.my_traces)
        round_num = 0
        while True:
            round_num += 1
            self.logger.info(f"{round_num}th rounds of offline learning")
            for fn in files:
                fp = os.path.join(self.agent.my_traces, fn)
                self.agent.replay_log(fp)

# TODO: implement this
class HybridExecutor(Mazerunner):
    def __init__(self, config):
        super().__init__(config)

    def run(self):
        raise OperationUnsupportedError("HybridExecutor not implemented")
