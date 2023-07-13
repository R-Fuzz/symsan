import copy
import logging
import functools
import json
import os
import pickle
import shutil
import subprocess
import sys
import tempfile
import time
import threading
import queue

from defs import AT_FILE
import executor
import minimizer

DEFAULT_TIMEOUT = 60
MAX_TIMEOUT = 10 * 60 # 10 minutes

MAX_ERROR_REPORTS = 30
MAX_CRASH_REPORTS = 30
MAX_FLIP_NUM = 512
# minimum number of hang files to increase timeout
MIN_HANG_FILES = 30

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

def mkdir(dirp):
    if not os.path.exists(dirp):
        os.makedirs(dirp)

def get_afl_cmd(fuzzer_stats):
    with open(fuzzer_stats) as f:
        for l in f:
            if l.startswith("command_line"):
                # format is "command_line: [cmd]"
                return l.lstrip('command_line:').strip().split()

def fix_at_file(cmd, testcase):
    cmd = copy.copy(cmd)
    if AT_FILE in cmd:
        idx = cmd.index(AT_FILE)
        cmd[idx] = testcase
        stdin = None
    else:
        with open(testcase, "rb") as f:
            stdin = f.read()

    return cmd, stdin

def run_command(cmd, testcase):
    cmd, stdin = fix_at_file(cmd, testcase)
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p.communicate(stdin)

class AFLExecutorState:
    def __init__(self):
        self.hang = set()
        self.processed = set()
        self.timeout = DEFAULT_TIMEOUT
        self.done = set()
        self.index = 0
        self.num_error_reports = 0
        self.num_crash_reports = 0
        self.crashes = set()

    def __setstate__(self, dict):
        self.__dict__ = dict

    def __getstate__(self):
        return self.__dict__

    def clear(self):
        self.hang = set()
        self.processed = set()

    def increase_timeout(self, logger):
        old_timeout = self.timeout
        if self.timeout < MAX_TIMEOUT:
            self.timeout *= 2
            logger.debug("Increase timeout %d -> %d"
                         % (old_timeout, self.timeout))
        else:
            # Something bad happened, but wait until AFL resolves it
            logger.debug("Hit the maximum timeout")
            # Back to default timeout not to slow down fuzzing
            self.timeout = DEFAULT_TIMEOUT
        # sleep for a minutes to wait until AFL resolves it
        time.sleep(60)
        # clear state for restarting
        self.clear()

    def tick(self):
        old_index = self.index
        self.index += 1
        return old_index

    def get_num_processed(self):
        return len(self.processed) + len(self.hang) + len(self.done)

class AFLExecutor:
    def __init__(self, config):
        self.logger = logging.getLogger(self.__class__.__qualname__)
        self.logger.setLevel(config.logging_level)
        self.cmd = config.cmd
        self.output = config.output_dir
        self.afl = config.afl_dir
        self.name = config.mazerunner_dir
        self.filename = ".cur_input"
        self.mail = config.mail
        self._unreachable_branches = []
        self._loop_info = {}
        self.tmp_dir = tempfile.mkdtemp()
        self.afl_cmd, afl_path, qemu_mode = self._parse_fuzzer_stats()
        self.minimizer = minimizer.TestcaseMinimizer(
            self.afl_cmd, afl_path, self.output, qemu_mode)
        self._import_state()
        if config.import_loopinfo_enabled:
            self._import_loop_info()
        self._make_dirs()

    @property
    def cur_input(self):
        return os.path.realpath(os.path.join(self.my_dir, self.filename))

    @property
    def afl_dir(self):
        return os.path.join(self.output, self.afl)

    @property
    def afl_queue(self):
        return os.path.join(self.afl_dir, "queue")

    @property
    def my_dir(self):
        return os.path.join(self.output, self.name)

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
    def metadata(self):
        return os.path.join(self.my_dir, "metadata")

    @property
    def bitmap(self):
        return os.path.join(self.my_dir, "bitmap")

    @property
    def dictionary(self):
        return os.path.join(self.my_dir, "dictionary")

    @property
    def unreachable_branches(self):
        if not self._unreachable_branches:
            path = os.path.join(self.my_dir, "unreachable_branches.json")
            if os.path.isfile(path):
                with open(path, 'r') as fp:
                    json.load(fp, self._unreachable_branches)
        return self._unreachable_branches

    @property
    def loopinfo(self):
        return self._loop_info

    def cleanup(self):
        try:
            self._export_state()
            #shutil.rmtree(self.tmp_dir)
        except:
            pass

    def sync_with_afl(self, seedBufferQ):
        pass

    def run(self):
        pass

    def _make_dirs(self):
        mkdir(self.tmp_dir)
        mkdir(self.my_queue)
        mkdir(self.my_hangs)
        mkdir(self.my_errors)

    # return cmd, afl_path, qemu_mode
    # cmd will be used in minimizer
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
            self.state = AFLExecutorState()

    def _import_loop_info(self):
        path = os.path.join(self.my_dir, "loops.json")
        if not os.path.isfile(path):
            program = self.cmd[0]
            loop_finder = os.path.join(os.path.dirname(__file__), 'static_anlysis.py')
            # run angr in a seperete process as it overwrites logging configs
            completed_process = subprocess.run([loop_finder, program, path], stdout=subprocess.DEVNULL)
            if completed_process.returncode != 0:
                raise RuntimeError(f"failed to run {loop_finder}")
        with open(path, 'r') as fp:
            json.load(fp, self._loop_info)

    def _sync_files(self):
        files = []
        for name in os.listdir(self.afl_queue):
            path = os.path.join(self.afl_queue, name)
            if os.path.isfile(path):
                files.append(path)

        files = list(set(files) - self.state.done - self.state.processed)
        return sorted(files,
                      key=functools.cmp_to_key(testcase_compare),
                      reverse=True)

    def _run_target(self, cur_input, tmp_dir, skipEpisodeNum, targetBA):
        # Trigger linearlize to remove complicate expressions
        q = executor.Executor(self.cmd, targetBA, self.dbNum, self.deli, self.pkglen, cur_input, self.my_dir, tmp_dir, self.shared_map_addr, skipEpisodeNum, bitmap=self.bitmap, argv=["-l", "1"])
        ret = q.run(self.state.timeout)
        self.logger.debug(f"Total={ret.total_time} s, "
                     f"Emulation={ret.emulation_time} s, "
                     f"Solver={ret.solving_time} s, "
                     f"Return={ret.returncode}")
        return q, ret

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
        for k, v in info.iteritems():
            text += "%s\n" % k
            text += "-" * 30 + "\n"
            text += "%s" % v + "\n" * 3
        try:
            devnull = open(os.devnull, "wb")
            proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=devnull, stderr=devnull)
            proc.communicate(text)
        except OSError:
            pass
        finally:
            devnull.close()

    def _check_crashes(self):
        for fuzzer in os.listdir(self.output):
            crash_dir = os.path.join(self.output, fuzzer, "crashes")
            if not os.path.exists(crash_dir):
                continue

            # initialize if it's first time to see the fuzzer
            if not fuzzer in self.state.crashes:
                self.state.crashes[fuzzer] = -1

            for name in sorted(os.listdir(crash_dir)):
                # skip readme
                if name == "README.txt":
                    continue

                # read id from the format "id:000000..."
                num = int(name[3:9])
                if num > self.state.crashes[fuzzer]:
                    self._report_crash(os.path.join(crash_dir, name))
                    self.state.crashes[fuzzer] = num

    def _report_error(self, fp, log):
        self.logger.debug("Error is occured: %s\nLog:%s" % (fp, log))
        # if no mail, then stop
        if self.mail is None:
            return

        # don't do too much
        if self.state.num_error_reports >= MAX_ERROR_REPORTS:
            return

        self.state.num_error_reports += 1
        self._send_mail("Error found", {"LOG": log}, [fp])

    def _report_crash(self, fp):
        self.logger.debug("Crash is found: %s" % fp)

        # if no mail, then stop
        if self.mail is None:
            return

        # don't do too much
        if self.state.num_crash_reports >= MAX_CRASH_REPORTS:
            return

        self.state.num_crash_reports += 1
        info = {}
        stdout, stderr = run_command(["timeout", "-k", "5", "5"] + self.afl_cmd, fp)
        info["STDOUT"] = stdout
        info["STDERR"] = stderr
        self._send_mail("Crash found", info, [fp])

    def _export_state(self):
        with open(self.metadata, "wb") as f:
            pickle.dump(self.state, f)
        path = os.path.join(self.my_dir, "unreachable_branches.json")
        with open(path, 'w') as fp:
            json.dump(self._unreachable_branches, fp)

    def _handle_empty_files(self):
        if len(self.state.hang) > MIN_HANG_FILES:
            self.state.increase_timeout(self.logger)
        else:
            self.logger.debug("Sleep for getting files")
            time.sleep(5)
