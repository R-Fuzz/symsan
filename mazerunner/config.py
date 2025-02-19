import collections
import json
import pickle
import os
import logging

import utils
from model import RLModelType

LOGGING_LEVEL = logging.INFO
MEMORY_LIMIT_SIZE = 15 * (1 << 30) # 15GB
DISK_LIMIT_SIZE = 1 * (1 << 30) # 1GB
# set FREQUENCY to 0 if you want to disable the feature
SYNC_FREQUENCY = 10 # sync mazerunner status with AFL every SYNC_FREQUENCY executions.
SAVE_FREQUENCY = 200 # save mazerunner status into disk every SAVE_FREQUENCY executions.
REPLAY_FREQUENCY = 0 # off-learning from replay buffer every REPLAY_FREQUENCY executions.
TARGET_REACHED_EXIT = True
TARGET_TRIGGERED_EXIT = False
BUG_TRIGGER_DISTANCE = 3 * 1000 # start bug triggering after reaching this distance value
# Solver configurations
USE_BUILTIN_SOLVER = False
MAX_DISTANCE = float(0x7FFFFFFFFFFFFFFF)
NESTED_BRANCH_ENABLED = True
OPTIMISTIC_SOLVING_ENABLED = True
# Learner configurations
DISCOUNT_FACTOR = 1
LEARNING_RATE = 1
EXPLORE_RATE = 0.5
# Executor configurations
SYMSAN_PIPE_TIMEOUT = 200 # milliseconds per symsan pipe message
DEFAULT_TIMEOUT = 5 # seconds per execution
MAX_TIMEOUT = 10 * 60
MAX_ERROR_REPORTS = 30
MAX_CRASH_REPORTS = 30
MAX_FLIP_NUM = 128
MAX_BRANCH_NUM = 33
# minimum number of hang files to increase timeout
MIN_HANG_FILES = 1
# Model configurations
DECIMAL_PRECISION = 200
# Path divergence handler configurations
HANDLE_PATH_DIVERGENCE_ENABLED = False
ADDRESS2LINE_PATH = '/usr/bin/addr2line'

class Config:
    __slots__ = ['__dict__',
                 '__weakref__',
                 'agent_type',
                 'logging_level',
                 'nested_branch_enabled',
                 'gep_solver_enabled',
                 'optimistic_solving_enabled',
                 'discount_factor',
                 'learning_rate',
                 "output_dir",
                 "afl_dir",
                 "mazerunner_dir",
                 "initial_seed_dir",
                 "cmd",
                 "sync_frequency",
                 "explore_rate",
                 'pipe_timeout',
                 "timeout",
                 "max_timeout",
                 "max_error_reports",
                 "max_crash_reports",
                 "max_flip_num",
                 "min_hang_files",
                 "memory_limit",
                 "disk_limit",
                 "save_frequency",
                 "replay_frequency",
                 "model_type",
                 "decimal_precision",
                 'max_distance',
                 'initial_policy',
                 'initial_distance',
                 'static_result_folder',
                 'use_ordered_dict',
                 'use_builtin_solver',
                 'defferred_solving_enabled',
                 'target_triggered_exit',
                 'target_reached_exit',
                 'bug_trigger_distance',
                 'addr2line_path',
                 'source_code_dir',
                 'handle_path_divergence',
    ]

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__qualname__)
        self._load_default()

    def load(self, path):
        if not path:
            return
        if not os.path.isfile(path):
            raise ValueError(f"{path} does not exist")
        with open(path, 'r') as file:
            new_config = json.load(file)
        for key, value in new_config.items():
            setattr(self, key, value)

    def save(self, path):
        if not path:
            return
        with open(path, 'w') as file:
            json.save(self.__dict__, file)
    
    def load_put_args(self, args):
        if args.debug_enabled:
            self.logging_level = logging.DEBUG
        if args.cmd:
            self.cmd = args.cmd
        if args.static_result_folder:
            self.static_result_folder = args.static_result_folder
            distance_file = os.path.join(self.static_result_folder, "distance.cfg.txt")
            self._load_distance_file(distance_file)
            self._load_initial_policy()
        if args.source_code_folder:
            self.source_code_dir = args.source_code_folder

    def load_args(self, args):
        if args.agent_type:
            self.agent_type = args.agent_type
        if args.model_type:
            if args.model_type == "distance":
                self.model_type = RLModelType.distance
            elif args.model_type == "reachability":
                self.model_type = RLModelType.reachability
            else:
                self.model_type = RLModelType.unknown
        if args.output_dir:
            self.output_dir = args.output_dir
        if args.fuzzer_dir:
            self.afl_dir = args.fuzzer_dir
        if args.mazerunner_dir:
            self.mazerunner_dir = os.path.join(args.output_dir, args.mazerunner_dir)
        if args.input_dir:
            self.initial_seed_dir = args.input_dir
        self.load_put_args(args)

    def _load_default(self):
        self.logging_level = LOGGING_LEVEL
        self.max_distance = MAX_DISTANCE
        self.nested_branch_enabled = NESTED_BRANCH_ENABLED
        self.optimistic_solving_enabled = OPTIMISTIC_SOLVING_ENABLED
        self.discount_factor = DISCOUNT_FACTOR
        self.learning_rate = LEARNING_RATE
        self.sync_frequency = SYNC_FREQUENCY
        self.replay_frequency = REPLAY_FREQUENCY
        self.explore_rate = EXPLORE_RATE
        self.pipe_timeout = SYMSAN_PIPE_TIMEOUT
        self.timeout = DEFAULT_TIMEOUT
        self.max_timeout = MAX_TIMEOUT
        self.max_error_reports = MAX_ERROR_REPORTS
        self.max_crash_reports = MAX_CRASH_REPORTS
        self.max_flip_num = MAX_FLIP_NUM
        self.min_hang_files = MIN_HANG_FILES
        self.memory_limit = MEMORY_LIMIT_SIZE
        self.disk_limit = DISK_LIMIT_SIZE
        self.save_frequency = SAVE_FREQUENCY
        self.decimal_precision = DECIMAL_PRECISION
        self.max_branch_num = MAX_BRANCH_NUM
        self.use_builtin_solver = USE_BUILTIN_SOLVER
        self.target_triggered_exit = TARGET_TRIGGERED_EXIT
        self.target_reached_exit = TARGET_REACHED_EXIT
        self.bug_trigger_distance = BUG_TRIGGER_DISTANCE
        self.addr2line_path = ADDRESS2LINE_PATH
        self.handle_path_divergence = HANDLE_PATH_DIVERGENCE_ENABLED
        self.gep_solver_enabled = False
        self.use_ordered_dict = False
        self.defferred_solving_enabled = False
        # The other configurations need to be set explicitly by config file or cmd arguments
        self.model_type = RLModelType.unknown
        self.afl_dir = ''
        self.agent_type = ''
        self.output_dir = ''
        self.mazerunner_dir = ''
        self.initial_seed_dir = ''
        self.cmd = ''
        self.static_result_folder = '/tmp'
        self.source_code_dir = '/tmp'
        self.initial_policy = {}
        self.initial_distance = collections.defaultdict(lambda: self.max_distance)

    def _load_distance_file(self, fp):
        if not os.path.isfile(fp):
            raise ValueError(f"distance file {fp} does not exist.")
        with open(fp, 'r') as file:
            for l in file.readlines():
                items = l.strip().split(',')
                assert len(items) == 3
                bid = int(items[0])
                d = float(items[2])
                self.initial_distance[bid] = d
                if d > self.max_distance or (self.max_distance == MAX_DISTANCE and d > 0):
                    self.max_distance = d

    def _load_initial_policy(self):
        policy_txt = os.path.join(self.static_result_folder, "policy.txt")
        if os.path.isfile(policy_txt):
            self.initial_policy = utils.get_policy_from_txt(policy_txt)
            self.logger.debug(f"initial policy loaded from {policy_txt}")
            return
        policy_pkl = os.path.join(self.static_result_folder, "policy.pkl")
        if os.path.isfile(policy_pkl):
            with open(policy_pkl, 'rb') as file:
                self.initial_policy = pickle.load(file)
            self.logger.debug(f"initial policy loaded from {policy_pkl}")
            return
        self.logger.warning(f"policy file does not exist, using random initial policy.")
