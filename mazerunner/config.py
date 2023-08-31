import json
import os
import logging

LOGGING_LEVEL = logging.INFO
MEMORY_LIMIT_PERCENTAGE = 85
DISK_LIMIT_SIZE = 32 * (1 << 30) # 32GB
# Solver configurations
RANDOM_INPUT = "AAAA"
MAX_DISTANCE = 0xFFFFFFFF
NESTED_BRANCH_ENABLED = True
GEP_SOLVER_ENABLED = False
OPTIMISTIC_SOLVING_ENABLED = True
# Learner configurations
DISCOUNT_FACTOR = 1
LEARNING_RATE = 0.5
EXPLORE_RATE = 0.5
# Executor configurations
SEED_SYNC_FREQUENCY = 100
SAVE_FREQUENCY = 200 # save mazerunner status into disk every SAVE_FREQUENCY executions.
DEFAULT_TIMEOUT = 60
MAX_TIMEOUT = 20 * 60
MAX_ERROR_REPORTS = 30
MAX_CRASH_REPORTS = 30
MAX_FLIP_NUM = 128
# minimum number of hang files to increase timeout
MIN_HANG_FILES = 30

class Config:
    __slots__ = ['__dict__', '__weakref__',
                 'logging_level', 
                 'random_input', 
                 'max_distance', 
                 'nested_branch_enabled', 
                 'gep_solver_enabled', 
                 'optimistic_solving_enabled', 
                 'discount_factor', 
                 'learning_rate',
                 "output_dir",
                 "afl_dir",
                 "mazerunner_dir",
                 "initial_seed_dir",
                 "mail",
                 "delimiter",
                 "pkglen",
                 "cmd",
                 "sync_frequency",
                 "explore_rate",
                 "timeout",
                 "max_timeout",
                 "max_error_reports",
                 "max_crash_reports",
                 "max_flip_num",
                 "min_hang_files",
                 "memory_limit",
                 "disk_limit",
                 "save_frequency"]

    def __init__(self):
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

    def reload(self, args):
        self.output_dir = args.output_dir
        self.afl_dir = args.afl_dir
        self.mazerunner_dir = os.path.join(args.output_dir, args.mazerunner_dir)
        self.initial_seed_dir = args.input
        self.mail = args.mail
        self.delimiter = args.deli
        self.pkglen = args.pkglen
        self.cmd = args.cmd
        if args.debug_enabled:
            self.logging_level = logging.DEBUG

    def _load_default(self):
        self.logging_level = LOGGING_LEVEL
        self.random_input = RANDOM_INPUT
        self.max_distance = MAX_DISTANCE
        self.nested_branch_enabled = NESTED_BRANCH_ENABLED
        self.gep_solver_enabled = GEP_SOLVER_ENABLED
        self.optimistic_solving_enabled = OPTIMISTIC_SOLVING_ENABLED
        self.discount_factor = DISCOUNT_FACTOR
        self.learning_rate = LEARNING_RATE
        self.sync_frequency = SEED_SYNC_FREQUENCY
        self.explore_rate = EXPLORE_RATE
        self.timeout = DEFAULT_TIMEOUT
        self.max_timeout = MAX_TIMEOUT
        self.max_error_reports = MAX_ERROR_REPORTS
        self.max_crash_reports = MAX_CRASH_REPORTS
        self.max_flip_num = MAX_FLIP_NUM
        self.min_hang_files = MIN_HANG_FILES
        self.memory_limit = MEMORY_LIMIT_PERCENTAGE
        self.disk_limit = DISK_LIMIT_SIZE
        self.save_frequency = SAVE_FREQUENCY
        # The following should obly be set by the mazerunner launcher
        self.output_dir = None
        self.afl_dir = None
        self.mazerunner_dir = None
        self.initial_seed_dir = None
        self.mail = None
        self.delimiter = None
        self.pkglen = None
        self.cmd = None
