import json
import os
import logging

# Default configurations
LOGGING_LEVEL = logging.ERROR
RANDOM_INPUT = "AAAA"
MAX_DISTANCE = 0xFFFFFFFF
UNION_TABLE_SIZE = 0xc00000000
NESTED_BRANCH_ENABLED = True
GEP_SOLVER_ENABLED = False
OPTIMISTIC_SOLVING_ENABLED = True
ONETIME_SOLVING_ENABLED = False
RECORD_REPLAY_MODE_ENABLED = False
DISCOUNT_FACTOR = 1
LEARNING_RATE = 0.5

class Config:
    __slots__ = ['__dict__', '__weakref__',
                 'logging_level', 
                 'random_input', 
                 'max_distance', 
                 'union_table_size', 
                 'nested_branch_enabled', 
                 'gep_solver_enabled', 
                 'optimistic_solving_enabled', 
                 'record_replay_mode_enabled', 
                 'onetime_solving_enabled',
                 'discount_factor', 
                 'learning_rate',
                 "output_dir",
                 "afl_dir",
                 "mazerunner_dir",
                 "input_path",
                 "mail",
                 "delimiter",
                 "pkglen",
                 "cmd",
                 "log_file"]

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
        self.mazerunner_dir = args.mazerunner_dir
        self.input_path = args.input
        self.mail = args.mail
        self.delimiter = args.deli
        self.pkglen = args.pkglen
        self.cmd = args.cmd
        if args.debug_enabled:
            self.logging_level = logging.DEBUG
        if args.log_file:
            self.log_file = args.log_file

    def _load_default(self):
        self.logging_level = LOGGING_LEVEL
        self.random_input = RANDOM_INPUT
        self.max_distance = MAX_DISTANCE
        self.union_table_size = UNION_TABLE_SIZE
        self.nested_branch_enabled = NESTED_BRANCH_ENABLED
        self.gep_solver_enabled = GEP_SOLVER_ENABLED
        self.optimistic_solving_enabled = OPTIMISTIC_SOLVING_ENABLED
        self.record_replay_mode_enabled = RECORD_REPLAY_MODE_ENABLED
        self.onetime_solving_enabled = ONETIME_SOLVING_ENABLED
        self.discount_factor = DISCOUNT_FACTOR
        self.learning_rate = LEARNING_RATE
