import json
import os
import logging

# Default configurations
LOGGING_LEVEL = logging.ERROR
# Default generated seeds directory
SEED_OUTPUT_DIR = "."
RANDOM_INPUT = "AAAA"
MAX_DISTANCE = 0xFFFFFFFF
UNION_TABLE_SIZE = 0xc00000000
IMPORT_LOOPINFO_ENABLED = False
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
                 'import_loopinfo_enabled', 
                 'nested_branch_enabled', 
                 'gep_solver_enabled', 
                 'optimistic_solving_enabled', 
                 'output_seed_dir', 
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
                 "cmd"]

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
            log_path = os.path.join(self.output_dir, self.mazerunner_dir + args.log_file)
            logging.basicConfig(filename=log_path, level=self.logging_level)

    def _load_default(self):
        self.logging_level = LOGGING_LEVEL
        self.random_input = RANDOM_INPUT
        self.max_distance = MAX_DISTANCE
        self.union_table_size = UNION_TABLE_SIZE
        self.import_loopinfo_enabled = IMPORT_LOOPINFO_ENABLED
        self.nested_branch_enabled = NESTED_BRANCH_ENABLED
        self.gep_solver_enabled = GEP_SOLVER_ENABLED
        self.optimistic_solving_enabled = OPTIMISTIC_SOLVING_ENABLED
        self.output_seed_dir = SEED_OUTPUT_DIR
        self.record_replay_mode_enabled = RECORD_REPLAY_MODE_ENABLED
        self.onetime_solving_enabled = ONETIME_SOLVING_ENABLED
        self.discount_factor = DISCOUNT_FACTOR
        self.learning_rate = LEARNING_RATE
