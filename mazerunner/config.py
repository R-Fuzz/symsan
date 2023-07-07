import json
import os
import logging

CONFIG_PATH = "./config.json"
LOGGING_LEVEL = logging.ERROR
OUTPUT_DIR = "."
MAX_DISTANCE = 0xFFFFFFFF
UNION_TABLE_SIZE = 0xc00000000
NESTED_BRANCH_ENABLED = True
GEP_SOLVER_ENABLED = False
OPTIMISTIC_SOLVING_ENABLED = True
ONETIME_SOLVING_ENABLED = False
TRACE_LOGGING_ENABLED = False
RECORD_REPLAY_MODE_ENABLED = False
DISCOUNT_FACTOR = 1
LEARNING_RATE = 0.5

class Config:
    def __init__(self):
        self._load_default_config()
        self.load_config()

    def load_config(self, path=None):
        if not path:
            path = self.config_path
        if os.path.isfile(path):
            with open(self.config_path, 'r') as file:
                new_config = json.load(file)
            for key, value in new_config.items():
                setattr(self, key, value)

    def _load_default_config(self):
        self.config_path = CONFIG_PATH
        self.logging_level = LOGGING_LEVEL
        self.max_distance = MAX_DISTANCE
        self.union_table_size = UNION_TABLE_SIZE
        self.nested_branch_enabled = NESTED_BRANCH_ENABLED
        self.gep_solver_enabled = GEP_SOLVER_ENABLED
        self.optimistic_solving_enabled = OPTIMISTIC_SOLVING_ENABLED
        self.output_dir = OUTPUT_DIR
        self.trace_logging_enabled = TRACE_LOGGING_ENABLED
        self.record_replay_mode_enabled = RECORD_REPLAY_MODE_ENABLED
        self.onetime_solving_enabled = ONETIME_SOLVING_ENABLED
        self.discount_factor = DISCOUNT_FACTOR
        self.learning_rate = LEARNING_RATE
