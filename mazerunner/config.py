import json
import os
import logging

CONFIG_PATH = "./config.json"
LOGGING_LEVEL = logging.ERROR
OUTPUT_SEED_DIR = "."
MAX_DISTANCE = 0xFFFFFFFF
MIN_DISTANCE = 0
UNION_TABLE_SIZE = 0xc00000000
NESTED_BRANCH_ENABLED = True
GEP_SOLVER_ENABLED = True
OPTIMISTIC_SOLVING_ENABLED = True

class Config:
    def __init__(self, path=None):
        if path:
            self.config_path = path
        else:
            self.config_path = CONFIG_PATH
        self._load_default_config()
        self.load_config()

    def load_config(self):
        if os.path.isfile(self.config_path):
            with open(self.config_path, 'r') as file:
                new_config = json.load(file)
            for key, value in new_config.items():
                setattr(self, key, value)

    def _load_default_config(self):
        self.logging_level = LOGGING_LEVEL
        self.max_distance = MAX_DISTANCE
        self.min_distance = MIN_DISTANCE
        self.union_table_size = UNION_TABLE_SIZE
        self.nested_branch = NESTED_BRANCH_ENABLED
        self.gep_solving = GEP_SOLVER_ENABLED
        self.optimistic_solving = OPTIMISTIC_SOLVING_ENABLED
        self.seed_dir = OUTPUT_SEED_DIR
