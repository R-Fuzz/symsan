#!/usr/bin/env python3
import sys
import os
import logging

from config import Config
from executor import Executor

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: {} target input".format(sys.argv[0]), file=sys.stderr)
        sys.exit(1)
    config = Config()
    config.program = sys.argv[1]
    input_file = sys.argv[2]
    options = os.environ['TAINT_OPTIONS']
    config.seed_dir = "."
    if "output_dir=" in options:
        config.seed_dir = options.split("output_dir=")[1].split(":")[0].split(" ")[0]
    config.logging_level = logging.INFO
    executor = Executor(config)
    executor.setup(input_file)
    executor.run()
    executor.process_request()
    executor.tear_down()
