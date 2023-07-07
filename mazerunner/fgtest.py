#!/usr/bin/env python3
import sys
import os
import logging

from agent import Agent, RLModel
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
    config.output_seed_dir = "."
    if "output_dir=" in options:
        config.output_seed_dir = options.split("output_dir=")[1].split(":")[0].split(" ")[0]
    config.logging_level = logging.INFO
    model = RLModel(config)
    fastgen_agent = Agent(config, model)
    executor = Executor(config, fastgen_agent)
    executor.setup(input_file, 0)
    executor.run()
    try:
        executor.process_request()
    finally:
        executor.tear_down()
