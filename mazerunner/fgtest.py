#!/usr/bin/env python3
import sys
import os
import logging

from agent import Agent, RLModel
from config import Config
from symsan import Executor

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: {} target input".format(sys.argv[0]), file=sys.stderr)
        sys.exit(1)
    config = Config()
    config.cmd = [sys.argv[1], sys.argv[2]]
    input_file = config.cmd[1]
    options = os.environ['TAINT_OPTIONS']
    config.output_seed_dir = "."
    if "output_dir=" in options:
        config.output_seed_dir = options.split("output_dir=")[1].split(":")[0].split(" ")[0]
    config.logging_level = logging.INFO
    model = RLModel()
    fastgen_agent = Agent(config, model)
    symsan = Executor(config, fastgen_agent)
    symsan.setup(input_file)
    symsan.run()
    try:
        symsan.process_request()
    finally:
        symsan.tear_down()
