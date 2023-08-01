#!/usr/bin/env python3
import sys
import os
import logging

from agent import Agent
from config import Config
from executor import SymSanExecutor
from utils import AT_FILE

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: {} target input".format(sys.argv[0]), file=sys.stderr)
        sys.exit(1)
    logging.basicConfig(level=logging.INFO)
    config = Config()
    config.cmd = [sys.argv[1], AT_FILE]
    output_seed_dir = "."
    options = os.environ['TAINT_OPTIONS']
    if "output_dir=" in options:
        output_seed_dir = options.split("output_dir=")[1].split(":")[0].split(" ")[0]
    fastgen_agent = Agent(config)
    symsan = SymSanExecutor(config, fastgen_agent, output_seed_dir)
    symsan.setup(sys.argv[2])
    symsan.run(timeout=3)
    try:
        symsan.process_request()
    finally:
        symsan.tear_down()
