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
        print(
            'Usage: BIN_ARGS="other cmdline args" TAINT_OPTIONS="output_dir=/path:debug=1" {} target input'
            .format(sys.argv[0]),
            file=sys.stderr)
        sys.exit(1)

    config = Config()
    config.gep_solver_enabled = True
    config.cmd = [sys.argv[1]]
    if 'BIN_ARGS' in os.environ:
        xargs = os.environ['BIN_ARGS'].split(' ')
        config.cmd += xargs
    config.cmd.append(AT_FILE)

    options = os.environ['TAINT_OPTIONS']
    if "debug=1" in options:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    output_seed_dir = "."
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
