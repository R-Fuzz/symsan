#!/usr/bin/env python3
import sys
import os
import queue
import logging

import agent
from explore_agent import ExploreAgent
from config import Config
from executor import Executor

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: {} target input".format(sys.argv[0]), file=sys.stderr)
        sys.exit(1)

    config = Config()
    config.program = sys.argv[1]
    input_file = sys.argv[2]
    seed_queue = queue.Queue()
    seed_queue.put(input_file)
    config.output_seed_dir = "./output"
    config.logging_level = logging.DEBUG
    model = agent.RLModel(config)
    explore_agent = ExploreAgent(config, model)
    executor = Executor(config, explore_agent)
    
    i = 0
    while not seed_queue.empty():
        next_input = seed_queue.get()
        print(f"executing {next_input}...")
        if not os.path.isfile(next_input):
            continue
        executor.setup(next_input, i)
        executor.run()
        i += 1
        try:
            executor.process_request()
        finally:
            executor.tear_down()
        for fname in executor.solver.generated_files:
            seed = os.path.join(config.output_seed_dir, fname)
            seed_queue.put(seed)
