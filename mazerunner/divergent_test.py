#!/usr/bin/env python3
import argparse
import os
import shutil
import logging

import executor_symsan_lib
import executor
from agent import LazyAgent
from config import Config
from utils import AT_FILE

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("-i", dest="input_file", default=None, help="initial seed directory")
    p.add_argument("-s", dest="static_result_folder", default=None, help="static analysis results folder that saves the distance information and initial policy")
    p.add_argument("-c", dest="source_code_folder", default=None, help="source code folder of the program under test")
    p.add_argument("-config", dest="config_path", default=None, help="path of configuration file")
    p.add_argument("-debug", dest="debug_enabled", action="store_true", help="Enable debug mode")
    p.add_argument("cmd", nargs="+", help=f"cmdline, use {AT_FILE} to denote a file")
    return p.parse_args()

if __name__ == "__main__":
    args = parse_args()
    config = Config()
    config.load(args.config_path)
    config.load_put_args(args)
    config.handle_path_divergence = True
    logging.basicConfig(level=config.logging_level)
    
    lazy_agent = LazyAgent(config)
    output_seed_dir = '/tmp/mazerunner_output'
    if not os.path.isdir(output_seed_dir):
        os.makedirs(output_seed_dir)

    if config.use_builtin_solver:
        ce = executor.ConcolicExecutor(config, lazy_agent, output_seed_dir)
    else:
        ce = executor_symsan_lib.ConcolicExecutor(config, lazy_agent, output_seed_dir)
    ce.setup(args.input_file)
    ce.run(timeout=3600)
    try:
        ce.process_request()
    finally:
        if config.handle_path_divergence:
            ce.handle_path_divergence()
        ce.tear_down(deep_clean=True)
        if os.path.isdir(output_seed_dir):
            shutil.rmtree(output_seed_dir, ignore_errors=True)
        if args.debug_enabled:
            symsan_res = ce.get_result()
            print(
                f"Total={symsan_res.total_time}ms, "
                f"Emulation={symsan_res.emulation_time}ms, "
                f"Solver={symsan_res.solving_time}ms, "
                f"Return={symsan_res.returncode}, "
                f"Distance={symsan_res.distance}, "
                f"Msg_count={symsan_res.symsan_msg_num}. \n"
                f"stdout:\n{symsan_res.stdout}\n"
                f"stderr:\n{symsan_res.stderr}\n"
            )
