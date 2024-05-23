#!/usr/bin/env python3
import sys
import os
import logging

from agent import Agent
from config import Config
from executor_symsan_lib import ConcolicExecutor
from utils import AT_FILE

def print_usage_exit():
    print(f'Usage:\nBIN_ARGS="other cmdline args" '
            f'TAINT_OPTIONS="taint_file=input_file:output_dir=/output/path:debug=1" '
            f'{sys.argv[0]} symsan_instrumented_bin @@',
        file=sys.stderr)
    print(f'Or\nBIN_ARGS="other cmdline args" '
            f'TAINT_OPTIONS="taint_file=input_file:output_dir=/output/path:debug=1" '
            f'{sys.argv[0]} symsan_instrumented_bin',
        file=sys.stderr)
    sys.exit(1)

if __name__ == "__main__":
    if ('TAINT_OPTIONS' not in os.environ
        or (len(sys.argv) != 3 and AT_FILE == sys.argv[-1])
        or (len(sys.argv) != 2 and AT_FILE != sys.argv[-1])
        ):
        print_usage_exit()
    is_stdin = (AT_FILE != sys.argv[-1] and len(sys.argv) == 2)
    config = Config()
    config.gep_solver_enabled = True
    config.cmd = [sys.argv[1]]
    if 'BIN_ARGS' in os.environ:
        xargs = os.environ['BIN_ARGS'].split(' ')
        config.cmd += xargs
    if not is_stdin:
        config.cmd.append(AT_FILE)

    options = os.environ['TAINT_OPTIONS']
    if "debug=1" in options:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    output_seed_dir = "."
    if "output_dir=" in options:
        output_seed_dir = options.split("output_dir=")[1].split(":")[0].split(" ")[0]
    if "taint_file=" not in options:
        print_usage_exit()
    input_file = options.split("taint_file=")[1].split(":")[0].split(" ")[0]
    fastgen_agent = Agent(config)
    ce = ConcolicExecutor(config, fastgen_agent, output_seed_dir)
    ce.setup(input_file)
    ce.run()
    try:
        ce.process_request()
    finally:
        if "debug=1" in options:
            symsan_res = ce.get_result()
            print(
                f"Total={symsan_res.total_time}ms, "
                f"Emulation={symsan_res.emulation_time}ms, "
                f"Solver={symsan_res.solving_time}ms, "
                f"Return={symsan_res.returncode}, "
                f"Distance={symsan_res.distance}, "
                f"Msg_count={symsan_res.symsan_msg_num}. "
                f"stdout:\n{symsan_res.stdout}\n"
                f"stderr:\n{symsan_res.stderr}\n"
            )
        ce.tear_down()
