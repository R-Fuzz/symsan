#!/usr/bin/env python3
build_folder = "/home/csong/fuzzing/symsan/b4"
import subprocess
import os
import sys
import glob
import argparse
import shutil
import logging

# Test sources (test/, metadata/) are read from here regardless of cwd; build
# outputs go under the build tree instead (see OUT_DIR), mirroring how lit
# keeps tests/symsan's outputs under b4/tests/symsan rather than the source dir.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

common_env = {
    "KO_CC": "clang-18",
    "KO_CXX": "clang++-18",
    "KO_DONT_OPTIMIZE": "1",
    "KO_USE_THOROUPY": "1",
    "KO_TRACE_BB": "1",
    # Emit __taint_solve_size/solve_bounds so OOB through a *symbolic* length
    # (e.g. memcpy(dst, src, *payload)) is solvable, not just concrete OOB.
    "KO_SOLVE_UB": "1",
}

ucsan_config = {
  "termination": {
    "loop": {
      "threshold": 10
    },
    "branch": {
      "always_true": False,
      "path_sensitive": False
    }
  },
  "handler": {
    "ubi_handler": {},
    "objtrace_handler": {},
    "forward_handler": {}
  },
  "scheduler": {
    "fifo": {
      "checksum": False
    }
  },
  # Explore the whole queue instead of halting on the first error event.
  # Tests assert exact/multiple error counts (e.g. malloc needs OOB+UAF,
  # stack_uar needs 2 UAFs), so stop-on-first-error would under-count them.
  "stop_on_error": False
}

tests = []

sys.path.append(os.path.join(SCRIPT_DIR, "..", "..", "fuzzer", "thoroupy"))

from manager import UcsanManager
from utils.process import populate_gdb

adapter = None

def parse_test(file, test_name):
    test = [test_name, "", []]
    c = open(file,"r").readlines()
    for line in c:
        if line.startswith("// METADATA:"):
            test[1] = line.split(":", maxsplit=2)[1].strip()
        elif line.startswith("// ENV:"):
            test.extend(line.split(":", maxsplit=2)[1].strip().split(" "))
        elif line.startswith("// FLAG:"):
            flags = line.split(":", maxsplit=2)[1].strip().split(" ")
            for flag in flags:
                if ',' in flag:
                    f, c = flag.split(",")
                    test[2].append([int(f), int(c)])
                else:
                    test[2].append([int(flag, 0), 0])
        elif line.startswith("// DISCARD:"):
            flags = line.split(":", maxsplit=2)[1].strip().split(" ")
            for flag in flags:
                    test[2].append([int(flag), -1])
    tests.append(test)

for file in glob.glob(os.path.join(SCRIPT_DIR, "test", "*.c")):
    parse_test(file, os.path.basename(file)[:-2])
# C++ tests get a "_cpp" suffix so they don't collide with the .c port of the
# same name (e.g. struct.c vs struct.cpp).
for file in glob.glob(os.path.join(SCRIPT_DIR, "test", "*.cpp")):
    parse_test(file, os.path.basename(file)[:-4] + "_cpp")

ko_clang = f"{build_folder}/bin/ko-clang"
ko_clangxx = f"{build_folder}/bin/ko-clang++"
# Build outputs (ll/, binary/, and whatever the manager drops relative to cwd
# e.g. solving-error/, blocking/) live under the build tree, keyed off the
# same build_folder ko-clang/ko-clang++ already resolve against.
OUT_DIR = os.path.join(build_folder, "tests", "ucsan")

GREEN = "\033[32m"
RED = "\033[31m"
ORANGE = "\033[33m"
YELLOW = "\033[33m"
RESET = "\033[0;0m"
colored = lambda color, text: f"{color}{text}{RESET}"

def run(cmd, cwd=build_folder, env=common_env):
    if isinstance(cmd, str):
        cmd = cmd.split(" ")
    return subprocess.run(cmd, check=True, cwd=cwd, env=env)

class Proxy():
    def __init__(self, value = "", color = ""):
        self._value = value
        self.color = None

    def set_value(self, value):
        self._value = value
    def get(self):
        return self._value

def perform_test(stage, *args, seed=None):
    stage.set_value("Start")
    env = os.environ.copy()
    env.update(common_env)

    test_name = args[0]
    metafile = args[1]
    flags = args[2]

    # Set METADATA for compilation
    env['METADATA'] = os.path.join(SCRIPT_DIR, "metadata", metafile)

    # Categorize ENV variables into UCSAN vs TAINT options
    # UCSAN flags (from ucsan_flags.inc)
    ucsan_flags = {'debug', 'trace_object', 'checker_nullderef', 'no_upcast',
                   'trace_bounds', 'no_enlarge', 'max_obj_size', 'input_file'}
    # Map old ucsan option names to KO_ compile env vars
    ucsan_to_ko = {'trace_bb': 'KO_TRACE_BB'}

    ucsan_options = {}
    taint_options = {}
    for arg in args[3:]:
        if arg in ucsan_to_ko:
            taint_options[ucsan_to_ko[arg]] = "1"
        elif arg in ucsan_flags:
            ucsan_options[arg] = "1"
        else:
            taint_options[arg] = "1"

    # For compilation, use all options
    compile_options = {}
    compile_options.update(ucsan_options)
    compile_options.update(taint_options)
    env.update(compile_options)

    # C++ tests use the "_cpp" suffix and compile from .cpp with ko-clang++.
    is_cpp = test_name.endswith("_cpp")
    if is_cpp:
        src = os.path.join(SCRIPT_DIR, "test", f"{test_name[:-4]}.cpp")
        cc = ko_clangxx
    else:
        src = os.path.join(SCRIPT_DIR, "test", f"{test_name}.c")
        cc = ko_clang

    # Test sources predate clang's C99 implicit-function-declaration rule
    # (hard error since clang-16); tolerate it here since it's a test property.
    compat_flags = "-Wno-error=implicit-function-declaration"

    # Compile with new command format
    compile_cmd = f"{cc} -g -S -emit-llvm {compat_flags} -o ll/{test_name}.ll {src}"
    run(compile_cmd, cwd=".", env=env)

    compile_binary_cmd = f"{cc} -g {compat_flags} -o binary/{test_name}.ucsan {src}"
    run(compile_binary_cmd, cwd=".", env=env)

    stage.set_value('Compiled')
    if flags:
        triggered = {}
        for flag in flags:
            triggered[flag[0]] = 0
        debug = True if level == logging.DEBUG else False

        # trace_bounds / solve_ub are both ucsan flags (UCSAN_OPTIONS) and
        # dfsan flags (TAINT_OPTIONS); see thoroupy/debug.py.  The dfsan side
        # labels the malloc'd object's bound and runs __taint_solve_size, which
        # is what makes an OOB through a *symbolic* length (e.g.
        # memcpy(d, s, *payload)) solvable.  Mirror trace_bounds into the taint
        # options and enable runtime solve_ub (paired with KO_SOLVE_UB).
        if 'trace_bounds' in ucsan_options:
            taint_options.setdefault('trace_bounds', "1")
            taint_options.setdefault('solve_ub', "1")

        # Build runtime env with properly categorized options
        runtime_env = {}
        runtime_env.update(taint_options)
        if ucsan_options:
            runtime_env['ucsan_options'] = ucsan_options

        m = UcsanManager(f'binary/{test_name}.ucsan', config=ucsan_config, terminate=False, env=runtime_env, adapter=adapter, seed=seed, debug=debug)
        m.run()
        for exit_status in m.exit_status:
            if exit_status > 255:
                exit_status = exit_status >> 8
            stage.set_value(f"Unexpected status: {exit_status}")
            triggered[exit_status] += 1

        message = []
        for flag in flags:
            key = flag[0]
            expected = flag[1]
            if expected == 0:
                expected = "any"
            if expected == -1:
                expected = "discard"
            v = triggered[flag[0]]
            message.append(f"{key}:{v}/{expected}")
        message = ",".join(message)
        stage.set_value(message)

        for flag in flags:
            if flag[1] == -1:
                continue
            if flag[1] != 0 and triggered[flag[0]] != flag[1]:
                raise Exception(f"Flag {flag[0]} triggered {triggered[flag[0]]} times, expected {flag[1]}")
            if flag[1] == 0 and triggered[flag[0]] == 0:
                raise Exception(f"Flag {flag[0]} not triggered")
        stage.set_value(f'Passed({message})')
    else:
        stage.set_value('Passed(Compile only)')
        stage.color = ORANGE

if __name__ == "__main__":
    target = None
    args = argparse.ArgumentParser()
    args.add_argument("-p", help="The build folder", default=build_folder)
    args.add_argument("-q", help="Quiet mode", action="store_true")
    args.add_argument("-v", '--verbose', help="Verbose", action="count", default=0)
    args.add_argument("-s", help="Stop immediately on error", action="store_true")
    args.add_argument("-f", "--file", help="Write log to file")
    args.add_argument("--skip", help="Skip specific tests", action="append", default=[])
    sub_parser = args.add_subparsers(title="tools")
    parser_test = sub_parser.add_parser("test", help="Run specific tests")
    parser_test.add_argument("test_name", help="The name of the test", nargs="+")
    parser_test.add_argument("-v", '--verbose', help="Verbose", action="count", default=0)
    parser_test.add_argument("-g", '--debug', help="Debug", action="store_true", default=False)

    def clean():
        shutil.rmtree(os.path.join(OUT_DIR, "ll"), ignore_errors=True)
        shutil.rmtree(os.path.join(OUT_DIR, "binary"), ignore_errors=True)
        os._exit(0)
    parser_clean = sub_parser.add_parser("clean", help="Clean up the test environment")
    parser_clean.set_defaults(func=clean)

    parser_run_seed = sub_parser.add_parser("run_seed", help="Run specific seed")
    parser_run_seed.add_argument("test_name", help="The name of the test")
    parser_run_seed.add_argument("seed", help="The seed to run")
    parser_run_seed.add_argument("-g", '--debug', help="Use gdb adapter to debug", action="store_true", default=False)

    def show_test():
        print("Available tests:\n\n\t", end="")
        print("\n\t".join([test[0] for test in tests]))
        print("")
        parser_test.print_help()
        os._exit(0)
    parser_list = sub_parser.add_parser("list", help="List all tests")
    parser_list.set_defaults(func=show_test)

    args = args.parse_args()

    build_folder = args.p if args.p else build_folder

    levels = [logging.WARNING, logging.INFO, logging.DEBUG]
    level = levels[min(args.verbose, len(levels) - 1)]

    seed = None
    if 'seed' in args:
        seed = args.seed
        level = logging.DEBUG

    logging.basicConfig(level = level ,format = '[%(asctime)s] %(levelname)s [%(name)s:%(lineno)s] %(message)s')

    if args.q:
        logging.disable(logging.CRITICAL)

    if args.file:
        fh = logging.FileHandler(args.file)
        fh.setLevel(level)
        logging.getLogger().addHandler(fh)

    if 'func' in args:
        args.func()

    if 'test_name' in args:
        target = args.test_name
    else:
        target = None
    if 'debug' in args and args.debug:
        adapter = populate_gdb

    # Check if ko-clang exists
    if not os.path.exists(ko_clang):
        print(f"{colored(RED, 'ERROR')}: ko-clang not found at {ko_clang}")
        print(f"Please build symsan first or specify correct build folder with -p")
        sys.exit(1)

    # Everything the manager itself drops relative to cwd (solving-error/,
    # blocking/, etc.) lands under OUT_DIR too, not the source tree.
    os.makedirs(OUT_DIR, exist_ok=True)
    os.chdir(OUT_DIR)
    os.makedirs("ll", exist_ok=True)
    os.makedirs("binary", exist_ok=True)
    tasks = []
    max_len = 0
    errors = 0
    for test in tests:
        if test[0] in args.skip:
            tasks.append((test[0], colored(YELLOW, "Skipped")))
            continue
        stage = Proxy()
        if target and test[0] not in target:
            continue
        if len(test[0]) > max_len:
            max_len = len(test[0]) // 16 * 16 + 16
        try:
            if args.verbose > 2:
                test.append("debug")
            perform_test(stage, *test, seed=seed)
            if stage.color:
                tasks.append((test[0], colored(stage.color, stage.get())))
            else:
                tasks.append((test[0], colored(GREEN, stage.get())))
        except Exception as e:
            logging.exception(e)
            errors += 1
            tasks.append((test[0], colored(RED, "Failed") + f"({stage.get()})"))
            if args.s:
                break

    print("\n\nTest results:")
    for task in tasks:
        print(f"{task[0]:{max_len}}: ", end="")
        print(task[1])

    if errors:
        print(f"\nOpps! Some tests failed!")
        print(f"You may use `{sys.argv[0]} test <test_name>` to run a specific test")
    sys.exit(0 if errors == 0 else 1)
