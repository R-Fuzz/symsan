#!/usr/bin/env python3
import argparse
import logging
import os
import time

import afl
import utils
from config import Config

logging.basicConfig(level=logging.INFO)

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("-agent", dest="agent_type", required=True, help="RL agent type")
    p.add_argument("-o", dest="output_dir", required=True, help="hybrid fuzzing output directory")
    p.add_argument("-a", dest="afl_dir", required=True, help="AFL name")
    p.add_argument("-n", dest="mazerunner_dir", default="mazerunner", help="mazerunner output directory")
    p.add_argument("-i", dest="input", default=None, help="initial seed directory")
    p.add_argument("-m", dest="mail", default=None, help="Interesting result will be sent to the Email address")
    p.add_argument("-deli", dest="deli", default=None, help="Delimiter used to split the input")
    p.add_argument("-pkglen", dest="pkglen", default=None, help="length of how many bytes used to split the input")
    p.add_argument("-log", dest="log_file", default=None, help="Enable logging to file")
    p.add_argument("-config", dest="config_path", default=None, help="path of configuration file")
    p.add_argument("-debug", dest="debug_enabled", action="store_true", help="Enable debug mode")
    p.add_argument("cmd", nargs="+", help=f"cmdline, use {utils.AT_FILE} to denote a file")
    return p.parse_args()

def check_args(args):
    if not args.cmd:
        raise ValueError("no cmd provided")
    if not os.path.isdir(args.output):
        raise ValueError('{args.output} no such directory')
    afl_path = os.path.join(args.output, args.afl_dir)
    if not os.path.isdir(afl_path):
        time.sleep(1)
        if not os.path.isdir(afl_path):
            raise ValueError('{args.afl_dir} no such directory')

def main():
    config = Config()
    args = parse_args()
    check_args(args)
    config.load(args.config_path)
    config.reload(args)

    if args.agent_type == "explore":
        e = afl.ExploreExecutor(config)
    elif args.agent_type == "exploit":
        e = afl.ExploitExecutor(config)
    elif args.agent_type == "record":
        e = afl.RecordExecutor(config)
    elif args.agent_type == "replay":
        e = afl.ReplayExecutor(config)
    elif args.agent_type == "qsym":
        e = afl.QSYMExecutor(config)
    # TODO: add RLhybrid(explore + exploit) agent
    else:
        raise ValueError(f"unknown agent type {args.agent_type}")
    try:
        e.run()
    finally:
        e.cleanup()

if __name__ == "__main__":
    main()
