#!/usr/bin/env python3
import argparse
import os
import random
import threading
import time

import afl
from config import Config
from utils import AT_FILE, monitor_memory, monitor_disk

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("-agent", dest="agent_type", required=True, help="RL agent type")
    p.add_argument("-o", dest="output_dir", required=True, help="hybrid fuzzing output path")
    p.add_argument("-n", dest="mazerunner_dir", default="mazerunner", help="mazerunner instance name")
    p.add_argument("-a", dest="afl_dir", default=None, help="AFL instance name")
    p.add_argument("-i", dest="input", default=None, help="initial seed directory")
    p.add_argument("-m", dest="mail", default=None, help="Interesting result will be sent to the Email address")
    p.add_argument("-config", dest="config_path", default=None, help="path of configuration file")
    p.add_argument("-debug", dest="debug_enabled", action="store_true", help="Enable debug mode")
    p.add_argument("-monitor_resource", dest="resource_monitor_enabled", action="store_true", help="Enable memory and disk usage monitor")
    p.add_argument("cmd", nargs="+", help=f"cmdline, use {AT_FILE} to denote a file")
    # TODO: implement these two options
    p.add_argument("-deli", dest="deli", default=None, help="Delimiter used to split the input")
    p.add_argument("-pkglen", dest="pkglen", default=None, help="length of how many bytes used to split the input")
    return p.parse_args()

def check_args(args):
    if not args.cmd:
        raise ValueError("no cmd provided")
    if args.agent_type == "qsym" and not args.afl_dir:
        raise ValueError("You must provide -a option")
    if not args.input and not args.afl_dir:
        raise ValueError("You must provide either -i or -a option")
    if not os.path.isdir(args.output_dir):
        raise ValueError('{args.output} no such directory')
    if args.afl_dir:
        # wait for afl fuzzer to start and initialize itself
        time.sleep(5)
        afl_path = os.path.join(args.output_dir, args.afl_dir)
        if not args.input and not os.path.isdir(afl_path):
            raise ValueError('{args.afl_dir} no such directory')

def main():
    random.seed(time.time())
    args = parse_args()
    check_args(args)
    config = Config()
    config.load(args.config_path)
    config.reload(args)

    if args.agent_type == "hybrid":
        e = afl.HybridExecutor(config)
    elif args.agent_type == "explore":
        e = afl.ExploreExecutor(config)
    elif args.agent_type == "exploit":
        e = afl.ExploitExecutor(config)
    elif args.agent_type == "record":
        e = afl.RecordExecutor(config)
    elif args.agent_type == "replay":
        e = afl.ReplayExecutor(config)
    elif args.agent_type == "qsym":
        e = afl.QSYMExecutor(config)
    else:
        raise ValueError(f"unknown agent type {args.agent_type}")
    
    if args.resource_monitor_enabled:
        # Start a background thread to check memory usage every 10 minutes
        memory_termination_event = threading.Event()
        memory_monitor = threading.Thread(target=monitor_memory, 
                                        args=(memory_termination_event, 10*60, config.memory_limit))
        memory_monitor.start()
        # Start a background thread to check disk usage every 10 minutes
        disk_termination_event = threading.Event()
        disk_monitor = threading.Thread(target=monitor_disk, 
                                        args=(disk_termination_event, 10*60, 
                                            config.mazerunner_dir, config.disk_limit))
        disk_monitor.start()
        e.check_resource_limit = lambda: (memory_termination_event.is_set() 
                                                or disk_termination_event.is_set())
    try:
        e.run()
    finally:
        e.cleanup()
        if args.resource_monitor_enabled:
            memory_termination_event.set()
            disk_termination_event.set()
            memory_monitor.join()
            disk_monitor.join()

if __name__ == "__main__":
    main()
