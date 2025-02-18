#!/usr/bin/env python3
import argparse
import logging
import random
import signal
import threading
import time
import psutil
import sys
import os

import afl
from config import Config
from utils import AT_FILE, get_folder_size

def monitor_disk(termination_event, interval, dir_path, disk_limit):
    while not termination_event.is_set():
        folder_size = get_folder_size(dir_path)
        if folder_size > disk_limit:
            print(f"Disk usage is {folder_size / 2**30}GB - terminating")
            termination_event.set()
        termination_event.wait(interval)

def monitor_memory(termination_event, interval, memory_limit):
    process = psutil.Process(os.getpid())
    while not termination_event.is_set():
        process_memory = process.memory_info().rss  # in bytes
        print(f"Memory usage is {int(process_memory/1000)}KB")
        if process_memory > memory_limit:
            print(f"Out of memory - terminating")
            termination_event.set()
        termination_event.wait(interval)

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("-a", dest="agent_type", default=None, help="RL agent type")
    p.add_argument("-m", dest="model_type", default="reachability", help="RL model type")
    p.add_argument("-o", dest="output_dir", default=None, help="hybrid fuzzing output path")
    p.add_argument("-s", dest="static_result_folder", default=None, help="static analysis results folder that saves the distance information and initial policy")
    p.add_argument("-c", dest="source_code_folder", default=None, help="source code folder of the program under test")
    p.add_argument("-f", dest="fuzzer_dir", default=None, help="AFL fuzzer instance name")
    p.add_argument("-n", dest="mazerunner_dir", default="mazerunner", help="mazerunner instance name")
    p.add_argument("-i", dest="input_dir", default=None, help="initial seed directory")
    p.add_argument("-config", dest="config_path", default=None, help="path of configuration file")
    p.add_argument("-debug", dest="debug_enabled", action="store_true", help="Enable debug mode")
    p.add_argument("-monitor_resource", dest="resource_monitor_enabled", action="store_true", help="Enable memory and disk usage monitor")
    p.add_argument("cmd", nargs="+", help=f"cmdline, use {AT_FILE} to denote a file")
    return p.parse_args()

def validate_args(args):
    if not args.cmd:
        raise ValueError("no cmd provided")
    if (args.config_path is None
        and any(arg is None for arg in [args.agent_type, args.output_dir, args.static_result_folder])):
        raise ValueError("You must provide either -config or -o -s -a options")
    if not os.path.isdir(args.output_dir):
        raise ValueError(f'{args.output_dir} no such directory')
    if args.agent_type == "record" and args.fuzzer_dir is None and args.input_dir is None:
        raise ValueError("You must provide either -i or -f option for record agent")

def main():
    random.seed(time.time())
    args = parse_args()
    validate_args(args)
    config = Config()
    config.load(args.config_path)
    config.load_args(args)
    
    logging.basicConfig(level=config.logging_level)
    logging.getLogger('Launcher').info("[*] spinning up mazerunner: " + " ".join(sys.argv))

    if config.agent_type == "explore":
        e = afl.RLExecutor(config, "explore")
    elif config.agent_type == "exploit":
        e = afl.RLExecutor(config, "exploit")
    elif config.agent_type == "record":
        e = afl.RecordExecutor(config)
    elif config.agent_type == "replay":
        e = afl.ReplayExecutor(config)
    elif config.agent_type == "symsan":
        e = afl.SymSanExecutor(config)
    else:
        raise ValueError(f"unknown agent type {config.agent_type}")
    
    if args.resource_monitor_enabled:
        # Start a background thread to check memory usage every minute
        memory_termination_event = threading.Event()
        memory_monitor = threading.Thread(target=monitor_memory, 
                                        args=(memory_termination_event, 1*60, config.memory_limit))
        memory_monitor.start()
        # Start a background thread to check disk usage every 10 minute
        disk_termination_event = threading.Event()
        disk_monitor = threading.Thread(target=monitor_disk, 
                                        args=(disk_termination_event, 10*60, 
                                            config.mazerunner_dir, config.disk_limit))
        disk_monitor.start()
        e.memory_termination_event = memory_termination_event
        e.disk_termination_event = disk_termination_event
    
    def close_monitors():
        if args.resource_monitor_enabled:
            memory_termination_event.set()
            disk_termination_event.set()
            memory_monitor.join()
            disk_monitor.join()

    def signal_handler(signum, frame):
        logging.info(f"Received signal {signum}, cleaning up...")
        e.cleanup()
        close_monitors()
        sys.exit(signum)

    for sig in (signal.SIGABRT, signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, signal_handler)
    try:
        e.run()
    finally:
        e.cleanup()
        close_monitors()
if __name__ == "__main__":
    main()
