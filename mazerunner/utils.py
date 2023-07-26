import os
import psutil
import copy
import subprocess
import time

AT_FILE = "@@"

def mkdir(dirp):
    if not os.path.exists(dirp):
        os.makedirs(dirp)

def fix_at_file(cmd, testcase):
    cmd = copy.copy(cmd)
    if AT_FILE in cmd:
        idx = cmd.index(AT_FILE)
        cmd[idx] = testcase
        stdin = None
    else:
        with open(testcase, "rb") as f:
            stdin = f.read()
    return cmd, stdin

def run_command(cmd, testcase):
    cmd, stdin = fix_at_file(cmd, testcase)
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p.communicate(stdin.encode())

def get_folder_size(dir_path):
    total = 0
    with os.scandir(dir_path) as it:
        for entry in it:
            if entry.is_file():
                total += entry.stat().st_size
            elif entry.is_dir():
                total += get_folder_size(entry.path)
    return total

def monitor_disk(termination_event, interval, dir_path, disk_limit):
    while not termination_event.is_set():
        folder_size = get_folder_size(dir_path)
        if folder_size > disk_limit:
            print(f"Disk usage is {folder_size / 2**30}GB - terminating")
            termination_event.set()
        time.sleep(interval)

def monitor_memory(termination_event, interval, memory_limit):
    total_memory = psutil.virtual_memory().total # in bytes
    process = psutil.Process(os.getpid())
    while not termination_event.is_set():
        process_memory = process.memory_info().rss  # in bytes
        percent_memory_used = (process_memory / total_memory) * 100
        if percent_memory_used > memory_limit:
            print(f"Memory usage is {percent_memory_used}% - terminating")
            termination_event.set()
        time.sleep(interval)
