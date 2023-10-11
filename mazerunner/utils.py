import os
import psutil
import copy
import subprocess
import time
import re

AT_FILE = "@@"
MILLION_SECONDS_SCALE = 1000
MAX_BUCKET_SIZE = 256
COUNT_CLASS_LOOKUP = [
    i if i <= 32 else
    33 if 33 <= i <= 63 else
    64 if 64 <= i <= 95 else
    96 if 96 <= i <= 127 else
    128 if 128 <= i <= 159 else
    160 if 160 <= i <= 191 else
    192 if 192 <= i <= 223 else
    224 if 224 <= i <= 255 else
    0  # default
    for i in range(MAX_BUCKET_SIZE)
]

def bucket_lookup(c):
    if c >= MAX_BUCKET_SIZE:
        return MAX_BUCKET_SIZE
    return COUNT_CLASS_LOOKUP[c]

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

def get_distance_from_fn(filename):
    match = re.search(r'dis:(\d+)', filename)
    return None if not match else int(match.group(1))

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
