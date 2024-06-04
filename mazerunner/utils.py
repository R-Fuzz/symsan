import os
import copy
import subprocess
import re
import resource

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
    with open(testcase, "rb") as f:
        file_content = f.read()
    if AT_FILE in cmd:
        idx = cmd.index(AT_FILE)
        cmd[idx] = testcase
        stdin = None
    else:
        with open(testcase, "rb") as f:
            stdin = file_content
    return cmd, stdin, file_content

def get_distance_from_fn(filename):
    match = re.search(r'dis:(\d+)', filename)
    return None if not match else float(match.group(1))

def get_id_from_fn(s):
    assert 'id:' in s and len(s) > len("id:......")
    return int(s[len("id:"):len("id:......")])

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

def find_local_min(nums):
    assert nums
    if len(nums) == 1:
        return [0]
    local_min = nums[0]
    global_min = nums[0]
    min_vals = set()
    min_indices = []
    
    for i, num in enumerate(nums):
        if i == 0:
            if num < nums[i+1]:
                min_vals.add(local_min)
            continue
        if num <= nums[i-1]:
            local_min = num
        if i < len(nums) - 1 and num <= nums[i-1] and num < nums[i+1] and num < global_min:
            min_vals.add(local_min)
        if i == len(nums) - 1 and num <= nums[i-1] and num < global_min:
            min_vals.add(local_min)
        if num < global_min:
            global_min = num

    for i, num in enumerate(nums):
        if num in min_vals:
            min_indices.append(i)
            min_vals.remove(num)
    
    return min_indices

def disable_core_dump():
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except ValueError:
        print(f"Failed to disable core dump. \n"
                    f"Please try to set it manually by running: "
                    f"'ulimit -c 0'")
