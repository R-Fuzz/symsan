import os
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
    return None if not match else float(match.group(1))

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

# find the bottom numbers in the given list
# test_cases = {
#     "case1": ([1, 2, 3], [0]),
#     "case2": ([3, 2, 1], [2]),
#     "case3": ([2, 1, 3], [1]),
#     "case4": ([2, 1, 3, 0, 4], [1, 3]),
#     "case5": ([0, 2, 1, 4, 5, 6, -1], [0, 2, 6]),
#     "case6": ([-1., -2.5], [1]),
#     "case7": ([0], [0]),
#     "case8": ([1, 1, 1, 1, 1], [0]),
#     "case9": ([1, 1, 1, 0, 1], [3]),
# }
def find_bottom_numbers(nums):
    assert nums
    if len(nums) == 1:
        return [0]
    min_val = nums[0]
    min_vals = set()
    min_indices = []
    
    for i, num in enumerate(nums):
        if i == 0:
            if num < nums[i+1]:
                min_vals.add(min_val)
            continue
        if num <= nums[i-1]:
            min_val = num
        if i < len(nums) - 1 and num <= nums[i-1] and num < nums[i+1]:
            min_vals.add(min_val)
        if i == len(nums) - 1 and num <= nums[i-1]:
            min_vals.add(min_val)

    for i, num in enumerate(nums):
        if num in min_vals:
            min_indices.append(i)
            min_vals.remove(num)
    
    return min_indices
