import copy
import os
import subprocess
import logging
import re
import resource

AT_FILE = "@@"
MILLI_SECONDS_SCALE = 1000
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
    total_size = 0
    seen_inodes = set()
    for dirpath, dirnames, filenames in os.walk(dir_path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            try:
                stat = os.stat(fp)
                if stat.st_ino not in seen_inodes:
                    seen_inodes.add(stat.st_ino)
                    total_size += stat.st_size
            except:
                continue
    return total_size

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

def make_critical_branches_file(policy, file_path):
    critical_branches = []
    for bid in policy:
        if policy[bid][0] is None and policy[bid][1] is None:
            continue
        if policy[bid][0] is None:
            critical_branches.append(bid)
        if policy[bid][1] is None:
            critical_branches.append(bid)
    with open(file_path, "w") as f:
        for bid in critical_branches:
            f.write(f"{bid}\n")


def get_critical_branches(policy):
    critical_branches = []
    for bid in policy:
        if policy[bid][0] is None and policy[bid][1] is None:
            continue
        if policy[bid][0] is None:
            critical_branches.append((bid, True))
        if policy[bid][1] is None:
            critical_branches.append((bid, False))
    return critical_branches

def get_policy_from_txt(file_path):
    policy = {}
    if not os.path.isfile(file_path):
        return policy
    with open(file_path, 'r') as file:
        for l in file.readlines():
            if not l.strip():
                continue
            if l.startswith('##########'):
                break
            items = l.strip().split(',')
            assert len(items) == 3
            bid = int(items[0])
            df = float(items[1]) if items[1] != 'inf' else None
            dt = float(items[2]) if items[2] != 'inf' else None
            policy[bid] = (df, dt)
    return policy

def hexdump(file_content, width=16):
    """
    Mimics the behavior of `xxd` and generates a hexadecimal dump of the given binary content.
    
    :param file_content: Binary content to be dumped.
    :param width: Number of bytes per line (default: 16).
    :return: A formatted hexdump string.
    """
    hex_lines = []
    for offset in range(0, len(file_content), width):
        chunk = file_content[offset : offset + width] 
        # Convert to hex
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        # Convert to ASCII representation (printable characters or '.')
        ascii_part = "".join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        # Format the line similar to xxd output
        hex_lines.append(f"{offset:08x}: {hex_part.ljust(width * 3)} {ascii_part}")
    return "\n".join(hex_lines)
