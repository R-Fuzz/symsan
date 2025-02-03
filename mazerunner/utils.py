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
        if policy[bid][0] is None or policy[bid][1] is None:
            critical_branches.append(bid)
    with open(file_path, "w") as f:
        for bid in critical_branches:
            f.write(f"{bid}\n")

class SourceCodeFinder:
    def __init__(self, config):
        """
        Initialize the SourceCodeFinder with a given configuration.

        :param config: An object containing necessary paths and settings.
        """
        self.config = config
        self.logger = logging.getLogger(self.__class__.__qualname__)
        self.bin_path = self.config.cmd[0]

        if not os.path.isfile(self.bin_path):
            self.logger.error(f"binary file {self.bin_path} does not exist.")
        if not os.path.isfile(self.config.addr2line_path):
            self.logger.error(f"addr2line not found in {self.config.addr2line_path }")

        # A dictionary for caching function info: {fn_guid -> (function_name, filename, start_line_number, end_line_number)}
        self.function_infos = self._load_function_info(
            os.path.join(config.static_result_folder, "function_info.txt")
        )
        # A dictionary for caching source code location: {bid -> (fn_guid, filename:line_number)}
        self.loc_bid_cache = self._load_loc_bid_mapping(
            os.path.join(self.config.static_result_folder, "bid_loc_mapping.txt")
        )
        # A dictionary for caching source code location: {addr -> (function_name, filename:line_number)}
        self.loc_addr_cache = {}
        # A dictionary for caching file contents: {full_path -> [lines]}
        self.file_contents = {}
        # A dictionary for caching full paths: {filename -> full_path}
        self.fn_to_fp = {}

    def find_abs_path(self, filename):
        """
        Recursively search for the specified filename within the configured source directory.

        :param filename: Name of the file to locate.
        :return: Absolute path of the first match, or an empty string if none is found.
        """
        if filename in self.fn_to_fp:
            return self.fn_to_fp[filename]
        for root, _, files in os.walk(self.config.source_code_dir):
            if filename in files:
                fp = os.path.join(root, filename)
                self.fn_to_fp[filename] = fp
                return fp
        self.logger.error(f"file {filename} not found in {self.config.source_code_dir}")
        self.fn_to_fp[filename] = ""
        return ""

    def find_loc_info(self, bid, addr=None):
        """
        Retrieve function/location info based on a basic block ID or an address.

        :param bid: Basic block ID (integer).
        :param addr: Optional memory address to query via addr2line.
        :return: A tuple (function_name, location_string) or ("", "") if not found.
        """
        if bid in self.loc_bid_cache:
            fn_guid, loc = self.loc_bid_cache[bid]
            if fn_guid in self.function_infos:
                func_name = self.function_infos[fn_guid][0]
                return (func_name, loc)

        if not addr:
            return ("", "")

        if addr in self.loc_addr_cache:
            return self.loc_addr_cache[addr]
        
        self.logger.debug(f"Loc info not found for bid {bid}, querying addr2line")
        # Convert the address to a hex string before calling addr2line
        cmd = [
            self.config.addr2line_path ,
            "-e", self.bin_path,
            "-p",  # More friendly format
            "-f",  # Show function name
            "-s",  # Suppress some redundant info
            hex(addr)
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
        except Exception as e:
            self.logger.error(f"Error running addr2line: {e}")
            self.loc_addr_cache[addr] = ("", "")
            return ("", "")

        if result.returncode != 0:
            self.logger.error(f"addr2line failed: {result.stderr}")
            self.loc_addr_cache[addr] = ("", "")
            return ("", "")

        # Example output might be "ckprefix at i386-dis.c:12312"
        output = result.stdout.strip()
        if " at " not in output:
            self.loc_addr_cache[addr] = ("", "")
            return ("", "")

        parts = output.split(" at ")
        if len(parts) < 1:
            self.loc_addr_cache[addr] = ("", "")
            return ("", "")

        func_name = parts[0].strip()
        if func_name.startswith("dfs$"):
            func_name = func_name[4:]
        loc = parts[1].strip()
        if not func_name or "??" in func_name:
            func_name = ""
        if not loc or "??" in loc:
            loc = ""

        self.loc_addr_cache[addr] = (func_name, loc)
        return func_name, loc

    def get_function_source_code(self, guid):
        """
        Return the source code of the function identified by the given GUID.

        :param guid: The unique GUID of the function as generated by LLVM.
        :return: The full source code of the function as a string, or an empty string if unavailable.
        """
        filename = self.function_infos[guid][1]
        start_line_number = self.function_infos[guid][2]
        end_line_number = self.function_infos[guid][3]
        fp = self.find_abs_path(filename)
        if not os.path.isfile(fp):
            return ""
        function_source_code = ""
        for i in range(start_line_number, end_line_number + 1):
            l = self._get_code_line(fp, i)
            if not l:
                break
            function_source_code += l + "\n"
        return function_source_code

    def get_code_line(self, filename, line_number):
        """
        Return the specific line content from the specified source file by line number.

        :param filename: Name of the source file.
        :param line_number: 1-based index of the line to retrieve.
        :return: The line's content without any trailing newline, or an empty string if out of range.
        """
        fp = self.find_abs_path(filename)
        if not os.path.isfile(fp):
            self.logger.warning(f"file {fp} does not exist.")
            return ""
        return self._get_code_line(fp, line_number)

    def _get_code_line(self, full_path, line_number):
        """
        Internal helper to retrieve a single line from a loaded file.

        :param full_path: Absolute path to the source file.
        :param line_number: 1-based index of the line to retrieve.
        :return: The line content without the trailing newline, or an empty string if invalid.
        """
        self._get_file_contents(full_path)

        lines = self.file_contents[full_path]
        if line_number < 1 or line_number > len(lines):
            self.logger.warning(f"Line number {line_number} out of range for file {full_path}")
            return ""

        return lines[line_number - 1].rstrip("\n")

    def _get_file_contents(self, full_path):
        """
        Internal helper to read and cache the entire file content.

        :param full_path: Absolute path to the source file.
        """
        if not os.path.isfile(full_path):
            self.file_contents[full_path] = []
            return

        if full_path not in self.file_contents:
            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    self.file_contents[full_path] = f.readlines()
            except Exception as e:
                self.logger.error(f"Error reading file {full_path}: {e}")
                self.file_contents[full_path] = []

    def _load_loc_bid_mapping(self, fp):
        """
        Load the mapping of BIDs to function GUID and source location from the given file.

        File format: Each line should have 3 comma-separated columns:
          1) Basic block ID (integer)
          2) Function GUID (integer)
          3) Location string (e.g., filename:line_number)

        :param fp: The path to the 'bid_loc_mapping.txt' file.
        :return: A dictionary with BID as the key and a tuple (fn_guid, loc) as the value.
        """
        d = {}
        if not os.path.isfile(fp):
            self.logger.error(f"file {fp} does not exist.")
            return d
        with open(fp, 'r') as file:
            for l in file.readlines():
                if not l.strip():
                    continue
                items = l.strip().split(',')
                assert len(items) == 3
                bid = int(items[0])
                fn_guid = int(items[1])
                loc = items[2]
                d[bid] = (fn_guid, loc)
        self.logger.debug(f"bid_loc_mapping loaded from {fp}, size: {len(d)}")
        return d

    def _load_function_info(self, fp):
        """
        Load function information from the specified file.

        File format: Each line should contain 5 comma-separated columns:
          1) Function GUID (integer)
          2) Function name (string)
          3) Source filename (string)
          4) Start line number (integer)
          5) End line number (integer)

        :param fp: The path to the 'function_info.txt' file.
        :return: A dictionary mapping function GUID to a tuple:
                 (function_name, filename, start_line, end_line).
        """
        d = {}
        if not os.path.isfile(fp):
            self.logger.error(f"file {fp} does not exist.")
            return d
        with open(fp, 'r') as file:
            for l in file.readlines():
                if not l.strip():
                    continue
                items = l.strip().split(',')
                assert len(items) == 5
                fn_guid = int(items[0])
                function_name = items[1]
                if function_name.startswith("dfs$"):
                    function_name = function_name[4:]
                filename = items[2]
                start_line_number = int(items[3])
                end_line_number = int(items[4])
                d[fn_guid] = (function_name, filename, start_line_number, end_line_number)
        self.logger.debug(f"function_info loaded from {fp}, size: {len(d)}")
        return d
