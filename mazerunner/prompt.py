
import collections
import logging
import os
import subprocess

import utils

class OrderedSet:
    def __init__(self, iterable=None):
        self._dict = collections.OrderedDict.fromkeys(iterable or [])

    def add(self, item):
        self._dict[item] = None

    def remove(self, item):
        self._dict.pop(item)

    def __iter__(self):
        return iter(self._dict)

    def __contains__(self, item):
        return item in self._dict

    def __len__(self):
        return len(self._dict)

    def __repr__(self):
        return f"OrderedSet({list(self._dict.keys())})"

class PromptBuilder:
    CRITICAL_BRANCHES_BASELINE_PROMPT = '''
You are an advanced concolic execution engine with expert knowledge in software testing, \
dynamic program analysis, and input generation techniques. \
You are currently testing the binutils project and are very familiar with its source code. \

The command line arguments are:
objdump -SD <input_file>

Your task is to analyze some critical branches in the program and generate inputs to cover them.
You have the following sources of information:
    1. critical branches and their corresponding conditions that must be satisfied
    2. Relevant Source Code: The corresponding binutils source code, with each line numbered at the beginning.

Using these materials, please write a python3 script to generate such input_file.
'''

    CONCRET_DIVERGENT_BRANCH_PROMPT = '''
You are an advanced concolic execution engine with expert knowledge in software testing, \
dynamic program analysis, and input generation techniques. \
Your expertise includes analyzing both symbolic and concrete branches in program execution. \
In concolic execution, while symbolic branches can be directly solved, \
concrete branches present unique challenges.

You are currently testing the binutils project and are very familiar with its source code. \
Your task is to analyze a specific concrete branch divergence \
by examining the following three sources of information:
	1.	Input Hexdump: A hexdump representation of the input content.
	2.	Symbolic Branch Trace: A chronologically ordered list of symbolic branch events during execution.
	3.	Relevant Source Code: The corresponding binutils source code, with each line numbered at the beginning.

Using these materials, please answer the following questions:
	1.	Identify Impactful Symbolic Branches:
List the symbolic branches from the provided trace \
that may have influenced or contributed to the observed concrete branch divergence. \
Explain your reasoning based on the trace information.
	2.	Determine Additional Influential Locations:
Identify potential program locations (using the format file_name:line_number) \
that are not present in the provided trace but could affect the concrete branch. \
Consider data dependencies, control flow interactions, or other relevant factors from the source code.
    '''
    
    def __init__(self, config, code_finder):
        self.config = config
        self.code_finder = code_finder
        self.logger = logging.getLogger(self.__class__.__qualname__)
        self._func_codes = {}

    def build_concret_divergent_branch_prompt(self, episode, divergent_branch_info, input_content):
        prompt_str = ""
        related_code_info = collections.defaultdict(set)
        policy = self.config.initial_policy
        
        # divergent branch handling
        d, ep_index, bid, action, loc, func_name = divergent_branch_info
        filepath = self.code_finder.get_fp_from_bid(bid)
        linenum = int(loc.split(":")[1])
        line_code = self.code_finder.get_code_line(filepath, linenum)
        divergent_branch_info_str = (f"func={func_name}, "
                                     f"loc={loc}, "
                                     f"code={{{line_code.strip()}}}")
        self.logger.debug(f"critical concret branch divergent: "
                            f"loc={loc}, "
                            f"func={func_name}, "
                            f"bid={bid}, "
                            f"action={action}, "
                            f"dB={d}, "
                            f"dF={policy[bid][0]}, "
                            f"dT={policy[bid][1]}, "
                            f"episode_index={ep_index}")
        self._get_function_code(bid, related_code_info)
        
        # trace handling
        compressed_trace = self._compress_trace(episode[:ep_index])
        trace_str = ""
        for addr, bid, action, d in compressed_trace:
            self._get_function_code(bid, related_code_info)
            fun_name, loc = self.code_finder.find_loc_info(bid, addr)
            linenum = int(loc.split(":")[1])
            filepath = self.code_finder.get_fp_from_bid(bid)
            line_code = self.code_finder.get_code_line(filepath, linenum)
            trace_str += (
                f"func={fun_name}, "
                f"loc={loc}, "
                f"code={{{line_code.strip()}}}\n"
            )
        
        # prompt building with related code info
        prompt_str += "<Source Code Begins>\n"
        for filepath in related_code_info:
            prompt_str += "##################################################\n"
            prompt_str += f"/* file={filepath} */\n"
            functions = sorted(related_code_info[filepath])
            for _, fn_guid in functions:
                prompt_str += self._func_codes[fn_guid] + '\n......\n'
        prompt_str += "<Source Code Ends>\n"
        
        # prompt building with input content
        prompt_str += "\n"
        prompt_str += "<Input Content Begins>\n"
        prompt_str += utils.hexdump(input_content) + '\n'
        prompt_str += "<Input Content Ends>\n"
        
        # prompt building with trace info
        prompt_str += "\n"
        prompt_str += "<Trace Info Begins>\n"
        prompt_str += trace_str
        prompt_str += "<Trace Info Ends>\n"

        # prompt building with concrete divergent branch
        prompt_str += "\n"
        prompt_str += "<Concrete Divergent Branch Info Begins>\n"
        prompt_str += divergent_branch_info_str + '\n'
        prompt_str += "<Concrete Divergent Branch Info Ends>\n"
        
        # prompt building with questions
        prompt_str += PromptBuilder.CONCRET_DIVERGENT_BRANCH_PROMPT
        return prompt_str
    
    def build_critical_branches_LLM_solver_prompt(self, critical_branches):
        prompt_str = ""
        related_code_info = collections.defaultdict(set)
        for i in range(len(critical_branches)):
            bid, action = critical_branches[i]
            self._get_function_code(bid, related_code_info)
            filepath = self.code_finder.get_fp_from_bid(bid)
            _, loc = self.code_finder.find_loc_info(bid)
            linenum = int(loc.split(":")[1])
            line_code = self.code_finder.get_code_line(filepath, linenum)
            critical_branches[i] = (bid, action, loc, line_code.strip())

        # prompt building with related code info
        prompt_str += "<Source Code Begins>\n"
        for filepath in related_code_info:
            prompt_str += "##################################################\n"
            prompt_str += f"/* file={filepath} */\n"
            functions = sorted(related_code_info[filepath])
            for _, fn_guid in functions:
                prompt_str += self._func_codes[fn_guid] + '\n......\n'
        prompt_str += "<Source Code Ends>\n"
        
        # prompt building with critical branches
        prompt_str += "<Critical Branches Begins>\n"
        for _, action, loc, line_code in critical_branches:
            prompt_str += f"loc={loc}, "
            prompt_str += f"code={{{line_code}}}, "
            branch_condition = "true" if action else "false"
            prompt_str += f"branch_condition={branch_condition} \n"
        prompt_str += "<Critical Branches Ends>\n"
        
        # prompt building with questions
        prompt_str += PromptBuilder.CRITICAL_BRANCHES_BASELINE_PROMPT
        return prompt_str

    def _compress_trace(self, trace):
        sub_trace = OrderedSet()
        for state in trace:
            state, action, d, bid = state.serialize()
            sub_trace.add((state[0], bid, action, d))
        return sub_trace

    def _get_function_code(self, bid, storage):
        fn_guid, _ = self.code_finder.loc_bid_cache.get(bid, (None, None))
        if fn_guid:
            if fn_guid not in self._func_codes:
                self._func_codes[fn_guid] = self.code_finder.get_function_source_code(fn_guid)
            func_info = self.code_finder.function_infos[fn_guid]
            file_path = self.code_finder.get_fp_from_func_id(fn_guid)
            start_line_number, _ = self.code_finder.get_func_range_from_func_id(fn_guid)
            storage[file_path].add((start_line_number, fn_guid))

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

        # A dictionary for caching function info: {fn_guid -> (function_name, filepath, start_line_number, end_line_number)}
        self.function_infos = self._load_function_info(
            os.path.join(config.static_result_folder, "function_info.txt")
        )
        # A dictionary for caching source code location: {bid -> (fn_guid, filepath:line_number)}
        self.loc_bid_cache = self._load_loc_bid_mapping(
            os.path.join(self.config.static_result_folder, "bid_loc_mapping.txt")
        )
        # A dictionary for caching source code location: {addr -> (function_name, filepath:line_number)}
        self.loc_addr_cache = {}
        # A dictionary for caching file contents: {file_path -> [lines]}
        self.file_contents = {}
    
    def get_func_name_from_func_id(self, guid):
        """
        Retrieve the function name from the given GUID.

        :param guid: The unique GUID of the function as generated by LLVM.
        :return: The function name as a string, or an empty string if not found.
        """
        return self.function_infos.get(guid, ("", ""))[0]
    
    def get_fp_from_func_id(self, guid):
        """
        Retrieve the file path from the given GUID.

        :param guid: The unique GUID of the function as generated by LLVM.
        :return: The file path as a string, or an empty string if not found.
        """
        return self.function_infos.get(guid, ("", ""))[1]
    
    def get_fp_from_bid(self, bid):
        """
        Retrieve the file path from the given BID.

        :param bid: The unique BID of the basic block.
        :return: The file path as a string, or an empty string if not found.
        """
        if bid not in self.loc_bid_cache:
            import ipdb; ipdb.set_trace()
        full_loc = self.loc_bid_cache.get(bid, (None, None))[1]
        return full_loc.split(":")[0] if full_loc else ""

    def get_func_range_from_func_id(self, guid):
        """
        Retrieve the start and end line numbers from the given GUID.

        :param guid: The unique GUID of the function as generated by LLVM.
        :return: A tuple (start_line, end_line) as integers, or (0, 0) if not found.
        """
        start_line_number = self.function_infos[guid][2]
        end_line_number = self.function_infos[guid][3]
        return start_line_number, end_line_number
    
    def get_func_id_from_bid(self, bid):
        """
        Retrieve the function GUID from the given BID.

        :param bid: The unique BID of the basic block.
        :return: The function GUID as an integer, or None if not found.
        """
        return self.loc_bid_cache.get(bid, (None, None))[0]

    def find_loc_info(self, bid, addr=None):
        """
        Retrieve function/location info based on a basic block ID or an address.

        :param bid: Basic block ID (integer).
        :param addr: Optional memory address to query via addr2line.
        :return: A tuple (function_name, location_string) or ("", "") if not found.
        """
        if bid in self.loc_bid_cache:
            fn_guid, full_loc = self.loc_bid_cache[bid]
            func_name = self.get_func_name_from_func_id(fn_guid)
            fp = full_loc.split(":")[0]
            linenum = int(full_loc.split(":")[1])
            loc = f"{os.path.basename(fp)}:{linenum}"
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
        return (func_name, loc)

    def get_function_source_code(self, guid):
        """
        Return the source code of the function identified by the given GUID.

        :param guid: The unique GUID of the function as generated by LLVM.
        :return: The full source code of the function as a string, or an empty string if unavailable.
        """
        fp = self.get_fp_from_func_id(guid)
        start_line_number, end_line_number = self.get_func_range_from_func_id(guid)
        if not os.path.isfile(fp):
            return ""
        function_source_code = ""
        for i in range(start_line_number - 1, end_line_number + 1):
            l = self.get_code_line(fp, i)
            function_source_code += f"{i} {l}\n"
        return function_source_code

    def get_code_line(self, file_path, line_number):
        """
        Internal helper to retrieve a single line from a loaded file.

        :param file_path: Absolute path to the source file.
        :param line_number: 1-based index of the line to retrieve.
        :return: The line content without the trailing newline, or an empty string if invalid.
        """
        if not os.path.isfile(file_path):
            self.logger.warning(f"source code file {file_path} does not exist.")
            return ""
        self._get_file_contents(file_path)

        lines = self.file_contents[file_path]
        if line_number < 1 or line_number > len(lines):
            self.logger.warning(f"Line number {line_number} out of range for file {file_path}")
            return ""

        return lines[line_number - 1].rstrip("\n")

    def _get_file_contents(self, file_path):
        """
        Internal helper to read and cache the entire file content.

        :param file_path: Absolute path to the source file.
        """
        if not os.path.isfile(file_path):
            self.file_contents[file_path] = []
            return

        if file_path not in self.file_contents:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    self.file_contents[file_path] = f.readlines()
            except Exception as e:
                self.logger.error(f"Error reading file {file_path}: {e}")
                self.file_contents[file_path] = []

    def _load_loc_bid_mapping(self, fp):
        """
        Load the mapping of BIDs to function GUID and source location from the given file.

        File format: Each line should have 3 comma-separated columns:
          1) Basic block ID (integer)
          2) Function GUID (integer)
          3) Location string (e.g., filepath:line_number)

        :param fp: The path to the 'bid_loc_mapping.txt' file.
        :return: A dictionary with BID as the key and a tuple (fn_guid, loc) as the value.
        """
        d = {}
        if not os.path.isfile(fp):
            self.logger.error(f"bid mapping file {fp} does not exist.")
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
          3) Source filepath (string)
          4) Start line number (integer)
          5) End line number (integer)

        :param fp: The path to the 'function_info.txt' file.
        :return: A dictionary mapping function GUID to a tuple:
                 (function_name, filepath, start_line, end_line).
        """
        d = {}
        if not os.path.isfile(fp):
            self.logger.error(f"function info file {fp} does not exist.")
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
                filepath = items[2]
                start_line_number = int(items[3])
                end_line_number = int(items[4])
                d[fn_guid] = (function_name, filepath, start_line_number, end_line_number)
        self.logger.debug(f"function_info loaded from {fp}, size: {len(d)}")
        return d
