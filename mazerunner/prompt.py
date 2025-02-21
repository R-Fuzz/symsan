
import collections
import logging
import os

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
You are currently testing the {project_name} project and are very familiar with its source code. \

The command line arguments are:
{cmd}

Your task is to analyze some critical branches in the program and generate inputs to cover them.
You have the following sources of information:
    1. critical branches and their corresponding conditions that must be satisfied
    2. Relevant Source Code: The corresponding {project_name} source code, with each line numbered at the beginning.

Using these materials, please write a python3 script to generate such input_file called poc.
'''

    SOLVE_DIVERGENT_BRANCH_PROMPT = '''
You are an advanced concolic execution engine with expert knowledge in software testing, \
dynamic program analysis, and input generation techniques. \
Your expertise includes analyzing both symbolic and concrete branches in program execution. \
In concolic execution, while symbolic branches can be directly solved, \
concrete branches present unique challenges.

You are currently testing the {project_name} project and are very familiar with its source code. \
Your task is to analyze a specific concrete branch divergence \
by examining the following three sources of information:
	1.	Input Hexdump: A hexdump representation of the input content.
	2.	Symbolic Branch Trace: A chronologically ordered list of symbolic branch events during execution.
	3.	Relevant Source Code: The corresponding {project_name} source code, with each line numbered at the beginning.

The command line arguments are:
{cmd}

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
    
    def __init__(self, config, code_finder, knowledge):
        self.config = config
        self.logger = logging.getLogger(self.__class__.__qualname__)
        self.code_finder = code_finder
        self.bin_to_project = knowledge["bin_to_project"]
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
        cmd_str, _ = PromptBuilder._fix_at_file(self.config.cmd)
        prompt_str += PromptBuilder.SOLVE_DIVERGENT_BRANCH_PROMPT.format(
            project_name=self.bin_to_project[self.config.cmd[0]],
            cmd=cmd_str
        )
        return prompt_str
    
    def build_LLM_baseline_prompt(self, critical_branches):
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
        cmd_str, _ = PromptBuilder._fix_at_file(self.config.cmd)
        prompt_str += PromptBuilder.CRITICAL_BRANCHES_BASELINE_PROMPT.format(
            project_name=self.bin_to_project[self.config.cmd[0]],
            cmd=cmd_str
        )
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

    def _fix_at_file(cmd):
        if utils.AT_FILE in cmd:
            idx = cmd.index(utils.AT_FILE)
            cmd[idx] = '[input_file]'
            is_stdin = False
        else:
            is_stdin = True
            cmd[idx] = ' < [input_file]'
        cmd[0] = os.path.basename(cmd[0])
        return " ".join(cmd), is_stdin
