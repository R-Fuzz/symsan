import collections
import config
import prompt

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

if __name__ == "__main__":
    config = config.Config()
    config._load_initial_policy()
    config.cmd = ['objdump', '-SD', '@@']
    code_finder = prompt.SourceCodeFinder(config)
    prompt_engine = prompt.PromptBuilder(config, code_finder)
    critical_branches = get_critical_branches(config.initial_policy)
    
    related_code_info = collections.defaultdict(set)
    for i in range(len(critical_branches)):
        bid, action = critical_branches[i]
        prompt_engine._get_function_code(bid, related_code_info)
        filepath = code_finder.get_fp_from_bid(bid)
        _, loc = code_finder.find_loc_info(bid)
        linenum = int(loc.split(":")[1])
        line_code = code_finder.get_code_line(filepath, linenum)
        critical_branches[i] = (bid, action, loc, line_code)

    prompt_str = ""
    # prompt building with related code info
    prompt_str += "<Source Code Begins>\n"
    for filepath in related_code_info:
        prompt_str += "##################################################\n"
        prompt_str += f"/* file={filepath} */\n"
        functions = sorted(related_code_info[filepath])
        for _, fn_guid in functions:
            prompt_str += prompt_engine._func_codes[fn_guid] + '\n......\n'
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
    prompt_str += CRITICAL_BRANCHES_BASELINE_PROMPT
    print(prompt_str)