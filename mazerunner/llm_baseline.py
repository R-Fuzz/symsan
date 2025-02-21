import argparse
import os
import config
from prompt import PromptBuilder
from source_code import SourceCodeFinder
from utils import AT_FILE, get_critical_branches, load_knowledge

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("-s", dest="static_result_folder", default=None, help="static analysis results folder that saves the distance information and initial policy")
    p.add_argument("-c", dest="source_code_folder", default=None, help="source code folder of the program under test")
    p.add_argument("-config", dest="config_path", default=None, help="path of configuration file")
    p.add_argument("-debug", dest="debug_enabled", action="store_true", help="Enable debug mode")
    p.add_argument("cmd", nargs="+", help=f"cmdline, use {AT_FILE} to denote a file")
    return p.parse_args()

def validate_args(args):
    if not args.cmd:
        raise ValueError("no cmd provided")
    if not os.path.isdir(args.static_result_folder):
        raise ValueError(f'{args.static_result_folder} no such directory')
    if not os.path.isdir(args.source_code_folder):
        raise ValueError(f'{args.source_code_folder} no such directory')

if __name__ == "__main__":
    args = parse_args()
    validate_args(args)
    knowledge = load_knowledge()
    config = config.Config()
    config.load(args.config_path)
    config.load_put_args(args)
    code_finder = SourceCodeFinder(config)
    prompt_engine = PromptBuilder(config, code_finder, knowledge)
    critical_branches = get_critical_branches(config.initial_policy)
    prompt_str = prompt_engine.build_LLM_baseline_prompt(critical_branches)
    print(prompt_str)