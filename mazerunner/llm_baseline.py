import config
import prompt
import utils

if __name__ == "__main__":
    config = config.Config()
    config._load_initial_policy()
    config.cmd = ['objdump', '-SD', '@@']
    code_finder = prompt.SourceCodeFinder(config)
    prompt_engine = prompt.PromptBuilder(config, code_finder)
    critical_branches = utils.get_critical_branches(config.initial_policy)
    prompt_str = prompt_engine.build_critical_branches_LLM_solver_prompt(critical_branches)
    print(prompt_str)