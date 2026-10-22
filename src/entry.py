import argparse
import json
import os
import sys

from dotenv import load_dotenv, set_key

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "."))

from ghidra_scripts.function_extractor import extract_functions

from llm.c_code_enhancer import CCodeEnhancer
from ghidra_scripts.dump_global_values import generate_global_files
from utils.add_missing_globals import add_missing_values
from llm.evasion_techniques import (
    DefensiveEvasion,
    validate_technique_parameters,
)
from compiler.orchestrator import CompilerOrchestrator
from Auxiliary.run_evaluation import evaluate_workspace, prepare_executable_dirs


class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'



STAGES = {
    1: "Extract functions from binary (Ghidra)",
    2: "Extract global variables & data (Ghidra)",
    3: "Beautify & refactor extracted code (LLM)",
    4: "Compile, repair & resolve missing symbols (gcc/g++)",
    5: "Apply defensive evasion techniques",
    6: "Evaluate fixed and generated binaries (CAPE / VirusTotal)",
}

ENV_PATH = os.path.abspath(".env")


def parse_args():
    parser = argparse.ArgumentParser(description="Decompilation Pipeline")
    parser.add_argument("--stage", type=int, choices=STAGES, default=1,
                        help="Stage to start/resume from (1-6)")
    parser.add_argument(
        "--workspace", type=str, required=True,
        help="Path to workspace directory",
    )
    parser.add_argument(
        "--exe", type=str, required=True,
        help="Path to target executable",
    )
    return parser.parse_args()


def mark_stage_complete(stage):
    """Updates LAST_COMPLETED_STAGE inside .env"""
    set_key(ENV_PATH, "LAST_COMPLETED_STAGE", str(stage))


def run_pipeline():
    if os.name == 'nt':
        os.system('color')
    load_dotenv()

    args = parse_args()
    start_stage = args.stage
    workspace_dir = os.path.abspath(args.workspace)
    input_exe_path = os.path.abspath(args.exe)
    prepare_executable_dirs(workspace_dir, input_exe_path)

    model_name = os.environ.get("LLM_MODEL", "deepseek-coder-v2")

    print(f"\n{Colors.HEADER}{Colors.BOLD}Running Stage {start_stage}: {STAGES[start_stage]}{Colors.RESET}")
    print(f"{Colors.HEADER}" + "=" * 60 + f"{Colors.RESET}")

    def print_stage(num, title):
        print(f"\n{Colors.BLUE}{Colors.BOLD}▶ Stage {num}: {title}{Colors.RESET}")

    if start_stage == 1:
        print_stage(1, STAGES[1])
        try:
            extract_functions(input_exe_path, workspace_dir=workspace_dir)
            mark_stage_complete(1)
            print(
                f"{Colors.GREEN}Stage 1 completed successfully! "
                "Check out the folder path and remove the useless functions."
                f"{Colors.RESET}"
            )
        except Exception as e:
            print(
                f"{Colors.RED}{Colors.BOLD}Fatal error in Stage 1:"
                f"{Colors.RESET} {Colors.RED}{e}{Colors.RESET}"
            )
            sys.exit(1)

    elif start_stage == 2:
        print_stage(2, STAGES[2])
        try:
            generate_global_files(input_exe_path, workspace_dir=workspace_dir)
            mark_stage_complete(2)
            print(f"{Colors.GREEN}Stage 2 completed successfully.{Colors.RESET}")
        except Exception as e:
            print(
                f"{Colors.RED}{Colors.BOLD}Fatal error in Stage 2:"
                f"{Colors.RESET} {Colors.RED}{e}{Colors.RESET}"
            )
            sys.exit(1)

    elif start_stage == 3:
        print_stage(3, STAGES[3])
        try:
            processor = CCodeEnhancer(model_name=model_name)
            extracted_dir = os.path.join(workspace_dir, "extracted_functions")
            if not os.path.exists(extracted_dir):
                print(
                    f"{Colors.RED}Error: {extracted_dir} does not exist. "
                    f"Cannot run Stage 3.{Colors.RESET}"
                )
                sys.exit(1)

            processor.process_directory(extracted_dir, workspace_dir=workspace_dir)

            mark_stage_complete(3)
            print(f"{Colors.GREEN}Stage 3 completed successfully.{Colors.RESET}")
        except Exception as e:
            print(
                f"{Colors.RED}{Colors.BOLD}Fatal error in Stage 3:"
                f"{Colors.RESET} {Colors.RED}{e}{Colors.RESET}"
            )

            sys.exit(1)

    elif start_stage == 4:
        try:
            add_missing_values(workspace_dir=workspace_dir, path_to_binary=input_exe_path)
            orch = CompilerOrchestrator(
                model_name=model_name,
                base_url=os.environ.get("LLM_BASE_URL"),
                max_retries=int(os.environ.get("COMPILE_MAX_RETRIES", "3")),
                workspace_dir=workspace_dir,
                binary_name=os.path.basename(input_exe_path),
            )
            orch.process_directory(os.path.join(workspace_dir, "processed_functions"))
            mark_stage_complete(4)
        except Exception as e:
            print(
                f"{Colors.RED}{Colors.BOLD}Fatal error in Stage 4:"
                f"{Colors.RESET} {Colors.RED}{e}{Colors.RESET}"
            )
            sys.exit(1)


    elif start_stage == 5:
        print_stage(5, STAGES[5])
        try:
            evader = DefensiveEvasion(model_name=model_name)
            source_dir = os.path.join(workspace_dir, "processed_functions")
            compiled_dir = os.path.join(workspace_dir, "compiled_successfully")
            source_extensions = (".c", ".cpp", ".cc", ".cxx")
            if os.path.isdir(compiled_dir) and any(
                filename.lower().endswith(source_extensions)
                and filename != "data_globals.c"
                and os.path.isfile(os.path.join(compiled_dir, filename))
                for filename in os.listdir(compiled_dir)
            ):
                source_dir = compiled_dir
                print(f"{Colors.CYAN}Using Stage 4 compiled sources from {compiled_dir}{Colors.RESET}")
            elif os.path.isdir(source_dir):
                print(f"{Colors.CYAN}Using processed sources from {source_dir}{Colors.RESET}")
            else:
                raise FileNotFoundError(
                    "No source files found in compiled_successfully or processed_functions"
                )
            exe_name = os.path.basename(input_exe_path)

            techniques_env = os.environ.get("EVASION_TECHNIQUES", "")
            if techniques_env:
                techniques = [t.strip() for t in techniques_env.split(",") if t.strip()]
                print(f"{Colors.CYAN}Applying selected techniques: {', '.join(techniques)}{Colors.RESET}")
            else:
                print(f"{Colors.YELLOW}No techniques provided via environment. Using defaults.{Colors.RESET}")
                techniques = ['junk_code_insertion', 'stack_string_xor_obfuscation']

            try:
                param_map = json.loads(os.environ.get("EVASION_PARAMS", "{}"))
            except json.JSONDecodeError as exc:
                raise ValueError("EVASION_PARAMS must contain valid JSON") from exc
            if not isinstance(param_map, dict):
                raise ValueError("EVASION_PARAMS must be a JSON object")
            for technique, params in param_map.items():
                validate_technique_parameters(technique, params)

            evader.process_directory_with_scoring(
                processed_dir=source_dir,
                workspace_dir=workspace_dir,
                exe_name=exe_name,
                techniques=techniques,
                param_map=param_map,
            )
            mark_stage_complete(5)
            print(f"{Colors.GREEN}Stage 5 completed successfully.{Colors.RESET}")
        except Exception as e:
            print(
                f"{Colors.RED}{Colors.BOLD}Fatal error in Stage 5:"
                f"{Colors.RESET} {Colors.RED}{e}{Colors.RESET}"
            )
            sys.exit(1)

    elif start_stage == 6:
        print_stage(6, STAGES[6])
        try:
            outcomes = evaluate_workspace(workspace_dir, input_exe_path)
            mark_stage_complete(6)
            completed = sum(
                outcome.get("status") in {"Completed", "CAPE only"}
                for outcome in outcomes
            )
            print(
                f"{Colors.GREEN}Stage 6 completed: evaluated {completed} "
                f"binary/binaries. See Results/comparisons.xlsx.{Colors.RESET}"
            )
        except Exception as e:
            print(
                f"{Colors.RED}{Colors.BOLD}Fatal error in Stage 6:"
                f"{Colors.RESET} {Colors.RED}{e}{Colors.RESET}"
            )
            sys.exit(1)

if __name__ == "__main__":
    run_pipeline()