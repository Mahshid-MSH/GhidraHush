import os
import sys
import glob
import argparse
import subprocess, pefile
from dotenv import load_dotenv, set_key

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "."))

from ghidra_scripts.function_extractor import extract_functions

from llm.c_code_enhancer import CCodeEnhancer
from ghidra_scripts.dump_global_values import generate_global_files
from utils.add_missing_globals import add_missing_values
from llm.evasion_techniques import DefensiveEvasion
import glob

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
    3: "Beautify & refactor extracted C code (LLM)",
    4: "Resolve & add missing global declarations",
    5: "Apply defensive evasion techniques",
    6: "Verify behavioral equivalence against original binary"
}

ENV_PATH = os.path.abspath(".env")


def parse_args():
    parser = argparse.ArgumentParser(description="Decompilation Pipeline")
    parser.add_argument("--stage", type=int, default=1, help="Stage to start/resume from (1-10)")
    parser.add_argument("--workspace", type=str, required=True, help="Path to workspace directory")
    parser.add_argument("--exe", type=str, required=True, help="Path to target executable")
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

    model_name = os.environ.get("LLM_MODEL", "deepseek-coder-v2")
    output_binary_path = os.environ.get("OUTPUT_EXECUTABLE", "binary_reconstructed.exe")

    print(f"\n{Colors.HEADER}{Colors.BOLD}Running Stage {start_stage}: {STAGES[start_stage]}{Colors.RESET}")
    print(f"{Colors.HEADER}" + "=" * 60 + f"{Colors.RESET}")
    
    def print_stage(num, title):
        print(f"\n{Colors.BLUE}{Colors.BOLD}▶ Stage {num}: {title}{Colors.RESET}")

    # ======================= Phase 1: Function Extraction ===========================
    if start_stage == 1:
        print_stage(1, STAGES[1])
        try:
            extract_functions(input_exe_path, workspace_dir=workspace_dir)
            mark_stage_complete(1)
            print(f"{Colors.GREEN}Stage 1 completed successfully! Check out the folder path and remove the useless functions.{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}{Colors.BOLD}Fatal error in Stage 1:{Colors.RESET} {Colors.RED}{e}{Colors.RESET}")
            sys.exit(1)

    # ================ Phase 2: Extract global variables and data ====================
    elif start_stage == 2:
        print_stage(2, STAGES[2])
        try:
            generate_global_files(input_exe_path, workspace_dir=workspace_dir)
            mark_stage_complete(2)
            print(f"{Colors.GREEN}Stage 2 completed successfully.{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}{Colors.BOLD}Fatal error in Stage 2:{Colors.RESET} {Colors.RED}{e}{Colors.RESET}")
            sys.exit(1)

    # ======================= Phase 3: Code Enhancer ===========================
    elif start_stage == 3:
        print_stage(3, STAGES[3])
        try:
            processor = CCodeEnhancer(model_name=model_name)
            extracted_dir = os.path.join(workspace_dir, "extracted_functions")
            if not os.path.exists(extracted_dir):
                print(f"{Colors.RED}Error: {extracted_dir} does not exist. Cannot run Stage 3.{Colors.RESET}")
                sys.exit(1)
            
            # Use process_directory to trigger the LLM triage logic
            processor.process_directory(extracted_dir, workspace_dir=workspace_dir)
            
            mark_stage_complete(3)
            print(f"{Colors.GREEN}Stage 3 completed successfully.{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}{Colors.BOLD}Fatal error in Stage 3:{Colors.RESET} {Colors.RED}{e}{Colors.RESET}")
            sys.exit(1)

    # ======================= Phase 4: Add Missing Globals ===========================
    elif start_stage == 4:
        print_stage(4, STAGES[4])
        try:
            # In your entry.py menu logic for Step 4
            add_missing_values(workspace_dir=workspace_dir, path_to_binary=input_exe_path)
            # NEW: Sync prototypes after missing globals are resolved
            extracted_dir = os.path.join(workspace_dir, "extracted_functions")
            header_path = os.path.join(workspace_dir, "data_globals.h")
            print(f"{Colors.CYAN}Syncing AST and prototypes...{Colors.RESET}")
            #sync_ast_and_headers(extracted_dir, header_path) 
            mark_stage_complete(4)
        except Exception as e:
            print(f"{Colors.RED}{Colors.BOLD}Fatal error in Stage 4:{Colors.RESET} {Colors.RED}{e}{Colors.RESET}")
            sys.exit(1)

    # ================== Phase 5: Apply Defensive Evasion ===============================
    
    elif start_stage == 5:
        print_stage(6, STAGES[5])
        try:
            evader = DefensiveEvasion(model_name=model_name)
            processed_dir = os.path.join(workspace_dir, "processed_functions")
            exe_name = os.path.basename(input_exe_path)
            
            # Fetch and parse the user's selected techniques from the environment
            techniques_env = os.environ.get("EVASION_TECHNIQUES", "")
            if techniques_env:
                techniques = [t.strip() for t in techniques_env.split(",") if t.strip()]
                print(f"{Colors.CYAN}Applying selected techniques: {', '.join(techniques)}{Colors.RESET}")
            else:
                print(f"{Colors.YELLOW}No techniques provided via environment. Using defaults.{Colors.RESET}")
                techniques = ['junk_code_insertion', 'string_encryption'] # Safe fallback
            
            evader.process_directory_with_scoring(
                processed_dir=processed_dir, 
                workspace_dir=workspace_dir,
                exe_name=exe_name,
                techniques=techniques
            )
            # NEW: Sync prototypes after evasion techniques alter the C code
            header_path = os.path.join(workspace_dir, "data_globals.h")
            print(f"{Colors.CYAN}Syncing AST and prototypes...{Colors.RESET}")
            #sync_ast_and_headers(processed_dir, header_path)
            mark_stage_complete(6)
            print(f"{Colors.GREEN}Stage 6 completed successfully.{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}{Colors.BOLD}Fatal error in Stage 6:{Colors.RESET} {Colors.RED}{e}{Colors.RESET}")
            sys.exit(1)

    # ================== Phase 6: Verify behavioral equivalence ===========================
    elif start_stage == 7:
        print_stage(7, STAGES[7])
        print(f"{Colors.YELLOW}Stage 7 is not yet implemented.{Colors.RESET}")
        sys.exit(0)

if __name__ == "__main__":
    run_pipeline()