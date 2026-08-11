import os
import sys
import glob
import argparse
import subprocess, pefile
from dotenv import load_dotenv, set_key

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "."))

from ghidra_scripts.function_extractor import extract_functions
from utils.generate_main_wrapper import generate_main_wrapper
from llm.c_code_enhancer import CCodeEnhancer
from ghidra_scripts.dump_global_values import generate_global_files
from utils.add_missing_globals import add_missing_values
from compiler.orchestrator import CompilerOrchestrator
from llm.evasion_techniques import DefensiveEvasion
from compiler.gcc_service import GCCService

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
    5: "Generate main wrapper script",
    6: "Apply defensive evasion techniques",
    7: "Compile LLM_globals.c & main.c",
    8: "Agentic compilation loop & patching (LLM)",
    9: "Link output objects into final executable",
    10: "Verify behavioral equivalence against original binary"
}

ENV_PATH = os.path.abspath(".env")

def parse_args():
    parser = argparse.ArgumentParser(description="Decompilation & Compilation Pipeline")
    parser.add_argument("--stage", type=int, default=1, help="Stage to start/resume from (1-10)")
    parser.add_argument("--workspace", type=str, required=True, help="Path to workspace directory")
    parser.add_argument("--exe", type=str, required=True, help="Path to target executable")
    return parser.parse_args()

def mark_stage_complete(stage):
    """Updates LAST_COMPLETED_STAGE inside .env"""
    set_key(ENV_PATH, "LAST_COMPLETED_STAGE", str(stage))



def detect_target_compiler(input_exe_path: str) -> str:
    """
    Inspects binary architecture via system 'file' or 'pefile'
    and returns the corresponding MinGW GCC compiler binary.
    """
    try:
        # Primary method: CLI 'file' command
        output = subprocess.check_output(["file", input_exe_path], text=True)
        if "x86-64" in output or "PE32+" in output:
            print("[Arch Detector] Detected 64-bit PE32+ executable.")
            return "x86_64-w64-mingw32-gcc"
        elif "80386" in output or "PE32 " in output:
            print("[Arch Detector] Detected 32-bit PE32 executable.")
            return "i686-w64-mingw32-gcc"
    except Exception:
        pass

    # Fallback method: Direct PE header inspection via pefile
    try:
        pe = pefile.PE(input_exe_path)
        # 0x8664 = IMAGE_FILE_MACHINE_AMD64, 0x14c = IMAGE_FILE_MACHINE_I386
        if pe.FILE_HEADER.Machine == 0x8664:
            print("[Arch Detector] Detected 64-bit PE via PE Header (AMD64).")
            return "x86_64-w64-mingw32-gcc"
        else:
            print("[Arch Detector] Detected 32-bit PE via PE Header (i386).")
            return "i686-w64-mingw32-gcc"
    except Exception as e:
        print(f"[Arch Detector] Detection failed ({e}). Defaulting to 32-bit compiler.")
        return "i686-w64-mingw32-gcc"

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
    target_compiler = detect_target_compiler(input_exe_path)

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
            print(f"{Colors.GREEN}Stage 1 completed successfully.{Colors.RESET}")
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
            add_missing_values(workspace_dir=workspace_dir)
            mark_stage_complete(4)
            print(f"{Colors.GREEN}Stage 4 completed successfully.{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}{Colors.BOLD}Fatal error in Stage 4:{Colors.RESET} {Colors.RED}{e}{Colors.RESET}")
            sys.exit(1)

    # ======================= Phase 5: Add main file =================================
    elif start_stage == 5:
        print_stage(5, STAGES[5])
        try:
            generate_main_wrapper(workspace_dir=workspace_dir)
            mark_stage_complete(5)
            print(f"{Colors.GREEN}Stage 5 completed successfully.{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}{Colors.BOLD}Fatal error in Stage 5:{Colors.RESET} {Colors.RED}{e}{Colors.RESET}")
            sys.exit(1)

    # ================== Phase 6: Apply Defensive Evasion ===============================
    elif start_stage == 6:
        print_stage(6, STAGES[6])
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
            mark_stage_complete(6)
            print(f"{Colors.GREEN}Stage 6 completed successfully.{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}{Colors.BOLD}Fatal error in Stage 6:{Colors.RESET} {Colors.RED}{e}{Colors.RESET}")
            sys.exit(1)

    # ======================= Phase 7: Compiling globals and main =============================
    elif start_stage == 7:
        print_stage(7, STAGES[7])
        main_path = None
        for root, dirs, files in os.walk(workspace_dir):
            if "main.c" in files:
                main_path = os.path.join(root, "main.c")
                break
        if not main_path:
            print(f"{Colors.RED}{Colors.BOLD}Fatal error in Stage 7:{Colors.RESET} {Colors.RED}Could not find main.c in {workspace_dir} or its subdirectories.{Colors.RESET}")
            sys.exit(1)
            
        try:
            gcc_service = GCCService(compiler=target_compiler, workspace_dir=workspace_dir)
            if not gcc_service.recompile_globals():
                raise Exception("Failed to compile LLM_globals.c")
            success, err_msg = gcc_service.compile_file(filepath=main_path, output_dir=workspace_dir)
            if not success:
                raise Exception(f"Failed to compile main.c: {err_msg}")
            
            mark_stage_complete(7)
            print(f"{Colors.GREEN}Stage 7 completed successfully.{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}{Colors.BOLD}Fatal error in Stage 7:{Colors.RESET} {Colors.RED}{e}{Colors.RESET}")
            sys.exit(1)

    # ================== Phase 8: Agentic compiler with retry logic ===================
    elif start_stage == 8:
        print_stage(8, STAGES[8])
        try:
            orchestrator = CompilerOrchestrator(
                model_name=model_name,
                base_url=os.environ.get('OLLAMA_HOST', 'http://ollama:11434'),
                max_retries=int(os.environ.get('COMPILER_MAX_RETRIES', 5)),
                compiler=target_compiler,
                workspace_dir=workspace_dir 
            )
            processed_dir = os.path.join(workspace_dir, "processed_functions")
            orchestrator.process_directory(processed_dir)
            mark_stage_complete(8)
            print(f"{Colors.GREEN}Stage 8 completed successfully.{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}{Colors.BOLD}Fatal error in Stage 8:{Colors.RESET} {Colors.RED}{e}{Colors.RESET}")
            sys.exit(1)

    # ================== Phase 9: Link final executable ==============================
    elif start_stage == 9:
        print_stage(9, STAGES[9])
        try:
            object_files = glob.glob(os.path.join(workspace_dir, "output_objects", "*.o"))
            
            object_files = [f for f in object_files if os.path.basename(f) not in ["main.o", "globals.o"]]
            
            obj_globals = os.path.join(workspace_dir, "globals.o")
            obj_main = os.path.join(workspace_dir, "main.o")
            executable_path = os.path.join(workspace_dir, output_binary_path)
            
            if not os.path.exists(obj_main):
                print(f"\n[{Colors.RED}{Colors.BOLD}FAILED{Colors.RESET}] Build failed: Essential object file main.o is missing.")
                sys.exit(1)

            linker_cmd = [target_compiler, obj_globals, obj_main] + object_files + ["-mconsole", "-lws2_32", "-o", executable_path]
            link_result = subprocess.run(linker_cmd)
            
            if link_result.returncode == 0:
                print(f"\n[{Colors.GREEN}{Colors.BOLD}SUCCESS{Colors.RESET}] Build successful: {Colors.BOLD}{executable_path}{Colors.RESET}")
                mark_stage_complete(9)
                print(f"{Colors.GREEN}Stage 9 completed successfully.{Colors.RESET}")
            else:
                print(f"\n[{Colors.RED}{Colors.BOLD}FAILED{Colors.RESET}] Linkage failed.")
                sys.exit(1)
        except Exception as e:
            print(f"{Colors.RED}{Colors.BOLD}Fatal error in Stage 9:{Colors.RESET} {Colors.RED}{e}{Colors.RESET}")
            sys.exit(1)

    # ================== Phase 10: Verify behavioral equivalence ===========================
    elif start_stage == 10:
        print_stage(10, STAGES[10])
        print(f"{Colors.YELLOW}Stage 10 is not yet implemented.{Colors.RESET}")
        sys.exit(0)

if __name__ == "__main__":
    run_pipeline()