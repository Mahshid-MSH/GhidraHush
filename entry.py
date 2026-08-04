import os
import sys
import yaml
import argparse
import subprocess
import glob

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))
from dotenv import load_dotenv, set_key
from src.ghidra_scripts.function_extractor import extract_functions
from src.utils.generate_main_wrapper import generate_main_wrapper
from src.llm.c_code_enhancer import CCodeEnhancer
from src.ghidra_scripts.dump_global_values import generate_global_files
from src.utils.add_missing_globals import add_missing_values
from src.compiler.orchestrator import CompilerOrchestrator

STAGES = {
    1: "Extract functions from binary (Ghidra)",
    2: "Extract global variables & data (Ghidra)",
    3: "Beautify & refactor extracted C code (LLM)",
    4: "Resolve & add missing global declarations",
    5: "Generate main wrapper script",
    6: "Compile LLM_globals.c & main.c",
    7: "Agentic compilation loop & patching (LLM)",
    8: "Link output objects into final executable"
}

def get_latest_workspace():
    """Finds the most recently modified workspace directory."""
    workspace_base = "workspace"
    if not os.path.exists(workspace_base):
        return None
    dirs = [
        os.path.join(workspace_base, d) 
        for d in os.listdir(workspace_base) 
        if os.path.isdir(os.path.join(workspace_base, d)) and not d.endswith("_ghidra")
    ]
    if not dirs:
        return None
    return max(dirs, key=os.path.getmtime)

def get_or_create_workspace(base_name="run", existing_workspace=None):
    """Returns an existing workspace or creates a new unique workspace."""
    if existing_workspace:
        if not os.path.exists(existing_workspace):
            print(f"Error: Specified workspace '{existing_workspace}' does not exist.")
            sys.exit(1)
        return os.path.abspath(existing_workspace)

    workspace_dir = "workspace"
    os.makedirs(workspace_dir, exist_ok=True)

    instance_path = os.path.join(workspace_dir, base_name)
    if not os.path.exists(instance_path):
        os.makedirs(instance_path)
        return os.path.abspath(instance_path)
        
    counter = 1
    while True:
        new_path = os.path.join(workspace_dir, f"{base_name}_{counter}")
        if not os.path.exists(new_path):
            os.makedirs(new_path)
            return os.path.abspath(new_path)
        counter += 1

def display_interactive_menu(workspace_dir):
    """Displays a menu showing pipeline stages and returns the chosen stage."""
    print("\n" + "=" * 60)
    print(f" PIPELINE CONTROL MENU | Workspace: {os.path.basename(workspace_dir)}")
    print("=" * 60)
    
    # Check progress heuristics
    has_extracted = os.path.exists(os.path.join(workspace_dir, "extracted_functions"))
    has_globals = os.path.exists(os.path.join(workspace_dir, "LLM_globals.h"))
    has_processed = os.path.exists(os.path.join(workspace_dir, "processed_functions"))
    has_main = os.path.exists(os.path.join(workspace_dir, "main.c"))
    has_compiled_main = os.path.exists(os.path.join(workspace_dir, "main.o"))
    has_output_objs = os.path.exists(os.path.join(workspace_dir, "output_objects"))

    for stage_num, stage_name in STAGES.items():
        status = "[ ]"
        if stage_num == 1 and has_extracted: status = "[\033[92m✓\033[0m]"
        elif stage_num == 2 and has_globals: status = "[\033[92m✓\033[0m]"
        elif stage_num == 3 and has_processed: status = "[\033[92m✓\033[0m]"
        elif stage_num == 4 and has_globals: status = "[\033[92m✓\033[0m]"
        elif stage_num == 5 and has_main: status = "[\033[92m✓\033[0m]"
        elif stage_num == 6 and has_compiled_main: status = "[\033[92m✓\033[0m]"
        elif stage_num == 7 and has_output_objs: status = "[\033[92m✓\033[0m]"
        
        print(f"  {stage_num}. {status} {stage_name}")

    print("  0. Exit")
    print("-" * 60)
    
    while True:
        try:
            choice = input("Select stage to start/resume from (0-8): ").strip()
            if choice == "0":
                print("Exiting pipeline.")
                sys.exit(0)
            choice_num = int(choice)
            if 1 <= choice_num <= 8:
                return choice_num
            print("Invalid option. Please enter a number between 0 and 8.")
        except ValueError:
            print("Invalid input. Please enter a valid number.")

def start_pipeline():
    load_dotenv()
    
    parser = argparse.ArgumentParser(description="Automated binary decompilation and source code extractor.")
    parser.add_argument(
        "--input", "-i", 
        default=os.environ.get("INPUT_EXE_PATH"),
        help="Path to the input executable malware file"
    )
    parser.add_argument(
        "--workspace", "-w", 
        default=None,
        help="Path to an existing workspace to resume"
    )
    parser.add_argument(
        "--resume", "-r", 
        action="store_true",
        help="Automatically open interactive menu for the most recent workspace"
    )
    parser.add_argument(
        "--start-stage", "-s", 
        type=int, 
        default=None,
        help="Directly specify stage (1-8) without interactive menu"
    )
    args = parser.parse_args()

    # Determine workspace directory
    target_workspace = args.workspace
    if args.resume and not target_workspace:
        target_workspace = get_latest_workspace()
        if not target_workspace:
            print("No previous workspace found to resume.")
            sys.exit(1)

    # Determine input executable path
    input_exe_path = args.input
    if not input_exe_path and not target_workspace:
        input_exe_path = input("Please enter the path to the exe malware:\n").strip()
        if not input_exe_path:
            print("Error: No executable path provided.")
            sys.exit(1)

    if input_exe_path:
        set_key(".env", "INPUT_EXE_PATH", input_exe_path)
        os.environ["INPUT_EXE_PATH"] = input_exe_path

    # Prepare Workspace
    if target_workspace:
        workspace_dir = os.path.abspath(target_workspace)
    else:
        binary_name = os.path.basename(input_exe_path)
        base_workspace_name = os.path.splitext(binary_name)[0]
        workspace_dir = get_or_create_workspace(base_workspace_name)

    print(f"\nActive Workspace: {workspace_dir}")

    # Determine starting stage (Command Line Flag vs Interactive Menu)
    if args.start_stage is not None:
        start_stage = args.start_stage
    elif target_workspace or args.resume:
        start_stage = display_interactive_menu(workspace_dir)
    else:
        start_stage = 1

    model_name = os.environ.get("LLM_MODEL")
    output_binary_path = os.environ.get("OUTPUT_EXECUTABLE", "binary_reconstructed.exe")
    
    print(f"\nRunning Pipeline Starting From Stage {start_stage}: {STAGES[start_stage]}")
    print("=" * 60)

    # ======================= Phase 1: Function Extraction ===========================
    if start_stage <= 1:
        print("\nStage 1: Extract functions from binary")
        extract_functions(input_exe_path, workspace_dir=workspace_dir)

    # ================ Phase 2: Extract global variables and data ====================
    if start_stage <= 2:
        print("\nStage 2: Extract global variables and data")
        generate_global_files(input_exe_path, workspace_dir=workspace_dir)

    # =======================     Phase 3: Code Enhancer   ===========================
    if start_stage <= 3:
        print("\nStage 3: Beautify and refactor extracted code")
        processor = CCodeEnhancer(model_name=model_name)
        
        extracted_dir = os.path.join(workspace_dir, "extracted_functions")
        if not os.path.exists(extracted_dir):
            print(f"Error: {extracted_dir} does not exist. Cannot run Stage 3.")
            sys.exit(1)
            
        c_files = processor.find_c_files(extracted_dir)

        if not c_files:
            print(f"No .c files found in directory: {extracted_dir}")
        else:
            for c_file in c_files:
                processor.process_function_file(c_file, workspace_dir=workspace_dir)

    # ======================= Phase 4: Add Missing Globals ===========================
    if start_stage <= 4:
        print("\nStage 4: Add missing global declarations")
        add_missing_values(workspace_dir=workspace_dir)

    # ======================= Phase 5: Add main file =================================
    if start_stage <= 5:
        print("\nStage 5: Generating main wrapper")
        generate_main_wrapper(workspace_dir=workspace_dir)

    # ======================= Phase 6: Compiling globals =============================
    if start_stage <= 6:
        print("\nStage 6: Compiling globals and main")
        source_globals = os.path.join(workspace_dir, "LLM_globals.c")
        obj_globals = os.path.join(workspace_dir, "globals.o")
        main_path = os.path.join(workspace_dir, "main.c")
        obj_main = os.path.join(workspace_dir, "main.o")
        
        try:
            subprocess.run(
                ["i686-w64-mingw32-gcc", f"-I{workspace_dir}", "-c", source_globals, "-o", obj_globals],
                check=True
            )
            subprocess.run(
                ["i686-w64-mingw32-gcc", f"-I{workspace_dir}", "-c", main_path, "-o", obj_main],
                check=True
            )
        except subprocess.CalledProcessError as e:
            print(f"Failed during Stage 6 compilation: {e}")
            sys.exit(1)

    # ================== Phase 7: Agentic compiler with retry logic ===================
    if start_stage <= 7:
        print("\nStage 7: Agentic compiler with retry logic")
        try:
            orchestrator = CompilerOrchestrator(
                model_name=model_name,
                base_url=os.environ.get('OLLAMA_HOST', 'http://127.0.0.1:11434'),
                max_retries=5,
                compiler="i686-w64-mingw32-gcc",
                workspace_dir=workspace_dir 
            )
            processed_dir = os.path.join(workspace_dir, "processed_functions")
            orchestrator.process_directory(processed_dir)    
        except Exception as e:
            print(f"Agentic compiler encountered a fatal error: {e}")
            sys.exit(1)

    # ================== Phase 8: Link final executable  ==============================
    if start_stage <= 8:
        print("\nStage 8: Link final executable")
        object_files = glob.glob(os.path.join(workspace_dir, "output_objects", "*.o"))
        
        obj_globals = os.path.join(workspace_dir, "globals.o")
        obj_main = os.path.join(workspace_dir, "main.o")
        executable_path = os.path.join(workspace_dir, output_binary_path)
        
        if object_files:
            linker_cmd = [
                "i686-w64-mingw32-gcc", 
                obj_globals, 
                obj_main
            ] + object_files + [
                "-mconsole", 
                "-o", 
                executable_path
            ]
            link_result = subprocess.run(linker_cmd)
            
            if link_result.returncode == 0:
                print(f"\n[\033[92mSUCCESS\033[0m] Build successful: {executable_path}")
            else:
                print("\n[\033[91mFAILED\033[0m] Linkage failed.")
        else:
            print("\n[\033[91mFAILED\033[0m] Build failed: No object files (.o) found in output_objects/.")

if __name__ == "__main__":
    start_pipeline()