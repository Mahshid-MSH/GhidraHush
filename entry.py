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

def create_workspace_instance(base_name="run"):
    """Creates a unique workspace directory for the current run."""
    workspace_dir = "workspace"
    os.makedirs(workspace_dir, exist_ok=True)
    
    instance_path = os.path.join(workspace_dir, base_name)
    if not os.path.exists(instance_path):
        os.makedirs(instance_path)
        return instance_path
        
    counter = 1
    while True:
        new_path = os.path.join(workspace_dir, f"{base_name}_{counter}")
        if not os.path.exists(new_path):
            os.makedirs(new_path)
            return new_path
        counter += 1

def start_pipeline():
    # Load environment variables from .env
    load_dotenv()
    
    # Setup argument parser for command-line execution / Docker passing
    parser = argparse.ArgumentParser(description="Automated malware beautification and build pipeline.")
    parser.add_argument(
        "--input", 
        "-i", 
        default=os.environ.get("INPUT_EXE_PATH"),
        help="Path to the input executable malware file"
    )
    args = parser.parse_args()

    model_name = os.environ.get("LLM_MODEL")
    output_binary_path = os.environ.get("OUTPUT_EXECUTABLE")
    print("Starting automated beautification and build process...")

    # Determine input path
    input_exe_path = args.input
    if not input_exe_path:
        input_exe_path = input("Please enter the path to the exe malware:\n").strip()
        if not input_exe_path:
            print("Error: No executable path provided.")
            sys.exit(1)

    # Persist and load into current environment immediately
    set_key(".env", "INPUT_EXE_PATH", input_exe_path)
    os.environ["INPUT_EXE_PATH"] = input_exe_path

    # ======================= Setup Workspace ========================================
    binary_name = os.path.basename(input_exe_path)
    base_workspace_name = os.path.splitext(binary_name)[0]
    workspace_dir = create_workspace_instance(base_workspace_name)
    print(f"\nAll output for this run will be saved in: {workspace_dir}")

    # ======================= Phase 1: Function Extraction ===========================
    print("\nStage 1: Extract functions from binary")
    # Make sure your extract_functions signature accepts workspace_dir
    extract_functions(input_exe_path, workspace_dir=workspace_dir)

    # ================ Phase 2: Extract global variables and data ====================
    print("Stage 2: Extract global variables and data")
    # Make sure generate_global_files signature accepts workspace_dir
    generate_global_files(input_exe_path, workspace_dir=workspace_dir)

    # =======================     Phase 3: Code Enhancer   ===========================
    print("\nStage 3: Beautify and refactor extracted code")
    processor = CCodeEnhancer(model_name=model_name)
    
    # Path updated to point to the new workspace target
    extracted_dir = os.path.join(workspace_dir, "extracted_functions", binary_name)
    
    if not os.path.exists(extracted_dir):
        extracted_dir = os.path.join(workspace_dir, "extracted_functions")
        
    c_files = processor.find_c_files(extracted_dir)

    if not c_files:
        print(f"No .c files found in directory: {extracted_dir}")
    else:
        for c_file in c_files:
            # Make sure process_function_file signature accepts workspace_dir
            processor.process_function_file(c_file, workspace_dir=workspace_dir)

    # ======================= Phase 4: Add Missing Globals ===========================
    print("\nStage 4: Add missing global declarations")
    # Make sure add_missing_values signature accepts workspace_dir
    add_missing_values(workspace_dir=workspace_dir)

    # ======================= Phase 5: Add main file =================================
    print("\nStage 5: Generating main wrapper")
    header_path = os.path.join(workspace_dir, "LLM_globals.h")
    main_path = os.path.join(workspace_dir, "main.c")
    generate_main_wrapper(workspace_dir=workspace_dir)
    # ======================= Phase 6: Compiling globals =============================
    print("\nStage 6: Compiling globals and main")
    source_globals = os.path.join(workspace_dir, "LLM_globals.c")
    obj_globals = os.path.join(workspace_dir, "globals.o")
    obj_main = os.path.join(workspace_dir, "main.o")
    
    try:
        # Pass the workspace_dir as an include path `-I` so it can find the header
        subprocess.run(
            ["i686-w64-mingw32-gcc", f"-I{workspace_dir}", "-c", source_globals, "-o", obj_globals],
            check=True
        )
    except subprocess.CalledProcessError:
        print("Failed to compile LLM_globals.c")
        sys.exit(1)
        
    try:
        subprocess.run(
            ["i686-w64-mingw32-gcc", f"-I{workspace_dir}", "-c", main_path, "-o", obj_main],
            check=True
        )
    except subprocess.CalledProcessError:
        print("[-] Failed to compile main.c")
        sys.exit(1)
        
    # ================== Phase 7: Agentic compiler with retry logic ===================
    print("\nStage 7: Agentic compiler with retry logic")
    try:
        orchestrator = CompilerOrchestrator(
            model_name=model_name,
            base_url=os.environ.get('OLLAMA_HOST', 'http://127.0.0.1:11434'),
            max_retries=5,
            compiler="i686-w64-mingw32-gcc",
            workspace_dir=workspace_dir  # Pass workspace instance down
        )
        
        # Route to the workspace-processed directory
        processed_dir = os.path.join(workspace_dir, "processed_functions")
        orchestrator.process_directory(processed_dir)
        
    except Exception as e:
        print(f"Agentic compiler encountered a fatal error: {e}")
        sys.exit(1)

    # ================== Phase 8: Link final executable  ==============================
    print("\nStage 8: Link final executable")
    # Search for object files inside the workspace output directory
    object_files = glob.glob(os.path.join(workspace_dir, "output_objects", "*.o"))
    
    executable_name = os.environ.get("EXECUTABLE", "binary_reconstructed.exe")
    # Place the final executable inside the workspace directory
    executable_path = os.path.join(workspace_dir, executable_name)
    
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
            print(f"Build successful: {executable_path}")
        else:
            print("Linkage failed.")
    else:
        print("Build failed: No object files (.o) were found in output_objects/.")

if __name__ == "__main__":
    start_pipeline()