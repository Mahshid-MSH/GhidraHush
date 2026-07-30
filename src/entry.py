import os
import sys
import yaml
import argparse
import subprocess
import glob
from function_extractor import extract_functions
from generate_main_wrapper import generate_main_wrapper
from c_code_enhancer import CCodeEnhancer
from dump_global_values import generate_global_files
from add_missing_globals import add_missing_values



def start_pipeline():
    
    model_name=os.environ.get("OLLAMA_HOST")
    output_binary_path = os.environ.get("OUTPUT_EXECUTABLE")
    print("Starting automated beautification and build process...")
    input_exe_path = input("Please enter the path to the exe malware:\n").strip()

    # ======================= Phase 1: Function Extraction ===========================
    print("\nStage 1: Extract functions from binary")
    extract_functions(input_exe_path)

    # ================ Phase 2: Extract global variables and data ====================
    print("Stage 2: Extract global variables and data")
    generate_global_files(input_exe_path)

    # =======================     Phase 3: Code Enhancer   ===========================
    print("\nStage 3: Beautify and refactor extracted code")
    processor = CCodeEnhancer(model_name=model_name)
    
    binary_name = os.path.basename(input_exe_path)
    extracted_dir = os.path.join("./extracted_functions", binary_name)
    
    if not os.path.exists(extracted_dir):
        extracted_dir = "./extracted_functions"
        
    c_files = processor.find_c_files(extracted_dir)

    if not c_files:
        print(f"No .c files found in directory: {extracted_dir}")
    else:
        for c_file in c_files:
            processor.process_function_file(c_file)

    # ======================= Phase 4: Add Missing Globals ===========================
    print("\nStage 4: Add missing global declarations")
    add_missing_values()

    # ======================= Phase 5: Add main file =================================
    print("\nStage 5: Generating main wrapper")
    generate_main_wrapper(header_path="LLM_globals.h", output_path="main.c")

    # ======================= Phase 6: Compiling globals =============================
    print("\nStage 6: Compiling globals and main")
    try:
        subprocess.run(
            ["i686-w64-mingw32-gcc", "-I.", "-c", "LLM_globals.c", "-o", "globals.o"],
            check=True
        )
    except subprocess.CalledProcessError:
        print("Failed to compile LLM_globals.c")
        sys.exit(1)
        
    try:
        subprocess.run(
            ["i686-w64-mingw32-gcc", "-I.", "-c", "main.c", "-o", "main.o"],
            check=True
        )
    except subprocess.CalledProcessError:
        print("[-] Failed to compile main.c")
        sys.exit(1)
        
    # ================== Phase 7: Agentic compiler with retry logic ===================
    print("\nStage 7: Agentic compiler with retry logic")
    try:
        subprocess.run(
            [sys.executable, "agentic_compiler.py", "./processed_functions", "--retries", "5"],
            check=True
        )
    except subprocess.CalledProcessError:
        print("Agentic compiler encountered a fatal error.")

    # ================== Phase 8: Link final executable  ==============================
    print("\nStage 8: Link final executable")
    object_files = glob.glob("output_objects/*.o")
    
    
    executable = os.environ.get("EXECUTABLE", "binary_reconstructed.exe") 
    
    if object_files:
        linker_cmd = [
            "i686-w64-mingw32-gcc", 
            "globals.o", 
            "main.o"
        ] + object_files + [
            "-mconsole", 
            "-o", 
            executable
        ]
        link_result = subprocess.run(linker_cmd)
        
        if link_result.returncode == 0:
            print(f"Build successful: {executable}")
        else:
            print("Linkage failed.")
    else:
        print("Build failed: No object files (.o) were found in output_objects/.")


if __name__ == "__main__":
    start_pipeline()