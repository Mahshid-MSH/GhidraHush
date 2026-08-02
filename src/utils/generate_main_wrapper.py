import os
import re
import textwrap

def generate_main_wrapper(workspace_dir="."):
    """Scans the header for the binary's entry point and generates a main.c wrapper."""
    header_path = os.path.join(workspace_dir, "LLM_globals.h")
    output_path = os.path.join(workspace_dir, "main.c")
    
    print("\nGenerating main.c wrapper...")
    
    if not os.path.exists(header_path):
        print(f"Error: {header_path} not found. Cannot generate main.c.")
        return False

    with open(header_path, "r", encoding="utf-8") as f:
        header_data = f.read()

    entry_candidates = ["entry", "WinMainCRTStartup", "mainCRTStartup", "_start", "wmain", "WinMain", "main"]
    found_entry = None
    
    for candidate in entry_candidates:
        pattern = rf"\b[\w\s\*]+\s+{candidate}\s*\([^)]*\)\s*;"
        if re.search(pattern, header_data):
            found_entry = candidate
            break
            
    if not found_entry:
        print("Warning: Could not find a recognized Ghidra entry point in the header.")
        print("Defaulting to 'entry()'. If compilation fails, check the binary's entry function name.")
        found_entry = "entry"

    print(f"Identified program entry point: {found_entry}()")

    c_code = textwrap.dedent(f"""\
        #include <windows.h>
        #include <stdint.h>
        #include "LLM_globals.h"

        int main(int argc, char* argv[]) {{
            {found_entry}();
            return 0;
        }}
    """)
    
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(c_code)
        
    print(f"Successfully wrote wrapper to {output_path}")
    return True