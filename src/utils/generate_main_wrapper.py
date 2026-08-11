import os
import re
import textwrap

def generate_main_wrapper(workspace_dir="."):
    """Scans header and all subdirectories for the binary's entry point.
       If main() is already implemented, skips generating a dummy wrapper."""
    header_path = os.path.join(workspace_dir, "LLM_globals.h")
    output_path = os.path.join(workspace_dir, "main.c")
    
    print("\nGenerating main.c wrapper...")

    combined_content = ""
    if os.path.exists(header_path):
        with open(header_path, "r", encoding="utf-8", errors="ignore") as f:
            combined_content += f.read() + "\n"

    # Scan ALL .c files, including main.c
    for root, dirs, files in os.walk(workspace_dir):
        for file in files:
            if file.endswith(".c"):
                file_path = os.path.join(root, file)
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    combined_content += f.read() + "\n"

    # Check if a main() implementation already exists
    main_impl_pattern = r"\bint\s+main\s*\([^)]*\)\s*\{"
    if re.search(main_impl_pattern, combined_content, re.MULTILINE | re.DOTALL):
        print("Identified existing 'main()' implementation in processed source code.")
        print("Skipping main.c wrapper generation to avoid duplicate symbol collisions.")
        
        # Only remove the output_path if we are certain it's a stale, GENERATED wrapper
        # To do this safely, check if the output file exists, but doesn't contain the main() we just found.
        if os.path.exists(output_path):
            with open(output_path, "r", encoding="utf-8", errors="ignore") as f:
                output_content = f.read()
            
            # If the output_path DOES NOT contain the main function itself, it's a stale wrapper and safe to delete
            if not re.search(main_impl_pattern, output_content, re.MULTILINE | re.DOTALL):
                os.remove(output_path)
                print(f"Removed stale wrapper at {output_path}")
        return True

    entry_candidates = ["entry", "WinMainCRTStartup", "mainCRTStartup", "_start", "wmain", "WinMain"]
    found_entry = None
    
    for candidate in entry_candidates:
        pattern = rf"\b[\w\s\*]+\s+{candidate}\s*\([^)]*\)"
        if re.search(pattern, combined_content, re.MULTILINE | re.DOTALL):
            found_entry = candidate
            break
            
    if not found_entry:
        print("Warning: Could not find a recognized Ghidra entry point in the codebase.")
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