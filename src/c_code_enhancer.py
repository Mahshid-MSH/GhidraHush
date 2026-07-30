import os
import sys
from ollama import Client
import re
from symbol_db import SymbolDB
import argparse
from symbol_db import SymbolDB
import pefile

class CCodeEnhancer:
    """Process C code for beautification using Ollama"""
    def __init__(self, model_name=os.environ.get('LLM_MODEL','deepseek-coder-v2'), base_url=None):
        if not base_url:
            base_url = os.environ.get('OLLAMA_HOST', 'http://localhost:11434')
        self.client = Client(host=base_url)
        self.model_name = model_name
        print(f"Connected to Ollama at {base_url}")
        print(f"Using model: {model_name}")


    def pre_process_ghidra_types(self, c_code):
        """Standardize Ghidra types via Python before the LLM sees them to guarantee fixes."""
        replacements = {
            r'\bundefined8\b': 'uint64_t',
            r'\bundefined4\b': 'uint32_t',
            r'\bundefined2\b': 'uint16_t',
            r'\bundefined1\b': 'uint8_t',
            r'\bushort\b': 'uint16_t',
            r'\bdword\b': 'uint32_t',
            r'\bword\b': 'uint16_t',
            r'\bbyte\b': 'uint8_t',
            r'\buint\b': 'uint32_t',               
            r'\b_([A-Z][A-Z0-9_]+)\b': r'\1'  # Catches _ANY_UPPERCASE_STRUCT and strips the '_'
        }
        for pattern, replacement in replacements.items():
            c_code = re.sub(pattern, replacement, c_code)
        return c_code
    
    def beautify_c_code(self, c_code):
        prompt = f"""You are an expert C/c++ programmer. Refactor the following Ghidra C/C++ code.
        
        ### RULES:
            1. OUTPUT HEADER: The very first line must be exactly: #include "LLM_globals.h"
            2. FUNCTION NAMING: Keep the original function name UNLESS it matches a real Windows API (e.g., Process32Next, CreateFile, ReadProcessMemory, CreateToolhelp32Snapshot, WriteFile, etc.). If it does, rename it to My_<OriginalName> (e.g., My_Process32Next). Do NOT change other names.
            3. LOCAL VARIABLES: Rename cryptic locals (local_1c, etc.) to meaningful names, but always declare them with proper C types at the top of the function. DO NOT leave any “local_” identifiers undeclared.
            4. TYPE REPLACEMENT: Use only standard <stdint.h> types (uint32_t, int32_t, uint16_t, uint8_t, etc.). Replace any remaining non‑standard types (undefined*, dword, word, byte, uint, ushort) completely.
            5. UNION/STRUCT DEFINITIONS: If the code references an unknown type like union_530 or _LARGE_INTEGER, you MUST insert a minimal definition before its first use. Use a header guard:

            ### CRITICAL RULES FOR SEARCH-AND-REPLACE BLOCKS
            **HEADER GUARD IMMUNITY:** Do not modify file-level preprocessor guards (`#ifndef`, `#define`, `#endif`) unless they are proven to be syntactically broken. If you must fix them, use clean, separate lines.
            #ifndef MY_UNION_530
            #define MY_UNION_530
            typedef union "{" SYSTEM_INFO s; /* adjust members as needed */ "}" union_530; You don't need to add the additional "" I have put here for readability. 
            #endif
            
            6. NO GHIDRA ARTIFACTS: Remove all __cdecl, __stdcall, __fastcall. Strip leading underscores from struct/union names (e.g., _TOKEN_PRIVILEGES → TOKEN_PRIVILEGES).
            7. DYNAMIC FUNCTION POINTERS: If a global variable like DAT_00409f74 is called as a function, you MUST cast it to the correct function pointer type. Do NOT write (*DAT_...)(...). Correct example:
            ((BOOL (*)(HANDLE, LPVOID))DAT_00409f74)(hProcess, addr);
            8. POINTER CASTS FOR API CALLS: When a DAT_… global is passed to an API that expects a pointer (e.g., ReadProcessMemory, StrStrA), cast it to the appropriate pointer type (LPVOID, LPCSTR, etc.). Example:
            ReadProcessMemory(h, (LPVOID)DAT_004095a0, buffer, size, &bytesRead);
            9. STRING LITERALS: Replace global string holders (s_…_004…) with the actual string literal. Example: s_SeDebugPrivilege_004074c4 → "SeDebugPrivilege".
            10. VOID FUNCTIONS: If a function returns void, NEVER assign its return value. Do not write `int x = VoidFunc();`. Just call `VoidFunc();`.
            11. CONST CORRECTNESS: When a string literal is assigned to a pointer, declare the pointer as const char*.
            12. GLOBAL VARIABLES: Keep all DAT_xxx names exactly as they are. Do not rename them. They are declared as uint32_t in the header; treat them as generic handles. If you need to store a pointer in a DAT_… variable, cast it explicitly.

        
        ### OUTPUT FORMAT:
        You MUST return ONLY a valid C code block wrapped in standard backticks (```c). Do not add explanations.

        ### INPUT CODE:
        {c_code}
        """

        print("Beautifying C code with LLM ...")

        response = ""
        for chunk in self.client.generate(model=self.model_name, prompt=prompt, stream=True, options={'temperature': 0}):
            response += chunk['response']
            
        return self.extract_raw_c_code(response, c_code)

    def extract_prototype(self, text):
        """Extracts ONLY the FUN_... C function prototype from the generated C code."""
        pattern = r'([a-zA-Z0-9_ \t\*]+)\s+((?:FUN_|My_|thunk_)[0-9a-fA-F_a-zA-Z]+|entry)\s*\(([^)]*)\)\s*\{'
        matches = re.findall(pattern, text)
        
        prototypes = []
        for match in matches:
            return_type = match[0].strip()
            func_name = match[1].strip()
            args = match[2].strip()
            args_cleaned = " ".join(args.split())
            prototype = f"{return_type} {func_name}({args_cleaned});"
            prototypes.append(prototype) 
            
        return prototypes[0] if prototypes else None

    
    def extract_raw_c_code(self, llm_output, original_code):
        """Extracts code from markdown blocks, stripping the language tag."""
        # This matches ``` followed by optional letters (c, markdown, cpp), 
        # then whitespace/newline, and captures everything until the next ```.
        match = re.search(r"```[a-zA-Z]*\s*\n(.*?)```", llm_output, re.DOTALL)
        
        if match:
            return match.group(1).strip()
            
        # Fallback: If the LLM just returned raw C code without backticks
        if "#include" in llm_output:
            return llm_output.strip()
            
        return original_code  # Ultimate fallback


    def append_prototype_to_header(self, prototype, header_path="LLM_globals.h"):
        if not prototype:
            return
        db = SymbolDB()
        # Parse the prototype to get function name
        match = re.search(r'([\w\s\*]+)\s+(\w+)\s*\(', prototype)
        ALL_IGNORED_FUNCTIONS=get_ignored_functions()
        if match:
            func_name = match.group(2).strip()
            if func_name in ALL_IGNORED_FUNCTIONS:
                print(f"Skipping system/libc API prototype: {func_name}")
                return

        if db.parse_and_upsert_prototype(prototype):
            db.export_header(header_path)
            print(f"Synced prototype to DB & Header: {prototype}")
        else:
            print(f"Failed to parse prototype for DB: {prototype}")

    def process_function_file(self, file_path, output_dir='processed_functions'):
        os.makedirs(output_dir, exist_ok=True)
        
        with open(file_path, 'r', encoding='utf-8') as f:
            original_code = f.read()
        print(f"\nProcessing: {os.path.basename(file_path)}")
        
        # Pre-process types (GUARANTEES undefined4 -> uint32_t)
        cleaned_code = self.pre_process_ghidra_types(original_code)
        result = self.beautify_c_code(cleaned_code)
        # Extract prototype and append to header
        prototype = self.extract_prototype(result)
        
        self.append_prototype_to_header(prototype, header_path="LLM_globals.h")
        base_name = os.path.splitext(os.path.basename(file_path))[0]
        beautified_path = os.path.join(output_dir, f"{base_name}.c")
        with open(beautified_path, 'w', encoding='utf-8') as f:
            f.write(result)
        print(f"Saved beautified file: {beautified_path}")
        
        return {
            'original': file_path,
            'beautified': beautified_path
            }


def get_ignored_functions():
    path = os.environ.get('INPUT_EXE_PATH')
    pe = pefile.PE(path)

    dynamic_api_functions = set()

    # It's good practice to check if the directory exists, 
    # as some packed or obfuscated binaries might strip the standard import table.
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            # entry.dll contains the library name (e.g., b'KERNEL32.dll')
            dll_name = entry.dll.decode('utf-8')
            
            # entry.imports contains the actual functions imported from this DLL
            for imp in entry.imports:
                # Functions can be imported by name or by ordinal
                if imp.name:
                    func_name = imp.name.decode('utf-8')
                    dynamic_api_functions.add(func_name)
                    # print(f"[*] Found: {dll_name} -> {func_name}")
                else:
                    # Handle ordinal imports if necessary
                    # print(f"[*] Found: {dll_name} -> Ordinal {imp.ordinal}")
                    pass
                    
    print(f"Total dynamic imported functions found: {len(dynamic_api_functions)}")
    print(dynamic_api_functions)

    ALL_IGNORED_FUNCTIONS = dynamic_api_functions
    return ALL_IGNORED_FUNCTIONS


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Beautify a single C function file using Ollama.")
    parser.add_argument("input_file", help="Path to the .c file to beautify")
    parser.add_argument("--model", default=os.environ.get('LLM_MODEL','deepseek-coder-v2'), help="Ollama model to use")
    args = parser.parse_args()
    enhancer = CCodeEnhancer(model_name=args.model)
    
    print("-" * 50)
    result = enhancer.process_function_file(args.input_file)
