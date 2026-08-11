import os,json,math
import sys
from ollama import Client
import re
import argparse
from database.symbol_db import SymbolDB
import pefile

class CCodeEnhancer:
    """Process C code for beautification using Ollama"""
    def __init__(self, model_name=None, base_url=None):
        
        self.base_url = base_url or os.environ.get('OLLAMA_HOST', 'http://ollama:11434')
        self.model_name = model_name or os.environ.get('LLM_MODEL', 'deepseek-coder-v2')
            
        self.client = Client(host=self.base_url)
        print(f"Connected to Ollama at {self.base_url}")

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

    
    def triage_function_names(self, function_names):
        """Asks the LLM to evaluate a list of function names and identify boilerplate."""
        
        prompt = f"""You are an expert reverse engineer. Analyze the following list of function names extracted from a decompiled Windows executable.
        
        Categorize each function into one of two categories:
        1. "IGNORE": Standard C/C++ library functions (e.g., printf, malloc, mbrlen, strnlen), Windows API, or MinGW/CRT compiler boilerplate (e.g., dtoa_lock, __main, exception handlers).
        2. "PROCESS": Custom application logic. 
        
        CRITICAL RULE: Core application entry points (e.g., "main", "WinMain", "DllMain", "entry", "_start") MUST be categorized as "PROCESS". Do not confuse the actual "main" with compiler boilerplate like "__main".

        You MUST respond ONLY with a valid JSON dictionary where the keys are the function names and the values are either "IGNORE" or "PROCESS". Do not wrap the output in markdown. Do not add explanations.
        
        Function Names:
        {json.dumps(function_names)}
        """

        print(f"Triaging {len(function_names)} functions with LLM...")
        
        response = ""
        for chunk in self.client.generate(model=self.model_name, prompt=prompt, stream=True, options={'temperature': 0}):
            response += chunk['response']
            
        # Clean the response in case the LLM disobeys and wraps it in markdown
        cleaned_response = response.strip()
        if cleaned_response.startswith("```json"):
            cleaned_response = cleaned_response[7:]
        if cleaned_response.startswith("```"):
            cleaned_response = cleaned_response[3:]
        if cleaned_response.endswith("```"):
            cleaned_response = cleaned_response[:-3]
            
        try:
            triage_results = json.loads(cleaned_response.strip())
            return triage_results
        except json.JSONDecodeError as e:
            print(f"[!] Triage failed to parse JSON: {e}")
            print(f"Raw output: {cleaned_response}")
            return {} # Fallback to empty if it fails
    
    def beautify_c_code(self, c_code):
        prompt = f"""You are an expert C/c++ programmer. Refactor the following Ghidra C/C++ code.
        
        ### RULES:
            1. OUTPUT HEADER: The very first line must be exactly: #include "LLM_globals.h". Immediately below that line, you must add any standard system headers required by the code (e.g., #include <windows.h>, #include <stdint.h>, #include <stdio.h>).
            2. FUNCTION NAMING: Keep the original function names exactly as they are. Do NOT rename any standard Windows API functions (e.g., CreateFileW, GetFileSize, MapViewOfFile)
            3. LOCAL VARIABLES: Rename cryptic locals (local_1c, etc.) to meaningful names, but always declare them with proper C types at the top of the function. DO NOT leave ANY variables (including Ghidra variables like psVar1, iVar2) undeclared. Scan the entire function body and ensure every variable used has a matching declaration at the top of the function block.
            4. TYPE REPLACEMENT: Use only standard <stdint.h> types (uint32_t, int32_t, uint16_t, uint8_t, etc.). Replace any remaining non‑standard types (undefined*, dword, word, byte, uint, ushort) completely.
            5. UNION/STRUCT DEFINITIONS: If the code references an unknown type like union_530 or _LARGE_INTEGER, you MUST insert a minimal definition before its first use. Use a header guard:
            6. You must strictly enforce the C89/C90 standard for variable declarations. ALL variables MUST be declared at the absolute beginning of the function block, immediately following the opening bracket. Do not declare any variables inline, inside if statements, or inside for/while/do-while loops.
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
        for chunk in self.client.generate(model=self.model_name, prompt=prompt, stream=True, options={'temperature': 0, 'num_ctx': 16384}):
            response += chunk['response']
            
        return self.extract_raw_c_code(response, c_code)


    def extract_prototype(self, text):
        """Extracts the first C function prototype from the generated code."""
        # Match return_type function_name(parameters) {
        pattern = r'^([a-zA-Z0-9_ \t\*]+)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)\s*\{'
        match = re.search(pattern, text, re.MULTILINE)
        if match:
            return_type = match.group(1).strip()
            func_name = match.group(2).strip()
            args = match.group(3).strip()
            args_cleaned = " ".join(args.split())
            return f"{return_type} {func_name}({args_cleaned});"
        return None

    
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

    def find_c_files(self, directory):
        """Recursively find all .c files in the specified directory."""
        c_files = []
        if not os.path.exists(directory):
            print(f"Warning: Directory {directory} does not exist.")
            return c_files
            
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith(".c"):
                    c_files.append(os.path.join(root, file))
        
        
        c_files.sort()
        return c_files


    def append_prototype_to_header(self, prototype, header_path="LLM_globals.h", workspace_dir="."):
        if not prototype:
            return
        db = SymbolDB(workspace_dir=workspace_dir)
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

    def process_function_file(self, file_path, workspace_dir, is_worthy=False):
        output_dir = os.path.join(workspace_dir, 'processed_functions')
        os.makedirs(output_dir, exist_ok=True)
        header_path = os.path.join(workspace_dir, "LLM_globals.h")
        
        with open(file_path, 'r', encoding='utf-8') as f:
            original_code = f.read()
            
        print(f"\nProcessing: {os.path.basename(file_path)}")
        
        # Pre-process Ghidra types and beautify the code
        cleaned_code = self.pre_process_ghidra_types(original_code)
        result = self.beautify_c_code(cleaned_code)
        
        if is_worthy:
            result = self.apply_custom_prompt(result)
            
        # Extract prototype and append to header
        prototype = self.extract_prototype(result)
        self.append_prototype_to_header(prototype, header_path=header_path, workspace_dir=workspace_dir)
        
        base_name = os.path.splitext(os.path.basename(file_path))[0]
        beautified_path = os.path.join(output_dir, f"{base_name}.c")
        
        with open(beautified_path, 'w', encoding='utf-8') as f:
            f.write(result)
            
        print(f"Saved beautified file: {beautified_path}")
        
        return {
            'original': file_path,
            'beautified': beautified_path,
            'status': 'processed'
        }
    
    def process_directory(self, input_dir, workspace_dir):
        """Gathers all .c files, runs batch LLM triage, and beautifies only custom logic."""
        c_files = self.find_c_files(input_dir)
        if not c_files:
            print(f"No .c files found in {input_dir}")
            return []

        # Map function names to file paths (e.g., 'printf' -> '/path/to/printf.c')
        file_map = {os.path.splitext(os.path.basename(f))[0]: f for f in c_files}
        func_names = list(file_map.keys())

        # Batch Triage
        triage_results = self.triage_function_names(func_names)
        db = SymbolDB(workspace_dir=workspace_dir)

        results = []
        print(f"\nTriage complete. Processing custom application logic...\n")

        # Refactoring Loop
        for func_name, file_path in file_map.items():
            # Default to 'PROCESS' if LLM missed the key in JSON
            decision = triage_results.get(func_name, "PROCESS").upper()

            if decision == "IGNORE":
                print(f"Triage: Skipping CRT/Boilerplate function '{func_name}'")
                
                # Remove function prototype entry from DB so it's not exported to LLM_globals.h
                db.remove_function(func_name)
                
                results.append({
                    'original': file_path,
                    'status': 'ignored_library_function'
                })
                continue

            # Beautify valid custom logic
            res = self.process_function_file(file_path, workspace_dir)
            results.append(res)

        return results

def get_ignored_functions():
    path = os.environ.get('INPUT_EXE_PATH')
    pe = pefile.PE(path)

    dynamic_api_functions = set()
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
                    # print(f"Found: {dll_name} -> {func_name}")
                else:
                    # Handle ordinal imports if necessary
                    # print(f"Found: {dll_name} -> Ordinal {imp.ordinal}")
                    pass
                    
    #print(f"Total dynamic imported functions found: {len(dynamic_api_functions)}")
    #print(dynamic_api_functions)

    ALL_IGNORED_FUNCTIONS = dynamic_api_functions
    return ALL_IGNORED_FUNCTIONS


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Beautify C function files using Ollama with LLM Triage.")
    parser.add_argument("input_path", help="Path to a single .c file OR a directory containing .c files")
    parser.add_argument("--workspace", default=".", help="Workspace directory for SymbolDB and headers")
    parser.add_argument("--model", default=os.environ.get('LLM_MODEL', 'deepseek-coder-v2'), help="Ollama model to use")
    
    args = parser.parse_args()
    enhancer = CCodeEnhancer(model_name=args.model)
    
    print("-" * 50)
    
    if os.path.isdir(args.input_path):
        # Batch Directory Mode: Performs Triage first, then Beautifies
        enhancer.process_directory(args.input_path, workspace_dir=args.workspace)
    elif os.path.isfile(args.input_path):
        # Single File Mode Fallback
        enhancer.process_function_file(args.input_path, workspace_dir=args.workspace)
    else:
        print(f"[!] Invalid path provided: {args.input_path}")