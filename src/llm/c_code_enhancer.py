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
    
    def beautify_c_code(self, c_code, callee_prototypes=""):
        context_block = ""
        if callee_prototypes:
            context_block = f"\n### KNOWN CALLEE PROTOTYPES:\nThe following functions are called in this file. You MUST strictly cast arguments to match these exact signatures:\n{callee_prototypes}\n"

        prompt = f"""You are an expert C/c++ programmer. Refactor the following Ghidra C/C++ code.
        ### RULES:
            1. OUTPUT HEADER: The very first line must be exactly: #include "LLM_globals.h". Immediately below that line, you must add any standard system headers required by the code.
            2. FUNCTION NAMING: Keep the original function names exactly as they are. Do NOT rename any standard Windows API functions.
            3. LOCAL VARIABLES: Rename cryptic locals (local_1c, etc.) to meaningful names, but always declare them with proper C types at the top of the function. DO NOT leave ANY variables undeclared.
            4. TYPE REPLACEMENT: Use only standard <stdint.h> types (uint32_t, int32_t, uint16_t, uint8_t, etc.). Replace any remaining non‑standard types completely.
            5. UNION/STRUCT DEFINITIONS: If the code references an unknown type, you MUST insert a minimal definition before its first use with a header guard.
            6. C89/C90 STANDARD: ALL variables MUST be declared at the absolute beginning of the function block.
            7. NO GHIDRA ARTIFACTS: Remove all __cdecl, __stdcall, __fastcall. Strip leading underscores from struct/union names.
            8. DYNAMIC FUNCTION POINTERS: If a global variable is called as a function, you MUST cast it to the correct function pointer type.
            9. POINTER CASTS FOR API CALLS: When a global is passed to an API that expects a pointer, cast it to the appropriate pointer type.
            10. STRING LITERALS: Replace global string holders with the actual string literal.
            11. VOID FUNCTIONS: If a function returns void, NEVER assign its return value.
            12. CONST CORRECTNESS: When a string literal is assigned to a pointer, declare the pointer as const char*.
            13. GLOBAL VARIABLES: Keep all DAT_xxx names exactly as they are. Treat them as generic handles.
            
            **HEADER GUARD IMMUNITY:** Do not modify file-level preprocessor guards unless proven broken.
            {context_block}
        
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
        if db.parse_and_upsert_prototype(prototype):
            db.export_header(header_path)
            print(f"Synced prototype to DB & Header: {prototype}")
        else:
            print(f"Failed to parse prototype for DB: {prototype}")

    def process_function_file(self, file_path, workspace_dir, call_graph=None, is_worthy=False):
        output_dir = os.path.join(workspace_dir, 'processed_functions')
        os.makedirs(output_dir, exist_ok=True)
        header_path = os.path.join(workspace_dir, "LLM_globals.h")
        
        with open(file_path, 'r', encoding='utf-8') as f:
            original_code = f.read()
            
        base_name = os.path.splitext(os.path.basename(file_path))[0]
        print(f"\nProcessing: {base_name}.c")
        
        # Fetch known prototypes for functions called by this file
        callee_prototypes_str = ""
        if call_graph and base_name in call_graph:
            db = SymbolDB(workspace_dir=workspace_dir)
            with db._get_conn() as conn:
                cursor = conn.cursor()
                prototypes = []
                for callee in call_graph[base_name]:
                    # call_graph format is "funcName_Address", we need just "funcName"
                    clean_callee = callee.split('_')[0] 
                    cursor.execute("SELECT return_type, name, parameters FROM functions WHERE name = ?", (clean_callee,))
                    row = cursor.fetchone()
                    if row:
                        prototypes.append(f"{row[0]} {row[1]}({row[2]});")
                callee_prototypes_str = "\n".join(prototypes)

        cleaned_code = self.pre_process_ghidra_types(original_code)
        
        # Pass the newly generated prototypes string to the LLM
        result = self.beautify_c_code(cleaned_code, callee_prototypes_str)
            
        prototype = self.extract_prototype(result)
        self.append_prototype_to_header(prototype, header_path=header_path, workspace_dir=workspace_dir)
        
        beautified_path = os.path.join(output_dir, f"{base_name}.c")
        with open(beautified_path, 'w', encoding='utf-8') as f:
            f.write(result)
            
        print(f"Saved beautified file: {beautified_path}")
        return {'original': file_path, 'beautified': beautified_path, 'status': 'processed'}
    
    def process_directory(self, input_dir, workspace_dir):
        """Gathers all .c files, runs batch LLM triage, and beautifies in bottom-up order."""
        import graphlib # Ensure this is imported at the top of llm_processor.py
        
        c_files = self.find_c_files(input_dir)
        if not c_files:
            print(f"No .c files found in {input_dir}")
            return []

        file_map = {os.path.splitext(os.path.basename(f))[0]: f for f in c_files}
        func_names = list(file_map.keys())

        # Load call graph generated by extract_functions.py
        graph_path = os.path.join(input_dir, "call_graph.json")
        call_graph = {}
        if os.path.exists(graph_path):
            with open(graph_path, "r", encoding="utf-8") as f:
                call_graph = json.load(f)
        # Batch Triage
        triage_results = self.triage_function_names(func_names)
        db = SymbolDB(workspace_dir=workspace_dir)
        results = []
        # Create a Directed Graph for Topological Sort
        ts = graphlib.TopologicalSorter()
        for caller, callees in call_graph.items():
            if caller in file_map:
                # Strip address hashes from callee names to match file_map keys
                clean_callees = {c.split('_')[0] for c in callees if c.split('_')[0] in file_map}
                ts.add(caller, *clean_callees)
        # Add any disconnected nodes (files without outgoing/incoming tracked calls)
        for f_name in func_names:
            if f_name not in call_graph:
                ts.add(f_name)

        print(f"\nTriage complete. Processing custom application logic (Bottom-Up)...\n")
        # Process topologically (Callees -> Callers)
        try:
            processing_order = list(ts.static_order())
        except graphlib.CycleError as e:
            print(f"[!] Cycle detected in call graph: {e}. Falling back to standard alphabetical order.")
            processing_order = func_names

        # Refactoring Loop
        for func_name in processing_order:
            if func_name not in file_map:
                continue    
            file_path = file_map[func_name]
            decision = triage_results.get(func_name, "PROCESS").upper()
            if decision == "IGNORE":
                print(f"Triage: Skipping CRT/Boilerplate function '{func_name}'")
                db.remove_function(func_name)
                results.append({
                    'original': file_path,
                    'status': 'ignored_library_function'
                })
                continue
            # Beautify passing the call graph for context injection
            res = self.process_function_file(file_path, workspace_dir, call_graph=call_graph)
            results.append(res)
        return results


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