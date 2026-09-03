import os,json,math
import sys
from ollama import Client
import re
import argparse
from database.symbol_db import SymbolDB
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)
from base_agent import BaseLLMAgent
import pefile

class CCodeEnhancer(BaseLLMAgent):
    """Process C code for beautification using Ollama"""
    def __init__(self, model_name=None, base_url=None):
        super().__init__(model_name, base_url)

    def pre_process_ghidra_types(self, c_code):
        """Standardize Ghidra types via Python before the LLM sees them to guarantee fixes."""
        replacements = {
            r'\bundefined8\b': 'uintptr_t',      
            r'\bundefined4\b': 'uint32_t',
            r'\bundefined2\b': 'uint16_t',
            r'\bundefined1\b': 'uint8_t',
            r'\bundefined\b': 'void',            
            r'\blonglong\b': 'int64_t',          
            r'\bulonglong\b': 'uint64_t',        
            r'\blong\b': 'int32_t',              
            r'\bushort\b': 'uint16_t',
            r'\bdword\b': 'uint32_t',
            r'\bword\b': 'uint16_t',
            r'\bbyte\b': 'uint8_t',
            r'\buint\b': 'uint32_t',
            r'\b_([A-Z][A-Z0-9_]+)\b': r'\1',
            r'__CheckForDebuggerJustMyCode\(&[A-Za-z0-9_]+\);': '',
            r'_RTC_CheckStackVars\(.*?\);': '',
            r'__RTC_CheckEsp\(\);': '',
            r'__security_check_cookie\(.*?\);': '' ,
            r'___security_cookie':''   
        }
        for pattern, replacement in replacements.items():
            c_code = re.sub(pattern, replacement, c_code)
        return c_code

    def _run_llm_pass(self, prompt_template, current_code, pass_name, base_name="unknown", workspace_dir="."):
        """Helper to run a specific LLM pass utilizing the base agent."""
        print(f"  -> Running {pass_name}...")
        prompt = prompt_template.replace("___C_CODE_PLACEHOLDER___", current_code)
        
        return self.process_llm_task(
            prompt=prompt,
            original_code=current_code,
            workspace_dir=workspace_dir,
            log_prefix=f"enhancer_{pass_name}",
            base_name=base_name,
            options={'temperature': 0, 'num_ctx': 16384}
        )


    def beautify_code(self, code, callee_prototypes="", base_name="unknown", workspace_dir="."):
        lang_name = "C"
        print(f"Beautifying {lang_name} code via Multi-Pass Pipeline...")

        # ---------------------------------------------------------
        # PASS 1: Syntax, Types & Dead Code Cleanup
        # ---------------------------------------------------------
        var_rule = (
            "3. C89 STANDARD: ALL variables MUST be declared at the absolute beginning of the function block." 
        )

        pass_1_prompt_c = f"""You are an expert C programmer. Clean up the following Ghidra pseudo-code by fixing types and variable names, while preserving the original logic and all side effects.

        ### STRICT RULES

        1. **FUNCTION NAME & SIGNATURE**: Keep the function name exactly as provided. Do not rename it. Preserve the parameter list and return type exactly as given (after type cleanup).

        2. **LOCAL VARIABLES**: Rename local variables that have Ghidra's cryptic names (e.g., `local_1c`, `uVar1`, `iVar2`) to meaningful, readable names that reflect their purpose.  
        - A **local variable** is any variable declared inside the function body.  
        - If a variable is used only as an intermediate step in a computation, you may inline it if it improves readability, but **never remove code that has side effects** (function calls, memory writes, etc.).

        3. **C89 COMPLIANCE**: All variables MUST be declared at the top of the function block, before any executable statements. Use `/* comments */` sparingly if they help clarity.

        4. **TYPE REPLACEMENT**: Use standard `<stdint.h>` types: `uint8_t`, `uint16_t`, `uint32_t`, `uint64_t`, `int32_t`, etc. Replace Ghidra's `undefined`, `undefined1/2/4/8`, `long`, `ulong`, `dword`, `word`, `byte` with the appropriate `stdint.h` type.

        5. **REMOVE CALLING CONVENTIONS & COMPILER ARTIFACTS**:
        - Remove all `__cdecl`, `__stdcall`, `__fastcall` keywords.
        - Remove Ghidra compiler artifacts: `ExceptionList`, `___security_cookie`, `__security_check_cookie`, `__RTC_CheckEsp`, `__RTC_CheckStackVars`, and any loop that fills stack memory with `0xcccccccc`.
        - Delete the variables associated with those artifacts.

        6. **PRESERVE LOGIC & SIDE EFFECTS**: Do **not** remove any function call, assignment, loop, condition, or memory operation. Only remove dead variables that are assigned but never used, and only if the assignment has no side effect.

        7. **GLOBAL VARIABLES**: If a variable name looks like a global (e.g., `DAT_`, `s_`, or a known symbol from `data_globals.h`), keep its name **exactly**. Do not rename it, do not redeclare it locally, and do not try to resolve its value. Assume it is declared in `data_globals.h`.

        8. **STRING LITERALS**: Preserve every string literal exactly as it appears. Do not replace it with a global or variable. If a string is inside a local array or passed directly to a function, keep it verbatim.

        9. **ONE FUNCTION ONLY**: Output only the cleaned version of the provided function. Do **not** include any other function, header, or `#include`. Do not add comments or explanations.

        ### EXAMPLE

        **INPUT (Ghidra pseudo-code)**:
        ```c
        undefined8 __stdcall FUN_140001000(undefined4 param_1)
        {{
            undefined8 uVar1;
            int4 local_1c;
            local_1c = param_1;
            uVar1 = (ulonglong)local_1c;
            return uVar1;
        }}
        ```
        ### OUTPUT (Cleaned C):

        uint64_t FUN_140001000(uint32_t param_1)
        {{
            uint32_t input_val;
            input_val = param_1;
            return (uint64_t)input_val;
        }}

        ### OUTPUT FORMAT

        Return ONLY valid C code wrapped in ```c backticks. No explanations.
        ### INPUT CODE
        ___C_CODE_PLACEHOLDER___

        """
        code_v1 = self._run_llm_pass(pass_1_prompt_c, code, "Pass_1", base_name,workspace_dir)
        # ---------------------------------------------------------
        # PASS 2: Pointers, Casts & API Signatures
        # ---------------------------------------------------------
        context_block = ""
        if callee_prototypes:
            context_block = f"\n### KNOWN CALLEE PROTOTYPES:\nYou MUST strictly cast arguments to match these exact signatures:\n{callee_prototypes}\n"

        pass_2_prompt_c = f"""You are an expert C programmer. Fix memory references, pointer casts, and API calls in the following cleaned Ghidra pseudo-code.
        
        ### STRICT RULES

        1. **POINTER RECOVERY**: If a parameter or local variable is typed as an integer (`uintptr_t`, `uint32_t`, etc.) but is used as a pointer, cast it to the appropriate pointer type. Example: `(const char *)filepath`.

        2. **ARRAY INDEXING**: Resolve complex pointer arithmetic into clean array indexing. If the base variable is an integer type, cast it to a pointer first. Example: `(*(char *)((int64_t)j + (int64_t)Buffer))` becomes `((char *)Buffer)[j]`.

        3. **GLOBAL POINTERS**: If a numeric constant (e.g., `0x140008164`) is used as a pointer, cast it to the appropriate pointer type (e.g., `(char *)0x140008164`). Do **not** treat it as a string literal or byte string.

        4. **GLOBAL VARIABLES**: If a variable name looks like a global (e.g., `DAT_`, `s_`, or a known symbol from `data_globals.h`), keep its name exactly. Do **not** replace it with a hardcoded string or number. Assume it is defined in `data_globals.h` and `data_globals.c`.

        5. **STRING LITERALS**: Preserve every string literal exactly as it appears in the input. Do **not** replace a local string literal with a global variable. If a string is a global (e.g., `s_some_string`), keep the variable name.

        6. **CONST CORRECTNESS**: When a string literal is assigned to a pointer, use `const char *`. Example: `const char *msg = "Hello";`.

        7. **FUNCTION POINTERS**: If a global variable is called as a function (e.g., `(*DAT_140001000)(...)`), cast it to the correct function pointer type before calling. Example: `((void (*)(int))DAT_140001000)(5);`. Use the known callee prototypes provided below if available.

        8. **API CALLS**: Ensure that all arguments to library/API functions are of the correct type. Cast pointers as needed to match the function signature. If a known callee prototype is provided, adhere to it strictly.
            {context_block}
        9. **ONE FUNCTION ONLY**: Output only the cleaned version of the provided function. Do **not** include any other function, header, or `#include`. Do not add conversational text or explanations.

        ### EXAMPLE

        **INPUT (Messy Pointer Casts & Integer APIs)**:
        ```c
        void process_file(uintptr_t filepath, uintptr_t buffer)
        {{
            int i = 0;
            FILE *fp = fopen(filepath, "rb");
            (*(char *)((int64_t)i + (int64_t)buffer)) = 'A';
        }}
        ```

        **OUTPUT (Clean Pointer Recoveries & Array Indexing)**:
        ```c
        void process_file(uintptr_t filepath, uintptr_t buffer)
        {{
            int i = 0;
            FILE *fp = fopen((const char *)filepath, "rb");
            ((char *)buffer)[i] = 'A';
        }}
        ```

        ### OUTPUT FORMAT
        Return ONLY valid C code wrapped in ```c backticks. No explanations.

        ### INPUT CODE
        ___C_CODE_PLACEHOLDER___
        """
        code_v2 = self._run_llm_pass(pass_2_prompt_c, code_v1, "Pass_2", base_name, workspace_dir)

        # ---------------------------------------------------------
        # PASS 3: Control Flow, Classes & Final Header
        # ---------------------------------------------------------
        pass_3_prompt_c = f"""You are an expert C reverse engineer. You will receive Ghidra pseudo-code. Convert it into clean, standard C (C99/C11) that compiles with MSVC or GCC.

                ### HARD REQUIREMENTS
                1. **COMPILABLE OUTPUT**
                - Your code must be valid C. It will be compiled immediately.
                - Any line that is not standard C is a failure.
                - All variables used in the function **must be declared** at the top of the function (C89 style) or at the start of a block, with appropriate types inferred from usage.
                - If the input references an undeclared variable (e.g., `local_8`, `uVar4`), **declare it** as a local variable with a suitable type based on how it is used.

                2. **NO GHIDRA / COMPILER ARTIFACTS**
                The following MUST NOT appear anywhere in your output:
                - `CONCAT44` / `CONCAT31` / `CONCATxx`
                - `local_X._0_1_`, `local_X._1_3_`, `local_X._2_1_`, etc.
                - `ExceptionList`
                - `__security_cookie` / `__security_check_cookie`, '___security_cookie'
                - `__RTC_CheckEsp` / `__RTC_CheckStackVars`
                - `LAB_` labels and `goto` statements (resolve into standard `while`/`for` loops or `if`/`else` blocks)
                - Loops that fill stack memory with `0xcccccccc` (remove them entirely)

                3. **CLEAN UP RAW POINTER ARITHMETIC**
                - Convert `*(type *)((intptr_t)ptr + offset)` into array indexing `ptr[index]` or struct field access where possible.
                - If a variable is typed as an integer but used as a pointer, cast it appropriately: `(char *)address`, `(uint32_t *)value`.
                - Avoid excessive nested casts; use intermediate typed pointers to improve readability.

                4. **INCLUDE HEADERS CORRECTLY**
                - The first line must be:
                    ```c
                    #include "data_globals.h"
                    ```
                    Then add standard C headers as needed (e.g., <stdio.h>, <stdlib.h>, <string.h>, <stdint.h>).

                    Do not include any other project headers.

                    GLOBAL VARIABLES

                        All global variables, arrays, and strings are declared in data_globals.h. Do not redeclare or redefine them.

                        Use them directly by name.

                        Do not replace global names with hardcoded values or strings.

                    PRESERVE BEHAVIOR EXACTLY

                        Keep every function call, assignment, loop condition, and memory operation.

                        Do not remove side effects.

                        When writing to files, use the correct size arguments. If the input shows a literal size (e.g., 464834), keep that number. If the size is derived from strlen or a variable, use the same expression.

                        Do not replace a size with a decompiler address constant like 0x416ba7. If you see such a constant used as a size, infer the correct size from context (e.g., strlen(inf), local_dc, etc.).

                        For memcpy, read, write, etc., the size argument must be an integer expression; if the input shows CONCAT44(a, b), replace it with the actual value (a << 32) | b or a + b only if it makes sense, otherwise use the appropriate size variable.

                    ONE FUNCTION ONLY

                        Output only the cleaned version of the provided function.

                        Do not include any other function, helper, or main.

                        The output must contain the function definition followed by a blank line. No extra text.

                ### EXAMPLE TRANSFORMATION

                **INPUT (Ghidra pseudo-code with raw pointer arithmetic and goto)**:
                ```c
                void *puVar1;
                uint32_t uVar2;
                puVar1 = malloc(0x18);
                *(uint32_t *)puVar1 = param_1;
                *(uint64_t *)((intptr_t)puVar1 + 8) = 0;
                uVar2 = 0;
                LAB_14000100:
                if (uVar2 < 5) {{
                    *(uint8_t *)((intptr_t)puVar1 + 0x10 + (intptr_t)uVar2) = 0xff;
                    uVar2 = uVar2 + 1;
                    goto LAB_14000100;
                }}
                return puVar1;
                ```
                **OUTPUT (Idiomatic C99)**:
                ```c
                #include "data_globals.h"
                #include <stdlib.h>
                #include <stdint.h>

                void* FUN_140001000(uint32_t param_1)
                {{
                    uint8_t* obj = (uint8_t*)malloc(24);
                    if (obj != NULL) {{
                        *(uint32_t*)obj = param_1;
                        *(uint64_t*)(obj + 8) = 0;
                        for (uint32_t i = 0; i < 5; i++) {{
                            obj[16 + i] = 0xff;
                        }}
                    }}
                    return obj;
                }}
                ```

                ### OUTPUT FORMAT
                Return ONLY valid C code wrapped in ```c backticks. No explanations.

                ### INPUT CODE
                ___C_CODE_PLACEHOLDER___
                """
        final_code = self._run_llm_pass(pass_3_prompt_c, code_v2, "Pass_3", base_name,workspace_dir)
        if not final_code:
            final_code = code_v2
        print("  -> Beautification complete.")
        return final_code


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

    def find_code_files(self, directory):
        """Recursively find all .c and files in the specified directory."""
        code_files = []
        if not os.path.exists(directory):
            return code_files
            
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith((".c")):
                    code_files.append(os.path.join(root, file))
        
        code_files.sort()
        return code_files


    def append_prototype_to_header(self, prototype, header_path="data_globals.h", workspace_dir="."):
        if not prototype:
            return
        db = SymbolDB(workspace_dir=workspace_dir)
        if db.parse_and_upsert_prototype(prototype):
            db.export_header(header_path)
            print(f"Synced prototype to DB & Header: {prototype}")
        else:
            print(f"Failed to parse prototype for DB: {prototype}")

    def process_function_file(self, file_path, workspace_dir, call_graph=None):
        output_dir = os.path.join(workspace_dir, 'processed_functions')
        os.makedirs(output_dir, exist_ok=True)
        header_path = os.path.join(workspace_dir, "data_globals.h")
        
        with open(file_path, 'r', encoding='utf-8') as f:
            original_code = f.read()
            
        base_name = os.path.splitext(os.path.basename(file_path))[0]
        print(f"\nProcessing: {base_name}")
        
        # Fetch known prototypes for functions called by this file
        callee_prototypes_str = ""
        if call_graph:
            db = SymbolDB(workspace_dir=workspace_dir)
            with db._get_conn() as conn:
                cursor = conn.cursor()
                prototypes = []

                # Find callees matching base_name using normalized caller lookup
                callees_for_base = []
                for raw_caller, callees in call_graph.items():
                    clean_caller = raw_caller.replace('@', '_')
                    if re.search(r'_[0-9a-fA-F]{6,}$', clean_caller):
                        clean_caller = clean_caller.rsplit('_', 1)[0]
                    if clean_caller == base_name:
                        callees_for_base = callees
                        break

                for callee in callees_for_base:
                    clean_callee = callee.replace('@', '_')
                    if re.search(r'_[0-9a-fA-F]{6,}$', clean_callee):
                        clean_callee = clean_callee.rsplit('_', 1)[0]
                        
                    cursor.execute("SELECT return_type, name, parameters FROM functions WHERE name = ?", (clean_callee,))
                    row = cursor.fetchone()
                    if row:
                        prototypes.append(f"{row[0]} {row[1]}({row[2]});")
                callee_prototypes_str = "\n".join(prototypes)


        cleaned_code = self.pre_process_ghidra_types(original_code)
        result = self.beautify_code(cleaned_code, callee_prototypes_str, base_name=base_name, workspace_dir=workspace_dir)          
        prototype = self.extract_prototype(result)
        self.append_prototype_to_header(prototype, header_path=header_path, workspace_dir=workspace_dir)
        
        ext = ".c"
        beautified_path = os.path.join(output_dir, f"{base_name}{ext}")
        with open(beautified_path, 'w', encoding='utf-8') as f:
            f.write(result)
            
        print(f"Saved beautified file: {beautified_path}")
        return {'original': file_path, 'beautified': beautified_path}
    
    def process_directory(self, input_dir, workspace_dir):
        """Gathers all .c files, runs batch LLM triage, and beautifies in bottom-up order."""
        import graphlib

        found_files = self.find_code_files(input_dir)
        if not found_files:
            print(f"No .c files found in {input_dir}")
            return []

        file_map = {os.path.splitext(os.path.basename(f))[0]: f for f in found_files}
        func_names = list(file_map.keys())

        graph_path = os.path.join(input_dir, "call_graph.json")
        call_graph = {}
        if os.path.exists(graph_path):
            with open(graph_path, "r", encoding="utf-8") as f:
                call_graph = json.load(f)

        db = SymbolDB(workspace_dir=workspace_dir)
        results = []

        # Helper function to normalize Ghidra/assembly symbol names
        def normalize_func_name(name):
            clean = name.replace('@', '_')
            if re.search(r'_[0-9a-fA-F]{6,}$', clean):
                clean = clean.rsplit('_', 1)[0]
            return clean

        # Create Directed Graph for Topological Sort
        ts = graphlib.TopologicalSorter()

        for raw_caller, callees in call_graph.items():
            caller = normalize_func_name(raw_caller)
            if caller in file_map:
                clean_callees = set()
                for c in callees:
                    clean_c = normalize_func_name(c)
                    # Include only if present in file_map and NOT a self-reference
                    if clean_c in file_map and clean_c != caller:
                        clean_callees.add(clean_c)
                
                ts.add(caller, *clean_callees)

        # Add any disconnected files
        for f_name in func_names:
            if f_name not in call_graph:
                ts.add(f_name)

        # Process topologically (Callees -> Callers)
        try:
            processing_order = list(ts.static_order())
        except graphlib.CycleError as e:
            print(f"Cycle detected in call graph: {e}. Falling back to standard alphabetical order.")
            processing_order = func_names

        # Refactoring Loop
        for func_name in processing_order:
            if func_name not in file_map:
                continue    
            file_path = file_map[func_name]
            res = self.process_function_file(file_path, workspace_dir, call_graph=call_graph)
            results.append(res)
            
        return results


if __name__ == "__main__": # -> it is used inside the bash script
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
        print(f"Invalid path provided: {args.input_path}")