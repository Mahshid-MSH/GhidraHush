import os
import json
import sys
import re
import argparse
import graphlib
from database.symbol_db import SymbolDB

current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from base_agent import BaseLLMAgent


class CCodeEnhancer(BaseLLMAgent):
    """Process C/C++ code for beautification using LLM multi-pass pipelines"""

    def __init__(self, model_name=None, base_url=None):
        super().__init__(model_name, base_url)

    def pre_process_ghidra_types(self, c_code):
        """Standardize Ghidra types via Python before the LLM sees them."""
        replacements = {
            r'\bunsigned\s+long\s+long\b': 'uint64_t',
            r'\bsigned\s+long\s+long\b': 'int64_t',
            r'\bunsigned\s+long\b': 'uint32_t',
            r'\bsigned\s+long\b': 'int32_t',
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
            r'__CheckForDebuggerJustMyCode\(&[A-Za-z0-9_]+\);': '',
            r'_RTC_CheckStackVars\(.*?\);': '',
            r'__RTC_CheckEsp\(\);': '',
            r'__security_check_cookie\(.*?\);': ''    
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
            options={'temperature': 0}
        )

    def beautify_code(self, code, callee_prototypes="", is_cpp=False, base_name="unknown", workspace_dir="."):
        lang_name = "C++" if is_cpp else "C"
        print(f"Beautifying {lang_name} code via Multi-Pass Pipeline...")

        var_rule = (
            "3. **C89 COMPLIANCE**: ALL variables MUST be declared at the top of the function block before executable statements." 
            if not is_cpp else 
            "3. **C++ SCOPE**: Declare variables as close as possible to their first use, following modern C++ best practices."
        )

        pass_1_prompt_c = f"""You are an expert C programmer. Clean up the following Ghidra pseudo-code by fixing types and variable names, while preserving the original logic and all side effects.

        ### STRICT RULES

        1. **FUNCTION NAME & SIGNATURE**: Keep the function name exactly as provided. Do not rename it. Preserve the parameter list and return type exactly as given (after type cleanup).

        2. **LOCAL VARIABLES**: Rename local variables that have Ghidra's cryptic names (e.g., `local_1c`, `uVar1`, `iVar2`) to meaningful, readable names that reflect their purpose.  
        - A **local variable** is any variable declared inside the function body.  
        - If a variable is used only as an intermediate step in a computation, you may inline it if it improves readability, but **never remove code that has side effects** (function calls, memory writes, etc.).

        {var_rule}

        4. **TYPE REPLACEMENT**: Use standard `<stdint.h>` types: `uint8_t`, `uint16_t`, `uint32_t`, `uint64_t`, `int32_t`, etc. Replace Ghidra's `undefined`, `undefined1/2/4/8`, `long`, `ulong`, `dword`, `word`, `byte` with the appropriate `stdint.h` type.

        5. **REMOVE CALLING CONVENTIONS & COMPILER ARTIFACTS**:
        - Remove all `__cdecl`, `__stdcall`, `__fastcall` keywords.
        - Remove Ghidra compiler artifacts: `ExceptionList`, `___security_cookie`, `__security_check_cookie`, `__RTC_CheckEsp`, `__RTC_CheckStackVars`, and any loop that fills stack memory with `0xcccccccc`.
        - Delete the variables associated with those artifacts.

        6. **PRESERVE LOGIC & SIDE EFFECTS**: Do **not** remove any function call, assignment, loop, condition, or memory operation. Only remove dead variables that are assigned but never used, and only if the assignment has no side effect.

        7. **GLOBAL VARIABLES**: If a variable name looks like a global (e.g., `DAT_`, `s_`, or a known symbol from `data_globals.h`), keep its name **exactly**. Do not rename it, do not redeclare it locally, and do not try to resolve its value. Assume it is declared in `data_globals.h`.

        8. **STRING LITERALS**: Preserve every string literal exactly as it appears. Do not replace it with a global or variable. If a string is inside a local array or passed directly to a function, keep it verbatim.

        9. **ONE FUNCTION ONLY**: Output only the cleaned version of the provided function. Do **not** include any other function, header, or `#include`. Do not add comments or explanations.

        ### OUTPUT FORMAT
        Return ONLY valid C code wrapped in ```c backticks. No explanations.

        ### INPUT CODE
        ___C_CODE_PLACEHOLDER___
        """

        pass_1_prompt_cpp = f"""You are an expert C++ programmer. Clean up the following Ghidra pseudo-code by fixing types and variable names, while preserving the original logic and all side effects.

        ### STRICT RULES

        1. **FUNCTION NAME & SIGNATURE**: Keep the function name exactly as provided. Do not rename it. Preserve the parameter list and return type exactly as given.

        2. **LOCAL VARIABLES**: Rename cryptic local variables (`local_1c`, `uVar1`) to meaningful names.

        {var_rule}

        4. **TYPE REPLACEMENT**: Use standard `<cstdint>` types (`uint8_t`, `uint32_t`, etc.).

        5. **REMOVE CALLING CONVENTIONS & ARTIFACTS**: Remove `__stdcall`, `ExceptionList`, `__security_cookie`, etc.

        6. **PRESERVE LOGIC & SIDE EFFECTS**: Retain all operations with side effects.

        7. **GLOBAL VARIABLES**: Retain global names (`DAT_`, `s_`).

        8. **STRING LITERALS**: Preserve string literals verbatim.

        9. **C++ OBJECTS – DEFER RECONSTRUCTION**: Do not convert explicit `this` pointers into C++ classes in this pass.

        10. **ONE FUNCTION ONLY**: Output only the cleaned version wrapped in ```cpp backticks.

        ### INPUT CODE
        ___C_CODE_PLACEHOLDER___
        """

        pass_1_prompt = pass_1_prompt_cpp if is_cpp else pass_1_prompt_c
        code_v1 = self._run_llm_pass(pass_1_prompt, code, "Pass_1", base_name, workspace_dir)

        context_block = ""
        if callee_prototypes:
            context_block = f"\n### KNOWN CALLEE PROTOTYPES:\nYou MUST strictly cast arguments to match these exact signatures:\n{callee_prototypes}\n"

        pass_2_prompt_c = f"""You are an expert C programmer. Fix memory references, pointer casts, and API calls in the following cleaned Ghidra pseudo-code.
        ### STRICT RULES

        1. **POINTER RECOVERY**: Cast integer types used as pointers to proper pointer types.
        2. **ARRAY INDEXING**: Convert `*(char *)((int64_t)j + Buffer)` to `Buffer[j]`.
        3. **GLOBAL POINTERS**: Cast numeric addresses used as pointers (e.g., `(char *)0x140008164`).
        4. **GLOBAL VARIABLES**: Maintain original global variable names.
        5. **STRING LITERALS**: Preserve string literals.
        6. **CONST CORRECTNESS**: Use `const char *` for string literal assignments.
        7. **FUNCTION POINTERS**: Cast global function pointers appropriately before calling.
        8. **API CALLS**: Cast function parameters to match known signatures.

        {context_block}

        9. **ONE FUNCTION ONLY**: Output only the cleaned function inside ```c backticks.

        ### INPUT CODE
        ___C_CODE_PLACEHOLDER___
        """

        pass_2_prompt_cpp = f"""You are an expert C++ programmer. Fix memory references, pointer casts, and API calls using C++ casts (`static_cast`, `reinterpret_cast`).

        {context_block}

        ### INPUT CODE
        ___C_CODE_PLACEHOLDER___
        """

        pass_2_prompt = pass_2_prompt_cpp if is_cpp else pass_2_prompt_c
        code_v2 = self._run_llm_pass(pass_2_prompt, code_v1, "Pass_2", base_name, workspace_dir)

        pass_3_prompt_c = f"""You are an expert C reverse engineer. Convert Ghidra pseudo-code into clean standard C (C99/C11).

        ### HARD REQUIREMENTS
        1. **COMPILABLE OUTPUT**: Valid C code. Header `#include "data_globals.h"` must be first.
        2. **NO GHIDRA ARTIFACTS**: Remove `CONCATxx`, `local_X._0_1_`, `LAB_` labels, and `goto` constructs.
        3. **CLEAN POINTER ARITHMETIC**: Use proper array/struct indexing.
        4. **ONE FUNCTION ONLY**: Output only the target function inside ```c backticks.

        ### INPUT CODE
        ___C_CODE_PLACEHOLDER___
        """

        pass_3_prompt_cpp = f"""You are an expert C++ reverse engineer. Convert Ghidra pseudo-code into clean C++17.

        ### HARD REQUIREMENTS
        1. **COMPILABLE C++17**: Include `#include "data_globals.h"`.
        2. **NO GHIDRA ARTIFACTS**: Eliminate `__autoclassinit2`, `CONCATxx`, `LAB_` labels.
        3. **C++ OBJECT RECONSTRUCTION**: Convert raw `this` pointer calls back to standard C++ objects (e.g., `std::ifstream`).
        4. **ONE FUNCTION ONLY**: Output only the target function inside ```cpp backticks.

        ### INPUT CODE
        ___C_CODE_PLACEHOLDER___
        """

        pass_3_prompt = pass_3_prompt_cpp if is_cpp else pass_3_prompt_c
        final_code = self._run_llm_pass(pass_3_prompt, code_v2, "Pass_3", base_name, workspace_dir)
        
        if not final_code:
            final_code = code_v2

        print("  -> Beautification complete.")
        return final_code

    def extract_prototype(self, text):
        """Extracts the first C/C++ function prototype from the generated code."""
        pattern = r'^([a-zA-Z0-9_ \t\*\&]+)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)\s*\{'
        match = re.search(pattern, text, re.MULTILINE | re.DOTALL)
        if match:
            return_type = match.group(1).strip()
            func_name = match.group(2).strip()
            args = " ".join(match.group(3).split())
            return f"{return_type} {func_name}({args});"
        return None

    def find_code_files(self, directory):
        """Recursively find all .c and .cpp files in the specified directory."""
        code_files = []
        if not os.path.exists(directory):
            return code_files
            
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith((".c", ".cpp")):
                    code_files.append(os.path.join(root, file))
        
        code_files.sort()
        return code_files

    def append_prototype_to_header(self, prototype, header_path="data_globals.h", db=None, workspace_dir="."):
        if not prototype:
            return
        local_db = db or SymbolDB(workspace_dir=workspace_dir)
        if local_db.parse_and_upsert_prototype(prototype):
            local_db.export_header(header_path)
            print(f"Synced prototype to DB & Header: {prototype}")
        else:
            print(f"Failed to parse prototype for DB: {prototype}")

    def process_function_file(self, file_path, workspace_dir, call_graph=None, db=None):
        output_dir = os.path.join(workspace_dir, 'processed_functions')
        os.makedirs(output_dir, exist_ok=True)
        header_path = os.path.join(workspace_dir, "data_globals.h")
        
        with open(file_path, 'r', encoding='utf-8') as f:
            original_code = f.read()
            
        base_name = os.path.splitext(os.path.basename(file_path))[0]
        print(f"\nProcessing: {base_name}")
        
        callee_prototypes_str = ""
        if call_graph and base_name in call_graph:
            prototypes = []
            callees = call_graph[base_name]
            
            for callee in callees:
                clean_callee = callee.strip()
                proto = None
                
                # 1. Attempt to fetch prototype from SymbolDB first
                if db:
                    try:
                        with db._get_conn() as conn:
                            cursor = conn.cursor()
                            # Query the exact columns from symbol_db.py schema
                            cursor.execute(
                                "SELECT return_type, name, parameters FROM functions WHERE name = ?", 
                                (clean_callee,)
                            )
                            row = cursor.fetchone()
                            if row:
                                # Reconstruct standard C prototype string
                                proto = f"{row[0]} {row[1]}({row[2]});"
                    except Exception as e:
                        print(f"  [!] DB lookup failed for {clean_callee}: {e}")
                
                # 2. Fallback: Request from call graph if it's structured as a dictionary
                if not proto and isinstance(callees, dict):
                    proto_candidate = callees.get(callee)
                    if isinstance(proto_candidate, str) and proto_candidate.strip():
                        proto = proto_candidate.strip()
                        
                if proto:
                    prototypes.append(proto)
                    
            callee_prototypes_str = "\n".join(prototypes)

        is_cpp = file_path.endswith(".cpp")
        cleaned_code = self.pre_process_ghidra_types(original_code)
        
        # Run Multi-Pass LLM Pipeline
        result = self.beautify_code(
            cleaned_code, 
            callee_prototypes_str, 
            is_cpp=is_cpp, 
            base_name=base_name, 
            workspace_dir=workspace_dir
        )          
        
        prototype = self.extract_prototype(result)
        
        # Save prototype back to DB & header
        self.append_prototype_to_header(prototype, header_path=header_path, db=db, workspace_dir=workspace_dir)
        
        ext = ".cpp" if is_cpp else ".c"
        beautified_path = os.path.join(output_dir, f"{base_name}{ext}")
        with open(beautified_path, 'w', encoding='utf-8') as f:
            f.write(result)
            
        print(f"Saved beautified file: {beautified_path}")
        return {'original': file_path, 'beautified': beautified_path}
    
    def process_directory(self, input_dir, workspace_dir):
        """Gathers all code files and beautifies in bottom-up topological order."""
        found_files = self.find_code_files(input_dir)
        if not found_files:
            print(f"No source files found in {input_dir}")
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

        ts = graphlib.TopologicalSorter()
        for caller, callees in call_graph.items():
            if caller in file_map:
                # FIXED: Preserve true callee function names
                clean_callees = {c.strip() for c in callees if c.strip() in file_map}
                ts.add(caller, *clean_callees)

        for f_name in func_names:
            if f_name not in call_graph:
                ts.add(f_name)

        try:
            processing_order = list(ts.static_order())
        except graphlib.CycleError as e:
            print(f"Cycle detected in call graph: {e}. Falling back to standard order.")
            processing_order = func_names

        for func_name in processing_order:
            if func_name not in file_map:
                continue    
            file_path = file_map[func_name]
            res = self.process_function_file(file_path, workspace_dir, call_graph=call_graph, db=db)
            results.append(res)

        return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Beautify C/C++ function files using LLM agents.")
    parser.add_argument("input_path", help="Path to a single file OR directory containing source files")
    parser.add_argument("--workspace", default=".", help="Workspace directory for SymbolDB and headers")
    parser.add_argument("--model", default=os.environ.get('LLM_MODEL', 'deepseek-expert'), help="LLM model to use")
    
    args = parser.parse_args()
    enhancer = CCodeEnhancer(model_name=args.model)
    
    print("-" * 50)
    
    if os.path.isdir(args.input_path):
        enhancer.process_directory(args.input_path, workspace_dir=args.workspace)
    elif os.path.isfile(args.input_path):
        enhancer.process_function_file(args.input_path, workspace_dir=args.workspace)
    else:
        print(f"Invalid path provided: {args.input_path}")