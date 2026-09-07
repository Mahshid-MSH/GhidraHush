import os
import json
import sys
import re
import shutil
import subprocess
import tempfile
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

    @staticmethod
    def _build_name_to_id_map(call_graph):
        """Maps each function's name (as recorded on its own top-level entry)
        to that entry's real func_id."""
        name_to_id = {}
        for node_id, entry in call_graph.items():
            name = entry.get("name") if isinstance(entry, dict) else None
            if name is None:
                name = node_id.rsplit('_', 1)[0]
            name_to_id.setdefault(name, node_id)
        return name_to_id

    @staticmethod
    def _resolve_callee_id(raw_id, call_graph, name_to_id):
        """Normalizes a callee id from call_graph.json to the id that
        callee's own top-level entry actually uses."""
        raw_id = raw_id.strip()
        if raw_id in call_graph:
            return raw_id
        base_name = raw_id.rsplit('_', 1)[0]
        return name_to_id.get(base_name, raw_id)

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
            r'_RTC_CheckStackVars\(.*?\);': '',
            r'__CheckForDebuggerJustMyCode\(.*?\);': '',
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

    def beautify_code(self, code, callee_prototypes="", is_cpp=False, base_name="unknown", workspace_dir=".", db=None):
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

        7. **GLOBAL VARIABLES & EXTERNAL SYMBOLS**: If a variable name looks like a global (e.g., `DAT_`, `s_`) or a known symbol, keep its name **exactly**. Do **not** define or re-declare structs, unions, enums, or external function prototypes locally. Assume all types and external prototypes are already provided by `data_globals.h`.

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

        7. **GLOBAL VARIABLES & TYPES**: Retain global names (`DAT_`, `s_`). Do **not** define custom structs, classes, enums, or auxiliary prototypes.

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
        8. **API CALLS**: Cast function parameters to match known signatures. Do **not** define structs, unions, enums, or function prototypes.

        {context_block}

        9. **ONE FUNCTION ONLY**: Output only the cleaned function inside ```c backticks.

        ### INPUT CODE
        ___C_CODE_PLACEHOLDER___
        """

        pass_2_prompt_cpp = f"""You are an expert C++ programmer. Fix memory references, pointer casts, and API calls using C++ casts (`static_cast`, `reinterpret_cast`). Do not define external structs or prototypes.

        {context_block}

        ### INPUT CODE
        ___C_CODE_PLACEHOLDER___
        """

        pass_2_prompt = pass_2_prompt_cpp if is_cpp else pass_2_prompt_c
        code_v2 = self._run_llm_pass(pass_2_prompt, code_v1, "Pass_2", base_name, workspace_dir)

        pass_3_prompt_c = f"""You are an expert C reverse engineer. Convert Ghidra pseudo-code into clean standard C (C99/C11).

        ### HARD REQUIREMENTS
        1. **COMPILABLE OUTPUT**: Valid C code. `#include "data_globals.h"` must be the first line. If this function calls any standard library function (`memcpy`, `malloc`, `strlen`, `printf`, etc.), add the matching standard header (`<string.h>`, `<stdlib.h>`, `<stdio.h>`, ...) directly after it -- do not rely on `data_globals.h` to provide these.
        2. **NO STRUCT OR PROTOTYPE DEFINITIONS**: **NEVER** define structs, unions, enums, or additional function prototypes. Assume all custom types, global variables, and external function prototypes are already fully declared in `data_globals.h`. Only work on the single target function provided.
        3. **TRANSLATE GHIDRA ARTIFACTS, DON'T JUST DELETE THEM**: These constructs encode real bit-level or control-flow semantics. Rewrite them to the equivalent plain C, then remove the artifact -- never delete them outright, since that silently changes behavior:
           - `CONCAT44(hi, lo)` -> `(((uint64_t)(hi) << 32) | (uint32_t)(lo))`, and the same pattern scaled to whatever bit widths the specific `CONCATxy` uses.
           - `SUBx y(val, n)` (take `y` bytes starting at byte offset `n`) -> `(uint<y*8>_t)((val) >> (n * 8))`.
           - `local_X._0_1_`-style sub-piece accesses -> a shift+mask (or explicit byte access) on `local_X` that reads/writes that exact same byte, not an approximation.
           - `goto`/`LAB_xxx`: restructure into `if`/`else`/`while`/`for`/`break`/`continue` ONLY when you are certain the resulting control flow is equivalent. If the jump structure is irreducible or ambiguous (e.g. jumps into the middle of a loop, multi-level jumps), keep a plain, clearly-named `goto` rather than guessing -- code that compiles but silently does the wrong thing is worse than an ugly `goto`.
           - Also remove any remaining `__autoclassinit2`-style compiler scaffolding once its effect (if any) has been preserved.
        4. **CLEAN POINTER ARITHMETIC**: Use proper array/struct indexing.
        5. **ONE FUNCTION ONLY**: Output only the target function (plus any headers from rule 1) inside ```c backticks.

        ### INPUT CODE
        ___C_CODE_PLACEHOLDER___
        """

        pass_3_prompt_cpp = f"""You are an expert C++ reverse engineer. Convert Ghidra pseudo-code into clean C++17.

        ### HARD REQUIREMENTS
        1. **COMPILABLE C++17**: `#include "data_globals.h"` must be the first line. If this function calls any standard/STL facility (`memcpy`, `std::string`, `std::vector`, etc.), add the matching header (`<cstring>`, `<string>`, `<vector>`, ...) directly after it -- do not rely on `data_globals.h` to provide these.
        2. **NO STRUCT OR PROTOTYPE DEFINITIONS**: **NEVER** define structs, classes, enums, unions, or extra function prototypes. Assume all types and external signatures are declared in `data_globals.h`. Work exclusively on the provided function body.
        3. **TRANSLATE GHIDRA ARTIFACTS, DON'T JUST DELETE THEM**: `CONCATxy`/`SUBxy`/sub-piece accesses encode real bit-level operations -- rewrite them as the equivalent shift/mask/cast expression (e.g. `CONCAT44(hi, lo)` -> `(((uint64_t)(hi) << 32) | (uint32_t)(lo))`), then remove the artifact. For `goto`/`LAB_xxx`, restructure into normal control flow only when you're certain it's equivalent; otherwise keep a plain `goto` rather than guess, since silently-wrong control flow is worse than an ugly one. Remove `__autoclassinit2`-style scaffolding once its effect is preserved.
        4. **C++ OBJECT RECONSTRUCTION -- ONLY WITH STRONG EVIDENCE**: You may convert raw `this`-pointer / vtable-style code into a standard C++ object (e.g. `std::ifstream`) only when the evidence is unambiguous (a recognizable mangled/demangled STL symbol, a matching vtable layout, or an unmistakable call pattern like the exact sequence of an `fstream` open/read/close). Do not guess a specific STL type from vague similarity (e.g. "it has a buffer and a size" is not enough to justify `std::vector`). When you are not certain, leave the original pointer/struct-offset access as-is rather than inventing an object model -- a wrong reconstruction is more misleading to an investigator than raw pointer arithmetic, because it looks authoritative.
        5. **ONE FUNCTION ONLY**: Output only the target function (plus any headers from rule 1) inside ```cpp backticks.

        ### INPUT CODE
        ___C_CODE_PLACEHOLDER___
        """

        pass_3_prompt = pass_3_prompt_cpp if is_cpp else pass_3_prompt_c
        final_code = self._run_llm_pass(pass_3_prompt, code_v2, "Pass_3", base_name, workspace_dir)
        
        if not final_code:
            final_code = code_v2

        print("  -> Beautification complete.")

        return {
            "code": final_code,
        }

    _PROTO_NAME_RE = re.compile(r'([A-Za-z_~][A-Za-z0-9_:~]*)\s*\(')
    _PROTO_CTRL_KEYWORDS = {'if', 'for', 'while', 'switch', 'return', 'catch', 'sizeof'}

    @staticmethod
    def _find_matching_paren(text, open_idx):
        depth = 0
        i = open_idx
        in_string = None
        while i < len(text):
            ch = text[i]
            if in_string:
                if ch == '\\':
                    i += 1
                elif ch == in_string:
                    in_string = None
            elif ch in ('"', "'"):
                in_string = ch
            elif ch == '(':
                depth += 1
            elif ch == ')':
                depth -= 1
                if depth == 0:
                    return i
            i += 1
        return None

    @staticmethod
    def _is_ctor_or_dtor(func_name):
        parts = func_name.split('::')
        if len(parts) < 2:
            return func_name.startswith('~')
        last, prev = parts[-1], parts[-2]
        return last == prev or last == '~' + prev

    def extract_prototype(self, text):
        if not text:
            return None
        text = re.sub(r'^```[a-zA-Z0-9_+]*\s*\n?', '', text.strip())
        text = re.sub(r'\n?```\s*$', '', text)

        for m in self._PROTO_NAME_RE.finditer(text):
            name_start, name_end = m.span(1)
            paren_open = m.end() - 1
            paren_close = self._find_matching_paren(text, paren_open)
            if paren_close is None:
                continue

            func_name = text[name_start:name_end].strip()
            if func_name in self._PROTO_CTRL_KEYWORDS:
                continue

            after = text[paren_close + 1:].lstrip()
            after = re.sub(r'^(const|noexcept|override|final)\b\s*', '', after)
            if not after.startswith('{'):
                continue

            args = " ".join(text[paren_open + 1:paren_close].split())
            head = text[:name_start]
            last_hash_end = -1
            for pp in re.finditer(r'^#.*$', head, re.MULTILINE):
                last_hash_end = pp.end()
            boundary = max(head.rfind(';'), head.rfind('}'), last_hash_end)
            return_type = head[boundary + 1:].strip()
            if not return_type and not self._is_ctor_or_dtor(func_name):
                continue

            prefix = f"{return_type} " if return_type else ""
            return f"{prefix}{func_name}({args});"
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

    def append_prototype_to_header(self, prototype, header_path="data_globals.h"):
        """Directly append updates to the header file without interacting with the database."""
        if not prototype:
            return
        try:
            with open(header_path, "a", encoding="utf-8") as f:
                f.write(f"\n{prototype}\n")
            print(f"Appended prototype to Header: {prototype}")
        except Exception as e:
            print(f"Failed to append prototype to header: {e}")

    def process_function_file(self, file_path, workspace_dir, call_graph=None, db=None, name_to_id=None):
        output_dir = os.path.join(workspace_dir, 'processed_functions')
        os.makedirs(output_dir, exist_ok=True)
        header_path = os.path.join(workspace_dir, "data_globals.h")
        
        with open(file_path, 'r', encoding='utf-8') as f:
            original_code = f.read()
            
        base_name = os.path.splitext(os.path.basename(file_path))[0]
        print(f"\nProcessing: {base_name}")

        callee_prototypes_str = ""
        if call_graph and base_name in call_graph:
            entry = call_graph[base_name]
            callees = entry.get("callees", []) if isinstance(entry, dict) else entry
            if name_to_id is None:
                name_to_id = self._build_name_to_id_map(call_graph)

            prototypes = []
            for callee_id in callees:
                clean_callee_id = self._resolve_callee_id(callee_id, call_graph, name_to_id)
                proto = None
                if db:
                    try:
                        row = db.get_function_by_func_id(clean_callee_id)
                        if row:
                            proto = f"{row[0]} {row[1]}({row[2]});"
                    except Exception as e:
                        print(f"  [!] DB lookup failed for {clean_callee_id}: {e}")
                if proto:
                    prototypes.append(proto)

            callee_prototypes_str = "\n".join(prototypes)

        is_cpp = file_path.endswith(".cpp")
        cleaned_code = self.pre_process_ghidra_types(original_code)
        
        enhancement = self.beautify_code(
            cleaned_code, 
            callee_prototypes_str, 
            is_cpp=is_cpp, 
            base_name=base_name, 
            workspace_dir=workspace_dir,
            db=db,
        )
        result = enhancement["code"]

        prototype = self.extract_prototype(result)
        
        # Save prototype back to header
        self.append_prototype_to_header(prototype, header_path=header_path)

        ext = ".cpp" if is_cpp else ".c"
        beautified_path = os.path.join(output_dir, f"{base_name}{ext}")
        with open(beautified_path, 'w', encoding='utf-8') as f:
            f.write(result)
            
        print(f"Saved beautified file: {beautified_path}")
        return {
            'original': file_path,
            'beautified': beautified_path,
        }

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

        name_to_id = self._build_name_to_id_map(call_graph)

        ts = graphlib.TopologicalSorter()
        for caller, entry in call_graph.items():
            if caller in file_map:
                callees = entry.get("callees", []) if isinstance(entry, dict) else entry
                resolved_callees = {self._resolve_callee_id(c, call_graph, name_to_id) for c in callees}
                clean_callees = {c for c in resolved_callees if c in file_map}
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
            res = self.process_function_file(file_path, workspace_dir, call_graph=call_graph, db=db, name_to_id=name_to_id)
            results.append(res)

        return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Beautify C/C++ function files using LLM agents.")
    parser.add_argument("input_path", help="Path to a single file OR directory containing source files")
    parser.add_argument("--workspace", default=".", help="Workspace directory for SymbolDB and headers")
    parser.add_argument("--model", default=os.environ.get('LLM_MODEL', 'deepseek-expert'), help="LLM model to use")
    
    args = parser.parse_args()
    enhancer = CCodeEnhancer(
        model_name=args.model
    )
    
    print("-" * 50)
    
    if os.path.isdir(args.input_path):
        enhancer.process_directory(args.input_path, workspace_dir=args.workspace)
    elif os.path.isfile(args.input_path):
        enhancer.process_function_file(args.input_path, workspace_dir=args.workspace)
    else:
        print(f"Invalid path provided: {args.input_path}")