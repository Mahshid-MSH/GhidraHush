import os
import json
import sys
import argparse
import graphlib
import json
import re       

current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from base_agent import BaseLLMAgent
from database.symbol_db import SymbolDB
from prompts import get_pass_1_prompt, get_pass_2_prompt, get_pass_3_prompt
from code_utils import (
    pre_process_ghidra_types,
    build_name_to_id_map,
    resolve_callee_id,
    extract_prototype,
    find_code_files,
    append_prototype_to_header,
)


class CCodeEnhancer(BaseLLMAgent):
    """
    Core Decompilation Cleanup Engine.
    
    Why this exists: Raw Ghidra decompilation is notoriously ugly and rarely compiles. 
    It contains synthetic variables (uVar1, piVar2), weird pointer arithmetic, and broken casts. 
    This class orchestrates a multi-pass LLM pipeline combined with static compilation 
    checks to transform raw Ghidra output into clean, compilable C/C++ code.
    """

    def __init__(self, model_name=None, base_url=None):
        super().__init__(model_name, base_url)

    def _run_llm_pass(self, prompt_template, current_code, pass_name, base_name="unknown", workspace_dir="."):
        """
        Injects code into the prompt template and executes the LLM task.
        
        Why it's here: Standardizes the logging and error-handling format across 
        all passes. Setting `temperature=0` is critical here—we want deterministic 
        code refactoring, not creative hallucinations.
        """
        print(f"  -> Running {pass_name}...")
        prompt = prompt_template.replace("___C_CODE_PLACEHOLDER___", current_code)
        
        return self.process_llm_task(
            prompt=prompt,
            original_code=current_code,
            workspace_dir=workspace_dir,
            log_prefix=f"enhancer_{pass_name}",
            base_name=base_name,
            options={
                'temperature': 0  # Force maximum determinism for code generation
            }
        )

    def beautify_code(self, code, callee_prototypes="", is_cpp=False,
                      base_name="unknown", workspace_dir=".", db=None):
        """
        The core multi-pass enhancement loop with a "Compile Gate" short-circuit.
        
        Why it's here: LLMs often fail to fix complex pointer/cast issues in a single pass.
        We use an iterative approach:
          - Pass 1: Syntax cleanup and variable renaming.
          - Pass 2+: Deep semantic fixes (pointers, Win32 constants).
        Crucially, we run a background compiler check (`_try_syntax_check`) after every pass. 
        If the code compiles, we STOP immediately. This saves API tokens and prevents 
        subsequent LLM passes from accidentally breaking already-working code.
        """
        lang_name = "C++" if is_cpp else "C"
        max_passes = int(os.environ.get("STAGE3_PASSES", "1"))
        print(f"Beautifying {lang_name} code ({max_passes} pass max)...")

        # C89 requires variables at the top of the block; C++ prefers local scope.
        # Enforcing this constraint prevents simple compiler errors later.
        var_rule = (
            "3. **C89 COMPLIANCE**: ALL variables MUST be declared at the top of the function block before executable statements."
            if not is_cpp else
            "3. **C++ SCOPE**: Declare variables as close as possible to their first use, following modern C++ best practices."
        )

        context_block = ""
        if callee_prototypes:
            context_block = (f"\n### KNOWN CALLEE PROTOTYPES:\nStrictly cast "
                             f"arguments to match these exact signatures:\n"
                             f"{callee_prototypes}\n")

        current = code
        for i in range(max_passes):
            prev = current

            # Determine the appropriate prompt for the current pass
            if i == 0:
                prompt = get_pass_1_prompt(is_cpp, var_rule)
            else:
                prompt = get_pass_2_prompt(is_cpp, context_block)

            current = self._run_llm_pass(prompt, current,
                                         f"Pass_{i + 1}", base_name,
                                         workspace_dir)
            
            # Fallback if LLM failed to return valid code
            if not current:
                current = prev
                
            # Compile Gate: If it compiles, stop burning API tokens and accept the code.
            gate = self._try_syntax_check(current, workspace_dir, is_cpp)
            if gate is not None and gate[0]:
                print(f"  -> compiles after pass {i + 1}; skipping remaining passes")
                break

            # Convergence Check: If the LLM stopped making changes, give up to avoid loops.
            if i > 0 and current == prev:
                print(f"  -> pass {i + 1} changed nothing; stopping")
                current = prev
                break

        # Deterministic insertion: Always better to use python for guaranteed formatting
        # rather than begging the LLM to remember to include a header file.
        current = self._ensure_header_include(current)

        print("  -> Beautification complete.")
        return {"code": current}

    def _try_syntax_check(self, code, workspace_dir, is_cpp):
        """
        Invokes the local compiler (GCC/Clang) to verify syntax.
        Returns (True, stderr) if successful, None if compiler is unavailable.
        """
        try:
            from code_utils import syntax_check
            return syntax_check(code, workspace_dir, is_cpp=is_cpp)
        except ImportError:
            return None

    def _ensure_header_include(self, code):
        """
        Deterministically injects `#include "data_globals.h"`.
        
        Why it's here: In earlier versions of this pipeline, an LLM pass was used 
        just to add include headers. LLMs are notoriously bad at arbitrary structural 
        rules. Doing it via regex/string manipulation guarantees the header is present 
        and prevents breaking multi-file compilation setups.
        """
        if re.search(r'#\s*include\s*"data_globals\.h"', code):
            return code
            
        lines = code.split("\n")
        i = 0
        # Skip over any leading file-level comment blocks before injecting
        if lines and lines[0].lstrip().startswith("/*"):
            while i < len(lines) and "*/" not in lines[i]:
                i += 1
            i += 1
            
        lines.insert(i, '\n#include "data_globals.h"')
        return "\n".join(lines)
    
    def process_function_file(self, file_path, workspace_dir, call_graph=None, db=None, name_to_id=None):
        """
        End-to-end processing for a single C/C++ function file.
        
        Why it's here: This method handles the "Context Assembly". Before asking the 
        LLM to fix a function, it looks at the call graph, finds all functions *this* 
        function calls, looks up their exact prototypes from the SQLite DB, and injects 
        them into the prompt. This prevents the LLM from hallucinating variable types 
        during function calls.
        """
        output_dir = os.path.join(workspace_dir, 'processed_functions')
        os.makedirs(output_dir, exist_ok=True)
        header_path = os.path.join(workspace_dir, "data_globals.h")
        
        with open(file_path, 'r', encoding='utf-8') as f:
            original_code = f.read()
            
        base_name = os.path.splitext(os.path.basename(file_path))[0]
        print(f"\nProcessing: {base_name}")

        # --- Context Injection Block ---
        # Fetch verified prototypes of all functions called by this file
        callee_prototypes_str = ""
        if call_graph and base_name in call_graph:
            entry = call_graph[base_name]
            callees = entry.get("callees", []) if isinstance(entry, dict) else entry
            
            if name_to_id is None:
                name_to_id = build_name_to_id_map(call_graph)

            prototypes = []
            for callee_id in callees:
                clean_callee_id = resolve_callee_id(callee_id, call_graph, name_to_id)
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
        
        # Remove Ghidra-specific junk types (e.g., 'undefined8') before LLM sees it
        cleaned_code = pre_process_ghidra_types(original_code)
        
        # Run the multi-pass LLM agent
        enhancement = self.beautify_code(
            cleaned_code, 
            callee_prototypes_str, 
            is_cpp=is_cpp, 
            base_name=base_name, 
            workspace_dir=workspace_dir,
            db=db,
        )
        result = enhancement["code"]

        # Extract the resulting prototype and globally expose it for future functions
        prototype = extract_prototype(result)
        append_prototype_to_header(prototype, header_path=header_path)

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
        """
        Orchestrates processing of an entire decompiled project using Topological Sort.
        
        Why it's here: If function `main()` calls `calculate_hash()`, we MUST process 
        `calculate_hash()` first so we can extract its definitive prototype and feed 
        it to the LLM when it processes `main()`. 
        
        By using a Directed Acyclic Graph (DAG) and topological sorting based on 
        `call_graph.json`, we process the codebase "bottom-up" (leaf functions first). 
        This is the secret to getting a decompiled codebase to successfully recompile.
        """
        found_files = find_code_files(input_dir)
        if not found_files:
            print(f"No source files found in {input_dir}")
            return []

        file_map = {os.path.splitext(os.path.basename(f))[0]: f for f in found_files}
        func_names = list(file_map.keys())

        # Load Ghidra call graph definitions
        graph_path = os.path.join(input_dir, "call_graph.json")
        call_graph = {}
        if os.path.exists(graph_path):
            with open(graph_path, "r", encoding="utf-8") as f:
                call_graph = json.load(f)

        db = SymbolDB(workspace_dir=workspace_dir)
        results = []
        name_to_id = build_name_to_id_map(call_graph)

        # Build the Directed Acyclic Graph (DAG) for processing
        ts = graphlib.TopologicalSorter()
        for caller, entry in call_graph.items():
            if caller in file_map:
                callees = entry.get("callees", []) if isinstance(entry, dict) else entry
                # Resolve names to ensure mapping matches the physical files
                resolved_callees = {resolve_callee_id(c, call_graph, name_to_id) for c in callees}
                clean_callees = {c for c in resolved_callees if c in file_map}
                
                # Register dependency: Caller depends on clean_callees
                ts.add(caller, *clean_callees)

        # Ensure isolated functions (nodes with no edges) are still processed
        for f_name in func_names:
            if f_name not in call_graph:
                ts.add(f_name)

        # Generate processing order. Fallback to arbitrary order if recursive functions exist.
        try:
            processing_order = list(ts.static_order())
        except graphlib.CycleError as e:
            print(f"Cycle detected in call graph (recursion): {e}. "
                  f"Falling back to standard alphabetical order.")
            processing_order = func_names

        # Execute the bottom-up generation
        for func_name in processing_order:
            if func_name not in file_map:
                continue    
            file_path = file_map[func_name]
            res = self.process_function_file(
                file_path, 
                workspace_dir, 
                call_graph=call_graph, 
                db=db, 
                name_to_id=name_to_id
            )
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