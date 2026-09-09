import os
import json
import sys
import argparse
import graphlib

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
    """Process C/C++ code for beautification using LLM multi-pass pipelines"""

    def __init__(self, model_name=None, base_url=None):
        super().__init__(model_name, base_url)

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

        # PASS 1: Variable Recovery, Artifact Removal & Syntax Cleanup
        pass_1_prompt = get_pass_1_prompt(is_cpp, var_rule)
        code_v1 = self._run_llm_pass(pass_1_prompt, code, "Pass_1", base_name, workspace_dir)

        context_block = ""
        if callee_prototypes:
            context_block = f"\n### KNOWN CALLEE PROTOTYPES:\nStrictly cast arguments to match these exact signatures:\n{callee_prototypes}\n"

        # PASS 2: Pointer Recovery, Casts & Win32 Constant Normalization
        pass_2_prompt = get_pass_2_prompt(is_cpp, context_block)
        code_v2 = self._run_llm_pass(pass_2_prompt, code_v1, "Pass_2", base_name, workspace_dir)

        # PASS 3: Compilation Readiness, Headers & Ghidra Artifact Rewrite
        pass_3_prompt = get_pass_3_prompt(is_cpp)
        final_code = self._run_llm_pass(pass_3_prompt, code_v2, "Pass_3", base_name, workspace_dir)
        
        if not final_code:
            final_code = code_v2

        print("  -> Beautification complete.")

        return {
            "code": final_code,
        }

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
        cleaned_code = pre_process_ghidra_types(original_code)
        
        enhancement = self.beautify_code(
            cleaned_code, 
            callee_prototypes_str, 
            is_cpp=is_cpp, 
            base_name=base_name, 
            workspace_dir=workspace_dir,
            db=db,
        )
        result = enhancement["code"]

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
        """Gathers all code files and beautifies in bottom-up topological order."""
        found_files = find_code_files(input_dir)
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

        name_to_id = build_name_to_id_map(call_graph)

        ts = graphlib.TopologicalSorter()
        for caller, entry in call_graph.items():
            if caller in file_map:
                callees = entry.get("callees", []) if isinstance(entry, dict) else entry
                resolved_callees = {resolve_callee_id(c, call_graph, name_to_id) for c in callees}
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