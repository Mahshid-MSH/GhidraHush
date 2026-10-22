import argparse
import graphlib
import json
import os
import re
import shutil
import sys

current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from base_agent import BaseLLMAgent
from database.symbol_db import SymbolDB
from prompts import get_pass_1_prompt
from code_utils import (
    pre_process_ghidra_types,
    build_name_to_id_map,
    resolve_callee_id,
    extract_prototype,
    find_code_files,
    append_prototype_to_header,
)
STUB_BODY_MARKERS = (
    "halt_baddata",
    "Bad instruction",
    "Unable to resolve",
    "Control flow encountered bad instruction data",
    "software_bkpt",
)

CONTROL_FLOW_RE = re.compile(r'\b(if|while|for|switch|goto|do)\b')

STUB_NAME_RE = re.compile(
    r'^(thunk_|std__|_?_?scrt_|__security_|_RTC_|__GSHandler|_guard_|__acrt_|__vcrt_|'
    r'FID_conflict|_alloca_probe|__chkstk|_?_?SEH_|__except_handler|__CxxFrameHandler|'
    r'_?_?DllMainCRTStartup|_?_?tmainCRTStartup|mainCRTStartup)',
    re.IGNORECASE,
)

LIBRARY_FUNCS = {
    "time", "memcpy", "memset", "memmove", "strlen", "strcmp", "strcpy", "strncpy",
    "malloc", "free", "calloc", "realloc", "printf", "sprintf", "puts", "exit",
    "atexit", "abort", "_amsg_exit", "_initterm", "_onexit",
}
ADDR_SUFFIX_RE = re.compile(r'_[0-9a-fA-F]{6,}$')


class CCodeEnhancer(BaseLLMAgent):
    def __init__(self, model_name=None, base_url=None):
        super().__init__(model_name, base_url)

    def _classify_stub(self, code, base_name):
        bare_name = ADDR_SUFFIX_RE.sub("", base_name)
        if bare_name in LIBRARY_FUNCS:
            return "known library function"
        if STUB_NAME_RE.match(bare_name):
            return "name matches CRT/thunk/library pattern"


        for marker in STUB_BODY_MARKERS:
            if marker in code:
                return f"contains Ghidra marker: {marker}"
        stripped = re.sub(r"/\*.*?\*/", "", code, flags=re.S)
        stripped = re.sub(r'//[^\n]*', '', stripped)
        start, end = stripped.find('{'), stripped.rfind('}')
        if start == -1 or end <= start:
            return "no function body"
        body = stripped[start + 1:end]

        statements = [s.strip() for s in body.split(';') if s.strip()]
        meaningful = []
        for statement in statements:
            if re.fullmatch(r"return(\s+(0|0x0|NULL))?", statement):
                continue
            if re.fullmatch(r"[\w\s\*]+", statement) and not statement.startswith("return"):
                continue
            meaningful.append(statement)

        if not meaningful:
            return "empty/trivial body"

        # Normalize a temporary assignment followed by its return to the call.
        if len(meaningful) == 2:
            match = re.fullmatch(r"return\s+(\w+)", meaningful[1])
            if match and re.match(
                rf"{re.escape(match.group(1))}\s*=\s*(\([\w\s\*:]+\))?\s*[\w:]+\s*\(",
                meaningful[0],
            ):
                meaningful = [meaningful[0].split("=", 1)[1].strip()]

        # Single call with no logic = forwarding thunk
        if (
            len(meaningful) == 1
            and "(" in meaningful[0]
            and "=" not in meaningful[0]
            and not CONTROL_FLOW_RE.search(body)
        ):
            return "single-call forwarding thunk"

        return None


    def _run_llm_pass(
        self,
        prompt_template,
        current_code,
        pass_name,
        base_name="unknown",
        workspace_dir=".",
    ):
        print(f"  -> Running {pass_name}...")
        prompt = prompt_template.replace("___C_CODE_PLACEHOLDER___", current_code)

        return self.process_llm_task(
            prompt=prompt,
            original_code=current_code,
            workspace_dir=workspace_dir,
            log_prefix=f"enhancer_{pass_name}",
            base_name=base_name,
            options={"temperature": 0},
        )

    def beautify_code(
        self, code, is_cpp=False, base_name="unknown", workspace_dir="."
    ):
        lang_name = "C++" if is_cpp else "C"
        print(f"Beautifying {lang_name} code (Single Pass)...")

        # C89 requires variables at the top of the block; C++ prefers local scope.
        var_rule = (
            "3. **C89 COMPLIANCE**: ALL variables MUST be declared at the top of "
            "the function block before executable statements."
            if not is_cpp else
            "3. **C++ SCOPE**: Declare variables as close as possible to their "
            "first use, following modern C++ best practices."
        )

        prompt = get_pass_1_prompt(is_cpp, var_rule)
        current = self._run_llm_pass(
            prompt, code, "Pass_1", base_name, workspace_dir
        )
        if not current:
            current = code

        # Deterministic header inclusion
        current = self._ensure_header_include(current)

        print("  -> Beautification complete.")
        return {"code": current}

    def _ensure_header_include(self, code):
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

    def process_function_file(
        self, file_path, workspace_dir, call_graph=None, db=None, name_to_id=None
    ):
        output_dir = os.path.join(workspace_dir, "processed_functions")
        os.makedirs(output_dir, exist_ok=True)
        header_path = os.path.join(workspace_dir, "data_globals.h")

        with open(file_path, 'r', encoding='utf-8') as f:
            original_code = f.read()

        base_name = os.path.splitext(os.path.basename(file_path))[0]
        print(f"\nProcessing: {base_name}")

        is_cpp = file_path.endswith(".cpp")

        # Remove Ghidra-specific junk types before LLM sees it
        cleaned_code = pre_process_ghidra_types(original_code)

        # Run the single-pass LLM agent
        enhancement = self.beautify_code(
            cleaned_code,
            is_cpp=is_cpp,
            base_name=base_name,
            workspace_dir=workspace_dir,
        )
        result = enhancement["code"]

        # Extract the resulting prototype and globally expose it for future functions
        prototype = extract_prototype(result)
        append_prototype_to_header(prototype, header_path=header_path)

        ext = ".cpp" if is_cpp else ".c"
        beautified_path = os.path.join(output_dir, f"{base_name}{ext}")
        with open(beautified_path, "w", encoding="utf-8") as f:
            f.write(result)

        print(f"Saved beautified file: {beautified_path}")
        return {
            'original': file_path,
            'beautified': beautified_path,
        }

    def filter_stubs(self, files, workspace_dir):
        """Quarantine stub functions and return files for the enhancement stage."""
        if os.environ.get("STAGE3_QUARANTINE", "1") != "1":
            return files

        qdir = os.path.join(workspace_dir, "quarantined")
        manifest_path = os.path.join(qdir, "quarantine_manifest.json")
        manifest = {}
        if os.path.exists(manifest_path):
            with open(manifest_path, "r", encoding="utf-8") as f:
                manifest = json.load(f)

        kept = []
        for path in files:
            base_name = os.path.splitext(os.path.basename(path))[0]
            with open(path, "r", encoding="utf-8") as f:
                code = f.read()

            reason = self._classify_stub(code, base_name)
            if not reason:
                kept.append(path)
                continue

            os.makedirs(qdir, exist_ok=True)
            dest = os.path.join(qdir, os.path.basename(path))
            shutil.move(path, dest)
            manifest[base_name] = {"reason": reason, "original_path": path}
            print(f"  -> QUARANTINED {base_name}: {reason}")

        if manifest:
            os.makedirs(qdir, exist_ok=True)
            with open(manifest_path, "w", encoding="utf-8") as f:
                json.dump(manifest, f, indent=2)

        return kept

    def process_directory(self, input_dir, workspace_dir):

        found_files = find_code_files(input_dir)
        found_files = self.filter_stubs(found_files, workspace_dir)
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
                resolved_callees = {
                    resolve_callee_id(callee, call_graph, name_to_id)
                    for callee in callees
                }
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
            print(
                f"Cycle detected in call graph (recursion): {e}. "
                "Falling back to standard alphabetical order."
            )
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
                name_to_id=name_to_id,
            )
            results.append(res)

        return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Beautify C/C++ function files using LLM agents."
    )
    parser.add_argument(
        "input_path", help="Path to a file or directory containing source files"
    )
    parser.add_argument(
        "--workspace", default=".", help="Workspace directory for symbols and headers"
    )
    parser.add_argument(
        "--model", default=os.environ.get("LLM_MODEL", "deepseek-expert"),
        help="LLM model to use",
    )

    args = parser.parse_args()
    enhancer = CCodeEnhancer(model_name=args.model)

    print("-" * 50)

    if os.path.isdir(args.input_path):
        enhancer.process_directory(args.input_path, workspace_dir=args.workspace)
    elif os.path.isfile(args.input_path):
        if enhancer.filter_stubs([args.input_path], args.workspace):
            enhancer.process_function_file(args.input_path, workspace_dir=args.workspace)
        else:
            print(f"{args.input_path} was quarantined; nothing to process.")
    else:
        print(f"Invalid path provided: {args.input_path}")