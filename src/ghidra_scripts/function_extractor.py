import pyghidra
import re
import os
import sys
import tempfile
import json
from collections import deque

pyghidra.start()
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import TaskMonitor

#frozenset for O(1) lookup time
CRT_IGNORE_SET = frozenset([
    "mainCRTStartup", "WinMainCRTStartup",
    "guard_check_icall", "__SEH_prolog4",
    "_ValidateLocalCookies", "_JumpToContinuation","try_load_library_from_system_directory",
    "mingw_get_invalid_parameter_handler", "mingw_set_invalid_parameter_handler",
    "pre_c_init", "pre_cpp_init",
    "abort", "atexit", "exit",
    "malloc", "calloc", "free", "memcpy","strlen"
])

COMPILER_PREFIXES = ('_', '.', '?', '<', 'FID_conflict:', 'mingw', 'gcc:_', 'g++:_')

def is_crt_or_external(function):
    """Returns True if the function is an external API, thunk, or CRT boilerplate."""
    if function is None:
        return True

    if function.isExternal() or function.isThunk() or function.isLibrary():
        return True

    func_name = function.getName()

    # Broad stroke: Catch anything starting with _, ., ?, < or known compiler prefixes
    if func_name.startswith(COMPILER_PREFIXES):
        return True

    if func_name in CRT_IGNORE_SET:
        return True

    # Check Ghidra FID tags and comments efficiently
    tags = [tag.getName() for tag in function.getTags()]
    if "LIBRARY" in tags:
        return True

    comment_str = (function.getComment() or "") + (function.getRepeatableComment() or "")
    if "Library" in comment_str:
        return True

    return False

def get_user_functions_top_down(program):
    """
    Traverses the call graph top-down starting from main/entry point,
    pruning CRT subtrees and returning only reachable user functions.
    """
    fm = program.getFunctionManager()
    root_funcs = []
    sym_table = program.getSymbolTable()

    # Look for explicit main symbols
    for name in ("main", "_main", "WinMain", "_WinMain@16", "wmain"):
        for sym in sym_table.getGlobalSymbols(name):
            f = fm.getFunctionAt(sym.getAddress())
            if f: root_funcs.append(f)

    # Locate PE entry points if stripped
    if not root_funcs:
        for entry_name in ("entry", "mainCRTStartup"):
            for sym in sym_table.getSymbolIterator(entry_name, True):
                f = fm.getFunctionAt(sym.getAddress())
                if f: root_funcs.append(f)

    # Fallback
    if not root_funcs:
        root_funcs = [f for f in fm.getFunctions(True) if not f.isExternal() and not f.isThunk()]

    visited = set()
    user_functions = []
    queue = deque(root_funcs) # O(1) pops

    while queue:
        curr_func = queue.popleft()
        
        addr_offset = curr_func.getEntryPoint().getOffset() 

        if addr_offset in visited:
            continue
        visited.add(addr_offset)

        callees = curr_func.getCalledFunctions(TaskMonitor.DUMMY)

        if is_crt_or_external(curr_func):
            # Queue its callees to bypass the CRT wrapper and find 'main'
            for callee in callees:
                if callee.getEntryPoint().getOffset() not in visited:
                    queue.append(callee)
        else:
            user_functions.append(curr_func)
            for callee in callees:
                if callee.getEntryPoint().getOffset() not in visited:
                    queue.append(callee)

    return user_functions


def extract_functions(file_path, workspace_dir):
    output_dir = os.path.join(workspace_dir, "extracted_functions")
    base_name = os.path.basename(file_path)
    file_output_dir = os.path.join(output_dir, base_name)
    os.makedirs(file_output_dir, exist_ok=True)

    call_graph = {}

    with tempfile.TemporaryDirectory() as tmpdir:
        with pyghidra.open_project(tmpdir, "GhidraHush_Tmp", create=True) as project:
            loader = pyghidra.program_loader().project(project).source(file_path)
            with loader.load() as load_results:
                load_results.save(TaskMonitor.DUMMY)

            program_path = f"/{base_name}"
            with pyghidra.program_context(project, program_path) as program:

                tx_id = program.startTransaction("Enable FID Analyzer")
                try:
                    options = program.getOptions("Analyzers")
                    options.setBoolean("Function ID", True)
                finally:
                    program.endTransaction(tx_id, True)

                print(f"Analyzing {file_path}...")
                pyghidra.analyze(program)  

                decompiler = DecompInterface()
                decompiler.openProgram(program)

                user_functions = get_user_functions_top_down(program)
                print(f"Found {len(user_functions)} user-defined functions.")

                extracted_data = []
                binary_has_cpp = False

                for function in user_functions:
                    clean_name = function.getName()

                    call_graph[clean_name] = [
                        f"{c.getName()}_{c.getEntryPoint().toString()}" 
                        for c in function.getCalledFunctions(TaskMonitor.DUMMY)
                    ]

                    # Decompile
                    results = decompiler.decompileFunction(function, 60, None)
                    c_code = results.getDecompiledFunction().getC() if results.decompileCompleted() else "Decompilation failed!"

                    # Detect C++ structures
                    if "::" in clean_name or "std::" in c_code or "operator new" in c_code or "this" in c_code:
                        binary_has_cpp = True

                    extracted_data.append((clean_name, c_code))
                # Write everything at once
                file_ext = ".cpp" if binary_has_cpp else ".c"
                
                for clean_name, c_code in extracted_data:
                    c_file_path = os.path.join(file_output_dir, f"{clean_name}{file_ext}")
                    with open(c_file_path, 'w', encoding='utf-8') as f:
                        f.write(c_code)
                    print(f" Extracted: {clean_name}{file_ext}")

    graph_path = os.path.join(file_output_dir, "call_graph.json")
    with open(graph_path, "w", encoding="utf-8") as f:
        json.dump(call_graph, f, indent=4)
        
    print(f"\nCall graph exported to {graph_path}")