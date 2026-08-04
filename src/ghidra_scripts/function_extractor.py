import pyghidra
import re
import os
import sys
import tempfile
import json

pyghidra.start()
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import TaskMonitor

def extract_functions(file_path, workspace_dir):
    output_dir = os.path.join(workspace_dir, "extracted_functions")
    
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    base_name = os.path.basename(file_path)
    file_output_dir = os.path.join(output_dir, base_name)
    os.makedirs(file_output_dir, exist_ok=True)

    call_graph = {} # INITIALIZE CALL GRAPH DICTIONARY

    with tempfile.TemporaryDirectory() as tmpdir:
        with pyghidra.open_project(tmpdir, "GhidraHush_Tmp", create=True) as project:
            
            loader = pyghidra.program_loader().project(project).source(file_path)
            with loader.load() as load_results:
                load_results.save(TaskMonitor.DUMMY)
            
            program_path = f"/{base_name}"
            
            # --- EVERYTHING BELOW MUST STAY INSIDE THIS 'WITH' BLOCK ---
            with pyghidra.program_context(project, program_path) as program:
                print(f"Analyzing {file_path}...")
                pyghidra.analyze(program)  
                listing = program.getListing()
                decompiler = DecompInterface()
                decompiler.openProgram(program)
                
                functions = program.getFunctionManager().getFunctions(True)

                CRT_IGNORE_LIST = [
                    "_start", "_INIT_0", "_FINI_0", 
                    "__libc_start_main", "__security_init_cookie", 
                    "___mingw_CRTStartup", "mainCRTStartup", "__gcc_register_frame"
                ]

                for function in functions:
                    func_name = function.getName()
                    
                    # --- NEW: Filtering Logic ---
                    # 1. Skip Externals (dynamically linked APIs from import tables)
                    if function.isExternal():
                        print(f" Skipping External API: {func_name}")
                        continue
                        
                    # 2. Skip Thunks (jump wrappers to imports)
                    if function.isThunk():
                        print(f" Skipping Thunk: {func_name}")
                        continue
                        
                    # 3. Skip Compiler Bootstrapping
                    if any(crt in func_name for crt in CRT_IGNORE_LIST):
                        print(f" Skipping CRT Boilerplate: {func_name}")
                        continue
                        
                    # 4. Skip FID matches (Standard Library Functions)
                    tags = [tag.getName() for tag in function.getTags()]
                    if "LIBRARY" in tags:
                        print(f" Skipping Library Function (FID): {func_name}")
                        continue
                    # ----------------------------

                    func_addr = function.getEntryPoint().toString()
                    clean_name = f"{func_name}_{func_addr}"
                     
                    # --- Extract Called Functions ---
                    callees = []
                    for callee in function.getCalledFunctions(TaskMonitor.DUMMY):
                        callee_name = callee.getName()
                        callee_addr = callee.getEntryPoint().toString()
                        callees.append(f"{callee_name}_{callee_addr}")
                    
                    # FIXED INDENTATION: Must be outside the 'for callee' loop
                    call_graph[clean_name] = callees
                    # -------------------------------------

                    results = decompiler.decompileFunction(function, 60, None)
                    c_code = results.getDecompiledFunction().getC() if results.decompileCompleted() else "Decompilation failed!"
                    
                    c_file_path = os.path.join(file_output_dir, f"{clean_name}.c")
                    with open(c_file_path, 'w', encoding='utf-8') as f:
                        f.write(c_code)
                    
                    # FIXED INDENTATION
                    print(f" Extracted: {func_name}")

    # ---Save Call Graph to JSON ---
    graph_path = os.path.join(file_output_dir, "call_graph.json")
    with open(graph_path, "w", encoding="utf-8") as f:
        json.dump(call_graph, f, indent=4)
    print(f"\nCall graph exported to {graph_path}")