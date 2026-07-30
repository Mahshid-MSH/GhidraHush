import pyghidra
import re
import os
import sys
import tempfile
import json

pyghidra.start()
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import TaskMonitor

def extract_functions(file_path, output_dir="extracted_functions"):
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
            with pyghidra.program_context(project, program_path) as program:
                print(f"Analyzing {file_path}...")
                pyghidra.analyze(program)  
                listing = program.getListing()
                decompiler = DecompInterface()
                decompiler.openProgram(program)
                
                functions = program.getFunctionManager().getFunctions(True)

                for function in functions:
                    func_name = function.getName()
                    func_addr = function.getEntryPoint().toString()
                    clean_name = f"{func_name}_{func_addr}"
                    
                    # --- Extract Called Functions ---
                    callees = []
                    for callee in function.getCalledFunctions(TaskMonitor.DUMMY):
                        callee_name = callee.getName()
                        callee_addr = callee.getEntryPoint().toString()
                        callees.append(f"{callee_name}_{callee_addr}")
                    call_graph[clean_name] = callees
                    # -------------------------------------

                    results = decompiler.decompileFunction(function, 60, None)
                    c_code = results.getDecompiledFunction().getC() if results.decompileCompleted() else "Decompilation failed!"
                    
                    c_file_path = os.path.join(file_output_dir, f"{clean_name}.c")
                    with open(c_file_path, 'w', encoding='utf-8') as f:
                        f.write(c_code)
                    print(f" Extracted: {func_name}")

    # ---Save Call Graph to JSON ---
    graph_path = os.path.join(file_output_dir, "call_graph.json")
    with open(graph_path, "w", encoding="utf-8") as f:
        json.dump(call_graph, f, indent=4)
    print(f"\nCall graph exported to {graph_path}")

