import pyghidra
import re
import os
import sys
import tempfile
import json
import glob
from collections import deque
from utils.getprocaddress_resolver import resolve_getprocaddress_types, propagate_downstream_types

pyghidra.start("-Xmx8g")
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.app.plugin.core.analysis import PdbUniversalAnalyzer
from ghidra.util.task import TaskMonitor
from java.io import File
from ghidra.program.model.data import FileDataTypeManager
from ghidra.program.model.pcode import HighFunctionDBUtil
from ghidra.program.model.symbol import SourceType

# Keywords that override all filters. If a function name contains these, it will be extracted.
TARGET_EXCEPTIONS = ["winmain", "entry"]

# Prefixes that should cause a function to be ignored if they appear at the start of the name
IGNORED_PREFIXES = ("unwind","~","___scrt","__","mingw","Ordinal")

def extract_functions(file_path, workspace_dir):
    output_dir = os.path.join(workspace_dir, "extracted_functions")
    base_name = os.path.basename(file_path)
    file_output_dir = os.path.join(output_dir, base_name)
    os.makedirs(file_output_dir, exist_ok=True)

    call_graph = {}

    # Look for the raw PDB file
    pdb_path = os.path.splitext(file_path)[0] + ".pdb"
    has_pdb = os.path.isfile(pdb_path)

    with tempfile.TemporaryDirectory() as tmpdir:
        with pyghidra.open_project(tmpdir, "GhidraHush_Tmp", create=True) as project:
            loader = pyghidra.program_loader().project(project).source(file_path)
            with loader.load() as load_results:
                load_results.save(TaskMonitor.DUMMY)

            program_path = f"/{base_name}"
            with pyghidra.program_context(project, program_path) as program:

                # --- Configure Options ---
                tx_id = program.startTransaction("Configure Options and PDB")
                try:
                    options = program.getOptions("Analyzers")
                    options.setBoolean("Function ID", True)
                    options.setBoolean("Demangler MSVC", True) # For Windows binaries
                    options.setBoolean("Demangler GNU", True)  # For GCC/MinGW binaries
                    options.setBoolean("Windows x86 PE RTTI Analyzer", True) # Run-Time Type Information (RTTI) helps Ghidra reconstruct C++ class
                    options.setBoolean("Windows PE x86 x64 Exception Handling", True) # for exception handling
                    options.setBoolean("ASCII Strings", True)
                    if options.contains("Decompiler Parameter ID.Timeout (secs)"):
                        options.setInt("Decompiler Parameter ID.Timeout (secs)", 300)
                    options.setBoolean("Windows x86 PE Imports", True)
                    if options.contains("Create Thunks"):
                        options.setBoolean("Create Thunks", True)

                    if has_pdb:
                        print(f"Found PDB: {pdb_path}. Loading symbols...")
                        PdbUniversalAnalyzer.setPdbFileOption(program, File(pdb_path))
                        options.setBoolean("PDB Universal", True)
                finally:
                    program.endTransaction(tx_id, True)

                print(f"Analyzing {file_path}...")
                pyghidra.analyze(program)

                # --- Load All Custom GDT Archives Automatically ---
                gdt_dir = os.path.abspath("gdt_archives")
                program_dtmgr = program.getDataTypeManager()
                gdt_files = glob.glob(os.path.join(gdt_dir, "*.gdt"))

                if gdt_files:
                    print(f"Found {len(gdt_files)} custom GDT archive(s). Loading into program context...")
                    
                    # Start a transaction before modifying the program's data types
                    tx_gdt = program.startTransaction("Load GDT Archives")
                    try:
                        for gdt_path in gdt_files:
                            print(f"    -> Loading: {os.path.basename(gdt_path)}")
                            gdt_file = File(gdt_path)
                            gdt_mgr = FileDataTypeManager.openFileArchive(gdt_file, False)
                            for dt in gdt_mgr.getAllDataTypes():
                                program_dtmgr.addDataType(dt, None)
                            gdt_mgr.close()
                    finally:
                        # Commit the changes
                        program.endTransaction(tx_gdt, True)
                else:
                    print(f"No custom GDT archives found in {gdt_dir}. Proceeding with default types.")
                # --------------------------------------------------

                # Decompiler setup
                decomp_options = DecompileOptions()
                decomp_options.setMaxPayloadMBytes(1024)   
                decompiler = DecompInterface()
                decompiler.setOptions(decomp_options)
                decompiler.openProgram(program)

                # --- RUN GETPROCADDRESS TYPE RESOLVER PASS ---
                print("Running dynamic API function pointer resolver...")
                target_funcs = resolve_getprocaddress_types(program, decompiler)

                if target_funcs:
                    propagate_downstream_types(program, decompiler, target_funcs)
                # ---------------------------------------------

                function_manager = program.getFunctionManager()
                all_functions = list(function_manager.getFunctions(True))
                print(f"Total functions in binary: {len(all_functions)}. Applying signature and name filters...")

                extracted_data = []
                binary_has_cpp = False

                for function in all_functions:
                    clean_name = function.getName()
                    lower_name = clean_name.lower()

                    is_exception = any(exc in lower_name for exc in TARGET_EXCEPTIONS)
                    # FILTER 1: Ignored Prefixes (__scrt, Unwind) & Underscores ---
                    if not is_exception:
                        if lower_name.startswith(IGNORED_PREFIXES):
                            continue
                    # Skip standard Thunks or Externals immediately
                    if not is_exception and (function.isExternal() or function.isThunk()):
                        continue
                    # Decompile the function
                    results = decompiler.decompileFunction(function, 300, TaskMonitor.DUMMY)
                    c_code = (
                        results.getDecompiledFunction().getC()
                        if results.decompileCompleted()
                        else "Decompilation failed!"
                    )
                    if c_code == "Decompilation failed!":
                        continue
                    if not is_exception:
                        # FILTER 2: Basic Library Strings 
                        if "/* Library Function" in c_code:
                            continue         
                        # FILTER 3: Thin wrappers/thunks (e.g. /* fwrite */) 
                        if f"/* {clean_name} */" in c_code:
                            continue
                        # FILTER 4: The Header & Prototype Check 
                        header_block = c_code.split('{', 1)[0]
                        if "std::" in header_block or "__thiscall" in header_block:
                            continue
                    # Populate the call graph
                    call_graph[clean_name] = [
                        f"{c.getName()}_{c.getEntryPoint().toString()}"
                        for c in function.getCalledFunctions(TaskMonitor.DUMMY)
                    ]
                    # Detect C++ structures
                    if "std::" in c_code:
                        binary_has_cpp = True

                    extracted_data.append((clean_name, c_code))
                file_ext = ".cpp" if binary_has_cpp else ".c"

                for clean_name, c_code in extracted_data:
                    safe_name = "".join(
                        [c if c.isalnum() or c in "_:~" else "_" for c in clean_name]
                    )

                    c_file_path = os.path.join(file_output_dir, f"{safe_name}{file_ext}")
                    with open(c_file_path, "w", encoding="utf-8") as f:
                        f.write(c_code)
                    print(f" Extracted: {safe_name}{file_ext}")

    graph_path = os.path.join(file_output_dir, "call_graph.json")
    with open(graph_path, "w", encoding="utf-8") as f:
        json.dump(call_graph, f, indent=4)

    print(f"\nExtracted {len(extracted_data)} total functions.")
    print(f"Call graph exported to {graph_path}")