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

    call_graph = {}   # We later build a dependency graph from it for the compilation stage. Using this method, we find a correct order to compile files

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
                
                functions = program.getFunctionManager().getFunctions(True) # This is the list of all the available functions that ghidra has extracted, but some of them are useless and should not be extracted, otherwise they will waste the LLM tokens.

                CRT_IGNORE_LIST = [
                # --- Entry points and CRT Initialization ---
                "mainCRTStartup", "WinMainCRTStartup", "__tmainCRTStartup",
                "__main", "pre_c_init", "pre_cpp_init", "___CTOR_LIST__", 
                "__CTOR_LIST__", ".ctors.65535", "___DTOR_LIST__", "__DTOR_LIST__",
                
                # --- MinGW Specific Setup/Teardown ---
                "__gcc_deregister_frame", "__gcc_register_frame", 
                "__do_global_ctors", "__do_global_dtors",
                "_pei386_runtime_relocator", "__dyn_tls_dtor", "__dyn_tls_init",
                "__mingw_enum_import_library_names", "__mingw_GetSectionCount", 
                "__mingw_GetSectionForAddress", "__mingw_TLScallback",
                "___w64_mingwthr_add_key_dtor", "___w64_mingwthr_remove_key_dtor",
                "__mingwthr_run_key_dtors.part.0", "__tlregdtor",
                "register_frame_ctor", "_FindPESection", "_FindPESectionByName", 
                "_FindPESectionExec", "_GetPEImageBase", "_ValidateImageBase", 
                "_ValidateImageBase.part.0", "_IsNonwritableInCurrentImage",
                "__write_memory.part.0",
                
                # --- Exception, Error Handling, and Math ---
                "__C_specific_handler", "_gnu_exception_handler", 
                "_get_invalid_parameter_handler", "_set_invalid_parameter_handler",
                "mingw_get_invalid_parameter_handler", "mingw_set_invalid_parameter_handler",
                "__mingw_invalidParameterHandler", "__report_error",
                "_matherr", "__mingw_raise_matherr", "__mingw_setusermatherr", 
                "__setusermatherr", "_fpreset", "fpreset", "signal",
                
                # --- C Standard Library Statically Linked Wrappers ---
                "abort", "atexit", "_onexit", "exit", "_cexit", "_amsg_exit",
                "malloc", "calloc", "free", "memcpy", "strlen", "strncmp",
                "fprintf", "vfprintf", "fwrite", "_initterm", "__iob_func", 
                "__acrt_iob_func", "__lconv_init", "my_lconv_init",
                
                # --- Command Line & Environment ---
                "__getmainargs", "__p__acmdln", "__p__commode", "__p__fmode",
                "__set_app_type", "_setargv", "___chkstk_ms",
                
                # --- Windows API Thunks (MinGW Wrappers) ---
                "DeleteCriticalSection", "EnterCriticalSection", "InitializeCriticalSection", 
                "LeaveCriticalSection", "GetLastError", "GetStartupInfoA", 
                "SetUnhandledExceptionFilter", "Sleep", "TlsGetValue", 
                "VirtualProtect", "VirtualQuery"
            ]

                for function in functions:
                    func_name = function.getName()
                    
                    # Filtering Logic -> I am using a filtering method in order to extract the useful functions only, which will then go through the LLM enhancement process
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
                    func_addr = function.getEntryPoint().toString()
                    clean_name = f"{func_name}"
                     
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

    # Save Call Graph to JSON
    graph_path = os.path.join(file_output_dir, "call_graph.json")
    with open(graph_path, "w", encoding="utf-8") as f:
        json.dump(call_graph, f, indent=4)
    print(f"\nCall graph exported to {graph_path}")