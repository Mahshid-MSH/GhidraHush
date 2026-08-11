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

    call_graph = {}

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

                # Ignore list for both MSVC and MinGW runtimes
                CRT_IGNORE_LIST = [
                    # --- MSVC Runtime, Startup & CRT Boilerplate ---
                    "mainCRTStartup", "WinMainCRTStartup", "__tmainCRTStartup",
                    "__security_init_cookie", "__security_check_cookie", "__alloca_probe",
                    "__except_handler4", "guard_check_icall", "__SEH_prolog4",
                    "_ValidateLocalCookies", "_JumpToContinuation", "_UnwindNestedFrames",
                    "__CreateFrameInfo", "try_load_library_from_system_directory",
                    
                    # --- MinGW Specific Setup/Teardown ---
                    "mingw_get_invalid_parameter_handler",
                    "mingw_set_invalid_parameter_handler",
                    "pre_c_init", "pre_cpp_init"
                    "__gcc_deregister_frame", "__gcc_register_frame", 
                    "__do_global_ctors", "__do_global_dtors",
                    "_pei386_runtime_relocator", "__dyn_tls_dtor", "__dyn_tls_init",
                    "__mingw_enum_import_library_names", "__mingw_GetSectionCount", 
                    "__mingw_GetSectionForAddress", "__mingw_TLScallback",
                    "___w64_mingwthr_add_key_dtor", "___w64_mingwthr_remove_key_dtor",
                    "__mingwthr_run_key_dtors.part.0", "__tlregdtor",
                    "register_frame_ctor", "_FindPESection", "_FindPESectionByName", 
                    "_FindPESectionExec", "_GetPEImageBase", "_ValidateImageBase", 
                    
                    # --- Exception, Error Handling, and Math ---
                    "__C_specific_handler", "_gnu_exception_handler", 
                    "_get_invalid_parameter_handler", "_set_invalid_parameter_handler",
                    "_EH4_CallFilterFunc", "_EH4_TransferToHandler", "_EH4_GlobalUnwind2", "_EH4_LocalUnwind",
                    "__invoke_watson", "_matherr", "signal",
                    
                    # --- C Standard Library Statically Linked Wrappers ---
                    "abort", "atexit", "_onexit", "exit", "_cexit", "_amsg_exit",
                    "malloc", "calloc", "free", "memcpy", "_memset", "strlen", "_strlen", 
                    "strcmp", "_strcmp", "strncmp", "fprintf", "vfprintf", "fwrite", 
                    "_initterm", "__iob_func", "__acrt_iob_func",
                    
                    # --- Command Line & Environment ---
                    "__getmainargs", "__p__acmdln", "__p__commode", "__p__fmode",
                    "__set_app_type", "_setargv", "___chkstk_ms", "__set_fmode", "__set_new_mode",
                    
                    # --- Windows API Thunks & Wrappers ---
                    "DeleteCriticalSection", "EnterCriticalSection", "InitializeCriticalSection", 
                    "LeaveCriticalSection", "GetLastError", "GetStartupInfoA", 
                    "SetUnhandledExceptionFilter", "Sleep", "TlsGetValue", 
                    "VirtualProtect", "VirtualQuery"
                ]

                # Substring patterns characteristic of MSVC/CRT/compiler helpers
                CRT_SUBSTRING_PATTERNS = [
                    "_scrt_", "_acrt_", "_vcrt_", "__std_", 
                    "___acrt_", "___scrt_", "___vcrt_",
                    "__CxxFrameHandler", "__InternalCxxFrameHandler",
                    "uninitialized_", "initialize_", "construct_", "destroy_"
                ]

                for function in functions:
                    func_name = function.getName()
                    
                    # Skip Externals (dynamically linked APIs from import tables)
                    if function.isExternal():
                        continue   
                    # Skip Thunks (jump wrappers to imports)
                    if function.isThunk():
                        continue   
                    # Skip Explicit CRT/Compiler Boilerplate Matches
                    if func_name in CRT_IGNORE_LIST:
                        print(f" Skipping CRT Boilerplate: {func_name}")
                        continue 
                    # Skip via Substring Patterns (Catches MSVC internal helper namespaces)
                    if any(pattern in func_name for pattern in CRT_SUBSTRING_PATTERNS):
                        print(f" Skipping Runtime/Compiler Helper: {func_name}")
                        continue
                    # Skip Library Functions tagged via FID
                    tags = [tag.getName() for tag in function.getTags()]
                    if "LIBRARY" in tags:
                        continue

                    # Skip functions starting with underscores (libc / compiler boilerplate)
                    # We also check for 'FID_conflict:_' to catch Ghidra's library matches
                    if func_name.startswith('_') or func_name.startswith('FID_conflict:_') or func_name.startswith('pre'):
                        print(f" Skipping Runtime/Library Function: {func_name}")
                        continue
                        
                    clean_name = f"{func_name}"
                     
                    # Extract Called Functions
                    callees = []
                    for callee in function.getCalledFunctions(TaskMonitor.DUMMY):
                        callee_name = callee.getName()
                        callee_addr = callee.getEntryPoint().toString()
                        callees.append(f"{callee_name}_{callee_addr}")
                    call_graph[clean_name] = callees
                    
                    results = decompiler.decompileFunction(function, 60, None)
                    c_code = results.getDecompiledFunction().getC() if results.decompileCompleted() else "Decompilation failed!"
                    
                    c_file_path = os.path.join(file_output_dir, f"{clean_name}.c")
                    with open(c_file_path, 'w', encoding='utf-8') as f:
                        f.write(c_code)
                    print(f" Extracted: {func_name}")

    graph_path = os.path.join(file_output_dir, "call_graph.json")
    with open(graph_path, "w", encoding="utf-8") as f:
        json.dump(call_graph, f, indent=4)
    print(f"\nCall graph exported to {graph_path}")