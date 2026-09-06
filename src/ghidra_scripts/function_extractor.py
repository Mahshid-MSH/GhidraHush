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

def make_function_id(function):
    """
    Stable, collision-free identifier for a Ghidra Function.
    """
    qualified_name = function.getName(True)  # e.g. "MyClass::Update", or "FUN_00401830" if unqualified
    safe_name = re.sub(r'[^A-Za-z0-9_~]', '_', qualified_name)
    addr_str = str(function.getEntryPoint())
    return f"{safe_name}_{addr_str}"


# Keywords that override all filters. If a function name contains these, it will be extracted.
TARGET_EXCEPTIONS = ["winmain", "entry"]

IGNORED_PREFIXES = (

    "unwind", "~", "___scrt", "__", "mingw", "Ordinal",
    "strcmp", "strcpy", "strlen", "strstr", "strncmp",
    "WinMainCRTStartup", "memset", "wcsnlen", "mbsrtowcs", "wcsrtombs",

    # --- Standard C Library: String Operations ---
    "strcat", "strncat", "strncpy", "strchr", "strrchr", "strtok", 
    "strcspn", "strspn", "strpbrk", "strspn", "strcasecmp", "strncasecmp",
    "wcscpy", "wcsncpy", "wcscat", "wcsncat", "wcscmp", "wcsncmp", 
    "wcslen", "wcsstr", "wcschr", "wcsrchr", "wcscasecmp", "wcsncasecmp",

    # --- Standard C Library: Memory Operations ---
    "memcpy", "memmove", "memcmp", "memchr", "bzero", "bcopy", "bcmp",

    # --- Standard C Library: Dynamic Memory & Conversions ---
    "malloc", "calloc", "realloc", "free", 
    "atoi", "atol", "atoll", "atof", "strtol", "strtoul", "strtod","atexit",

    # --- Standard C Library: I/O & Formatting ---
    "printf", "fprintf", "sprintf", "snprintf", "vprintf", "vfprintf", "abort","atexit",
    "vsprintf", "vsnprintf", "scanf", "fscanf", "sscanf", "atoi","calloc","dtoa_lock",
    "fopen", "fclose", "fread", "fwrite", "fseek", "ftell", "dtoa_lock_cleanup",
    "puts", "gets", "fgets", "fputs", "putchar", "getchar", "FindPESection","fprintf",
    # --- MSVC / Universal CRT Startup & Internals ---
    "mainCRTStartup", "wmainCRTStartup", "wWinMainCRTStartup", "DllMainCRTStartup","strchr","signal",
    "_initterm", "_initterm_e", "_cexit", "_exit", "exit", "abort","localconv","mbrlen","memset",
    "__security_init_cookie", "__security_check_cookie","init_codepage_func",
    "_seh_filter_exe", "_seh_filter_dll", 
    "_configure_wide_argv", "_configure_narrow_argv",
    "_initialize_narrow_environment", "_initialize_wide_environment",
    "__acrt_iob_func", "__stdio_common_vfprintf", "__stdio_common_vsprintf",
    "_amsg_exit", "_get_initial_narrow_environment", "_get_initial_wide_environment",

    # --- Compiler Linker Artifacts & Mangling Prefixes ---
    "_imp__", "__imp_", "??", "@"
)

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
                load_results.save(TaskMonitor.DUMMY) # -> This one is done to make sure that monitoring wont cancel if it is taking too long

            program_path = f"/{base_name}"
            with pyghidra.program_context(project, program_path) as program:

                # --- Configure Options ---
                tx_id = program.startTransaction("Configure Options and PDB")
                try:
                    options = program.getOptions("Analyzers")
                    options.setBoolean("Function ID", True)
                    options.setBoolean("Demangler MSVC", True) # For Windows binaries
                    options.setBoolean("Demangler GNU", True)  # For GCC/MinGW binaries
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

                # FIX COMPILER HELPER FUNCTIONS ---   -> This stage should take place right after the analysis is done. 

                # ----------------- Explanation about what we are trying to do:(just in case you are curious :) ) -------------------------------------

                #After Ghidra finishes analyzing the binary, this code tries to clean up certain compiler-generated helper functions so that the decompiled code becomes more correct.

                # When Ghidra sees these functions in a compiled binary, it may interpret them as ordinary functions.

                # 1. __chkstk (stack probing/allocation) -> The operating system doesn't necessarily want a program to suddenly jump the stack pointer down by 100 KB. 
                # So the compiler may generate code that touches the stack gradually.

                # 2.__alloca_probe (dynamic stack allocation) -> this is for when the size isn't necessarily known at compile time. So the compiler needs special machinery to adjust the stack safely.
                # 3.__security_check_cookie (buffer overflow protection) -> This MF is responsible for the canary stuff. The lord of the nightmares.
                print("Applying Call Fixups and patching MinGW stack probes...")
                tx_helpers = program.startTransaction("Fix Compiler Helpers")
                try:
                    fm = program.getFunctionManager()
                    mem = program.getMemory() # This lets you read/write bytes in the program's memory representation
                    listing = program.getListing() # This gives you access to instructions, code units, data, bluh bluh
                    ref_mgr = program.getReferenceManager() # This helps you find references to things

                    for func in fm.getFunctions(True):
                        func_name = func.getName().lower()
                        
                        # 1. MinGW Stack Probes: NOP out call sites so EAX (allocation size) is preserved
                        if "chkstk_ms" in func_name:
                            func.setInline(False)
                            func.setCallFixup(None)
                            
                            entry_point = func.getEntryPoint()
                            for ref in ref_mgr.getReferencesTo(entry_point):
                                if ref.getReferenceType().isCall():
                                    call_addr = ref.getFromAddress()
                                    inst = listing.getInstructionAt(call_addr)
                                    if inst:
                                        length = inst.getLength() # find how many bytes the CALL occupies
                                        listing.clearCodeUnits(call_addr, call_addr.add(length - 1), False) # What is this doing? It wants to remove ghidra's current instruction/code-unit interpretation for these bytes
                                        mem.setBytes(call_addr, b'\x90' * length)  # the hexadecimal opcode for the NOP
                                        # By overwriting the 5-byte CALL instruction with 5 NOP instructions, we are "patching out" the function call. 
                                        # Why do we have to fill it with NOP? MinGW calling convention is in a way that helper may receive information in a register such as EAX.
                                        # So, If you remove the helper call, you avoid the helper modifying registers in a way that confuses the reverse-engineered code.
                        # MSVC Stack Allocators: Apply MSVC fixup
                        elif "chkstk" in func_name or "alloca_probe" in func_name:
                            func.setInline(False)
                            func.setCallFixup("__chkstk")
                        
                        # Security Cookie Checks: Force inline
                        elif "security_check_cookie" in func_name:
                            func.setInline(True)
                            
                finally:
                    program.endTransaction(tx_helpers, True)
                # --------------------------------------------------

                # Load All Custom GDT Archives Automatically ---
                gdt_dir = os.path.abspath("gdt_archives")
                program_dtmgr = program.getDataTypeManager()
                gdt_files = glob.glob(os.path.join(gdt_dir, "*.gdt"))

                if gdt_files:
                    print(f"Found {len(gdt_files)} custom GDT archive(s). Loading into program context...")
                    
                    # Start a transaction before modifying the program's data types -> I did this because otherwise all the modifications would be lost
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
                        program.endTransaction(tx_gdt, True)
                else:
                    print(f"No custom GDT archives found in {gdt_dir}. Proceeding with default types.")
                #-------------------------------------------------------------------------------------- Decompilation starts from here --------------------------------------------------
                # Decompiler setup
                decomp_options = DecompileOptions()
                decomp_options.setMaxPayloadMBytes(1024)   
                decompiler = DecompInterface()
                decompiler.setOptions(decomp_options)
                decompiler.openProgram(program)

                # RUN GETPROCADDRESS TYPE RESOLVER PASS --- => Some malwares use getProcAddr instead of directly calling
                print("Running dynamic API function pointer resolver...")
                target_funcs = resolve_getprocaddress_types(program, decompiler)

                if target_funcs:
                    propagate_downstream_types(program, decompiler, target_funcs)
                # ---------------------------------------------

                function_manager = program.getFunctionManager()
                all_functions = list(function_manager.getFunctions(True))
                print(f"Total functions in binary: {len(all_functions)}. Applying signature and name filters...")

                # Get the Memory Manager for the current program ---
                memory = program.getMemory()

                extracted_data = []
                binary_has_cpp = False

                for function in all_functions:
                    # Filter out functions in non-executable memory blocks ---
                    entry_point = function.getEntryPoint()
                    memory_block = memory.getBlock(entry_point)
                    
                    # If the memory block doesn't exist, or is NOT marked as executable (e.g. .pdata), skip it
                    if memory_block is None or not memory_block.isExecute():
                        continue

                    clean_name = function.getName()
                    lower_name = clean_name.lower()

                    is_exception = any(exc in lower_name for exc in TARGET_EXCEPTIONS)
                    # FILTER 1: Ignored Prefixes (__scrt, Unwind) & Underscores ---
                    if not is_exception:
                        if lower_name.startswith(IGNORED_PREFIXES):
                            continue
                    # FILTER 2: Skip standard Thunks or Externals immediately
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
                        # FILTER 3: Basic Library Strings 
                        if "/* Library Function" in c_code: # -> ghidra will put comment on functions it assumes are library functions
                            continue         

                    # --- C++ DETECTION PASS ---
                    full_name = function.getName(True)  # Retrieves full namespace path (e.g., Class::Method)
                    if not binary_has_cpp:
                        if "::" in full_name or clean_name.startswith("~"):
                            binary_has_cpp = True
                        elif re.search(r'\b(__thiscall|operator new|operator delete)\b', c_code):
                            binary_has_cpp = True

                    # Identity used for the call graph key, the DB join key,
                    # and the output file name (see make_function_id docstring
                    # for why the bare name isn't safe to use for any of these).
                    func_id = make_function_id(function)

                    # Populate the call graph. Callee ids are computed with the
                    # exact same function, so they match up with the callee's
                    # own func_id regardless of which order functions are
                    # visited in.
                    call_graph[func_id] = {
                        "name": full_name,
                        "callees": [
                            make_function_id(c)
                            for c in function.getCalledFunctions(TaskMonitor.DUMMY)
                        ],
                    }

                    extracted_data.append((func_id, full_name, c_code))

                # Dynamic extension selection based on C++ detection
                file_ext = ".cpp" if binary_has_cpp else ".c"
                if binary_has_cpp:
                    print("C++ indicators detected in decompiled functions. Exporting all files as .cpp...")
                else:
                    print("No C++ artifacts detected. Exporting all files as .c...")

                for func_id, full_name, c_code in extracted_data:
                    c_file_path = os.path.join(file_output_dir, f"{func_id}{file_ext}")
                    with open(c_file_path, "w", encoding="utf-8") as f:
                        f.write(c_code)
                    print(f" Extracted: {func_id}{file_ext}  (symbol: {full_name})")

    graph_path = os.path.join(file_output_dir, "call_graph.json")
    with open(graph_path, "w", encoding="utf-8") as f:
        json.dump(call_graph, f, indent=4)

    print(f"\nExtracted {len(extracted_data)} total functions.")
    print(f"Call graph exported to {graph_path}")