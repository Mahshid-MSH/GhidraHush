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

import hashlib

def make_function_id(function):
    """
    Stable, collision-free identifier for a Ghidra Function with length protection.
    """
    qualified_name = function.getName(True)
    safe_name = re.sub(r'[^A-Za-z0-9_~]', '_', qualified_name)
    addr_str = str(function.getEntryPoint())
    
    # Truncate extremely long mangled names and append an MD5 hash to prevent filename limits
    if len(safe_name) > 120:
        name_hash = hashlib.md5(qualified_name.encode('utf-8')).hexdigest()[:8]
        safe_name = safe_name[:120] + f"_{name_hash}"
        
    return f"{safe_name}_{addr_str}"


def resolve_thunk(function):
    """Ghidra's getCalledFunctions() can return a thunk (jump-stub) Function
    object for a callee instead of the real implementation it jumps to --
    same name, but its own separate (stub) entry point address. Thunks are
    filtered out of the extracted/decompiled set entirely (see FILTER 2 in
    extract_functions), so a thunk's own address is never a top-level key
    in call_graph.json or a filename on disk. If make_function_id() is run
    on the thunk itself, the resulting callee id can't match anything --
    silently dropping that dependency edge for any downstream consumer
    (e.g. a topological sort) that filters callees against known ids.
    Resolving through the thunk chain here means every callee id lines up
    with the callee's own top-level entry, exactly like a direct call.
    """
    if function is not None and function.isThunk():
        target = function.getThunkedFunction(True)  # True: follow multi-hop thunk chains
        if target is not None:
            return target
    return function


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

    project_location = os.path.join(workspace_dir, "ghidra_project")
    project_name = f"{base_name}_ghidra"
    os.makedirs(project_location, exist_ok=True)

    # Both pipeline stages need to see the SAME fully-analyzed program --
    # PDB symbols, custom GDT archives, GetProcAddress-resolved API types,
    # compiler-helper fixups. This used to run inside a
    # tempfile.TemporaryDirectory() project that got deleted the instant
    # this function returned, while dump_global_values.py opened a
    # completely separate, freshly (re-)analyzed project with none of
    # that enrichment. One persistent, shared project fixes that at the
    # source instead of duplicating the whole analysis setup twice.
    try:
        project_cm = pyghidra.open_project(project_location, project_name, create=False)
        print(f"Opened existing shared Ghidra project at {project_location}/{project_name}")
    except FileNotFoundError:
        project_cm = pyghidra.open_project(project_location, project_name, create=True)
        print(f"Created shared Ghidra project at {project_location}/{project_name}")

    with project_cm as project:
            program_path = f"/{base_name}"
            existing_file = project.getProjectData().getFile(program_path)
            needs_full_analysis = existing_file is None

            if needs_full_analysis:
                loader = pyghidra.program_loader().project(project).source(file_path)
                with loader.load() as load_results:
                    load_results.save(TaskMonitor.DUMMY) # -> This one is done to make sure that monitoring wont cancel if it is taking too long

                program_path = f"/{base_name}"
            else:
                print(f"{program_path} already exists in the shared project -- reusing the "
                      f"existing analyzed program instead of re-importing/re-analyzing. Delete "
                      f"{project_location} if you need a clean re-analysis.")

            with pyghidra.program_context(project, program_path) as program:
                if needs_full_analysis:

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

                    # Persist the enriched analysis back into the shared
                    # project now, so dump_global_values.py (or any other
                    # later stage) sees exactly this -- PDB types, GDT
                    # types, GetProcAddress-resolved API types, compiler
                    # fixups -- without redoing any of it.
                    try:
                        program.getDomainFile().save(TaskMonitor.DUMMY)
                        print("Saved enriched analysis back to the shared project.")
                    except Exception as e:
                        print(f"  [warn] could not save analysis back to the shared project: {e} "
                              f"-- later stages may not see this enrichment.")
                else:
                    # Reused, already-analyzed program: skip re-running
                    # PDB/GDT/GetProcAddress analysis, but a decompiler
                    # instance is still needed below for the extraction
                    # loop, so set that part up on its own.
                    # Decompiler setup
                    decomp_options = DecompileOptions()
                    decomp_options.setMaxPayloadMBytes(1024)   
                    decompiler = DecompInterface()
                    decompiler.setOptions(decomp_options)
                    decompiler.openProgram(program)

                function_manager = program.getFunctionManager()
                all_functions = list(function_manager.getFunctions(True))
                print(f"Total functions in binary: {len(all_functions)}. Applying signature and name filters...")

                # Get the Memory Manager for the current program ---
                memory = program.getMemory()

                extracted_data = []
                binary_has_cpp = False

                skip_counts = {"non_exec": 0, "prefix": 0, "thunk_external": 0, "decompile_failed": 0, "library_fn": 0}

                for function in all_functions:
                    # Filter out functions in non-executable memory blocks ---
                    entry_point = function.getEntryPoint()
                    memory_block = memory.getBlock(entry_point)
                    
                    # If the memory block doesn't exist, or is NOT marked as executable (e.g. .pdata), skip it
                    if memory_block is None or not memory_block.isExecute():
                        skip_counts["non_exec"] += 1
                        continue

                    clean_name = function.getName()
                    lower_name = clean_name.lower()

                    is_exception = any(exc in lower_name for exc in TARGET_EXCEPTIONS)
                    # FILTER 1: Ignored Prefixes (__scrt, Unwind) & Underscores ---
                    if not is_exception:
                        if lower_name.startswith(IGNORED_PREFIXES):
                            skip_counts["prefix"] += 1
                            continue
                    # FILTER 2: Skip standard Thunks or Externals immediately
                    if not is_exception and (function.isExternal() or function.isThunk()):
                        skip_counts["thunk_external"] += 1
                        continue
                    # Decompile the function
                    results = decompiler.decompileFunction(function, 300, TaskMonitor.DUMMY)
                    c_code = (
                        results.getDecompiledFunction().getC()
                        if results.decompileCompleted()
                        else "Decompilation failed!"
                    )
                    if c_code == "Decompilation failed!":
                        # This used to be a silent continue -- a function
                        # that fails to decompile (timeout, hard pcode
                        # failure, etc, as opposed to DetectVPC-style
                        # "completed but truncated") vanished from
                        # extracted_functions/ with ZERO trace anywhere in
                        # the log. If a thread entry point or any other
                        # function you actually care about was ever
                        # dropped here, this was the only place that could
                        # have told you, and it wasn't telling you.
                        skip_counts["decompile_failed"] += 1
                        err_msg = results.getErrorMessage() if results else "?"
                        print(f"  [warn] decompile did not complete for {clean_name} @ {entry_point} "
                              f"-- excluded from extracted_functions/: {err_msg}")
                        continue
                    if not is_exception:
                        # FILTER 3: Basic Library Strings 
                        if "/* Library Function" in c_code: # -> ghidra will put comment on functions it assumes are library functions
                            skip_counts["library_fn"] += 1
                            print(f"  [info] {clean_name} @ {entry_point} matched a known library function "
                                  f"signature -- excluded from extracted_functions/")
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
                    # visited in. Each callee is resolved through resolve_thunk()
                    # first: getCalledFunctions() can return a thunk stub rather
                    # than the real target, and computing the id straight off the
                    # stub would produce an id that never matches the callee's
                    # actual top-level entry (see resolve_thunk docstring).
                    call_graph[func_id] = {
                        "name": full_name,
                        "callees": [
                            make_function_id(resolve_thunk(c))
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
    print(f"Skipped: {skip_counts['non_exec']} non-executable, {skip_counts['prefix']} ignored-prefix, "
          f"{skip_counts['thunk_external']} thunk/external, {skip_counts['decompile_failed']} decompile-failed, "
          f"{skip_counts['library_fn']} matched-library-function.")
    print(f"Call graph exported to {graph_path}")