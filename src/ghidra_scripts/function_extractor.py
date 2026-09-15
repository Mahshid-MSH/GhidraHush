import glob
import hashlib
import json
import os
import re
import sys
import tempfile
from collections import deque

# PyGhidra VM Initialization
import pyghidra
pyghidra.start("-Xmx8g")

# Ghidra API Imports
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.app.plugin.core.analysis import PdbUniversalAnalyzer
from ghidra.program.model.data import FileDataTypeManager
from ghidra.program.model.pcode import HighFunctionDBUtil
from ghidra.program.model.symbol import SourceType
from ghidra.util.task import TaskMonitor
from java.io import File

# Local Project Utilities
from utils.getprocaddress_resolver import (
    propagate_downstream_types,
    resolve_getprocaddress_types,
)

# Constants & Filters
TARGET_EXCEPTIONS = ["winmain", "entry"]

IGNORED_PREFIXES = (
    # Compiler / Runtime Artifacts & Linker Prefixes
    "unwind", "~", "___scrt", "mingw", "Ordinal", "WinMainCRTStartup",
    "_imp__", "__imp_", "??", "@","__",
    
    # Standard C Library: String & Memory Operations
    "strcat", "strncat", "strcpy", "strncpy", "strlen", "strstr", "strchr", 
    "strrchr", "strtok", "strcspn", "strspn", "strpbrk", "strcmp", "strncmp", 
    "strcasecmp", "strncasecmp", "wcscpy", "wcsncpy", "wcscat", "wcsncat", 
    "wcscmp", "wcsncmp", "wcslen", "wcsstr", "wcschr", "wcsrchr", "wcscasecmp", 
    "wcsncasecmp", "wcsnlen", "mbsrtowcs", "wcsrtombs", "memcpy", "memmove", 
    "memcmp", "memchr", "memset", "bzero", "bcopy", "bcmp",

    # Dynamic Memory & Conversions
    "malloc", "calloc", "realloc", "free", "atoi", "atol", "atoll", "atof", 
    "strtol", "strtoul", "strtod", "atexit",

    # Standard I/O & Formatting
    "printf", "fprintf", "sprintf", "snprintf", "vprintf", "vfprintf", 
    "vsprintf", "vsnprintf", "scanf", "fscanf", "sscanf", "fopen", "fclose", 
    "fread", "fwrite", "fseek", "ftell", "puts", "gets", "fgets", "fputs", 
    "putchar", "getchar", "abort", "dtoa_lock", "dtoa_lock_cleanup", "FindPESection",

    # MSVC / Universal CRT Startup & Internals
    "mainCRTStartup", "wmainCRTStartup", "wWinMainCRTStartup", "DllMainCRTStartup",
    "signal", "_initterm", "_initterm_e", "_cexit", "_exit", "exit", 
    "localconv", "mbrlen", "__security_init_cookie", "__security_check_cookie",
    "init_codepage_func", "_seh_filter_exe", "_seh_filter_dll", 
    "_configure_wide_argv", "_configure_narrow_argv",
    "_initialize_narrow_environment", "_initialize_wide_environment",
    "__acrt_iob_func", "__stdio_common_vfprintf", "__stdio_common_vsprintf",
    "_amsg_exit", "_get_initial_narrow_environment", "_get_initial_wide_environment"
)


def make_function_id(function):
    """Generates a stable, collision-free identifier for a Ghidra Function with length protection."""
    qualified_name = function.getName(True)
    safe_name = re.sub(r'[^A-Za-z0-9_~]', '_', qualified_name)
    addr_str = str(function.getEntryPoint())
    
    if len(safe_name) > 120:
        name_hash = hashlib.md5(qualified_name.encode('utf-8')).hexdigest()[:8]
        safe_name = f"{safe_name[:120]}_{name_hash}"
        
    return f"{safe_name}_{addr_str}"


def resolve_thunk(function):
    """Resolves thunk (jump-stub) chains to return the actual target Function implementation."""
    if function is not None and function.isThunk():
        target = function.getThunkedFunction(True)
        if target is not None:
            return target
    return function


def configure_analysis_options(program, has_pdb, pdb_path):
    """Configures analyzer settings and loads PDB symbols if available."""
    tx_id = program.startTransaction("Configure Options and PDB")
    try:
        options = program.getOptions("Analyzers")
        options.setBoolean("Function ID", True)
        options.setBoolean("Demangler MSVC", True)
        options.setBoolean("Demangler GNU", True)
        options.setBoolean("Windows PE x86 x64 Exception Handling", True)
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


def patch_compiler_helpers(program):
    """Fixes compiler-generated helper functions (__chkstk, security cookies) to prevent decompilation artifacts."""
    print("Applying Call Fixups and patching MinGW stack probes...")
    tx_helpers = program.startTransaction("Fix Compiler Helpers")
    try:
        fm = program.getFunctionManager()
        mem = program.getMemory()
        listing = program.getListing()
        ref_mgr = program.getReferenceManager()

        for func in fm.getFunctions(True):
            func_name = func.getName().lower()
        
            # MinGW Stack Probes: NOP out call sites to preserve allocation size in EAX
            if "chkstk_ms" in func_name:
                func.setInline(False)
                func.setCallFixup(None)
            
                entry_point = func.getEntryPoint()
                for ref in ref_mgr.getReferencesTo(entry_point):
                    if ref.getReferenceType().isCall():
                        call_addr = ref.getFromAddress()
                        inst = listing.getInstructionAt(call_addr)
                        if inst:
                            length = inst.getLength()
                            listing.clearCodeUnits(call_addr, call_addr.add(length - 1), False)
                            mem.setBytes(call_addr, b'\x90' * length)
            
            # MSVC Stack Allocators
            elif "chkstk" in func_name or "alloca_probe" in func_name:
                func.setInline(False)
                func.setCallFixup("__chkstk")
        
            # Security Cookie Checks: Force inline
            elif "security_check_cookie" in func_name:
                func.setInline(True)
    finally:
        program.endTransaction(tx_helpers, True)


def load_gdt_archives(program, gdt_dir="gdt_archives"):
    """Loads custom Ghidra Data Type (.gdt) archives into the program context."""
    abs_gdt_dir = os.path.abspath(gdt_dir)
    program_dtmgr = program.getDataTypeManager()
    gdt_files = glob.glob(os.path.join(abs_gdt_dir, "*.gdt"))

    if not gdt_files:
        print(f"No custom GDT archives found in {abs_gdt_dir}. Proceeding with default types.")
        return

    print(f"Found {len(gdt_files)} custom GDT archive(s). Loading into program context...")
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


def setup_decompiler(program):
    """Initializes and returns a configured DecompInterface instance."""
    decomp_options = DecompileOptions()
    decomp_options.setMaxPayloadMBytes(1024)   
    decompiler = DecompInterface()
    decompiler.setOptions(decomp_options)
    decompiler.openProgram(program)
    return decompiler


def extract_functions(file_path, workspace_dir):
    output_dir = os.path.join(workspace_dir, "extracted_functions")
    base_name = os.path.basename(file_path)
    file_output_dir = os.path.join(output_dir, base_name)
    os.makedirs(file_output_dir, exist_ok=True)

    pdb_path = os.path.splitext(file_path)[0] + ".pdb"
    has_pdb = os.path.isfile(pdb_path)

    project_location = os.path.join(workspace_dir, "ghidra_project")
    project_name = f"{base_name}_ghidra"
    os.makedirs(project_location, exist_ok=True)

    # Manage shared project persistence
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
                load_results.save(TaskMonitor.DUMMY)
        else:
            print(f"{program_path} already exists in the shared project -- reusing analyzed program.")

        with pyghidra.program_context(project, program_path) as program:
            if needs_full_analysis:
                configure_analysis_options(program, has_pdb, pdb_path)
                
                print(f"Analyzing {file_path}...")
                pyghidra.analyze(program)

                patch_compiler_helpers(program)
                load_gdt_archives(program)

                decompiler = setup_decompiler(program)

                print("Running dynamic API function pointer resolver...")
                target_funcs = resolve_getprocaddress_types(program, decompiler)
                if target_funcs:
                    propagate_downstream_types(program, decompiler, target_funcs)

                try:
                    program.getDomainFile().save(TaskMonitor.DUMMY)
                    print("Saved enriched analysis back to the shared project.")
                except Exception as e:
                    print(f"  [warn] Could not save analysis back to the shared project: {e}")
            else:
                decompiler = setup_decompiler(program)

            function_manager = program.getFunctionManager()
            all_functions = list(function_manager.getFunctions(True))
            memory = program.getMemory()

            print(f"Total functions in binary: {len(all_functions)}. Applying signature and name filters...")

            extracted_data = []
            call_graph = {}
            binary_has_cpp = False
            skip_counts = {
                "non_exec": 0, 
                "prefix": 0, 
                "thunk_external": 0, 
                "decompile_failed": 0, 
                "library_fn": 0
            }

            for function in all_functions:
                entry_point = function.getEntryPoint()
                memory_block = memory.getBlock(entry_point)
                
                # Check executable section bounds
                if memory_block is None or not memory_block.isExecute():
                    skip_counts["non_exec"] += 1
                    continue

                clean_name = function.getName()
                lower_name = clean_name.lower()
                is_exception = any(exc in lower_name for exc in TARGET_EXCEPTIONS)

                # Filter 1: Ignored runtime prefixes
                if not is_exception and lower_name.startswith(IGNORED_PREFIXES):
                    skip_counts["prefix"] += 1
                    continue

                # Filter 2: External/Thunk routines
                if not is_exception and (function.isExternal() or function.isThunk()):
                    skip_counts["thunk_external"] += 1
                    continue

                # Decompile Function
                results = decompiler.decompileFunction(function, 300, TaskMonitor.DUMMY)
                c_code = (
                    results.getDecompiledFunction().getC()
                    if results.decompileCompleted()
                    else "Decompilation failed!"
                )

                if c_code == "Decompilation failed!":
                    skip_counts["decompile_failed"] += 1
                    err_msg = results.getErrorMessage() if results else "?"
                    print(f"  [warn] Decompile failed for {clean_name} @ {entry_point}: {err_msg}")
                    continue

                # Filter 3: Library Signatures
                if not is_exception and "/* Library Function" in c_code:
                    skip_counts["library_fn"] += 1
                    print(f"  [info] {clean_name} @ {entry_point} matched library signature -- excluded.")
                    continue

                # C++ Heuristic Check
                full_name = function.getName(True)
                if not binary_has_cpp:
                    if "::" in full_name or clean_name.startswith("~"):
                        binary_has_cpp = True
                    elif re.search(r'\b(__thiscall|operator new|operator delete)\b', c_code):
                        binary_has_cpp = True

                func_id = make_function_id(function)

                call_graph[func_id] = {
                    "name": full_name,
                    "callees": [
                        make_function_id(resolve_thunk(c))
                        for c in function.getCalledFunctions(TaskMonitor.DUMMY)
                    ],
                }

                extracted_data.append((func_id, full_name, c_code))

            # Export decompiled source files
            file_ext = ".cpp" if binary_has_cpp else ".c"
            fmt_msg = "C++ indicators detected. Exporting as .cpp..." if binary_has_cpp else "Exporting as .c..."
            print(fmt_msg)

            for func_id, full_name, c_code in extracted_data:
                c_file_path = os.path.join(file_output_dir, f"{func_id}{file_ext}")
                with open(c_file_path, "w", encoding="utf-8") as f:
                    f.write(c_code)
                print(f" Extracted: {func_id}{file_ext}  (symbol: {full_name})")

    # Export Call Graph
    graph_path = os.path.join(file_output_dir, "call_graph.json")
    with open(graph_path, "w", encoding="utf-8") as f:
        json.dump(call_graph, f, indent=4)

    print(f"\nExtracted {len(extracted_data)} total functions.")
    print(f"Skipped: {skip_counts['non_exec']} non-executable, {skip_counts['prefix']} ignored-prefix, "
          f"{skip_counts['thunk_external']} thunk/external, {skip_counts['decompile_failed']} decompile-failed, "
          f"{skip_counts['library_fn']} matched-library-function.")
    print(f"Call graph exported to {graph_path}")