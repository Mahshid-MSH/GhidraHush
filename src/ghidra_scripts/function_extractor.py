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

# ==============================================================================
# KNOWN ANTI-ANALYSIS BYTE SIGNATURES
# ==============================================================================
# Format: (Byte Sequence, Label)
ANTI_ANALYSIS_SIGNATURES = [
    # --- Hypervisor / VM Detection Backdoors ---
    # 4 bytes: Virtual PC Backdoor -> Replaced with CPUID (0F A2) + two NOPs to keep EBX unknown
    (b"\x0F\x3F\x07\x0B", b"\x0F\xA2\x90\x90", "Virtual PC Backdoor (Patched to CPUID)"),
    
    # 3 bytes: VMCALL Instruction -> Replaced with 3 NOPs
    (b"\x0F\x01\xC1",     b"\x90\x90\x90",     "VMCALL Instruction (NOP-padded)"),
    
    # 3 bytes: VMMCALL Instruction -> Replaced with 3 NOPs
    (b"\x0F\x01\xD9",     b"\x90\x90\x90",     "VMMCALL Instruction (NOP-padded)"),
    
    # --- Anti-Debugging & Exception Traps ---
    # 2 bytes: INT 2D -> Replaced with 2 NOPs
    (b"\xCD\x2D",         b"\x90\x90",         "INT 2D Debugger Interrupt Trap (NOP-padded)"),
    
    # 1 byte: ICEBP / INT1 -> Replaced with 1 NOP
    (b"\xF1",             b"\x90",             "ICEBP / INT1 Single-Step Trap (NOP)"),
    
    # 2 bytes: UD2 Undefined Instruction -> Replaced with 2 NOPs
    (b"\x0F\x0B",         b"\x90\x90",         "UD2 Undefined Instruction (NOP-padded)"),
    
    # --- Sensitive CPU Table Instructions (Redpill / Anti-VM) ---
    # 3 bytes: SIDT -> Replaced with 3 NOPs
    (b"\x0F\x01\x38",     b"\x90\x90\x90",     "SIDT (Store Interrupt Descriptor Table) (NOP-padded)"),
    
    # 3 bytes: SGDT -> Replaced with 3 NOPs
    (b"\x0F\x01\x10",     b"\x90\x90\x90",     "SGDT (Store Global Descriptor Table) (NOP-padded)"),
    
    # 3 bytes: SLDT -> Replaced with 3 NOPs
    (b"\x0F\x01\x00",     b"\x90\x90\x90",     "SLDT (Store Local Descriptor Table) (NOP-padded)"),
    
    # 3 bytes: STR -> Replaced with 3 NOPs
    (b"\x0F\x00\x08",     b"\x90\x90\x90",     "STR  (Store Task Register) (NOP-padded)")
]


def make_function_id(function):
    """
    Stable, collision-free identifier for a Ghidra Function with length protection.
    """
    qualified_name = function.getName(True)
    safe_name = re.sub(r'[^A-Za-z0-9_~]', '_', qualified_name)
    addr_str = str(function.getEntryPoint())
    
    if len(safe_name) > 120:
        name_hash = hashlib.md5(qualified_name.encode('utf-8')).hexdigest()[:8]
        safe_name = safe_name[:120] + f"_{name_hash}"
        
    return f"{safe_name}_{addr_str}"


def resolve_thunk(function):
    if function is not None and function.isThunk():
        target = function.getThunkedFunction(True)
        if target is not None:
            return target
    return function


TARGET_EXCEPTIONS = ["winmain", "entry"]

IGNORED_PREFIXES = (
    "unwind", "~", "___scrt", "__", "mingw", "Ordinal",
    "strcmp", "strcpy", "strlen", "strstr", "strncmp",
    "WinMainCRTStartup", "memset", "wcsnlen", "mbsrtowcs", "wcsrtombs",
    "strcat", "strncat", "strncpy", "strchr", "strrchr", "strtok", 
    "strcspn", "strspn", "strpbrk", "strspn", "strcasecmp", "strncasecmp",
    "wcscpy", "wcsncpy", "wcscat", "wcsncat", "wcscmp", "wcsncmp", 
    "wcslen", "wcsstr", "wcschr", "wcsrchr", "wcscasecmp", "wcsncasecmp",
    "memcpy", "memmove", "memcmp", "memchr", "bzero", "bcopy", "bcmp",
    "malloc", "calloc", "realloc", "free", 
    "atoi", "atol", "atoll", "atof", "strtol", "strtoul", "strtod","atexit",
    "printf", "fprintf", "sprintf", "snprintf", "vprintf", "vfprintf", "abort","atexit",
    "vsprintf", "vsnprintf", "scanf", "fscanf", "sscanf", "atoi","calloc","dtoa_lock",
    "fopen", "fclose", "fread", "fwrite", "fseek", "ftell", "dtoa_lock_cleanup",
    "puts", "gets", "fgets", "fputs", "putchar", "getchar", "FindPESection","fprintf",
    "mainCRTStartup", "wmainCRTStartup", "wWinMainCRTStartup", "DllMainCRTStartup","strchr","signal",
    "_initterm", "_initterm_e", "_cexit", "_exit", "exit", "abort","localconv","mbrlen","memset",
    "__security_init_cookie", "__security_check_cookie","init_codepage_func",
    "_seh_filter_exe", "_seh_filter_dll", 
    "_configure_wide_argv", "_configure_narrow_argv",
    "_initialize_narrow_environment", "_initialize_wide_environment",
    "__acrt_iob_func", "__stdio_common_vfprintf", "__stdio_common_vsprintf",
    "_amsg_exit", "_get_initial_narrow_environment", "_get_initial_wide_environment",
    "_imp__", "__imp_", "??", "@"
)


def patch_anti_analysis_patterns(program):
    mem = program.getMemory()
    listing = program.getListing()
    tx = program.startTransaction("Patch Anti-Analysis Signatures")
    patched_count = 0
    try:
        for block in mem.getBlocks():
            if not block.isExecute():
                continue
            start_addr = block.getStart()
            end_addr = block.getEnd()
            
            # Unpack target, replacement, and description
            for target_pattern, replacement_pattern, desc in ANTI_ANALYSIS_SIGNATURES:
                curr_addr = start_addr
                while curr_addr is not None and curr_addr.compareTo(end_addr) <= 0:
                    found_addr = mem.findBytes(curr_addr, end_addr, target_pattern, None, True, TaskMonitor.DUMMY)
                    if found_addr is None:
                        break
                    
                    length = len(target_pattern)
                    listing.clearCodeUnits(found_addr, found_addr.add(length - 1), False)
                    # Write the exact-length replacement bytes
                    mem.setBytes(found_addr, replacement_pattern)
                    print(f"  [patch] Neutralized {desc} at {found_addr}")
                    patched_count += 1
                    curr_addr = found_addr.add(length)
    finally:
        program.endTransaction(tx, True)
    return patched_count


def patch_function_bad_data(program, function):
    """
    Fallback method: If a function hits halt_baddata(), scans the body for non-decoded 
    or bad code units and overwrites them with NOPs.
    """
    mem = program.getMemory()
    listing = program.getListing()
    body = function.getBody()
    tx = program.startTransaction("Repair Function Bad Data")
    patched = False
    try:
        for range_obj in body.getAddressRanges():
            curr = range_obj.getMinAddress()
            max_addr = range_obj.getMaxAddress()
            while curr is not None and curr.compareTo(max_addr) <= 0:
                inst = listing.getInstructionAt(curr)
                if inst is None:
                    # Undefined byte / data in execution path -> NOP 1 byte
                    listing.clearCodeUnits(curr, curr, False)
                    mem.setBytes(curr, b'\x90')
                    patched = True
                    curr = curr.add(1)
                else:
                    curr = curr.add(inst.getLength())
    finally:
        program.endTransaction(tx, True)
    return patched


def extract_functions(file_path, workspace_dir):
    output_dir = os.path.join(workspace_dir, "extracted_functions")
    base_name = os.path.basename(file_path)
    file_output_dir = os.path.join(output_dir, base_name)
    os.makedirs(file_output_dir, exist_ok=True)

    call_graph = {}
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

                print(f"Analyzing {file_path}...")
                pyghidra.analyze(program)

                # --- FIX COMPILER HELPERS & ANTI-ANALYSIS PATTERNS ---
                print("Neutralizing anti-analysis signatures and MinGW stack probes...")
                patch_anti_analysis_patterns(program)

                tx_helpers = program.startTransaction("Fix Compiler Helpers")
                try:
                    fm = program.getFunctionManager()
                    mem = program.getMemory()
                    listing = program.getListing()
                    ref_mgr = program.getReferenceManager()

                    for func in fm.getFunctions(True):
                        func_name = func.getName().lower()
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
                        elif "chkstk" in func_name or "alloca_probe" in func_name:
                            func.setInline(False)
                            func.setCallFixup("__chkstk")
                        elif "security_check_cookie" in func_name:
                            func.setInline(True)
                            
                finally:
                    program.endTransaction(tx_helpers, True)

                # Load Custom GDT Archives
                gdt_dir = os.path.abspath("gdt_archives")
                program_dtmgr = program.getDataTypeManager()
                gdt_files = glob.glob(os.path.join(gdt_dir, "*.gdt"))

                if gdt_files:
                    print(f"Found {len(gdt_files)} custom GDT archive(s). Loading into program context...")
                    tx_gdt = program.startTransaction("Load GDT Archives")
                    try:
                        for gdt_path in gdt_files:
                            gdt_file = File(gdt_path)
                            gdt_mgr = FileDataTypeManager.openFileArchive(gdt_file, False)
                            for dt in gdt_mgr.getAllDataTypes():
                                program_dtmgr.addDataType(dt, None)
                            gdt_mgr.close()
                    finally:
                        program.endTransaction(tx_gdt, True)

                # Decompiler setup
                decomp_options = DecompileOptions()
                decomp_options.setMaxPayloadMBytes(1024)   
                decompiler = DecompInterface()
                decompiler.setOptions(decomp_options)
                decompiler.openProgram(program)

                print("Running dynamic API function pointer resolver...")
                target_funcs = resolve_getprocaddress_types(program, decompiler)
                if target_funcs:
                    propagate_downstream_types(program, decompiler, target_funcs)

                function_manager = program.getFunctionManager()
                all_functions = list(function_manager.getFunctions(True))
                memory = program.getMemory()

                extracted_data = []
                binary_has_cpp = False
                skip_counts = {"non_exec": 0, "prefix": 0, "thunk_external": 0, "decompile_failed": 0, "library_fn": 0}

                for function in all_functions:
                    entry_point = function.getEntryPoint()
                    memory_block = memory.getBlock(entry_point)
                    
                    if memory_block is None or not memory_block.isExecute():
                        skip_counts["non_exec"] += 1
                        continue

                    clean_name = function.getName()
                    lower_name = clean_name.lower()
                    is_exception = any(exc in lower_name for exc in TARGET_EXCEPTIONS)

                    if not is_exception:
                        if lower_name.startswith(IGNORED_PREFIXES):
                            skip_counts["prefix"] += 1
                            continue
                        if function.isExternal() or function.isThunk():
                            skip_counts["thunk_external"] += 1
                            continue

                    # First Decompilation Attempt
                    results = decompiler.decompileFunction(function, 300, TaskMonitor.DUMMY)
                    c_code = (
                        results.getDecompiledFunction().getC()
                        if results.decompileCompleted()
                        else "Decompilation failed!"
                    )

                    # --- REPAIR PASS IF HALT_BADDATA IS DETECTED ---
                    if "halt_baddata" in c_code or "Bad instruction" in c_code:
                        print(f"  [warn] Detected truncated control flow in {clean_name} @ {entry_point}. Applying bad-data repair...")
                        if patch_function_bad_data(program, function):
                            # Re-decompile after NOPing bad bytes
                            results = decompiler.decompileFunction(function, 300, TaskMonitor.DUMMY)
                            if results.decompileCompleted():
                                c_code = results.getDecompiledFunction().getC()
                                print(f"  [success] Successfully repaired and re-decompiled {clean_name}")

                    if c_code == "Decompilation failed!":
                        skip_counts["decompile_failed"] += 1
                        err_msg = results.getErrorMessage() if results else "?"
                        print(f"  [warn] decompile did not complete for {clean_name} @ {entry_point}: {err_msg}")
                        continue

                    if not is_exception and "/* Library Function" in c_code:
                        skip_counts["library_fn"] += 1
                        continue         

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

                file_ext = ".cpp" if binary_has_cpp else ".c"
                for func_id, full_name, c_code in extracted_data:
                    c_file_path = os.path.join(file_output_dir, f"{func_id}{file_ext}")
                    with open(c_file_path, "w", encoding="utf-8") as f:
                        f.write(c_code)

    graph_path = os.path.join(file_output_dir, "call_graph.json")
    with open(graph_path, "w", encoding="utf-8") as f:
        json.dump(call_graph, f, indent=4)

    print(f"\nExtracted {len(extracted_data)} total functions.")
    print(f"Skipped: {skip_counts['non_exec']} non-executable, {skip_counts['prefix']} ignored-prefix, "
          f"{skip_counts['thunk_external']} thunk/external, {skip_counts['decompile_failed']} decompile-failed, "
          f"{skip_counts['library_fn']} matched-library-function.")
    print(f"Call graph exported to {graph_path}")