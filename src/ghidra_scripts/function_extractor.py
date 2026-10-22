import glob
import hashlib
import json
import os
import re
from collections import deque

# Start the PyGhidra JVM before importing Ghidra APIs.
import pyghidra
pyghidra.start("-Xmx8g")

# Ghidra APIs
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.program.model.data import FileDataTypeManager
from ghidra.util.task import TaskMonitor
from java.io import File

# Project utilities
from utils.getprocaddress_resolver import (
    propagate_downstream_types,
    resolve_getprocaddress_types,
)

# ---------------------------------------------------------------------------
# Constants & Filters
# ---------------------------------------------------------------------------
TARGET_EXCEPTIONS = ["winmain", "entry"]

# User entry points, normalized without leading underscores.
USER_ENTRY_NAMES = {"main", "wmain", "winmain", "wwinmain", "dllmain"}

# True PREFIXES (compared against the lowercased raw name).
IGNORED_PREFIXES = (
    "unwind", "ordinal", "mingw", "_imp__", "__imp_", "??", "@", "__",
)
IGNORED_PREFIXES_LOWER = tuple(p.lower() for p in IGNORED_PREFIXES)

# Prefixes checked after normalization.
IGNORED_NORMALIZED_PREFIXES = ("findpesection", "pei386")

# Exact matches avoid excluding user functions such as ``free_list``.
_IGNORED_EXACT_RAW = (
    # Standard C Library: String & Memory Operations
    "strcat", "strncat", "strcpy", "strncpy", "strlen", "strnlen", "strstr",
    "strchr", "strrchr", "strtok", "strcspn", "strspn", "strpbrk", "strcmp",
    "strncmp", "strcasecmp", "strncasecmp", "wcscpy", "wcsncpy", "wcscat",
    "wcsncat", "wcscmp", "wcsncmp", "wcslen", "wcsstr", "wcschr", "wcsrchr",
    "wcscasecmp", "wcsncasecmp", "wcsnlen", "mbsrtowcs", "wcsrtombs", "memcpy",
    "memmove", "memcmp", "memchr", "memset", "bzero", "bcopy", "bcmp",
    # Dynamic Memory & Conversions
    "malloc", "calloc", "realloc", "free", "atoi", "atol", "atoll", "atof",
    "strtol", "strtoul", "strtod", "atexit",
    # Standard I/O & Formatting
    "printf", "fprintf", "sprintf", "snprintf", "vprintf", "vfprintf",
    "vsprintf", "vsnprintf", "scanf", "fscanf", "sscanf", "fopen", "fclose",
    "fread", "fwrite", "fseek", "ftell", "puts", "gets", "fgets", "fputs",
    "putchar", "getchar", "abort", "dtoa_lock", "dtoa_lock_cleanup",
    # MSVC / Universal CRT Startup & Internals
    "mainCRTStartup", "wmainCRTStartup", "WinMainCRTStartup", "wWinMainCRTStartup",
    "DllMainCRTStartup", "signal", "_initterm", "_initterm_e", "_cexit", "_exit",
    "exit", "localconv", "mbrlen", "__security_init_cookie",
    "__security_check_cookie", "init_codepage_func", "_seh_filter_exe",
    "_seh_filter_dll", "_configure_wide_argv", "_configure_narrow_argv",
    "_initialize_narrow_environment", "_initialize_wide_environment",
    "__acrt_iob_func", "__stdio_common_vfprintf", "__stdio_common_vsprintf",
    "_amsg_exit", "_get_initial_narrow_environment", "_get_initial_wide_environment",
    # MinGW CRT internals
    "_setargv", "_matherr", "_fpreset", "_gnu_exception_handler",
    "_IsNonwritableInCurrentImage", "_GetPEImageBase", "_ValidateImageBase",
    "mark_section_writable", "_lock_file", "_unlock_file", "wcrtomb", "mbrtowc",
)


def normalize_name(name):
    """Lowercase, strip leading underscores and any stdcall '@N' suffix."""
    return name.lower().lstrip("_").split("@")[0]


IGNORED_EXACT = {normalize_name(n) for n in _IGNORED_EXACT_RAW}


def is_ignored_runtime(lower_name):
    """True for CRT / libc / compiler-runtime functions that should not be emitted."""
    if lower_name.startswith(IGNORED_PREFIXES_LOWER):
        return True
    base = normalize_name(lower_name)
    return base in IGNORED_EXACT or base.startswith(IGNORED_NORMALIZED_PREFIXES)


def is_user_entry(name):
    return name.lstrip("_").lower() in USER_ENTRY_NAMES


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def make_function_id(function):
    """Build a stable function ID, shortening long names with a hash."""
    qualified_name = function.getName(True)
    safe_name = re.sub(r'[^A-Za-z0-9_~]', '_', qualified_name)
    addr_str = str(function.getEntryPoint())

    if len(safe_name) > 120:
        name_hash = hashlib.md5(qualified_name.encode('utf-8')).hexdigest()[:8]
        safe_name = f"{safe_name[:120]}_{name_hash}"

    return f"{safe_name}_{addr_str}"


def resolve_thunk(function):
    """Return a thunk's implementation when available."""
    if function is not None and function.isThunk():
        target = function.getThunkedFunction(True)
        if target is not None:
            return target
    return function


def collect_children(function, function_manager, reference_manager, listing):
    """Return direct callee IDs and called or referenced child functions."""
    callee_ids = []
    children = []

    for callee in function.getCalledFunctions(TaskMonitor.DUMMY):
        actual_callee = resolve_thunk(callee)
        callee_ids.append(make_function_id(actual_callee))
        children.append(actual_callee)

    for inst in listing.getInstructions(function.getBody(), True):
        for ref in reference_manager.getReferencesFrom(inst.getAddress()):
            if ref.getReferenceType().isData():
                ref_func = function_manager.getFunctionAt(ref.getToAddress())
                if ref_func:
                    children.append(resolve_thunk(ref_func))

    return callee_ids, children


def collapse_edges(all_edges, emitted_ids):
    """Collapse traversed-but-unemitted functions from exported call edges."""
    collapsed = {}
    for fid in emitted_ids:
        result = []
        seen = set()
        stack = list(reversed(all_edges.get(fid, [])))
        while stack:
            cid = stack.pop()
            if cid in seen:
                continue
            seen.add(cid)
            if cid in emitted_ids:
                result.append(cid)
            else:
                stack.extend(reversed(all_edges.get(cid, [])))
        collapsed[fid] = result
    return collapsed


def configure_analysis_options(program, has_pdb, pdb_path):
    """Configures analyzer settings and loads PDB symbols if available."""
    tx_id = program.startTransaction("Configure Options and PDB")
    try:
        options = program.getOptions("Analyzers")
        options.setBoolean("Function ID", True)
        options.setBoolean("Demangler MSVC", True)
        options.setBoolean("Demangler GNU", True)
        try:
            from ghidra.app.util.demangler import DemanglerOptions
            d_opts = DemanglerOptions()
            d_opts.setApplySignature(True)
            program.setProperty("_demangler_apply_sig", "1")
        except Exception as e:
            print(f"  [warn] DemanglerOptions unavailable: {e}")
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
        print(
            f"No custom GDT archives found in {abs_gdt_dir}. "
            "Proceeding with default types."
        )
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


# ---------------------------------------------------------------------------
# Main extraction
# ---------------------------------------------------------------------------
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
    try:
        project_cm = pyghidra.open_project(project_location, project_name, create=False)
        print(
            "Opened existing shared Ghidra project at "
            f"{project_location}/{project_name}"
        )
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
            print(
                f"{program_path} already exists in the shared project -- "
                "reusing analyzed program."
            )

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
                    print(
                        "  [warn] Could not save analysis back to the "
                        f"shared project: {e}"
                    )
            else:
                decompiler = setup_decompiler(program)

            function_manager = program.getFunctionManager()
            memory = program.getMemory()
            reference_manager = program.getReferenceManager()
            listing = program.getListing()

            # ------------------------------------------------------------------
            # FIND ACTUAL ROOT ENTRY POINTS
            # ------------------------------------------------------------------
            roots = []
            for f in function_manager.getFunctions(True):
                # "_main" / "__main"-style names are normalized by is_user_entry().
                # Skip "__main" (the GCC static-ctor runner) -- it is not user code.
                if f.getName() == "__main":
                    continue
                if is_user_entry(f.getName()):
                    roots.append(f)

            # If stripped or weirdly compiled, fall back to the binary entry points.
            # The traversal now walks THROUGH the CRT, so user code is still reached
            # even when main could not be identified by name.
            if not roots:
                print(
                    "  [info] No standard main found. "
                    "Falling back to binary Entry Points."
                )
                entry_iter = program.getSymbolTable().getExternalEntryPointIterator()
                while entry_iter.hasNext():
                    addr = entry_iter.next()
                    func = function_manager.getFunctionAt(addr)
                    if func:
                        roots.append(func)

            # Include function targets discovered in Stage 2 global data.
            extra_path = os.path.join(workspace_dir, "missing_function_targets.json")
            if os.path.isfile(extra_path):
                try:
                    have = {r.getEntryPoint().getOffset() for r in roots}
                    space = program.getAddressFactory().getDefaultAddressSpace()
                    with open(extra_path, encoding="utf-8") as fh:
                        extra_items = json.load(fh)
                    for item in extra_items:
                        off = int(item["address"], 16)
                        fn = function_manager.getFunctionAt(space.getAddress(off))
                        if fn is not None and off not in have:
                            roots.append(fn)
                            have.add(off)
                    print(f"  [info] added roots from {os.path.basename(extra_path)}")
                except Exception as e:
                    print(f"  [warn] could not read {extra_path}: {e}")

            print(f"Total root functions found to begin traversal: {len(roots)}")
            for r in roots:
                print(f"  [root] {r.getName()} @ {r.getEntryPoint()}")

            # ------------------------------------------------------------------
            # TOP-DOWN GRAPH TRAVERSAL (BFS)
            #
            # Enqueue children before filtering so traversal can pass through CRT
            # and library functions to reach user code.
            # ------------------------------------------------------------------
            extracted_data = []       # (func_id, full_name, c_code) for emitted functions
            node_names = {}           # func_id -> full_name for emitted functions
            all_edges = {}            # func_id -> direct callee ids, for ALL visited functions
            binary_has_cpp = False

            skip_counts = {
                "non_exec": 0, "prefix": 0, "thunk_external": 0,
                "decompile_failed": 0, "library_fn": 0
            }

            queue = deque(roots)
            visited_addrs = set()

            while queue:
                function = queue.popleft()

                function = resolve_thunk(function)
                entry_point = function.getEntryPoint()
                func_addr = entry_point.getOffset()

                # Guard against infinite recursion / diamond patterns
                if func_addr in visited_addrs:
                    continue
                visited_addrs.add(func_addr)

                memory_block = memory.getBlock(entry_point)

                # Check executable section bounds
                if memory_block is None or not memory_block.isExecute():
                    skip_counts["non_exec"] += 1
                    continue

                # ---- Walk first, filter second -------------------------------
                func_id = make_function_id(function)
                callee_ids, children = collect_children(
                    function, function_manager, reference_manager, listing
                )
                all_edges[func_id] = callee_ids
                for child in children:
                    if child.getEntryPoint().getOffset() not in visited_addrs:
                        queue.append(child)
                # --------------------------------------------------------------

                clean_name = function.getName()
                lower_name = clean_name.lower()
                is_exception = any(exc in lower_name for exc in TARGET_EXCEPTIONS)

                # External/Thunk routines
                if not is_exception and (function.isExternal() or function.isThunk()):
                    skip_counts["thunk_external"] += 1
                    continue

                # Ignored runtime functions: not emitted, but their callees were
                # already enqueued above, so the walk continues through them.
                if not is_exception and is_ignored_runtime(lower_name):
                    skip_counts["prefix"] += 1
                    continue

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

                if not is_exception and "/* Library Function" in c_code:
                    skip_counts["library_fn"] += 1
                    print(
                        f"  [info] {clean_name} @ {entry_point} matched "
                        "library signature -- excluded."
                    )
                    continue

                # C++ Heuristic Check
                full_name = function.getName(True)
                if not binary_has_cpp:
                    if "::" in full_name or clean_name.startswith("~"):
                        binary_has_cpp = True
                    elif re.search(r'\b(__thiscall|operator new|operator delete)\b', c_code):
                        binary_has_cpp = True

                node_names[func_id] = full_name
                extracted_data.append((func_id, full_name, c_code))

            # Build the exported graph: emitted nodes only, with edges collapsed
            # through any traversed-but-not-emitted (CRT/libc) functions.
            emitted_ids = set(node_names.keys())
            collapsed = collapse_edges(all_edges, emitted_ids)
            call_graph = {
                fid: {"name": node_names[fid], "callees": collapsed[fid]}
                for fid, _, _ in extracted_data
            }

            # Export decompiled source files
            file_ext = ".cpp" if binary_has_cpp else ".c"
            fmt_msg = (
                "C++ indicators detected. Exporting as .cpp..."
                if binary_has_cpp else "Exporting as .c..."
            )
            print(fmt_msg)

            for func_id, full_name, c_code in extracted_data:
                c_file_path = os.path.join(file_output_dir, f"{func_id}{file_ext}")
                with open(c_file_path, "w", encoding="utf-8") as f:
                    f.write(c_code)

    graph_path = os.path.join(file_output_dir, "call_graph.json")
    with open(graph_path, "w", encoding="utf-8") as f:
        json.dump(call_graph, f, indent=4)

    print(f"\nExtracted {len(extracted_data)} top-down reachable functions.")
    print(
        f"Traversal skipped: {skip_counts['non_exec']} non-executable, "
        f"{skip_counts['prefix']} ignored-runtime, "
        f"{skip_counts['thunk_external']} thunk/external, "
        f"{skip_counts['decompile_failed']} decompile-failed, "
        f"{skip_counts['library_fn']} matched-library-function."
    )
    print(f"Call graph exported to {graph_path}")