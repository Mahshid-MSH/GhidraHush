import sys, os
import pyghidra
import re
import warnings
import struct
import jpype
from database.symbol_db import SymbolDB
from ghidra.program.model.data import Array, Pointer, Structure, Union, Enum, TypeDef, ArrayDataType, ByteDataType
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import StringDataType, UnicodeDataType


C_KEYWORDS = {
    'auto', 'break', 'case', 'char', 'const', 'continue', 'default', 'do', 
    'double', 'else', 'enum', 'extern', 'float', 'for', 'goto', 'if', 'int', 
    'long', 'register', 'return', 'short', 'signed', 'sizeof', 'static', 
    'struct', 'switch', 'typedef', 'union', 'unsigned', 'void', 'volatile',
    'while',"BOOL","BYTE","CHAR","DWORD","HANDLE","HGLOBAL","HKEY","HMODULE","HWND",
    "LPCSTR","LPDWORD","LPOVERLAPPED","LPSECURITY_ATTRIBUTES","LPSTR","LPVOID",
    "LSTATUS","PLONG","ULONG","FARPROC","WORD","LONG","UINT","WPARAM","LPARAM","FILE","HINSTANCE","ATOM"
}
warnings.filterwarnings("ignore", category=DeprecationWarning)

def sanitize_c_name(name):
    if not name: return "unknown_type"
    name = name.replace("struct ", "").replace("enum ", "").replace("union ", "")
    name = re.sub(r'[^a-zA-Z0-9_]', '_', name)
    if name in C_KEYWORDS or (name and name[0].isdigit()):
        name = '_' + name
    return name

NOISE_TYPE_EXACT_NAMES = ("LIST_ENTRY", "RTL_CRITICAL_SECTION_DEBUG")

def is_noise_type_name(raw_name):
    """
    True for well-known Windows/PE internal type names that add bulk to the
    header without adding malware-analysis value (PE structs, TEB/PEB debug
    plumbing, etc). Matched on the *unsanitized* Ghidra name, stripping
    leading underscores first, since WinAPI struct tags are conventionally
    underscore-prefixed (e.g. '_IMAGE_SECTION_HEADER', '_LIST_ENTRY') -- a
    plain `.startswith("IMAGE_")` check misses those entirely.

    Note this deliberately does NOT blacklist RTL_CRITICAL_SECTION /
    CRITICAL_SECTION themselves -- only their internal DebugInfo plumbing --
    since CRITICAL_SECTION commonly shows up as a real, meaningful global.
    """
    if not raw_name:
        return False
    bare = raw_name.lstrip('_')
    if bare.startswith("IMAGE_"):
        return True
    if bare in NOISE_TYPE_EXACT_NAMES:
        return True
    return False

def is_likely_real_text(data):
    """Sanity-check a Ghidra string-ish type actually decoded as real text
    before trusting getValue() -- U+FFFD means Ghidra's decoder had to
    invent characters, i.e. this was never real text."""
    dt_name = data.getDataType().getName().lower()
    if not ('string' in dt_name or 'unicode' in dt_name):
        return False  # plain char[]/char array -- never trust as text
    raw = data.getValue()
    if raw is None:
        return False
    s = str(raw)
    if '\ufffd' in s:
        return False
    # decoded text much shorter than the declared buffer -> binary with
    # embedded NULs, not a real string
    decl_len = data.getLength()
    if decl_len > 4 and len(s) < decl_len * 0.5:
        return False
    return True

def read_memory_bytes(addr, size, program):
    """
    Robustly reads `size` raw bytes from the program's memory image at
    `addr`, returning a Python `bytes` object, or None if they genuinely
    can't be read.

    Memory.getBytes(Address, byte[]) is a Java method that wants a real
    Java byte[]. Handing it a plain Python bytearray through pyghidra/JPype
    is NOT guaranteed to marshal correctly, and both call sites that used
    to do this wrapped the call in a bare `except: pass` -- so any
    marshaling failure was silently swallowed and fell straight through to
    a hard-coded "{ 0 }", which is almost certainly why previously-zeroed
    buffers stayed zero even after being sized correctly. Building an
    explicit JPype byte[] via jpype.JArray(jpype.JByte) is the reliable way
    to call this API, and printing on failure means a real problem won't
    silently masquerade as "this memory is just zero".
    """
    try:
        jbuf = jpype.JArray(jpype.JByte)(size)
        program.getMemory().getBytes(addr, jbuf)
        return bytes(b & 0xFF for b in jbuf)
    except Exception as e:
        print(f"  [warn] failed to read {size} byte(s) at {addr}: {e}")
        return None

def is_string_data(data):
    if not data or not data.isDefined():
        return False
    dt_name = data.getDataType().getName().lower()
    return 'string' in dt_name or 'char' in dt_name or 'unicode' in dt_name

def parse_ghidra_type_and_dim(dt):
    """Splits Ghidra types into base C type and array dimension suffix, supporting complex types."""
    if dt is None: return "uint8_t", ""
    
    dim_str = ""
    while isinstance(dt, Array):
        dim_str += f"[{dt.getNumElements()}]"
        dt = dt.getDataType() 

    ptr_str = ""
    while isinstance(dt, Pointer):
        ptr_str += "*"
        underlying = dt.getDataType()
        if underlying is None or underlying.getName().lower() == "default":
            return "void" + ptr_str, dim_str
        if is_noise_type_name(underlying.getName()):
            # e.g. PIMAGE_SECTION_HEADER, PRTL_CRITICAL_SECTION_DEBUG -- keep
            # the pointer, drop the dependency on the noisy pointee type.
            return "void" + ptr_str, dim_str
        dt = underlying

    if isinstance(dt, (Structure, Union, Enum, TypeDef)) and is_noise_type_name(dt.getName()):
        # Embedded by value (not by pointer): preserve the exact byte size
        # so struct layout/offsets downstream stay correct, but don't pull
        # in (or generate a typedef for) the noisy type itself.
        try:
            size = max(dt.getLength(), 1)
        except Exception:
            size = 1
        return "uint8_t", dim_str + f"[{size}]"

    if isinstance(dt, (Structure, Union, Enum, TypeDef)):
        c_type = sanitize_c_name(dt.getName())
    else:
        name = dt.getName().lower()
        type_map = {
            'undefined1': 'uint8_t',  'byte': 'uint8_t',   'char': 'int8_t', 'sbyte': 'int8_t', 'bool': 'uint8_t',
            'undefined2': 'uint16_t', 'word': 'uint16_t',  'short': 'int16_t', 'ushort': 'uint16_t',
            'undefined4': 'uint32_t', 'dword': 'uint32_t', 'int': 'int32_t', 'uint': 'uint32_t', 'size_t': 'uint32_t',
            'undefined8': 'uint64_t', 'qword': 'uint64_t', 'long': 'int64_t', 'ulong': 'uint64_t', 'long long': 'int64_t',
            'float': 'float', 'double': 'double', 'string': 'char', 'terminatedcstring': 'char'
        }
        c_type = type_map.get(name, sanitize_c_name(dt.getName()))

    return c_type + ptr_str, dim_str


def is_unneeded_data(data, symbol, program):
    """
    Returns True if the data is a PE header or compiler artifact.
    """
    if data:
        addr = data.getMinAddress()
        block = program.getMemory().getBlock(addr)
        if block and block.getName() == "Headers":
            return True
            
        dt = data.getDataType()
        dt_name = dt.getName()
            
        # Skip PE Structs by Data Type Name (handles '_IMAGE_...'-style tags too)
        if is_noise_type_name(dt_name):
            return True

    if symbol:
        if symbol.getSource() == SourceType.USER_DEFINED:
            return False
            
        name = symbol.getName()
        # Blacklist common compiler, linker, and auto-generated prefixes
        ignore_prefixes = (
            "s_", "u_",           # Auto-generated string labels
            "__",                 # Compiler/Runtime vars
            "_MINGW",             # MinGW runtime
            "_imp_",              # Import thunks
            "IMAGE_",             # PE Header symbols
            "_rdata",             # Section base labels
            "_CSWTCH_",           # Auto-generated Switch jump tables
            "_func_",             # Auto-generated function pointers
            "fpi", "p", "pmem_"   # Math/Runtime internals
        )
        
        if name.startswith(ignore_prefixes):
            return True
            
    return False

def extract_and_store_type(dt, db, seen_types):
    """Recursively parses Ghidra composites and registers them into the Database."""
    if dt is None: return
    
    while isinstance(dt, (Pointer, Array)):
        dt = dt.getDataType()
        if dt is None: return

    if is_noise_type_name(dt.getName()):
        # Don't register a typedef for it, and don't recurse into its
        # members either -- parse_ghidra_type_and_dim() already collapses
        # any field of this type to an opaque, byte-accurate placeholder,
        # so there's nothing here that needs a name in the output header.
        return

    name = sanitize_c_name(dt.getName())
    if name in seen_types or name in C_KEYWORDS or name.startswith(("uint", "int", "char", "float", "double", "void", "undefined", "byte", "word", "dword", "qword")):
        return
        
    seen_types.add(name)

    if isinstance(dt, (Structure, Union)):
        kind = "union" if isinstance(dt, Union) else "struct"
        
        for i in range(dt.getNumComponents()):
            comp = dt.getComponent(i)
            if comp: extract_and_store_type(comp.getDataType(), db, seen_types)
            
        lines = [f"typedef {kind} {name} {{"]
        for i in range(dt.getNumComponents()):
            comp = dt.getComponent(i)
            if not comp: continue
            c_type, dim = parse_ghidra_type_and_dim(comp.getDataType())
            field_name = sanitize_c_name(comp.getFieldName() or f"field_{i}")
            lines.append(f"    {c_type} {field_name}{dim};")
        lines.append(f"}} {name};\n")
        db.add_custom_type(name, "\n".join(lines))

    elif isinstance(dt, Enum):
        lines = [f"typedef enum {name} {{"]
        for enum_name in dt.getNames():
            val = dt.getValue(enum_name)
            lines.append(f"    {sanitize_c_name(enum_name)} = {val},")
        lines.append(f"}} {name};\n")
        db.add_custom_type(name, "\n".join(lines))
        
    elif isinstance(dt, TypeDef):
        extract_and_store_type(dt.getBaseDataType(), db, seen_types)
        base_type, dim = parse_ghidra_type_and_dim(dt.getBaseDataType())
        db.add_custom_type(name, f"typedef {base_type} {name}{dim};\n")

def auto_collate_large_arrays(program, min_size=1024):
    """Dynamically collapses fragmented contiguous data into single arrays."""
    listing = program.getListing()
    ref_mgr = program.getReferenceManager()
    sym_table = program.getSymbolTable()
    mem = program.getMemory()
    
    tx = program.startTransaction("Auto-Collate Fragmented Arrays")
    try:
        for block in mem.getBlocks():
            if not block.isInitialized() or block.isExecute():
                continue
            addr = block.getStart()
            end_addr = block.getEnd()
            while addr < end_addr:
                data = listing.getDataAt(addr)
                if not data:
                    addr = addr.add(1)
                    continue
                data_len = data.getLength()
                
                has_refs = ref_mgr.hasReferencesTo(addr)
                sym = sym_table.getPrimarySymbol(addr)
                is_named_by_user = sym and sym.getSource() != SourceType.DEFAULT
                
                if has_refs or is_named_by_user:
                    current_size = data_len
                    scan_addr = addr.add(data_len)
                    
                    while scan_addr < end_addr:
                        if ref_mgr.hasReferencesTo(scan_addr):
                            break
                            
                        scan_sym = sym_table.getPrimarySymbol(scan_addr)
                        if scan_sym and scan_sym.getSource() != SourceType.DEFAULT:
                            break
                            
                        scan_data = listing.getDataAt(scan_addr)
                        if not scan_data:
                            break
                            
                        current_size += scan_data.getLength()
                        try:
                            scan_addr = scan_addr.add(scan_data.getLength())
                        except:
                            break
                            
                    if current_size >= min_size:
                        head_name = sym.getName() if sym else f"DAT_{addr.toString()}"
                        print(f"Auto-Collapsing payload '{head_name}' at {addr.toString()} (Size: {current_size} bytes)")
                        listing.clearCodeUnits(addr, scan_addr.subtract(1), False)
                        byte_type = ByteDataType.dataType
                        array_type = ArrayDataType(byte_type, current_size, 1)
                        listing.createData(addr, array_type)
                        if sym:
                            sym_table.createLabel(addr, head_name, SourceType.USER_DEFINED)
                        addr = scan_addr
                        continue
                try:
                    addr = addr.add(data_len)
                except:
                    break
                    
    except Exception as e:
        print(f"Error during array collation: {e}")
    finally:
        program.endTransaction(tx, True)


def get_data_value_string(data, program):
    """Recursively returns C values, defaulting uninitialized (.bss) blocks safely to { 0 }."""
    if not data: return "{ 0 }"

    mem_block = program.getMemory().getBlock(data.getAddress())
    if mem_block and not mem_block.isInitialized():
        return "{ 0 }"
        
    dt = data.getDataType()
    
    if isinstance(dt, (Array, Structure)):
        num_comps = data.getNumComponents()
        if num_comps > 0:
            elements = []
            for i in range(num_comps):
                comp = data.getComponent(i)
                elements.append(get_data_value_string(comp, program))
            return "{" + ", ".join(elements) + "}"
        else:
            length = data.getLength()
            if length > 0:
                buf = read_memory_bytes(data.getAddress(), length, program)
                if buf is not None:
                    return "{" + ", ".join([f"0x{b:02x}" for b in buf]) + "}"
            return "{ 0 }"
            
    elif isinstance(dt, Union):
        if data.getNumComponents() > 0:
            return "{" + get_data_value_string(data.getComponent(0), program) + "}"
        return "{ 0 }"
            
    elif isinstance(dt, Pointer):
        val = data.getValue()
        if hasattr(val, 'getOffset'): return f"(void*)0x{val.getOffset():x}"
        return "NULL"
        
    elif isinstance(dt, Enum):
        val = data.getValue()
        if hasattr(val, 'getValue'): return f"0x{val.getValue():x}"
        return "0"
        
    else:
        val = data.getValue()
        if val is None or str(val) == "(null)": return "0"
        
        num = None
        if hasattr(val, 'getValue'): num = val.getValue()
        elif hasattr(val, 'getOffset'): num = val.getOffset()
        elif isinstance(val, (int, float)): num = val
        
        if isinstance(num, int):
            size = dt.getLength()
            if size == 1: num &= 0xFF
            elif size == 2: num &= 0xFFFF
            elif size == 4: num &= 0xFFFFFFFF
            elif size == 8: num &= 0xFFFFFFFFFFFFFFFF
            return f"0x{num:x}"
            
        return str(val)

def escape_c_string(val):
    """Escapes strings to valid C escape sequences."""
    if not val:
        return ""
    escaped = []
    for char in str(val):
        code = ord(char)
        if char == '\\': escaped.append('\\\\')
        elif char == '"': escaped.append('\\"')
        elif char == '\n': escaped.append('\\n')
        elif char == '\r': escaped.append('\\r')
        elif char == '\t': escaped.append('\\t')
        elif 32 <= code <= 126: escaped.append(char)
        else: escaped.append(f'\\x{code & 0xff:02x}')
    return "".join(escaped)

def generate_global_files(path_to_binary, workspace_dir="."):
    db = SymbolDB(workspace_dir=workspace_dir)    
    
    TEB_PEB_IGNORE_LIST = [
        "ExceptionList", "LastError", "Tls", "Gdi", "Reserved", "StackBase", 
        "StackLimit", "ProcessEnvironmentBlock", "EnvironmentPointer", 
        "glDispatchTable", "TxnScope", "FiberData", "ArbitraryUserPointer", 
        "ThreadLocalStorage", "Win32ThreadInfo", "EtwTraceData", "DeallocationStack"
    ]
    RUNTIME_SYMBOLS = {
        "mingw_pcinit", "mingw_pcppinit", "mingw_initcharmax",
        "mingw_initltsdrot_force", "mingw_initltsdyn_force", "mingw_initltssuo_force",
        "mingw_app_type", "mainret", "managedapp", "fpreset", "fthunk",
        "p_92992", "hname", "key_dtor_list", "the_secs", "was_init_94382",
        "argc", "argv", "envp", "startinfo", "stUserMathErr", "handler",
        "has_cctor", "initialized", "register_frame_ctor", "switchD",
        "switchdataD_1400041a4", "switchdataD_1400042d0",
        "caseD_", "CLSID","IID",
        "_fmode", "_commode", "_dowildcard", "_newmode", "_environ", "__initenv"
    }
    
    print(f"Initializing Ghidra and opening: {path_to_binary}")
    
    with pyghidra.open_program(path_to_binary) as flat_api:
        program = flat_api.currentProgram
        listing = program.getListing()
        symbol_table = program.getSymbolTable()
        ref_mgr = program.getReferenceManager()
        fn_mgr = program.getFunctionManager()

        # Retain collating large arrays in initialized memory
        auto_collate_large_arrays(program, min_size=1024)
        
        seen_names = set()
        seen_types = set()
        processed_addrs = set()

        def infer_undefined_extent(addr, max_size=4096):
            """
            Best-effort size guess for a symbol Ghidra never defined as real
            data -- i.e. `data.isDefined()` is False and all we have is the
            default 1-byte 'undefined' placeholder (or no code unit at all).
            Walks forward until it hits the next symbol, the next incoming
            reference, the next chunk of data Ghidra *has* defined, or the
            end of the memory block, and treats that gap as the variable's
            likely extent.

            This is a heuristic, not a guarantee -- it will over- or
            under-shoot for tightly packed globals with no distinguishing
            xrefs between them. Anything the exporter sizes via this path
            (rather than from a real Ghidra-defined type) is worth a manual
            look before you trust the layout. It exists to replace the old
            behavior of silently asserting every such symbol was a single
            uint8_t, which was flatly wrong for buffers/arrays like
            serverports[]/inputL[] in the original source.
            """
            mem_block = program.getMemory().getBlock(addr)
            if mem_block is None:
                return 1

            block_end = mem_block.getEnd()
            scan_addr = addr.add(1)
            size = 1

            while scan_addr.compareTo(block_end) <= 0 and size < max_size:
                if symbol_table.getPrimarySymbol(scan_addr) is not None:
                    break
                if ref_mgr.hasReferencesTo(scan_addr):
                    break
                scan_data = listing.getDataAt(scan_addr)
                if scan_data is not None and scan_data.isDefined():
                    break
                try:
                    scan_addr = scan_addr.add(1)
                except Exception:
                    break
                size += 1

            return size

        def read_raw_bytes_value_string(addr, size):
            """
            The old fallback here just asserted "{ 0 }" for anything Ghidra
            never wrapped in a typed Data object -- which is wrong whenever
            the symbol lives in an *initialized* section (.data/.rdata):
            those bytes are physically present in the file, Ghidra just
            never got around to typing them. inputL[]/serverports[] are
            exactly this case -- compiled-in literal arrays that Ghidra left
            untyped, so their real values were being silently zeroed out.

            We can't recover the original *element type* (Ghidra never told
            us it was int[] vs char[] vs a struct array), so this still
            emits a plain byte array -- but the actual bytes, and therefore
            the real data, are preserved instead of discarded. If you need
            proper element-level typing (e.g. int32_t[96] instead of
            uint8_t[384]), retype the symbol in Ghidra and re-run.

            .bss stays "{ 0 }" on purpose: it's genuinely zero-filled at
            load time, there's nothing real to read.
            """
            mem_block = program.getMemory().getBlock(addr)
            if mem_block is None or not mem_block.isInitialized():
                return "{ 0 }"
            buf = read_memory_bytes(addr, size, program)
            if buf is not None and any(buf):
                return "{" + ", ".join(f"0x{b:02x}" for b in buf) + "}"
            return "{ 0 }"

        def process_global(addr, data, sym):
            if addr in processed_addrs:
                return

            mem_block = program.getMemory().getBlock(addr)
            # Do NOT skip uninitialized blocks (.bss)!
            if not mem_block or mem_block.isExecute():
                return
            
            block_name = mem_block.getName().lower()
            if any(sec in block_name for sec in ['.debug', '.pdata', '.xdata', '.eh_frame', '.reloc', '.rsrc',
                                                   'headers', '.idata', '.didata']):
                # .idata/.didata hold the PE import directory table, IAT/ILT
                # thunks, and hint/name entries (e.g. the _idata_5_*,
                # _idata_7* symbols and the DWORD_004220xx import-descriptor
                # fields) -- linker/loader metadata, not application globals.
                return
            
            if fn_mgr.getFunctionContaining(addr) is not None:
                return
            
            if is_unneeded_data(data, sym, program):
                return

            is_user_sym = sym and sym.getSource() == SourceType.USER_DEFINED
            refs = ref_mgr.getReferencesTo(addr)
            is_used_in_function = False
            for ref in refs:
                from_addr = ref.getFromAddress()
                if fn_mgr.getFunctionContaining(from_addr) is not None:
                    is_used_in_function = True
                    break
            
            if not is_used_in_function and not is_user_sym:
                return
                
            raw_name = sym.getName() if sym else f"DAT_{addr.toString()}"
            if raw_name in TEB_PEB_IGNORE_LIST or raw_name in RUNTIME_SYMBOLS or raw_name in C_KEYWORDS:
                return
            if raw_name.startswith(("__imp_", "_refptr_", "__xc_", "__xi_", "__xd_", "_CRT", "__mingw", "__native", "__lib64")):
                return
            
            name = sanitize_c_name(raw_name)
            if name in seen_names:
                name = f"{name}_{addr.toString()}"
            seen_names.add(name)
            processed_addrs.add(addr)

            if data and data.isDefined():
                if is_string_data(data) and is_likely_real_text(data):
                    raw_str = str(data.getValue() or "")
                    val = escape_c_string(raw_str)
                    db.add_or_update_global(name, gtype="const char", value_or_expr=val, is_string=True)
                else:
                    dt = data.getDataType()
                    extract_and_store_type(dt, db, seen_types)
                    c_type, dim = parse_ghidra_type_and_dim(dt)
                    val_str = get_data_value_string(data, program)
                    db.add_or_update_global(name, gtype=f"{c_type}{dim}", value_or_expr=val_str, is_string=False)

                inferred_size = infer_undefined_extent(addr)
                if inferred_size > 1:
                    val_str = read_raw_bytes_value_string(addr, inferred_size)
                    db.add_or_update_global(name, gtype=f"uint8_t[{inferred_size}]",
                                             value_or_expr=val_str, is_string=False)
                else:
                    val_str = read_raw_bytes_value_string(addr, 1)
                    db.add_or_update_global(name, gtype="uint8_t", value_or_expr=val_str, is_string=False)

        # Pass 1: Extract collated large arrays & defined globals
        data_iter = listing.getDefinedData(True)
        for data in data_iter:
            addr = data.getAddress()
            sym = symbol_table.getPrimarySymbol(addr)
            process_global(addr, data, sym)

        # Pass 2: Extract uninitialized (.bss) and standard global symbols
        sym_iter = symbol_table.getSymbolIterator(True)
        for sym in sym_iter:
            addr = sym.getAddress()
            data = listing.getDataAt(addr)
            process_global(addr, data, sym)

    db.export_header("data_globals.h")
    db.export_source("data_globals.c")