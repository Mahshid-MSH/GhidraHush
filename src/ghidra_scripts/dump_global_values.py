import sys, os
import pyghidra
import re
import warnings
import struct
import jpype
from database.symbol_db import SymbolDB
from ghidra.program.model.data import Array, Pointer, Structure, Union, Enum, TypeDef, ArrayDataType, ByteDataType, FunctionDefinition
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import StringDataType, UnicodeDataType
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor


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

# Exact bare names (leading underscores stripped before matching) that are
# Windows/CRT internals and should never appear in the output header.
NOISE_TYPE_EXACT_NAMES = frozenset({
    # SEH / exception handling
    "LIST_ENTRY",
    "RTL_CRITICAL_SECTION_DEBUG",
    "EXCEPTION_RECORD",
    "EXCEPTION_POINTERS",
    "FLOATING_SAVE_AREA",
    "CONTEXT",
    # TEB / PEB / NT internals
    "NT_TIB",
    "TEB",
    "TEB_ACTIVE_FRAME",
    "TEB_ACTIVE_FRAME_CONTEXT",
    "CLIENT_ID",
    "PROCESSOR_NUMBER",
    "ACTIVATION_CONTEXT",
    "ACTIVATION_CONTEXT_STACK",
    "RTL_ACTIVATION_CONTEXT_STACK_FRAME",
    "GDI_TEB_BATCH",
    "GUID",
    "CURDIR",
    "STRING",
    "UNICODE_STRING",
    "RTL_DRIVE_LETTER_CURDIR",
    "RTL_USER_PROCESS_PARAMETERS",
    "PEB",
    "PEB_LDR_DATA",
    "LDR_DATA_TABLE_ENTRY",
    "ASSEMBLY_STORAGE_MAP",
    "LEAP_SECOND_DATA",
    # CRT locale / multibyte / time internals
    "crt_locale_data_public",
    "crt_locale_data",
    "crt_locale_refcount",
    "crt_locale_pointers",
    "crt_multibyte_data",
    "crt_lc_time_data",
    "lconv",
    # CRT atexit / onexit machinery
    "onexit_table_t",
    # CRT argv / startup
    "crt_argv_mode",
    # Win32 large integer helpers  (the sample never uses these directly;
    # they only appear as transitive members of the PEB/TEB graph)
    "LARGE_INTEGER",
    "ULARGE_INTEGER",
    # exception disposition enum (SEH ABI detail)
    "EXCEPTION_DISPOSITION",
    # misc runtime / compiler helpers
    "exception",
})

# Prefixes (on the bare, underscore-stripped name) whose whole family is noise.
NOISE_TYPE_PREFIXES = (
    "IMAGE_",          # PE header structs
    "PEB_u_",          # PEB anonymous union/struct sub-types
    "TEB_u_",          # TEB anonymous union/struct sub-types
    "LARGE_INTEGER_",  # LARGE_INTEGER sub-types
    "ULARGE_INTEGER_", # ULARGE_INTEGER sub-types
    "unnamed_tag_",    # Ghidra auto-named anonymous sub-types
    "unnamed_type_",   # ditto
)

# Function-name prefixes that mark CRT/mingw-runtime/locale/exception-glue
# plumbing rather than anything belonging to the sample's own logic.
# is_unneeded_data() already filters globals by an equivalent symbol-name
# prefix list, but Pass 3 (function signature type extraction, below) walks
# Function objects directly and had no equivalent filter -- so in the
# common case where the user hasn't curated extracted_functions/ yet, it
# walked every CRT startup/locale/multibyte/SEH-glue function in the
# binary and pulled in their entire transitive type graph (_TEB, _PEB,
# _CONTEXT, __crt_locale_data, lconv, ...). This is deliberately narrower
# than a type-name blacklist would be: types like _CONTEXT/_EXCEPTION_*
# can be genuinely relevant to a sample's own anti-debug/anti-VM logic
# (e.g. this binary's own IsDebuggerRunning/DetectVMWare/IsInSandbox), so
# filtering by *function* origin instead of by *type name* avoids hiding
# those when they're reached from code that actually matters.
FUNC_NOISE_PREFIXES = (
    "__", "_CRT", "_MINGW", "mingw_", "__gnu", "__mb", "__lc",
    "_onexit", "_atexit", "_initterm", "_amsg_exit",
    "_configthreadlocale", "_set_new", "_seh_", "_except_handler",
    "_XcptFilter", "__report_gsfailure",
)

def is_noise_function_name(name):
    if not name:
        return False
    return name.startswith(FUNC_NOISE_PREFIXES)

def is_noise_type_name(raw_name):
    """
    True for well-known Windows/CRT/PE internal type names that add bulk to
    the output header without adding malware-analysis value.

    Matching is done on the *bare* name (leading underscores stripped), since
    WinAPI/CRT struct tags are conventionally underscore-prefixed in Ghidra's
    type database (e.g. '_TEB', '_PEB', '__crt_locale_data') -- a plain
    equality or prefix check on the raw string would miss all of them.

    Two tiers:
      NOISE_TYPE_EXACT_NAMES  -- the type's bare name is in the frozenset
      NOISE_TYPE_PREFIXES     -- the type's bare name starts with a
                                 noise-family prefix (PEB_u_*, TEB_u_*,
                                 IMAGE_*, unnamed_tag_*, ...)

    Note: RTL_CRITICAL_SECTION / CRITICAL_SECTION are intentionally NOT
    blocked -- they show up as real, meaningful globals in many samples.
    Only their DebugInfo plumbing (RTL_CRITICAL_SECTION_DEBUG, LIST_ENTRY)
    is in the block-list.
    """
    if not raw_name:
        return False
    bare = raw_name.lstrip('_')
    if bare in NOISE_TYPE_EXACT_NAMES:
        return True
    if bare.startswith(NOISE_TYPE_PREFIXES):
        return True
    return False

def is_likely_real_text(data, program=None):
    """Sanity-check that a Ghidra string-ish type actually decoded as real
    text before trusting it. Two cases, since Ghidra represents them
    completely differently:

      - Ghidra's own *dynamic* 'string'/'unicode' types: getValue() already
        returns decoded text. Guard against U+FFFD (Ghidra's decoder had to
        invent characters -> not real text) and against decoded length far
        shorter than the declared buffer (binary with embedded NULs).

      - A plain, statically-sized `char[N]` array (the common case for a
        stripped/no-debug binary): getValue() does NOT return decoded text
        for these -- it's an array of individual char components -- so we
        decode the raw bytes ourselves (up to the first NUL, standard
        C-string semantics) and check they're mostly printable.
    """
    dt_name = data.getDataType().getName().lower()

    if 'string' in dt_name or 'unicode' in dt_name:
        raw = data.getValue()
        if raw is None:
            return False
        s = str(raw)
        if '\ufffd' in s:
            return False
        decl_len = data.getLength()
        if decl_len > 4 and len(s) < decl_len * 0.5:
            return False
        return True

    if 'char' in dt_name and program is not None:
        length = data.getLength()
        if length <= 0:
            return False
        buf = read_memory_bytes(data.getAddress(), length, program)
        if not buf:
            return False
        term = buf.find(b'\x00')
        text_len = term if term >= 0 else len(buf)
        if text_len == 0:
            return False
        if any(not (32 <= b <= 126 or b in (9, 10, 13)) for b in buf[:text_len]):
            return False  # non-printable byte inside the text run -> not text
        if length > 4 and text_len < length * 0.3:
            return False  # mostly padding, not a meaningful string
        return True

    return False  # anything else -- never trust as text


def extract_c_string_value(data, program):
    """Companion to is_likely_real_text(): pull the actual text out using
    whichever method matches how that True came back. For Ghidra's dynamic
    'string'/'unicode' types this is just getValue(); for a plain char[]
    array it's the same manual byte-decode used above, truncated at the
    first NUL."""
    dt_name = data.getDataType().getName().lower()
    if 'string' in dt_name or 'unicode' in dt_name:
        return str(data.getValue() or "")
    length = data.getLength()
    buf = read_memory_bytes(data.getAddress(), length, program) or b""
    term = buf.find(b'\x00')
    text_bytes = buf[:term] if term >= 0 else buf
    return text_bytes.decode('latin-1')

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
        # Bulk array read failed -- fall back to a byte-at-a-time read via
        # Memory.getByte(), which never touches the array-marshaling path
        # that's failing above. Only warn if THIS also fails.
        try:
            mem = program.getMemory()
            out = bytearray(size)
            cur = addr
            for i in range(size):
                out[i] = mem.getByte(cur) & 0xFF
                cur = cur.add(1)
            return bytes(out)
        except Exception as e2:
            print(f"  [warn] failed to read {size} byte(s) at {addr}: {e} (fallback also failed: {e2})")
            return None

def is_string_data(data):
    if not data or not data.isDefined():
        return False
    dt_name = data.getDataType().getName().lower()
    return 'string' in dt_name or 'char' in dt_name or 'unicode' in dt_name

def ensure_function_pointer_typedef(func_def, db, seen_types):
    """
    Registers a standalone, correctly-shaped typedef for a Ghidra
    FunctionDefinition -- the type Ghidra gives function-pointer pointees,
    auto-named after their own return/argument types (e.g. '_func_void',
    '_func_void_PVOID_DWORD_PVOID'):

        typedef RET (*NAME)(ARG1, ARG2, ...);

    Previously this auto-generated name was treated like any other
    struct/typedef tag and simply pointed at (`_func_void*`), but nothing
    ever *defined* `_func_void` anywhere in the header -- guaranteed
    "unknown type name" errors for every function pointer in the binary.
    Defining the name itself as the function-pointer type (rather than as
    a phantom pointee you then slap a `*` onto) is both what makes it
    compile and what keeps single- vs double-indirection correct.

    Returns the sanitized name to use as the base type wherever this
    pointer type shows up. That name already denotes "pointer to
    function" -- callers must NOT append another '*' for the pointer
    level that led here.
    """
    name = sanitize_c_name(func_def.getName())
    if name in seen_types:
        return name
    seen_types.add(name)

    ret_type, ret_dim = parse_ghidra_type_and_dim(func_def.getReturnType(), db, seen_types)
    params = []
    for arg in func_def.getArguments():
        p_type, p_dim = parse_ghidra_type_and_dim(arg.getDataType(), db, seen_types)
        params.append(f"{p_type}{p_dim}")
    if func_def.hasVarArgs():
        params.append("...")
    param_list = ", ".join(params) if params else "void"

    db.add_custom_type(name, f"typedef {ret_type}{ret_dim} (*{name})({param_list});\n")
    return name


def parse_ghidra_type_and_dim(dt, db, seen_types):
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
        if isinstance(underlying, FunctionDefinition):
            # The typedef this returns already denotes "pointer to
            # function" -- drop the '*' this loop iteration just added so
            # we don't end up with a pointer-to-function-pointer instead.
            func_name = ensure_function_pointer_typedef(underlying, db, seen_types)
            return func_name + ptr_str[:-1], dim_str
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
            'undefined8': 'uint64_t', 'qword': 'uint64_t', 'long long': 'int64_t',
            'float': 'float', 'double': 'double', 'string': 'char', 'terminatedcstring': 'char',
            'void': 'void'
        }
        if name in ('long', 'ulong'):
            # See comment above the type_map literal: don't hardcode a
            # width for these -- ask Ghidra what it actually is for this
            # program (4 on Windows, always -- but stay generic).
            try:
                size = dt.getLength()
            except Exception:
                size = 4
            width_map = {1: '8', 2: '16', 4: '32', 8: '64'}
            bits = width_map.get(size, '32')
            c_type = f"int{bits}_t" if name == 'long' else f"uint{bits}_t"
        else:
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

        # Skip any global whose DataType is itself a noise type (e.g. a
        # global of type _onexit_table_t or __crt_locale_pointers). Without
        # this, a symbol named module_local_atexit_table would pass the
        # symbol-name prefix filter below (it doesn't start with "__" etc.)
        # but is pure CRT machinery -- its type name reveals that.
        # Unwrap one level of TypeDef/Pointer so that e.g. a pointer-to-TEB
        # global is also caught.
        if is_noise_type_name(dt_name):
            return True
        try:
            base = dt.getBaseDataType() if isinstance(dt, TypeDef) else (
                dt.getDataType() if isinstance(dt, (Array, Pointer)) else None)
            if base is not None and is_noise_type_name(base.getName()):
                return True
        except Exception:
            pass

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
            "fpi", "p_", "pmem_"   # Math/Runtime internals
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

    if isinstance(dt, FunctionDefinition):
        # Function-pointer pointee (Ghidra's auto-named '_func_...' types).
        # ensure_function_pointer_typedef() is the single place that both
        # registers the correct typedef AND owns seen_types bookkeeping for
        # these names -- don't duplicate that logic here, or this path and
        # parse_ghidra_type_and_dim()'s pointer walk can race to mark a name
        # "seen" before either one has actually written a definition for it.
        ensure_function_pointer_typedef(dt, db, seen_types)
        return

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
            c_type, dim = parse_ghidra_type_and_dim(comp.getDataType(), db, seen_types)
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
        base_type, dim = parse_ghidra_type_and_dim(dt.getBaseDataType(), db, seen_types)
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
        elif isinstance(val, str) and len(val) == 1:
            # Ghidra's CharDataType.getValue() comes back as a single-
            # character Python str via JPype (java.lang.Character), not a
            # numeric type -- none of the branches above catch it, and
            # falling straight to the old `return str(val)` below emitted
            # that bare character completely unquoted, e.g. `{S, o, m, e,
            # ...}` -- not valid C. Route it through the same hex-byte
            # formatting every other scalar in this array already gets.
            num = ord(val)
        
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

def load_curated_function_entry_points(workspace_dir, path_to_binary):
    """
    Builds the set of entry-point address strings for functions the user
    has already curated into extracted_functions/<binary_name>/ -- i.e.
    whatever's left after running function_extractor.py and deleting the
    ones that weren't useful/user-defined.

    Returns None if that directory doesn't exist or is empty, so callers
    can fall back to the old "referenced from any function in the binary"
    behavior instead of silently extracting zero globals for someone who
    hasn't run function_extractor.py yet.

    File names are func_ids from function_extractor.py's make_function_id():
        f"{sanitized_qualified_name}_{entry_point_address}" + ".c"/".cpp"
    The entry point address is always the last underscore-separated,
    all-hex-digit token before the extension (Ghidra's Address.toString()
    for a plain default-space address is just hex digits, no separators),
    so it comes back out with a plain regex -- no need to reparse it
    through Ghidra's address factory.
    """
    base_name = os.path.basename(path_to_binary)
    func_dir = os.path.join(workspace_dir, "extracted_functions", base_name)
    if not os.path.isdir(func_dir):
        return None

    addr_strings = set()
    for fname in os.listdir(func_dir):
        stem, ext = os.path.splitext(fname)
        if ext.lower() not in (".c", ".cpp"):
            continue  # skips call_graph.json and anything else stray
        m = re.match(r'^.*_([0-9A-Fa-f]+)$', stem)
        if m:
            addr_strings.add(m.group(1))

    return addr_strings or None


def generate_global_files(path_to_binary, workspace_dir="."):
    db = SymbolDB(workspace_dir=workspace_dir)

    # Start each analysis run from a clean slate for globals/custom types.
    # Without this, `globals`/`custom_types` only ever grow: every symbol
    # any *past* (possibly looser) version of the filters below ever let
    # through stays in symbols.db forever and gets re-emitted by
    # export_header() on every subsequent run -- which is why deleting a
    # row from data_globals.h by hand never sticks: the .h is just a view
    # over the .db, and the .db was never cleared. `excluded_globals` /
    # `excluded_custom_types` (see manage_symbols.py) and `functions` are
    # deliberately left untouched here: the former is your permanent
    # denylist, the latter accumulates across incremental per-function
    # enhancement runs done later by c_code_enhancer.py.
    db.reset_globals()
    db.reset_custom_types()

    # If the user has already run function_extractor.py and pruned
    # extracted_functions/ down to just the functions they care about,
    # scope global extraction to references from THOSE functions only.
    # This is strictly better than the prefix/name-based noise filters
    # above: instead of trying to guess "is this compiler/runtime
    # plumbing" after the fact, it just never looks at globals that are
    # only touched by code the user already judged uninteresting (CRT
    # startup, mingw thread-safe init, exception glue, etc. -- none of
    # that lives in extracted_functions/ once it's been cleaned up).
    curated_addrs = load_curated_function_entry_points(workspace_dir, path_to_binary)
    if curated_addrs is not None:
        print(f"Found {len(curated_addrs)} curated function(s) in extracted_functions/ -- "
              f"scoping global extraction to references from those functions only.")
    else:
        print("No curated extracted_functions/ folder found for this binary -- falling back to "
              "'referenced from any function in the binary'. Run function_extractor.py and prune "
              "it down to the functions you care about, then re-run this script for tighter results.")

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
                containing_func = fn_mgr.getFunctionContaining(from_addr)
                if containing_func is None:
                    continue
                if curated_addrs is not None and containing_func.getEntryPoint().toString() not in curated_addrs:
                    # Referenced from a real function, but not one the user
                    # kept in extracted_functions/ -- almost certainly CRT
                    # startup, mingw plumbing, exception-handling glue,
                    # etc. Don't let it count as "used".
                    continue
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
            if db.is_global_excluded(name):
                # Permanently blacklisted via manage_symbols.py. Ghidra will
                # keep finding this symbol every run because it genuinely is
                # referenced from code, but the user has already judged it
                # noise -- honor that instead of silently re-adding it.
                return
            if name in seen_names:
                name = f"{name}_{addr.toString()}"
            seen_names.add(name)
            processed_addrs.add(addr)

            if data and data.isDefined():
                if is_string_data(data) and is_likely_real_text(data, program):
                    raw_str = extract_c_string_value(data, program)
                    val = escape_c_string(raw_str)
                    db.add_or_update_global(name, gtype="const char", value_or_expr=val, is_string=True)
                else:
                    dt = data.getDataType()
                    extract_and_store_type(dt, db, seen_types)
                    c_type, dim = parse_ghidra_type_and_dim(dt, db, seen_types)
                    val_str = get_data_value_string(data, program)
                    db.add_or_update_global(name, gtype=f"{c_type}{dim}", value_or_expr=val_str, is_string=False)
            else:
                # Ghidra never wrapped this symbol in a typed Data object --
                # this is the ONLY case the raw-byte fallback belongs to.
                # Previously this ran unconditionally after the typed branch
                # above too, so its add_or_update_global() call silently
                # overwrote every correctly-typed global (structs, enums,
                # typedefs -- everything) with a generic uint8_t/uint8_t[N],
                # which is why the exported header showed nothing but byte
                # arrays even for symbols Ghidra had real type info for.
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

        # Pass 3: Extract types that only ever appear in a function's own
        # signature (return type / parameters) -- these are invisible to
        # Pass 1/2 above since nothing there ever walks Function objects,
        # only Data at addresses. Without this, a type like an enum used
        # solely as a by-value parameter never gets a typedef emitted, even
        # though a later stage may already be generating a prototype that
        # references it by name.
        for func in fn_mgr.getFunctions(True):
            if curated_addrs is not None and func.getEntryPoint().toString() not in curated_addrs:
                continue
            if curated_addrs is None and is_noise_function_name(func.getName()):
                # Only applies in the uncurated fallback -- once
                # extracted_functions/ has been pruned, curated_addrs
                # already scopes this precisely and this check is a no-op.
                continue
            extract_and_store_type(func.getReturnType(), db, seen_types)
            for param in func.getParameters():
                extract_and_store_type(param.getDataType(), db, seen_types)

        # Pass 4: types that only ever appear as a LOCAL variable inside a
        # function body -- e.g. a thread entry point declared
        # `DWORD WINAPI DL_Thread(LPVOID param)` (so Pass 3 above only
        # ever sees void*), which then does
        #     download_s *ds = (download_s *)param;
        # The struct is real and meaningful, but neither the global-data
        # walk nor the function-signature walk above ever looks at it --
        # it's purely a decompiler-inferred local type. Ask the decompiler
        # directly via HighFunction's local symbol map.
        decomp = DecompInterface()
        decomp.openProgram(program)
        monitor = ConsoleTaskMonitor()
        pass4_processed = 0
        pass4_types_before = len(seen_types)
        try:
            for func in fn_mgr.getFunctions(True):
                if curated_addrs is not None and func.getEntryPoint().toString() not in curated_addrs:
                    continue
                if curated_addrs is None and is_noise_function_name(func.getName()):
                    continue
                fname = func.getName()
                fentry = func.getEntryPoint().toString()
                try:
                    result = decomp.decompileFunction(func, 60, monitor)
                except Exception as e:
                    print(f"  [warn] Pass 4: decompile raised for {fname} @ {fentry}: {e}")
                    continue
                if result is None:
                    print(f"  [warn] Pass 4: no decompile result for {fname} @ {fentry}")
                    continue
                if not result.decompileCompleted():
                    # A pcode-level error (e.g. Ghidra's own
                    # "Unable to resolve constructor" warning) does NOT
                    # necessarily mean nothing usable came back -- Ghidra
                    # often still produces a partially-populated
                    # HighFunction with everything it managed to resolve
                    # before/around the failure point. Only bail if there's
                    # truly nothing to read.
                    msg = result.getErrorMessage() if result else "?"
                    print(f"  [warn] Pass 4: decompile incomplete for {fname} @ {fentry}: {msg} "
                          f"-- attempting partial local-symbol read anyway")
                high_func = result.getHighFunction()
                if high_func is None:
                    print(f"  [warn] Pass 4: no HighFunction for {fname} @ {fentry} -- skipped, "
                          f"any locals cast to a struct in this function were NOT recovered")
                    continue
                pass4_processed += 1
                for hv in high_func.getLocalSymbolMap().getSymbols():
                    try:
                        extract_and_store_type(hv.getDataType(), db, seen_types)
                    except Exception:
                        continue
        finally:
            decomp.dispose()
        print(f"Pass 4: decompiled {pass4_processed} curated function(s) for local-variable types, "
              f"registered {len(seen_types) - pass4_types_before} new type(s).")

    db.export_header("data_globals.h")
    db.export_source("data_globals.c")