#!/usr/bin/env python3
"""
dump_global_values.py
---------------------
Stage 2: extracts global variables, custom types and function-pointer
typedefs referenced by the curated functions, and stores them in the
SymbolDB (which renders data_globals.h / data_globals.c).

Changelog (compile-rate fixes):
 [1] C_KEYWORDS split into TRUE_C_KEYWORDS vs WINAPI_TYPES. WinAPI names
     (HANDLE, DWORD, LPVOID, ...) are defined by windows.h and must NOT be
     mangled to _HANDLE etc. by sanitize_c_name().
 [2] caseD_/switchdataD_ runtime symbols are prefix-matched, not exact.
 [3] size_t width comes from dt.getLength() (uint64_t on x64); added
     'undefined' -> uint8_t; longlong/ulonglong mapped to stdint.
 [4] String escapes use 3-digit octal (self-terminating) instead of
     greedy hex escapes ("\x41"+"B" parsed as one broken char).
 [5] Primitive-name filter is exact-match (BUILTIN_TYPE_NAMES) instead of
     startswith(); typedefs already defined by windows.h are passed
     through instead of re-emitted (redefinition errors).
 [6] Function-pointer typedefs: fnptr_ prefix (no name collisions),
     signature-level dedup (identical callbacks share one typedef),
     array returns collapsed to void*.
 [7] Enumerators deduplicated and E_-prefixed (file-scope in C; collided
     with each other and with windows.h macros like TRUE/FALSE/NULL).
 [8] Disambiguation suffixes for duplicate global names are C-sanitized.
 [9] SECTION_MARKER_SYMBOLS (_data/_rdata/_bss/...) checked FIRST in
     is_unneeded_data: COFF imports mark them USER_DEFINED, so they
     bypassed every prefix denylist AND shared addresses with real
     variables ('_data' aliased 'shellcode', and the processed_addrs
     guard silently dropped the real symbol).
 [10] Executable-block data extraction, v2: shellcode/blob globals in
      .text are extracted when any non-call/non-jump reference targets
      the address (isData() alone misses COMPUTED refs from lea/&global).
      The function-containing check is bypassed for exec blocks, because
      Ghidra may have disassembled a data blob into a pseudo-function.
"""

import os
import re
import sys
import struct
import warnings

import jpype
import pyghidra
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.data import (
    Array, ArrayDataType, ByteDataType, Enum, FunctionDefinition, 
    Pointer, StringDataType, Structure, TypeDef, UnicodeDataType, Union
)
from ghidra.program.model.symbol import SourceType
from ghidra.util.task import ConsoleTaskMonitor

from database.symbol_db import SymbolDB

warnings.filterwarnings("ignore", category=DeprecationWarning)

# --- Constants & Configuration ---

# FIX [9]: MinGW/COFF linker section markers. These label section
# boundaries, not program variables -- but Ghidra imports them from the
# COFF symbol table with USER_DEFINED source, so they bypass the prefix
# denylists. They MUST be checked before the USER_DEFINED early-return in
# is_unneeded_data, because they share addresses with real variables and
# shadow them (observed: '_data' aliasing 'shellcode' at the same address,
# causing the real symbol to be dropped by the processed_addrs guard).
SECTION_MARKER_SYMBOLS = frozenset({
    "_data", "_rdata", "_bss", "_edata", "_end",
    "__data_start__", "__data_end__", "__bss_start__", "__bss_end__",
})

# FIX [1]: only actual C keywords get the '_' escaping treatment.
TRUE_C_KEYWORDS = {
    'auto', 'break', 'case', 'char', 'const', 'continue', 'default', 'do', 
    'double', 'else', 'enum', 'extern', 'float', 'for', 'goto', 'if', 'int', 
    'long', 'register', 'return', 'short', 'signed', 'sizeof', 'static', 
    'struct', 'switch', 'typedef', 'union', 'unsigned', 'void', 'volatile',
    'while',
}

# FIX [1]: these are NOT keywords -- windows.h defines them. Mangling them
# (HANDLE -> _HANDLE) produced undeclared identifiers in every generated file.
WINAPI_TYPES = frozenset({
    "BOOL", "BYTE", "CHAR", "DWORD", "HANDLE", "HGLOBAL", "HKEY", 
    "HMODULE", "HWND", "LPCSTR", "LPDWORD", "LPOVERLAPPED", "LPSECURITY_ATTRIBUTES", 
    "LPSTR", "LPVOID", "LSTATUS", "PLONG", "ULONG", "FARPROC", "WORD", "LONG", 
    "UINT", "WPARAM", "LPARAM", "FILE", "HINSTANCE", "ATOM"
})

# Full set: used ONLY to decide whether a *global variable name* would
# collide with a known type name (a global named HANDLE would shadow the
# windows.h typedef and break compilation), so it is skipped entirely.
C_KEYWORDS = TRUE_C_KEYWORDS | WINAPI_TYPES

# FIX [5]: exact-match set of primitive/type names that must never be
# emitted as custom type definitions. Replaces the old startswith() check,
# which silently dropped legitimate types like 'intWrapper'.
BUILTIN_TYPE_NAMES = frozenset({
    'void', 'bool', 'char', 'sbyte', 'byte', 'short', 'ushort', 'int', 'uint',
    'long', 'ulong', 'longlong', 'ulonglong', 'long long',
    'float', 'double', 'string', 'terminatedcstring',
    'undefined', 'undefined1', 'undefined2', 'undefined4', 'undefined8',
    'word', 'dword', 'qword', 'code', 'size_t',
    'uint8_t', 'uint16_t', 'uint32_t', 'uint64_t',
    'int8_t', 'int16_t', 'int32_t', 'int64_t',
    'uintptr_t', 'intptr_t',
})

NOISE_TYPE_EXACT_NAMES = frozenset({
    "LIST_ENTRY", "RTL_CRITICAL_SECTION_DEBUG", "EXCEPTION_RECORD", "EXCEPTION_POINTERS",
    "FLOATING_SAVE_AREA", "CONTEXT", "NT_TIB", "TEB", "TEB_ACTIVE_FRAME",
    "TEB_ACTIVE_FRAME_CONTEXT", "CLIENT_ID", "PROCESSOR_NUMBER", "ACTIVATION_CONTEXT",
    "ACTIVATION_CONTEXT_STACK", "RTL_ACTIVATION_CONTEXT_STACK_FRAME", "GDI_TEB_BATCH",
    "GUID", "CURDIR", "STRING", "UNICODE_STRING", "RTL_DRIVE_LETTER_CURDIR",
    "RTL_USER_PROCESS_PARAMETERS", "PEB", "PEB_LDR_DATA", "LDR_DATA_TABLE_ENTRY",
    "ASSEMBLY_STORAGE_MAP", "LEAP_SECOND_DATA", "crt_locale_data_public",
    "crt_locale_data", "crt_locale_refcount", "crt_locale_pointers", "crt_multibyte_data",
    "crt_lc_time_data", "lconv", "onexit_table_t", "crt_argv_mode", "LARGE_INTEGER",
    "ULARGE_INTEGER", "EXCEPTION_DISPOSITION", "exception",
})

NOISE_TYPE_PREFIXES = (
    "IMAGE_", "PEB_u_", "TEB_u_", "LARGE_INTEGER_", "ULARGE_INTEGER_", 
    "unnamed_tag_", "unnamed_type_",
)

FUNC_NOISE_PREFIXES = (
    "__", "_CRT", "_MINGW", "mingw_", "__gnu", "__mb", "__lc",
    "_onexit", "_atexit", "_initterm", "_amsg_exit",
    "_configthreadlocale", "_set_new", "_seh_", "_except_handler",
    "_XcptFilter", "__report_gsfailure",
)

TEB_PEB_IGNORE_LIST = {
    "ExceptionList", "LastError", "Tls", "Gdi", "Reserved", "StackBase", 
    "StackLimit", "ProcessEnvironmentBlock", "EnvironmentPointer", 
    "glDispatchTable", "TxnScope", "FiberData", "ArbitraryUserPointer", 
    "ThreadLocalStorage", "Win32ThreadInfo", "EtwTraceData", "DeallocationStack"
}

RUNTIME_SYMBOLS = {
    "mingw_pcinit", "mingw_pcppinit", "mingw_initcharmax",
    "mingw_initltsdrot_force", "mingw_initltsdyn_force", "mingw_initltssuo_force",
    "mingw_app_type", "mainret", "managedapp", "fpreset", "fthunk",
    "p_92992", "hname", "key_dtor_list", "the_secs", "was_init_94382",
    "argc", "argv", "envp", "startinfo", "stUserMathErr", "handler",
    "has_cctor", "initialized", "register_frame_ctor", "switchD",
    "CLSID", "IID",
    "_fmode", "_commode", "_dowildcard", "_newmode", "_environ", "__initenv"
}

# FIX [2]: these are symbol *families* (address-templated names), so exact
# matching never fired. Prefix-match instead.
RUNTIME_SYMBOL_PREFIXES = ("caseD_", "switchdataD_")

# --- Core Helper Functions ---

def sanitize_c_name(name):
    if not name: return "unknown_type"
    name = name.replace("struct ", "").replace("enum ", "").replace("union ", "")
    name = re.sub(r'[^a-zA-Z0-9_]', '_', name)
    # FIX [1]: only escape true C keywords, never WinAPI type names.
    if name in TRUE_C_KEYWORDS or (name and name[0].isdigit()):
        name = '_' + name
    return name

def is_noise_function_name(name):
    if not name: return False
    return name.startswith(FUNC_NOISE_PREFIXES)

def is_noise_type_name(raw_name):
    if not raw_name: return False
    bare = raw_name.lstrip('_')
    if bare in NOISE_TYPE_EXACT_NAMES or bare.startswith(NOISE_TYPE_PREFIXES):
        return True
    return False

def is_likely_real_text(data, program=None):
    dt_name = data.getDataType().getName().lower()

    if 'string' in dt_name or 'unicode' in dt_name:
        raw = data.getValue()
        if raw is None: return False
        s = str(raw)
        if '\ufffd' in s: return False
        decl_len = data.getLength()
        if decl_len > 4 and len(s) < decl_len * 0.5:
            return False
        return True

    if 'char' in dt_name and program is not None:
        length = data.getLength()
        if length <= 0: return False
        buf = read_memory_bytes(data.getAddress(), length, program)
        if not buf: return False
        term = buf.find(b'\x00')
        text_len = term if term >= 0 else len(buf)
        if text_len == 0: return False
        if any(not (32 <= b <= 126 or b in (9, 10, 13)) for b in buf[:text_len]):
            return False
        if length > 4 and text_len < length * 0.3:
            return False 
        return True

    return False 

def extract_c_string_value(data, program):
    dt_name = data.getDataType().getName().lower()
    if 'string' in dt_name or 'unicode' in dt_name:
        return str(data.getValue() or "")
    length = data.getLength()
    buf = read_memory_bytes(data.getAddress(), length, program) or b""
    term = buf.find(b'\x00')
    text_bytes = buf[:term] if term >= 0 else buf
    return text_bytes.decode('latin-1')

def read_memory_bytes(addr, size, program):
    try:
        jbuf = jpype.JArray(jpype.JByte)(size)
        program.getMemory().getBytes(addr, jbuf)
        return bytes(b & 0xFF for b in jbuf)
    except Exception as e:
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
    if not data or not data.isDefined(): return False
    dt_name = data.getDataType().getName().lower()
    return 'string' in dt_name or 'char' in dt_name or 'unicode' in dt_name

# FIX [6]: signature -> typedef-name cache so identical function-pointer
# signatures share one typedef instead of colliding via INSERT OR IGNORE.
_FPTR_SIG_CACHE = {}

def reset_fptr_cache():
    """Call once per binary run so typedef numbering is deterministic."""
    _FPTR_SIG_CACHE.clear()

def ensure_function_pointer_typedef(func_def, db, seen_types):
    # FIX [6]: 'fnptr_' prefix guarantees the typedef name cannot collide
    # with a struct/union/enum/global of the same sanitized name.
    base = "fnptr_" + sanitize_c_name(func_def.getName())

    if base in seen_types:
        return base
    seen_types.add(base)  # recursion guard: must precede parse_* recursion

    ret_type, ret_dim = parse_ghidra_type_and_dim(func_def.getReturnType(), db, seen_types)
    if ret_dim:
        # FIX [6]: C forbids functions returning arrays; collapse to pointer.
        ret_type, ret_dim = "void*", ""

    params = []
    for arg in func_def.getArguments():
        p_type, p_dim = parse_ghidra_type_and_dim(arg.getDataType(), db, seen_types)
        params.append(f"{p_type}{p_dim}")
    if func_def.hasVarArgs():
        params.append("...")
    param_list = ", ".join(params) if params else "void"

    # FIX [6]: reuse an existing typedef when the signature is identical
    # (common for callbacks). Different signatures under the same base name
    # (C++ overloads) still resolve first-wins -- but they no longer poison
    # a struct/global with the same name.
    signature = f"{ret_type}({param_list})"
    cached = _FPTR_SIG_CACHE.get(signature)
    if cached is not None:
        seen_types.add(cached)
        return cached
    _FPTR_SIG_CACHE[signature] = base

    db.add_custom_type(base, f"typedef {ret_type} (*{base})({param_list});\n")
    return base

def parse_ghidra_type_and_dim(dt, db, seen_types):
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
            func_name = ensure_function_pointer_typedef(underlying, db, seen_types)
            return func_name + ptr_str[:-1], dim_str
        if is_noise_type_name(underlying.getName()):
            return "void" + ptr_str, dim_str
        dt = underlying

    if isinstance(dt, (Structure, Union, Enum, TypeDef)):
        # FIX [5]: windows.h already defines these names (DWORD, HANDLE, ...).
        # Pass the name through -- re-emitting our own typedef was a
        # guaranteed 'redefinition' error against the Windows headers.
        if isinstance(dt, TypeDef) and sanitize_c_name(dt.getName()) in WINAPI_TYPES:
            return sanitize_c_name(dt.getName()) + ptr_str, dim_str

        if is_noise_type_name(dt.getName()):
            try:
                size = max(dt.getLength(), 1)
            except Exception:
                size = 1
            return "uint8_t", dim_str + f"[{size}]"

        c_type = sanitize_c_name(dt.getName())
    else:
        name = dt.getName().lower()
        type_map = {
            'undefined1': 'uint8_t',  'byte': 'uint8_t',   'char': 'int8_t', 'sbyte': 'int8_t', 'bool': 'uint8_t',
            'undefined2': 'uint16_t', 'word': 'uint16_t',  'short': 'int16_t', 'ushort': 'uint16_t',
            'undefined4': 'uint32_t', 'dword': 'uint32_t', 'int': 'int32_t', 'uint': 'uint32_t',
            'undefined8': 'uint64_t', 'qword': 'uint64_t', 'long long': 'int64_t',
            'float': 'float', 'double': 'double', 'string': 'char', 'terminatedcstring': 'char',
            'undefined': 'uint8_t',   # FIX [3]: was unmapped -> emitted invalid C
            'longlong': 'int64_t',    # FIX [3]: Ghidra 64-bit names (the shim
            'ulonglong': 'uint64_t',  # also covers them, but do not generate
                                      # unresolved bases in the first place)
            'void': 'void'
            # FIX [3]: 'size_t' REMOVED from the map -- it is width-resolved
            # below from the actual byte size (uint64_t on x64, not uint32_t).
        }
        # FIX [3]: pointer/width-sensitive types resolved by real size.
        if name in ('long', 'ulong', 'size_t', 'ssize_t'):
            try:
                size = dt.getLength()
            except Exception:
                size = 8 if name == 'size_t' else 4  # Windows ABI defaults
            bits = {1: '8', 2: '16', 4: '32', 8: '64'}.get(size, '32')
            c_type = f"uint{bits}_t" if name in ('ulong', 'size_t') else f"int{bits}_t"
        else:
            c_type = type_map.get(name, sanitize_c_name(dt.getName()))

    return c_type + ptr_str, dim_str

def is_unneeded_data(data, symbol, program):
    # FIX [9]: section markers first -- frequently USER_DEFINED (COFF symbol
    # table), so this must precede the USER_DEFINED early-return below.
    if symbol and symbol.getName() in SECTION_MARKER_SYMBOLS:
        return True

    if data:
        addr = data.getMinAddress()
        block = program.getMemory().getBlock(addr)
        if block and block.getName() == "Headers":
            return True
            
        dt = data.getDataType()
        dt_name = dt.getName()

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
        ignore_prefixes = (
            "s_", "u_", "__", "_MINGW", "_imp_", "IMAGE_", 
            "_rdata", "_CSWTCH_", "_func_", "fpi", "p_", "pmem_"
        )
        
        if name.startswith(ignore_prefixes):
            return
            
    return False

def extract_and_store_type(dt, db, seen_types):
    if dt is None: return
    
    while isinstance(dt, (Pointer, Array)):
        dt = dt.getDataType()
        if dt is None: return

    if isinstance(dt, FunctionDefinition):
        ensure_function_pointer_typedef(dt, db, seen_types)
        return

    if is_noise_type_name(dt.getName()):
        return

    name = sanitize_c_name(dt.getName())
    # FIX [5]: exact-match against primitives instead of startswith(); also
    # skip WinAPI names entirely (windows.h owns those definitions).
    if name in seen_types or name in BUILTIN_TYPE_NAMES or name in WINAPI_TYPES:
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
        # FIX [7]: enumerators are file-scope identifiers in C. Two enums
        # declaring the same name -- or an enumerator colliding with a
        # windows.h macro (TRUE, FALSE, NULL, MAX_PATH, ...) -- caused
        # redefinition / macro-expansion syntax errors. Deduplicate per
        # original name and emit with an E_ prefix.
        lines = [f"typedef enum {name} {{"]
        for enum_name in dt.getNames():
            safe = sanitize_c_name(enum_name)
            key = f"enumconst:{safe}"
            if key in seen_types:
                continue
            seen_types.add(key)
            val = dt.getValue(enum_name)
            lines.append(f"    E_{safe} = {val},")
        lines.append(f"}} {name};\n")
        db.add_custom_type(name, "\n".join(lines))
        
    elif isinstance(dt, TypeDef):
        extract_and_store_type(dt.getBaseDataType(), db, seen_types)
        base_type, dim = parse_ghidra_type_and_dim(dt.getBaseDataType(), db, seen_types)
        # Note: dim attaches to the typedef NAME, which is valid C:
        # 'typedef uint8_t buf_t[64];'
        db.add_custom_type(name, f"typedef {base_type} {name}{dim};\n")

def auto_collate_large_arrays(program, min_size=1024):
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
            num = ord(val)
        
        if isinstance(num, int):
            size = dt.getLength()
            if size == 1: num &= 0xFF
            elif size == 2: num &= 0xFFFF
            elif size == 4: num &= 0xFFFFFFFF
            elif size == 8: num &= 0xFFFFFFFFFFFFFFFF
            return f"0x{num:x}"

        # 4-byte float literals get an 'f' suffix (avoids
        # double-to-float conversion warnings with -Werror setups).
        if isinstance(num, float):
            try: size = dt.getLength()
            except Exception: size = 8
            return f"{num}f" if size == 4 else f"{num}"
            
        return str(val)

def escape_c_string(val):
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
        # FIX [4]: octal, exactly 3 digits. C hex escapes are unbounded, so
        # "\x41" followed by 'B' parsed as one broken char "\x41B". A
        # 3-digit octal escape is capped by the standard, hence
        # self-terminating: "\001" + "2" parses correctly as char 1, '2'.
        else: escaped.append(f'\\{code & 0xff:03o}')
    return "".join(escaped)

def load_curated_function_entry_points(workspace_dir, path_to_binary):
    base_name = os.path.basename(path_to_binary)
    func_dir = os.path.join(workspace_dir, "extracted_functions", base_name)
    if not os.path.isdir(func_dir):
        return None

    addr_strings = set()
    for fname in os.listdir(func_dir):
        stem, ext = os.path.splitext(fname)
        if ext.lower() not in (".c", ".cpp"):
            continue 
        m = re.match(r'^.*_([0-9A-Fa-f]+)$', stem)
        if m:
            addr_strings.add(m.group(1))

    return addr_strings or None


# --- Modular Extractor Class ---

class GlobalValueExtractor:
    def __init__(self, program, db, curated_addrs):
        self.program = program
        self.db = db
        self.curated_addrs = curated_addrs
        
        self.seen_names = set()
        self.seen_types = set()
        self.processed_addrs = set()
        
        self.listing = program.getListing()
        self.symbol_table = program.getSymbolTable()
        self.ref_mgr = program.getReferenceManager()
        self.fn_mgr = program.getFunctionManager()

    def _infer_undefined_extent(self, addr, max_size=4096):
        mem_block = self.program.getMemory().getBlock(addr)
        if mem_block is None:
            return 1

        block_end = mem_block.getEnd()
        scan_addr = addr.add(1)
        size = 1

        while scan_addr.compareTo(block_end) <= 0 and size < max_size:
            if self.symbol_table.getPrimarySymbol(scan_addr) is not None:
                break
            if self.ref_mgr.hasReferencesTo(scan_addr):
                break
            scan_data = self.listing.getDataAt(scan_addr)
            if scan_data is not None and scan_data.isDefined():
                break
            try:
                scan_addr = scan_addr.add(1)
            except Exception:
                break
            size += 1

        return size

    def _read_raw_bytes_value_string(self, addr, size):
        mem_block = self.program.getMemory().getBlock(addr)
        if mem_block is None or not mem_block.isInitialized():
            return "{ 0 }"
        buf = read_memory_bytes(addr, size, self.program)
        if buf is not None and any(buf):
            return "{" + ", ".join(f"0x{b:02x}" for b in buf) + "}"
        return "{ 0 }"

    def _process_global(self, addr, data, sym):
        if addr in self.processed_addrs:
            return

        mem_block = self.program.getMemory().getBlock(addr)
        if not mem_block:
            return

        block_name = mem_block.getName().lower()
        if any(sec in block_name for sec in ['.debug', '.pdata', '.xdata', '.eh_frame',
                                             '.reloc', '.rsrc', 'headers', '.idata', '.didata']):
            return

        if mem_block.isExecute():
            # FIX [10-v2]: shellcode blobs in .text are extractable, but a
            # real FUNCTION ENTRY never is. getFunctionAt (exact address)
            # catches function symbols even where a blob was disassembled;
            # containing-check stays bypassed for genuinely embedded data.
            if self.fn_mgr.getFunctionAt(addr) is not None:
                return
            if not any(not (r.getReferenceType().isCall()
                            or r.getReferenceType().isJump())
                       for r in self.ref_mgr.getReferencesTo(addr)):
                return
        elif self.fn_mgr.getFunctionContaining(addr) is not None:
            return


        if is_unneeded_data(data, sym, self.program):
            return

        is_user_sym = sym and sym.getSource() == SourceType.USER_DEFINED
        refs = self.ref_mgr.getReferencesTo(addr)
        is_used_in_function = False
        for ref in refs:
            from_addr = ref.getFromAddress()
            containing_func = self.fn_mgr.getFunctionContaining(from_addr)
            if containing_func is None:
                continue
            if self.curated_addrs is not None and containing_func.getEntryPoint().toString() not in self.curated_addrs:
                continue
            is_used_in_function = True
            break
    
        if not is_used_in_function and not is_user_sym:
            return
        
        raw_name = sym.getName() if sym else f"DAT_{addr.toString()}"
        # FIX [2]: prefix-match runtime symbol families. C_KEYWORDS here is
        # the full union: a *global* whose name collides with any known type
        # (C keyword or WinAPI type) is skipped rather than renamed, because
        # shadowing it breaks compilation.
        if (raw_name in TEB_PEB_IGNORE_LIST
                or raw_name in RUNTIME_SYMBOLS
                or raw_name.startswith(RUNTIME_SYMBOL_PREFIXES)
                or raw_name in C_KEYWORDS):
            return
        if raw_name.startswith(("__imp_", "_refptr_", "__xc_", "__xi_", "__xd_", "_CRT", "__mingw", "__native", "__lib64")):
            return
    
        name = sanitize_c_name(raw_name)
        if self.db.has_function(name):
            return   # name collides with a known function prototype
        if self.db.is_global_excluded(name):
            return
            
        if name in self.seen_names:
            # FIX [8]: sanitize the suffix too -- address strings are not
            # guaranteed C-safe in every address space.
            name = sanitize_c_name(f"{name}_{addr.toString()}")
            if name in self.seen_names:
                return
            
        self.seen_names.add(name)
        self.processed_addrs.add(addr)

        if data and data.isDefined():
            if is_string_data(data) and is_likely_real_text(data, self.program):
                raw_str = extract_c_string_value(data, self.program)
                val = escape_c_string(raw_str)
                self.db.add_or_update_global(name, gtype="const char", value_or_expr=val, is_string=True)
            else:
                dt = data.getDataType()
                extract_and_store_type(dt, self.db, self.seen_types)
                c_type, dim = parse_ghidra_type_and_dim(dt, self.db, self.seen_types)
                val_str = get_data_value_string(data, self.program)
                self.db.add_or_update_global(name, gtype=f"{c_type}{dim}", value_or_expr=val_str, is_string=False)
        else:
            inferred_size = self._infer_undefined_extent(addr)
            if inferred_size > 1:
                val_str = self._read_raw_bytes_value_string(addr, inferred_size)
                self.db.add_or_update_global(name, gtype=f"uint8_t[{inferred_size}]", value_or_expr=val_str, is_string=False)
            else:
                val_str = self._read_raw_bytes_value_string(addr, 1)
                self.db.add_or_update_global(name, gtype="uint8_t", value_or_expr=val_str, is_string=False)

    def extract_defined_and_bss_globals(self):
        """Pass 1 & 2: Extract defined arrays/globals and uninitialized BSS."""
        # Pass 1: Extract collated large arrays & defined globals
        data_iter = self.listing.getDefinedData(True)
        for data in data_iter:
            addr = data.getAddress()
            sym = self.symbol_table.getPrimarySymbol(addr)
            self._process_global(addr, data, sym)

        # Pass 2: Extract uninitialized (.bss) and standard global symbols
        sym_iter = self.symbol_table.getSymbolIterator(True)
        for sym in sym_iter:
            if self.fn_mgr.getFunctionAt(sym.getAddress()) is not None:
                continue
            addr = sym.getAddress()
            data = self.listing.getDataAt(addr)
            self._process_global(addr, data, sym)

    def extract_function_signatures(self):
        """Pass 3: Extract types appearing only in a function's own signature."""
        for func in self.fn_mgr.getFunctions(True):
            if self.curated_addrs is not None and func.getEntryPoint().toString() not in self.curated_addrs:
                continue
            if self.curated_addrs is None and is_noise_function_name(func.getName()):
                continue
                
            extract_and_store_type(func.getReturnType(), self.db, self.seen_types)
            for param in func.getParameters():
                extract_and_store_type(param.getDataType(), self.db, self.seen_types)

    def extract_local_variables(self):
        """Pass 4: Extract types appearing only as local variables."""
        decomp = DecompInterface()
        decomp.openProgram(self.program)
        monitor = ConsoleTaskMonitor()
        
        pass4_processed = 0
        pass4_types_before = len(self.seen_types)
        
        try:
            for func in self.fn_mgr.getFunctions(True):
                if self.curated_addrs is not None and func.getEntryPoint().toString() not in self.curated_addrs:
                    continue
                if self.curated_addrs is None and is_noise_function_name(func.getName()):
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
                    msg = result.getErrorMessage() if result else "?"
                    print(f"  [warn] Pass 4: decompile incomplete for {fname} @ {fentry}: {msg} -- attempting partial read anyway")
                    
                high_func = result.getHighFunction()
                if high_func is None:
                    print(f"  [warn] Pass 4: no HighFunction for {fname} @ {fentry} -- skipped.")
                    continue
                    
                pass4_processed += 1
                for hv in high_func.getLocalSymbolMap().getSymbols():
                    try:
                        extract_and_store_type(hv.getDataType(), self.db, self.seen_types)
                    except Exception:
                        continue
        finally:
            decomp.dispose()
            
        print(f"Pass 4: decompiled {pass4_processed} curated function(s) for local-variable types, "
              f"registered {len(self.seen_types) - pass4_types_before} new type(s).")

# --- Main Entry Point ---

def generate_global_files(path_to_binary, workspace_dir="."):
    db = SymbolDB(workspace_dir=workspace_dir)
    db.reset_globals()
    db.reset_custom_types()
    reset_fptr_cache()  # FIX [6]: deterministic typedef numbering per run

    curated_addrs = load_curated_function_entry_points(workspace_dir, path_to_binary)
    if curated_addrs is not None:
        print(f"Found {len(curated_addrs)} curated function(s) in extracted_functions/ -- "
              f"scoping global extraction to references from those functions only.")
    else:
        print("No curated extracted_functions/ folder found for this binary -- falling back to "
              "'referenced from any function in the binary'. Run function_extractor.py and prune "
              "it down to the functions you care about, then re-run this script for tighter results.")

    print(f"Initializing Ghidra and opening: {path_to_binary}")
    
    project_location = os.path.join(workspace_dir, "ghidra_project")
    project_name = f"{os.path.basename(path_to_binary)}_ghidra"
    program_path = f"/{os.path.basename(path_to_binary)}"

    if not os.path.isdir(project_location):
        raise RuntimeError(
            f"No shared Ghidra project found at {project_location}. Run Stage 1 "
            f"(function_extractor.py) on this binary first -- Stage 2 depends on "
            f"the already-analyzed program it produces."
        )

    print(f"Opening shared Ghidra project: {project_location}/{project_name}")
    with pyghidra.open_project(project_location, project_name, create=False) as project:
        existing_file = project.getProjectData().getFile(program_path)
        if existing_file is None:
            raise RuntimeError(f"{program_path} was not found in the shared project at {project_location}.")

        print(f"Opening already-analyzed program: {program_path}")
        with pyghidra.program_context(project, program_path) as program:
            # Retain collating large arrays in initialized memory
            auto_collate_large_arrays(program, min_size=1024)
            
            # Execute Extraction Passes via the modular class
            extractor = GlobalValueExtractor(program, db, curated_addrs)
            extractor.extract_defined_and_bss_globals()
            extractor.extract_function_signatures()
            extractor.extract_local_variables()

    db.export_header("data_globals.h")
    db.export_source("data_globals.c")