#!/usr/bin/env python3
"""Extract globals and custom types into the Stage 2 symbol database.

Objects are planned from symbols and references, pointer values are emitted as
symbolic references when evidence supports them, and recovered layouts are
verified with compile-time size/offset assertions. Extraction reads the shared
Ghidra project without mutating its listing.
"""

import bisect
import os
import re
import shutil
import struct
import warnings
from collections import deque

import jpype
import pyghidra
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.address import AddressSet
from ghidra.program.model.data import (
    AbstractStringDataType, Array, BitFieldDataType, Enum, FunctionDefinition,
    Pointer, Structure, TypeDef, Union
)
from ghidra.program.model.symbol import SourceType
from ghidra.util.task import ConsoleTaskMonitor

try:
    from database.symbol_db import SymbolDB
except ImportError:                       # flat layout
    from symbol_db import SymbolDB

warnings.filterwarnings("ignore", category=DeprecationWarning)

# --- Tunables ---------------------------------------------------------------

MIN_BLOB_SIZE = 1024            # unreferenced adjacent fragments >= this are one object
EMIT_LAYOUT_ASSERTS = True      # _Static_assert(sizeof/offsetof) for every emitted struct/union
SYMBOLIZE_EXTERNALS = True      # `(T)Sleep` for pointers to imported API thunks
ADDR_SCORE_THRESHOLD = 3        # see _addr_score

# --- Constants & Configuration ----------------------------------------------

SECTION_MARKER_SYMBOLS = frozenset({
    "_data", "_rdata", "_bss", "_edata", "_end",
    "__data_start__", "__data_end__", "__bss_start__", "__bss_end__",
})

TRUE_C_KEYWORDS = {
    'auto', 'break', 'case', 'char', 'const', 'continue', 'default', 'do',
    'double', 'else', 'enum', 'extern', 'float', 'for', 'goto', 'if', 'int',
    'long', 'register', 'return', 'short', 'signed', 'sizeof', 'static',
    'struct', 'switch', 'typedef', 'union', 'unsigned', 'void', 'volatile',
    'while',
    # C99/C11/GNU keywords that were missing
    'inline', 'restrict', 'asm', 'typeof', '_Bool', '_Complex', '_Imaginary',
    '_Static_assert', '_Generic', '_Noreturn', '_Atomic', '_Alignas',
    '_Alignof', '_Thread_local',
}

# Fast path only. The compiler oracle (type_probe.py) is the actual source of
# truth for "does the SDK already define this"; this list merely avoids
# emitting typedefs we already know <windows.h> provides.
WINAPI_TYPES = frozenset({
    "BOOL", "BYTE", "CHAR", "DWORD", "HANDLE", "HGLOBAL", "HKEY",
    "HMODULE", "HWND", "LPCSTR", "LPDWORD", "LPOVERLAPPED", "LPSECURITY_ATTRIBUTES",
    "LPSTR", "LPVOID", "LSTATUS", "PLONG", "ULONG", "FARPROC", "WORD", "LONG",
    "UINT", "WPARAM", "LPARAM", "FILE", "HINSTANCE", "ATOM",
    # FIX: previously missing -> re-typedef'd and (only) rescued by the oracle
    "HRESULT", "PVOID", "PBYTE", "PDWORD", "LPBYTE", "LPWORD", "WCHAR",
    "LPWSTR", "LPCWSTR", "LPCVOID", "SIZE_T", "ULONG_PTR", "DWORD_PTR",
    "LONG_PTR", "UINT_PTR", "INT_PTR", "DWORD64", "ULONGLONG", "LONGLONG",
    "USHORT", "UCHAR", "SHORT", "INT", "BOOLEAN", "HDC", "HBRUSH", "HICON",
    "HMENU", "HCURSOR", "HFONT", "HBITMAP", "HRSRC", "HLOCAL",
})

C_KEYWORDS = TRUE_C_KEYWORDS | WINAPI_TYPES

# Names that are always provided by the toolchain: never emit a typedef.
PASSTHRU_TYPEDEFS = frozenset({
    'size_t', 'ssize_t', 'ptrdiff_t', 'wchar_t', 'intptr_t', 'uintptr_t',
    'uint8_t', 'uint16_t', 'uint32_t', 'uint64_t',
    'int8_t', 'int16_t', 'int32_t', 'int64_t',
})

BUILTIN_TYPE_NAMES = frozenset({
    'void', 'bool', 'char', 'sbyte', 'byte', 'short', 'ushort', 'int', 'uint',
    'long', 'ulong', 'longlong', 'ulonglong', 'long long',
    'float', 'double', 'string', 'terminatedcstring',
    'undefined', 'undefined1', 'undefined2', 'undefined4', 'undefined8',
    'word', 'dword', 'qword', 'code',
    'uchar', 'schar', 'longdouble',
}) | PASSTHRU_TYPEDEFS

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

# Generic CRT names. FIX: these are only dropped when the symbol is NOT
# USER_DEFINED -- a symbol the analyst renamed is by definition wanted
# (`argc`, `handler`, `initialized` are plausible user globals).
RUNTIME_SYMBOLS = {
    "mingw_pcinit", "mingw_pcppinit", "mingw_initcharmax",
    "mingw_initltsdrot_force", "mingw_initltsdyn_force", "mingw_initltssuo_force",
    "mingw_app_type", "mainret", "managedapp", "fpreset", "fthunk",
    "hname", "key_dtor_list", "the_secs",
    "argc", "argv", "envp", "startinfo", "stUserMathErr", "handler",
    "has_cctor", "initialized", "register_frame_ctor", "switchD",
    "CLSID", "IID",
    "_fmode", "_commode", "_dowildcard", "_newmode", "_environ", "__initenv"
}
# Address/number-templated families. FIX: `p_92992` / `was_init_94382` were
# hard-coded exact names (overfit to one binary); match the family instead.
RUNTIME_SYMBOL_PREFIXES = ("caseD_", "switchdataD_")
RUNTIME_SYMBOL_RE = re.compile(r'^(p|was_init|fpi|pmem)_\d+$')
CRT_NAME_PREFIXES = ("__imp_", "_refptr_", "__xc_", "__xi_", "__xd_", "_CRT",
                     "__mingw", "__native", "__lib64")
# Compiler/CRT data labels, dropped for any non-user symbol.
CRT_DATA_PREFIXES = ("__", "_MINGW", "_imp_", "IMAGE_", "_rdata", "_CSWTCH_",
                     "_func_", "fpi_", "pmem_")
# Ghidra's auto-generated string labels. The decompiler inlines string literals,
# so these are not needed as globals -- UNLESS another data object points at
# them (then they are pulled in by the pointer closure, see `_plan`).
AUTO_STRING_PREFIXES = ("s_", "u_")

IGNORED_BLOCK_MARKERS = ('.debug', '.pdata', '.xdata', '.eh_frame', '.reloc',
                         '.rsrc', 'headers', '.idata', '.didata',
                         '.crt', '.ctors', '.dtors', '.tls')

_SIGNED_NAMES = {'char', 'schar', 'sbyte', 'short', 'int', 'long', 'longlong'}
_UNSIGNED_NAMES = {'uchar', 'byte', 'bool', 'ushort', 'word', 'uint', 'dword',
                   'ulong', 'qword', 'ulonglong', 'wchar16', 'wchar32',
                   'wchar_t', 'sword'}

# --- Core helper functions ----------------------------------------------------

def sanitize_c_name(name):
    if not name: return "unknown_type"
    name = name.replace("struct ", "").replace("enum ", "").replace("union ", "")
    name = re.sub(r'[^a-zA-Z0-9_]', '_', name)
    if name in TRUE_C_KEYWORDS or (name and name[0].isdigit()):
        name = '_' + name
    return name

def is_noise_function_name(name):
    if not name: return False
    return name.startswith(FUNC_NOISE_PREFIXES)

def is_noise_type_name(raw_name):
    if not raw_name: return False
    bare = raw_name.lstrip('_')
    return bare in NOISE_TYPE_EXACT_NAMES or bare.startswith(NOISE_TYPE_PREFIXES)

def escape_c_bytes(buf):
    """Exact byte-wise C string-literal body.
    FIX: the old escape_c_string() worked on a decoded `str` and did
    `code & 0xff`, so wide/UTF-8 text silently changed bytes. Octal escapes are
    always 3 digits, so a following digit can never extend them; '?' is escaped
    to stay safe under trigraph-enabled modes."""
    out = []
    for b in buf:
        c = chr(b)
        if c == '\\': out.append('\\\\')
        elif c == '"': out.append('\\"')
        elif c == '?': out.append('\\?')
        elif c == '\n': out.append('\\n')
        elif c == '\r': out.append('\\r')
        elif c == '\t': out.append('\\t')
        elif 32 <= b <= 126: out.append(c)
        else: out.append(f'\\{b:03o}')
    return "".join(out)

def fmt_int(val, size, signed):
    bits = size * 8
    val &= (1 << bits) - 1
    if signed:
        if val >> (bits - 1):
            val -= (1 << bits)
        if size == 8 and val == -(1 << 63):
            return "(-9223372036854775807LL-1)"
        return str(val)
    return f"0x{val:x}"

def fmt_float(raw, size, big_endian):
    """Bit-exact C literal (C99 hex-float) for a 4/8-byte IEEE value.
    NaN payloads cannot be expressed as a portable constant and are lost."""
    fmt = ('>' if big_endian else '<') + ('f' if size == 4 else 'd')
    v = struct.unpack(fmt, raw)[0]
    if v != v:
        return '__builtin_nanf("")' if size == 4 else '__builtin_nan("")'
    if v in (float('inf'), float('-inf')):
        base = '__builtin_inff()' if size == 4 else '__builtin_inf()'
        return base if v > 0 else '-' + base
    if v == 0:
        return "-0.0" if str(v).startswith('-') else "0"
    return float.hex(v) + ('f' if size == 4 else '')

def hex_list(buf):
    """`{0x01, 0x02}` with trailing zero bytes dropped (static storage is
    zero-filled), or `{0}` if everything is zero."""
    end = len(buf)
    while end > 0 and buf[end - 1] == 0:
        end -= 1
    if end == 0:
        return "{0}"
    return "{" + ", ".join(f"0x{b:02x}" for b in buf[:end]) + "}"

def read_memory_bytes(addr, size, program):
    if size <= 0:
        return b""
    try:
        jbuf = jpype.JArray(jpype.JByte)(size)
        program.getMemory().getBytes(addr, jbuf)
        try:
            return memoryview(jbuf).tobytes()
        except Exception:
            return bytes(b & 0xFF for b in jbuf)
    except Exception as e:
        print(f"  [warn] failed to read {size} byte(s) at {addr}: {e}")
        return None

def is_noise_data(data, symbol, program):
    """Block/type based noise (independent of how the object was reached)."""
    if symbol and symbol.getName() in SECTION_MARKER_SYMBOLS:
        return True
    if data:
        addr = data.getMinAddress()
        block = program.getMemory().getBlock(addr)
        if block and block.getName() == "Headers":
            return True
        dt = data.getDataType()
        if is_noise_type_name(dt.getName()):
            return True
        try:
            base = dt.getBaseDataType() if isinstance(dt, TypeDef) else (
                dt.getDataType() if isinstance(dt, (Array, Pointer)) else None)
            if base is not None and is_noise_type_name(base.getName()):
                return True
        except Exception:
            pass
    return False

def is_unneeded_data(data, symbol, program, allow_auto_strings=False):
    """FIX: the old version ended with a bare `return` (None == falsy) inside
    the prefix check, so the whole prefix filter was dead code. It now returns
    True.  The old prefixes were also applied to IMPORTED (COFF) symbols and
    included a bare `p_`, which would drop real globals like `p_state`; that is
    narrowed (regex family, non-user symbols only).  `s_`/`u_` are Ghidra's own
    auto labels and are only dropped for DEFAULT/ANALYSIS symbols."""
    if is_noise_data(data, symbol, program):
        return True
    if symbol is None:
        return False
    src = symbol.getSource()
    if src == SourceType.USER_DEFINED:
        return False
    name = symbol.getName()
    if name.startswith(CRT_DATA_PREFIXES) or RUNTIME_SYMBOL_RE.match(name):
        return True
    if (not allow_auto_strings and src in (SourceType.DEFAULT, SourceType.ANALYSIS)
            and name.startswith(AUTO_STRING_PREFIXES)):
        return True
    return False

def load_curated_function_entry_points(workspace_dir, path_to_binary):
    """-> {entry_offset(int): function_name} or None.
    FIX: entry points were compared as strings (`toString()` vs file suffix),
    so a case/zero-padding mismatch silently excluded everything.  Compared as
    integers now.  The regex also required >=6 hex digits: `foo_bad`, `x_cafe`
    are NOT addresses."""
    base_name = os.path.basename(path_to_binary)
    func_dir = os.path.join(workspace_dir, "extracted_functions", base_name)
    if not os.path.isdir(func_dir):
        return None
    out = {}
    for fname in os.listdir(func_dir):
        stem, ext = os.path.splitext(fname)
        if ext.lower() not in (".c", ".cpp"):
            continue
        m = re.match(r'^(.*)_([0-9A-Fa-f]{6,16})$', stem)
        if m:
            out[int(m.group(2), 16)] = m.group(1)
    return out or None


# --- Type registry -------------------------------------------------------------

class TypeRegistry:
    """Ghidra DataType -> C declarations in the SymbolDB (custom_types)."""

    def __init__(self, db, ptr_size, big_endian=False):
        self.db = db
        self.ptr_size = ptr_size
        self.big_endian = big_endian
        self.seen = set()
        self.enum_consts = set()
        self._origin = {}
        self._fn_resolved = {}      # fnptr_<name> -> typedef actually emitted
        self._fn_by_sig = {}        # signature   -> first typedef with it
        self._fields_cache = {}

    # -- basics ----------------------------------------------------------------
    @staticmethod
    def strip(dt):
        """Resolve typedef chains."""
        while isinstance(dt, TypeDef):
            nxt = dt.getBaseDataType()
            if nxt is None or nxt is dt:
                break
            dt = nxt
        return dt

    @staticmethod
    def is_char(dt):
        dt = TypeRegistry.strip(dt)
        return (not isinstance(dt, (Array, Pointer, Structure, Union, Enum))
                and dt.getName().lower() in ('char', 'uchar', 'schar'))

    def scalar_info(self, dt):
        """-> (ctype, kind, size, signed); kind in int|float|bytes|void.
        One classifier is used for BOTH the declared type and the initializer,
        so the two can never disagree."""
        name = dt.getName().lower()
        try: length = dt.getLength()
        except Exception: length = -1
        if name == 'void' or length == 0:
            return "void", "void", 0, False
        if name in ('float', 'double', 'longdouble', 'long double') and length in (4, 8):
            return ('float' if length == 4 else 'double'), "float", length, True
        if name.startswith('float') or 'double' in name:
            # x87 80/96/128-bit: no portable literal -> exact bytes
            return "uint8_t", "bytes", max(length, 1), False
        if name == 'char':
            return "char", "int", 1, True
        if name in ('uchar', 'byte', 'bool', 'undefined', 'undefined1'):
            return "uint8_t", "int", 1, False
        if name in ('schar', 'sbyte'):
            return "int8_t", "int", 1, True
        if length not in (1, 2, 4, 8):
            return "uint8_t", "bytes", max(length, 1), False
        signed = name in _SIGNED_NAMES or (name.startswith('int') and name[3:].isdigit())
        if name in _UNSIGNED_NAMES or name.startswith(('uint', 'undefined')):
            signed = False
        return f"{'int' if signed else 'uint'}{length * 8}_t", "int", length, signed

    def enum_ctype(self, dt):
        """FIX: a C `enum` is int-sized; a 1/2/8-byte Ghidra enum inside a
        struct would silently change the layout. Only 4-byte enums keep their
        name; the rest become exact-width integers."""
        n = dt.getLength()
        if n == 4:
            return sanitize_c_name(dt.getName())
        return f"uint{n * 8}_t" if n in (1, 2, 8) else "uint8_t"

    # -- C type naming -----------------------------------------------------------
    def parse(self, dt):
        """-> (ctype, dim_suffix)."""
        if dt is None:
            return "uint8_t", ""
        dims = ""
        while isinstance(dt, Array):
            dims += f"[{dt.getNumElements()}]"
            dt = dt.getDataType()
        stars = ""
        while isinstance(dt, Pointer):
            stars += "*"
            under = dt.getDataType()
            if under is None or under.getName().lower() == "default":
                return "void" + stars, dims
            ubase = self.strip(under)
            if isinstance(ubase, FunctionDefinition):
                return self._fnptr(ubase) + stars[:-1], dims
            # FIX: pointer-to-array used to produce a nonexistent type name
            while isinstance(ubase, Array):
                under = ubase.getDataType()
                ubase = self.strip(under)
            if is_noise_type_name(under.getName()) or is_noise_type_name(ubase.getName()):
                return "void" + stars, dims
            dt = under
        if dt is None:
            return "void" + stars, dims

        if isinstance(dt, TypeDef):
            n = sanitize_c_name(dt.getName())
            if n in PASSTHRU_TYPEDEFS or n in WINAPI_TYPES:
                return n + stars, dims
            base = self.strip(dt)
            if is_noise_type_name(dt.getName()) or is_noise_type_name(base.getName()):
                return self._noise(dt, stars, dims)
            return n + stars, dims
        if isinstance(dt, (Structure, Union)):
            if is_noise_type_name(dt.getName()):
                return self._noise(dt, stars, dims)
            return sanitize_c_name(dt.getName()) + stars, dims
        if isinstance(dt, Enum):
            if is_noise_type_name(dt.getName()):
                return self._noise(dt, stars, dims)
            return self.enum_ctype(dt) + stars, dims
        if isinstance(dt, FunctionDefinition):
            return self._fnptr(dt) + stars, dims
        ctype, kind, size, _ = self.scalar_info(dt)
        if kind == "bytes":
            return ctype + stars, dims + f"[{size}]"
        return ctype + stars, dims

    @staticmethod
    def _noise(dt, stars, dims):
        if stars:
            return "void" + stars, dims
        try: size = max(dt.getLength(), 1)
        except Exception: size = 1
        return "uint8_t", dims + f"[{size}]"

    # -- registration ------------------------------------------------------------
    def register(self, dt):
        if dt is None: return
        while isinstance(dt, (Pointer, Array)):
            dt = dt.getDataType()
            if dt is None: return
        if isinstance(dt, FunctionDefinition):
            self._fnptr(dt)
            return
        if is_noise_type_name(dt.getName()):
            return
        if isinstance(dt, TypeDef):
            self._reg_typedef(dt)
        elif isinstance(dt, (Structure, Union)):
            self._reg_composite(dt)
        elif isinstance(dt, Enum):
            self._reg_enum(dt)

    def _claim(self, dt, name):
        if name in self.seen or name in BUILTIN_TYPE_NAMES or name in WINAPI_TYPES:
            return False
        self.seen.add(name)
        try:
            self._origin[name] = dt.getPathName()
        except Exception:
            pass
        return True

    def _fwd(self, kind, name):
        # FIX: recursive / mutually recursive types. The forward typedef is its
        # own custom_type, created BEFORE the members are walked, so a pointer
        # back to a type that is still being defined always has a declaration.
        # (Identical typedef redefinition is legal in C11 / GNU C, which is
        # what the SDK-deferral alias in symbol_db already relies on.)
        self.db.add_custom_type(f"{name}__fwd", f"typedef {kind} {name} {name};\n")

    def _reg_composite(self, dt):
        kind = "union" if isinstance(dt, Union) else "struct"
        name = sanitize_c_name(dt.getName())
        if not self._claim(dt, name):
            return
        self._fwd(kind, name)
        fields = self.struct_fields(dt)
        for f in fields:
            if f["kind"] == "field":
                self.register(f["dt"])
            elif f["kind"] == "bits":
                self.register(f["base"])
        pack = 0 if kind == "union" else self._pack_value(dt)
        total = dt.getLength()
        lines = []
        if pack:
            lines.append(f"#pragma pack(push, {pack})")
        lines.append(f"typedef {kind} {name} {{")
        for f in fields:
            if f["kind"] == "pad":
                lines.append(f"    uint8_t {f['name']}[{f['len']}];")
            elif f["kind"] == "bits":
                lines.append(f"    {f['ctype']} {f['name']} : {f['bits']};")
            else:
                c_type, dim = self.parse(f["dt"])
                lines.append(f"    {c_type} {f['name']}{dim};")
        if kind == "union" and total > 0:
            # raw view: lets the initializer preserve ALL bytes whichever
            # member was active (C can only initialise one member otherwise)
            lines.append(f"    uint8_t _raw_bytes_[{total}];")
        elif not fields:
            lines.append("    uint8_t _empty_;")
        lines.append(f"}} {name};")
        if pack:
            lines.append("#pragma pack(pop)")
        if EMIT_LAYOUT_ASSERTS and total > 0:
            # [DIRTY] layout is part of the type: verify instead of trusting.
            # GH_STATIC_ASSERT (header shim) = static_assert under g++, _Static_assert under
            # gcc: the .cpp files are compiled with g++, which rejects the C11 keyword.
            lines.append(f'GH_STATIC_ASSERT(sizeof({name}) == {total}, '
                         f'"layout mismatch: sizeof({name})");')
            for f in fields:
                if f["kind"] in ("field", "pad") and kind == "struct":
                    lines.append(f'GH_STATIC_ASSERT(offsetof({name}, {f["name"]}) == '
                                 f'{f["off"]}, "layout mismatch: {name}.{f["name"]}");')
        self.db.add_custom_type(name, "\n".join(lines) + "\n")

    @staticmethod
    def _pack_value(dt):
        """0 = natural alignment (Ghidra packing enabled, default value),
        N = explicit #pragma pack(N), 1 = Ghidra 'not packed': components sit
        at explicit offsets with explicit undefined padding, so the only
        faithful C rendering is byte-exact packing."""
        try:
            if dt.hasExplicitPackingValue():
                return int(dt.getExplicitPackingValue())
            if dt.isPackingEnabled():
                return 0
        except Exception:
            pass
        return 1

    def struct_fields(self, dt):
        """Single source of truth for member layout; used by the declaration
        AND by the initializer so they cannot drift apart."""
        key = None
        try: key = dt.getPathName() + f"#{dt.getLength()}"
        except Exception: pass
        if key in self._fields_cache:
            return self._fields_cache[key]
        is_union = isinstance(dt, Union)
        out, used = [], set()
        pad_start, pad_len = None, 0

        def unique(base, off):
            n = sanitize_c_name(base)
            if n in used:
                n = f"{n}_0x{off:x}"
            used.add(n)
            return n

        def flush():
            nonlocal pad_start, pad_len
            if pad_len > 0:
                out.append({"kind": "pad", "name": unique(f"_pad_0x{pad_start:x}", pad_start),
                            "off": pad_start, "len": pad_len, "dt": None})
            pad_start, pad_len = None, 0

        covered = 0
        # Byte-exact (pack 1) rendering has no compiler-inserted padding, so a
        # hole between components must become an explicit member or every later
        # member shifts. With natural alignment the compiler pads by itself and
        # adding our own would double it.
        byte_exact = (not is_union) and self._pack_value(dt) == 1
        for i in range(dt.getNumComponents()):
            comp = dt.getComponent(i)
            if comp is None:
                continue
            off = 0 if is_union else comp.getOffset()
            length = comp.getLength()
            if byte_exact and off > covered:
                flush()
                out.append({"kind": "pad", "name": unique(f"_pad_0x{covered:x}", covered),
                            "off": covered, "len": off - covered, "dt": None})
                covered = off
            cdt = comp.getDataType()
            try:
                undef = comp.isUndefined()
            except Exception:
                undef = (comp.getFieldName() is None
                         and cdt.getName().lower().startswith('undefined'))
            if undef and not is_union and length > 0:
                if pad_start is not None and off == pad_start + pad_len:
                    pad_len += length
                else:
                    flush()
                    pad_start, pad_len = off, length
                covered = max(covered, off + length)
                continue
            flush()
            name = unique(comp.getFieldName() or f"field_0x{off:x}", off)
            if isinstance(cdt, BitFieldDataType):
                base = cdt.getBaseDataType()
                bc, bk, _, _ = self.scalar_info(self.strip(base)) if not isinstance(
                    self.strip(base), Enum) else (self.enum_ctype(self.strip(base)), "int", 0, False)
                out.append({"kind": "bits", "name": name, "off": off, "len": length,
                            "base": base, "ctype": bc, "bits": cdt.getBitSize(),
                            "bit_off": cdt.getBitOffset(), "dt": cdt})
            else:
                out.append({"kind": "field", "name": name, "off": off, "len": length, "dt": cdt})
            covered = max(covered, off + length)
        flush()
        total = dt.getLength()
        if not is_union and total > covered:
            out.append({"kind": "pad", "name": unique(f"_pad_0x{covered:x}", covered),
                        "off": covered, "len": total - covered, "dt": None})
        if key is not None:
            self._fields_cache[key] = out
        return out

    def _reg_enum(self, dt):
        name = sanitize_c_name(dt.getName())
        if not self._claim(dt, name):
            return
        lines = [f"typedef enum {name} {{"]
        n_emitted = 0
        for enum_name in dt.getNames():
            safe = sanitize_c_name(enum_name)
            key = f"enumconst:{safe}"
            if key in self.enum_consts:     # enumerators share one namespace in C
                continue
            self.enum_consts.add(key)
            lines.append(f"    E_{safe} = {dt.getValue(enum_name)},")
            n_emitted += 1
        if n_emitted == 0:                  # FIX: `enum X { };` is not valid C
            lines.append(f"    E_{name}__placeholder = 0,")
        lines.append(f"}} {name};\n")
        self.db.add_custom_type(name, "\n".join(lines))

    def _reg_typedef(self, dt):
        name = sanitize_c_name(dt.getName())
        if name in PASSTHRU_TYPEDEFS:
            return
        base = self.strip(dt)
        if is_noise_type_name(base.getName()):
            return
        if not self._claim(dt, name):
            return
        if isinstance(base, (Structure, Union)):
            kind = "union" if isinstance(base, Union) else "struct"
            bname = sanitize_c_name(base.getName())
            if bname == name:               # `typedef struct Foo {..} Foo` pair
                self.seen.discard(name)
                self.register(base)
                return
            # forward-declare the alias too: `Node_t *next` inside Node itself
            self._fwd(kind, bname)
            self.db.add_custom_type(name, f"typedef {kind} {bname} {name};\n")
            self.register(base)
            return
        if isinstance(base, FunctionDefinition):
            fp = self._fnptr(base)
            self.db.add_custom_type(name, f"typedef {fp} {name};\n")
            return
        self.register(base)
        base_type, dim = self.parse(base)
        # `dim` attaches to the typedef NAME: `typedef uint8_t buf_t[64];`
        # is valid C (an array typedef), not a bug.
        self.db.add_custom_type(name, f"typedef {base_type} {name}{dim};\n")

    # -- function pointers --------------------------------------------------------
    def _cc_attr(self, fd):
        if self.ptr_size != 4:
            return ""                       # one ABI on x64: attribute is ignored
        try:
            cc = str(fd.getGenericCallingConvention()).lower()
        except Exception:
            return ""
        for k in ("stdcall", "fastcall", "thiscall"):
            if k in cc:
                return f"__{k} "
        return ""

    def _fnptr(self, fd):
        base = "fnptr_" + sanitize_c_name(fd.getName())
        if base in self._fn_resolved:
            return self._fn_resolved[base]
        self._fn_resolved[base] = base      # recursion guard (before recursing)
        # FIX: parameter / return struct types were only NAMED here, never
        # registered, so a struct that appears only in a callback signature was
        # used but never defined.
        self.register(fd.getReturnType())
        ret_type, ret_dim = self.parse(fd.getReturnType())
        if ret_dim:
            ret_type = "void*"
        params = []
        for arg in fd.getArguments():
            self.register(arg.getDataType())
            p_type, p_dim = self.parse(arg.getDataType())
            params.append(f"{p_type}{p_dim}")
        if fd.hasVarArgs():
            params.append("...")
        param_list = ", ".join(params) if params else "void"
        cc = self._cc_attr(fd)
        # FIX: calling convention is part of the signature. A stdcall callee
        # called through a cdecl pointer corrupts the stack on x86.
        sig = f"{cc}{ret_type}({param_list})"
        existing = self._fn_by_sig.get(sig)
        if existing is not None:
            # FIX: always define `base` too (previously returned the cached
            # name but left `base` itself undefined for later lookups).
            self.db.add_custom_type(base, f"typedef {existing} {base};\n")
            return base
        self._fn_by_sig[sig] = base
        self.db.add_custom_type(
            base, f"typedef {ret_type} ({cc}*{base})({param_list});\n")
        return base


# --- Data object model ---------------------------------------------------------

class Obj:
    """One recovered global: [start, end) in the default address space."""
    __slots__ = ("addr", "start", "end", "name", "raw_name", "data", "block",
                 "writable", "blob")

    def __init__(self, addr, end, name, raw_name, data, block, blob):
        self.addr = addr
        self.start = addr.getOffset()
        self.end = end
        self.name = name
        self.raw_name = raw_name
        self.data = data
        self.block = block
        self.writable = bool(block.isWrite())
        self.blob = blob


# --- Extractor -----------------------------------------------------------------

class GlobalValueExtractor:
    def __init__(self, program, db, curated):
        self.program = program
        self.db = db
        self.curated = curated              # {entry_offset: name} | None

        self.mem = program.getMemory()
        self.listing = program.getListing()
        self.symbol_table = program.getSymbolTable()
        self.ref_mgr = program.getReferenceManager()
        self.fn_mgr = program.getFunctionManager()
        self.space = program.getAddressFactory().getDefaultAddressSpace()
        self.ptr_size = program.getDefaultPointerSize()
        self.big_endian = bool(program.getLanguage().isBigEndian())
        self.endian = 'big' if self.big_endian else 'little'
        self.reg = TypeRegistry(db, self.ptr_size, self.big_endian)
        self.seen_types = self.reg.seen     # kept for callers that peek at it

        self.seen_names = set()
        self.renames = []                   # (ghidra_name, c_name, address)
        self.missing_funcs = {}             # entry offset -> name (pointed at, never extracted)
        self.objs = {}                      # start offset -> Obj
        self.obj_starts = []                # sorted
        self.rejected = set()               # (offset, allow_auto_strings)
        self.queue = deque()

        self.bounds = []                    # sorted referenced/named offsets
        self.bound_set = set()
        self.reloc_offs = set()             # cells carrying a base relocation
        self.gref = {}                      # cell offset -> ("mem", to)|("ext", label)
        self.img_lo = 0
        self.img_hi = 0
        self._fix = []                      # fixups of the object being emitted
        self.stats = {"objects": 0, "ptr_symbolic": 0, "ptr_literal": 0,
                      "fixups": 0, "failed": 0}
        self._warned = 0

    # ---- small utilities ---------------------------------------------------------
    def _addr(self, off):
        try:
            return self.space.getAddress(off)
        except Exception:
            return None

    def _same_space(self, block):
        return block.getStart().getAddressSpace().getSpaceID() == self.space.getSpaceID()

    def _warn(self, msg):
        self._warned += 1
        if self._warned <= 40:
            print(f"  [warn] {msg}")
        elif self._warned == 41:
            print("  [warn] (further warnings suppressed)")

    def _read(self, off, size):
        """Raw bytes, or None for BSS / unreadable (treated as zero)."""
        if size <= 0:
            return b""
        a = self._addr(off)
        if a is None:
            return None
        blk = self.mem.getBlock(a)
        if blk is None or not blk.isInitialized():
            return None
        return read_memory_bytes(a, size, self.program)

    # ---- [SECONDWRITE] object segmentation ------------------------------------------
    def _build_boundaries(self):
        """Offsets that start an object: every named symbol and every address
        that something references.  FIX: this is computed once, non-mutating.
        The old auto_collate_large_arrays() rewrote the Ghidra listing in place
        (clearCodeUnits + createData) and walked memory one address at a time."""
        all_set = AddressSet()
        lo, hi = None, 0
        for blk in self.mem.getBlocks():
            if not self._same_space(blk):
                continue
            all_set.add(blk.getStart(), blk.getEnd())
            s, e = blk.getStart().getOffset(), blk.getEnd().getOffset() + 1
            lo = s if lo is None else min(lo, s)
            hi = max(hi, e)
        self.img_lo, self.img_hi = (lo or 0), hi
        bounds = set()
        for sym in self.symbol_table.getSymbolIterator(True):
            if sym.getSource() == SourceType.DEFAULT or sym.isExternal():
                continue
            a = sym.getAddress()
            if all_set.contains(a):
                bounds.add(a.getOffset())
        for a in self.ref_mgr.getReferenceDestinationIterator(all_set, True):
            bounds.add(a.getOffset())
        self.bounds = sorted(bounds)
        self.bound_set = bounds

    # ---- [RELOC] hard evidence --------------------------------------------------------
    def _build_evidence(self):
        try:
            for r in self.program.getRelocationTable().getRelocations():
                self.reloc_offs.add(r.getAddress().getOffset())
        except Exception as e:
            print(f"  [warn] relocation table unavailable ({e}); relying on references/heuristics")
        data_set = AddressSet()
        for blk in self.mem.getBlocks():
            if self._same_space(blk) and not blk.isExecute():
                data_set.add(blk.getStart(), blk.getEnd())
        for a in self.ref_mgr.getReferenceSourceIterator(data_set, True):
            for ref in self.ref_mgr.getReferencesFrom(a):
                if ref.isExternalReference():
                    try:
                        self.gref[a.getOffset()] = ("ext", ref.getExternalLocation().getLabel())
                    except Exception:
                        pass
                    break
                if ref.isMemoryReference() and not ref.getReferenceType().isFlow():
                    self.gref[a.getOffset()] = ("mem", ref.getToAddress().getOffset())
                    break
        print(f"Evidence: {len(self.reloc_offs)} relocated cell(s), "
              f"{len(self.gref)} data cell(s) with analyzer references.")

    def _owner_start(self, addr):
        """Start of the object that contains `addr` (planned object, then a
        defined Data unit, else the address itself)."""
        off = addr.getOffset()
        i = bisect.bisect_right(self.obj_starts, off) - 1
        if i >= 0:
            o = self.objs[self.obj_starts[i]]
            if o.start <= off < o.end:
                return o.addr
        d = self.listing.getDefinedDataContaining(addr)
        if d is not None:
            return d.getMinAddress()
        return addr

    def _compute_extent(self, start, data, block):
        """-> (size, is_blob).  An object runs to the next referenced/named
        address, but references INTO a defined composite do not split it (the
        analyzer's type is explicit evidence; a bare reference is not)."""
        s = start.getOffset()
        blk_end = block.getEnd().getOffset() + 1
        defined = data is not None and data.isDefined()
        head_len = max(data.getLength(), 1) if defined else 1
        i = bisect.bisect_left(self.bounds, s + head_len)
        nxt = min(self.bounds[i] if i < len(self.bounds) else blk_end, blk_end)
        j = bisect.bisect_right(self.obj_starts, s)
        if j < len(self.obj_starts):
            nxt = min(nxt, self.obj_starts[j])
        span = max(nxt - s, 1)
        if defined and head_len >= span:
            return head_len, False
        composite = defined and isinstance(
            self.reg.strip(data.getDataType()),
            (Structure, Union, Array, AbstractStringDataType))
        if not composite and span >= MIN_BLOB_SIZE:
            return span, True               # fragmented table/payload -> one byte object
        if defined:
            return head_len, False
        d = self.listing.getDefinedDataAfter(start)
        if d is not None:
            dn = d.getMinAddress().getOffset()
            if s < dn < nxt:
                nxt = dn
        return max(nxt - s, 1), False

    # ---- candidate filtering & planning ---------------------------------------------------
    def _is_data_candidate(self, addr, block):
        if block is None or not self._same_space(block):
            return False
        name = block.getName().lower()
        if any(m in name for m in IGNORED_BLOCK_MARKERS):
            return False
        if block.isExecute():
            if self.fn_mgr.getFunctionAt(addr) is not None:
                return False
            if not any(not (r.getReferenceType().isCall() or r.getReferenceType().isJump())
                       for r in self.ref_mgr.getReferencesTo(addr)):
                return False
        elif self.fn_mgr.getFunctionContaining(addr) is not None:
            return False
        return True

    def _plan(self, addr, allow_auto_strings=False):
        start = self._owner_start(addr)
        off = start.getOffset()
        obj = self.objs.get(off)
        if obj is not None:
            return obj
        key = (off, allow_auto_strings)
        if key in self.rejected:
            return None
        obj = self._plan_new(start, allow_auto_strings)
        if obj is None:
            self.rejected.add(key)
            return None
        self.objs[off] = obj
        bisect.insort(self.obj_starts, off)
        self.queue.append(obj)
        return obj

    def _plan_new(self, start, allow_auto_strings):
        block = self.mem.getBlock(start)
        if not self._is_data_candidate(start, block):
            return None
        data = self.listing.getDataAt(start)
        sym = self.symbol_table.getPrimarySymbol(start)
        if is_unneeded_data(data, sym, self.program, allow_auto_strings):
            return None
        user = sym is not None and sym.getSource() == SourceType.USER_DEFINED
        raw = sym.getName() if sym is not None else f"DAT_{start.toString()}"
        if raw in TEB_PEB_IGNORE_LIST or raw in C_KEYWORDS:
            return None
        if not user and (raw in RUNTIME_SYMBOLS
                         or raw.startswith(RUNTIME_SYMBOL_PREFIXES)
                         or raw.startswith(CRT_NAME_PREFIXES)):
            return None
        name = sanitize_c_name(raw)
        if self.db.has_function(name) or self.db.is_global_excluded(name):
            return None
        if name in self.seen_names:
            name = sanitize_c_name(f"{name}_{start.toString()}")
            if name in self.seen_names:
                return None
        self.seen_names.add(name)
        if name != raw:
            # The decompiled function bodies use Ghidra's name; record every
            # divergence so it can be reconciled (global_name_map.tsv).
            self.renames.append((raw, name, start.toString()))
        size, blob = self._compute_extent(start, data, block)
        return Obj(start, start.getOffset() + size, name, raw, data, block, blob)

    def _collect_roots(self):
        roots = set()
        n_funcs = 0
        for func in self.fn_mgr.getFunctions(True):
            if self.curated is not None and func.getEntryPoint().getOffset() not in self.curated:
                continue
            n_funcs += 1
            for a in self.ref_mgr.getReferenceSourceIterator(func.getBody(), True):
                for ref in self.ref_mgr.getReferencesFrom(a):
                    if not ref.isMemoryReference() or ref.getReferenceType().isFlow():
                        continue
                    to = ref.getToAddress()
                    if self.mem.contains(to):
                        # FIX: ownership is resolved through the object extent,
                        # so a reference to field +8 of a struct/array keeps the
                        # whole object. The old code only looked at refs to the
                        # base address and dropped such objects.
                        roots.add(self._owner_start(to).getOffset())
        if self.curated is not None:
            missing = [o for o in self.curated if self.fn_mgr.getFunctionAt(
                self._addr(o)) is None]
            if missing:
                print(f"  [warn] {len(missing)} curated file(s) do not match any function entry "
                      f"(e.g. {hex(missing[0])}); check the `_<ADDR>` suffix convention.")
        for sym in self.symbol_table.getSymbolIterator(True):
            if sym.getSource() == SourceType.USER_DEFINED and not sym.isExternal():
                a = sym.getAddress()
                if self.mem.contains(a):
                    roots.add(self._owner_start(a).getOffset())
        print(f"Roots: {len(roots)} object(s) referenced from {n_funcs} function(s) "
              f"or user-named.")
        return roots

    # ---- [DDISASM] symbolization --------------------------------------------------------------
    def _is_object_start(self, value, addr):
        return value in self.bound_set or self.fn_mgr.getFunctionAt(addr) is not None

    def _addr_score(self, cell_off, value, untyped):
        """Evidence combination in the spirit of Ddisasm's symbolization:
          +3 base relocation on the cell (RetroWrite/Egalito: ground truth)
          +3 analyzer reference from the cell
          +1 value lands in a loaded, non-header block
          +2 target is an object/function START   /  -1 if it is the MIDDLE
          -3 small integer (< 0x10000)
          -2 typed integer with no hard evidence (a `dword` that merely looks
             like an address -- only untyped cells may rely on the heuristic)
        Accepted at >= ADDR_SCORE_THRESHOLD."""
        if not (self.img_lo <= value < self.img_hi):
            return -9
        a = self._addr(value)
        if a is None or not self.mem.contains(a):
            return -9
        blk = self.mem.getBlock(a)
        if blk is None or blk.getName() == "Headers":
            return -9
        reloc = cell_off in self.reloc_offs
        g = self.gref.get(cell_off)
        s = 1
        if reloc: s += 3
        if g is not None: s += 3
        s += 2 if self._is_object_start(value, a) else -1
        if value < 0x10000: s -= 3
        if not untyped and not reloc and g is None: s -= 2
        return s

    @staticmethod
    def _ext_name(label):
        if not label:
            return None
        m = re.match(r'^_?([A-Za-z_][A-Za-z0-9_]*)(?:@\d+)?$', label)
        return m.group(1) if m else None

    @staticmethod
    def _make_function_id(func):
        """Same recipe as function_extractor.make_function_id(): the id is also
        the stem of the extracted file and the key in call_graph.json / the
        functions table."""
        q = str(func.getName(True))
        safe = re.sub(r'[^A-Za-z0-9_~]', '_', q)
        if len(safe) > 120:
            import hashlib
            safe = f"{safe[:120]}_{hashlib.md5(q.encode('utf-8')).hexdigest()[:8]}"
        return f"{safe}_{func.getEntryPoint().toString()}"

    def _function_c_name(self, func):
        off = func.getEntryPoint().getOffset()
        n = sanitize_c_name(func.getName())
        if self.db.has_function(n):
            return n
        row = self.db.get_function_by_func_id(self._make_function_id(func))
        if row:
            return row[1]
        if self.curated is not None and off in self.curated:
            name = sanitize_c_name(self.curated[off])
            self.db.add_predeclaration(name, f"extern void {name}();")
            return name
        if self.curated is None and not is_noise_function_name(func.getName()):
            self.db.add_predeclaration(n, f"extern void {n}();")
            return n
        # A real function that nobody extracted: no definition will exist, so a
        # symbolic reference would not link. Keep the literal and REPORT it --
        # this is exactly the list of functions Stage 1's call-graph walk missed
        # (callbacks reachable only through data tables).
        self.missing_funcs[off] = func.getName()
        return None

    def _func_target(self, func):
        try:
            if func.isThunk():
                th = func.getThunkedFunction(True)
                if th is not None and th.isExternal() and SYMBOLIZE_EXTERNALS:
                    n = self._ext_name(th.getName())
                    return ("ext", n) if n else None
            if func.isExternal():
                n = self._ext_name(func.getName()) if SYMBOLIZE_EXTERNALS else None
                return ("ext", n) if n else None
        except Exception:
            pass
        n = self._function_c_name(func)
        return ("func", n) if n else None

    def _resolve_target(self, value):
        """value -> ('func'|'ext', name) | ('obj', Obj, offset) | None."""
        a = self._addr(value)
        if a is None or not self.mem.contains(a):
            return None
        blk = self.mem.getBlock(a)
        if blk is None or blk.getName() == "Headers":
            return None
        f = self.fn_mgr.getFunctionAt(a)
        if f is not None:
            return self._func_target(f)
        if blk.isExecute():
            return None
        # Pointer closure: anything a global points at must exist as a global,
        # whether or not code references it directly. Auto string labels (s_*)
        # are allowed here, which is how string tables get their strings.
        obj = self._plan(a, allow_auto_strings=True)
        if obj is None:
            return None
        return ("obj", obj, value - obj.start)

    @staticmethod
    def _tgt_expr(tgt, cast):
        if tgt[0] in ("func", "ext"):
            return f"({cast}){tgt[1]}"
        _, obj, off = tgt
        if off == 0:
            return f"({cast})&{obj.name}"
        # symbol+offset form: `&arr[k]`-style pointers keep their relation to
        # the object instead of a frozen absolute address
        return f"({cast})((char *)&{obj.name} + {off})"

    def _symbolize(self, cell_off, value, cast):
        if value == 0:
            return None
        g = self.gref.get(cell_off)
        if g is not None and g[0] == "ext" and SYMBOLIZE_EXTERNALS:
            n = self._ext_name(g[1])
            if n:
                return f"({cast}){n}"
        tgt = self._resolve_target(value)
        return None if tgt is None else self._tgt_expr(tgt, cast)

    # ---- value rendering (reads memory, not Ghidra Data instances) -------------------------
    def _value(self, obj, dt, aoff, size):
        dt = self.reg.strip(dt)
        raw = self._read(aoff, size)
        zero = raw is None or not any(raw)
        if isinstance(dt, Array):
            return self._v_array(obj, dt, aoff, raw, zero)
        if isinstance(dt, Structure):
            return self._v_struct(obj, dt, aoff, zero)
        if isinstance(dt, Union):
            return self._v_union(obj, dt, aoff, size, raw, zero)
        if isinstance(dt, Pointer):
            return self._v_pointer(dt, aoff, size, raw)
        if zero:
            return "0"
        if isinstance(dt, AbstractStringDataType):
            return self._v_string(dt, raw)
        if isinstance(dt, Enum):
            n = min(dt.getLength(), len(raw))
            return fmt_int(int.from_bytes(raw[:n], self.endian), n, n == 4)
        if isinstance(dt, FunctionDefinition):
            return "0"
        ctype, kind, sz, signed = self.reg.scalar_info(dt)
        if kind == "float":
            return fmt_float(raw[:sz], sz, self.big_endian)
        if kind == "bytes":
            return hex_list(raw)
        if kind == "int":
            val = int.from_bytes(raw[:sz], self.endian)
            if sz == self.ptr_size:
                untyped = dt.getName().lower().startswith('undefined')
                if self._addr_score(aoff, val, untyped) >= ADDR_SCORE_THRESHOLD:
                    e = self._symbolize(aoff, val, ctype)
                    if e:
                        self.stats["ptr_symbolic"] += 1
                        return e
            return fmt_int(val, sz, signed)
        return "0"

    def _v_string(self, dt, raw):
        w = self._string_width(dt)
        if w == 1:
            lit = self._c_string(raw, force=True)
            return lit if lit is not None else "0"
        n = len(raw) // w
        return self._units(raw, w, n)

    @staticmethod
    def _string_width(dt):
        nm = dt.getName().lower()
        if 'unicode' in nm:
            return 4 if '32' in nm else 2
        return 1

    def _units(self, raw, w, n):
        vals = [int.from_bytes(raw[i * w:(i + 1) * w], self.endian) for i in range(n)]
        while vals and vals[-1] == 0:
            vals.pop()
        if not vals:
            return "{0}"
        return "{" + ", ".join(f"0x{v:x}" for v in vals) + "}"

    @staticmethod
    def _c_string(raw, force):
        """Byte-exact literal with trailing NULs dropped (static storage
        zero-fills the rest of `char name[N]`)."""
        end = len(raw)
        while end > 0 and raw[end - 1] == 0:
            end -= 1
        if end == 0:
            return None
        body = raw[:end]
        if not force and any(not (32 <= b <= 126 or b in (9, 10, 13, 0)) for b in body):
            return None
        return '"' + escape_c_bytes(body) + '"'

    def _v_array(self, obj, dt, aoff, raw, zero):
        if zero:
            return "{0}"
        elem = dt.getDataType()
        n = dt.getNumElements()
        elen = dt.getElementLength()
        if n == 0:
            return "{0}"
        if self.reg.is_char(elem):
            lit = self._c_string(raw, force=False)
            if lit is not None:
                return lit
        estripped = self.reg.strip(elem)
        if (not isinstance(estripped, (Array, Structure, Union, Pointer, Enum,
                                       AbstractStringDataType))
                and elen in (1, 2, 4, 8)):
            ctype, kind, sz, signed = self.reg.scalar_info(estripped)
            if kind == "int" and not (sz == self.ptr_size):
                items = [fmt_int(int.from_bytes(raw[i * sz:(i + 1) * sz], self.endian), sz, signed)
                         for i in range(n)]
                return self._trim(items)
        items = [self._value(obj, elem, aoff + i * elen, elen) for i in range(n)]
        return self._trim(items)

    @staticmethod
    def _trim(items):
        while items and items[-1] in ("0", "{0}", "0x0"):
            items.pop()
        return "{" + ", ".join(items) + "}" if items else "{0}"

    def _v_struct(self, obj, dt, aoff, zero):
        if zero:
            return "{0}"
        parts = []
        for f in self.reg.struct_fields(dt):
            foff = aoff + f["off"]
            if f["kind"] == "pad":
                r = self._read(foff, f["len"])
                v = hex_list(r) if r else "{0}"
            elif f["kind"] == "bits":
                v = self._v_bits(f, foff)
            else:
                cdt = self.reg.strip(f["dt"])
                if isinstance(cdt, AbstractStringDataType):
                    r = self._read(foff, f["len"])
                    v = self._v_string(cdt, r) if r and any(r) else "0"
                else:
                    v = self._value(obj, f["dt"], foff, f["len"])
            if v not in ("0", "{0}"):
                parts.append(f".{f['name']} = {v}")
        return "{" + ", ".join(parts) + "}" if parts else "{0}"

    def _v_bits(self, f, foff):
        if self.big_endian:
            self._warn("bit-field initialisers are only implemented for little-endian targets")
            return "0"
        r = self._read(foff, f["len"])
        if not r:
            return "0"
        v = (int.from_bytes(r, 'little') >> f["bit_off"]) & ((1 << f["bits"]) - 1)
        return str(v) if v else "0"

    def _v_union(self, obj, dt, aoff, size, raw, zero):
        if zero:
            return "{0}"
        fields = self.reg.struct_fields(dt)
        # pointer cells inside a union cannot be attributed to a member
        # without knowing which one is active
        cells = self._scan_cells(aoff, raw)
        if cells:
            if obj.writable:
                for rel, e in cells:
                    self._fix.append((aoff - obj.start + rel, self.ptr_size, e))
            else:
                self._warn(f"{obj.name}: read-only union holds pointer cells; literal bytes kept")
        first = fields[0] if fields else None
        if first is not None and first["kind"] == "field" and first["len"] == size:
            return "{ ." + first["name"] + " = " + self._value(obj, first["dt"], aoff, size) + " }"
        return "{ ._raw_bytes_ = " + hex_list(raw) + " }"

    def _scan_cells(self, aoff, raw):
        """[(relative offset, uintptr_t expression)] for evidence-backed pointer cells."""
        out = []
        ptr = self.ptr_size
        if not raw or aoff % ptr:
            return out
        for rel in range(0, len(raw) - ptr + 1, ptr):
            cell = raw[rel:rel + ptr]
            if not any(cell):
                continue
            val = int.from_bytes(cell, self.endian)
            if self._addr_score(aoff + rel, val, True) >= ADDR_SCORE_THRESHOLD:
                e = self._symbolize(aoff + rel, val, "uintptr_t")
                if e:
                    out.append((rel, e))
        return out

    def _v_pointer(self, dt, aoff, size, raw):
        if raw is None or not any(raw):
            return "0"
        val = int.from_bytes(raw[:size], self.endian)
        ctype, dim = self.reg.parse(dt)
        e = self._symbolize(aoff, val, ctype)
        if e:
            self.stats["ptr_symbolic"] += 1
            return e
        # Unresolvable (target not emitted / outside the image / small
        # constant): keep the literal -- but never silently.
        self.stats["ptr_literal"] += 1
        a = self._addr(val)
        if a is not None and self.mem.contains(a):
            self._warn(f"pointer at {hex(aoff)} -> {hex(val)} kept as literal "
                       f"(target not emitted; stale if layout changes)")
        return f"({ctype})0x{val:x}"

    # ---- object emission --------------------------------------------------------------------
    @staticmethod
    def _untyped_decl(start, size):
        if size in (1, 2, 4, 8) and start % size == 0:
            return f"uint{size * 8}_t", "", True
        return "uint8_t", f"[{size}]", False

    def _emit_string(self, obj, dt, dlen):
        w = self._string_width(dt)
        raw = self._read(obj.start, dlen)
        zero = raw is None or not any(raw)
        if w == 1:
            ctype = "char" if obj.writable else "const char"
            lit = None if zero else self._c_string(raw, force=True)
            return ctype, f"[{dlen}]", (lit if lit is not None else "{0}")
        if dlen % w:
            return "uint8_t", f"[{dlen}]", ("{0}" if zero else hex_list(raw))
        return f"uint{w * 8}_t", f"[{dlen // w}]", ("{0}" if zero else self._units(raw, w, dlen // w))

    def _emit_untyped(self, obj):
        """[TIE/RETYPD] no evidence for a richer type -> lattice top: integers
        of the extent's width, else a byte array. The only upgrade is
        symbolized pointer cells (see `_addr_score`)."""
        s, size = obj.start, obj.end - obj.start
        ctype, dim, scalar = self._untyped_decl(s, size)
        raw = self._read(s, size)
        if raw is None or not any(raw):
            return f"{ctype}{dim}", ("0" if scalar else "{0}")
        cells = self._scan_cells(s, raw)
        ptr = self.ptr_size
        if not cells:
            lit = fmt_int(int.from_bytes(raw, self.endian), size, False) if scalar else hex_list(raw)
            return f"{ctype}{dim}", lit
        self.stats["ptr_symbolic"] += len(cells)
        if size == ptr:
            return "uintptr_t", cells[0][1]
        if not obj.writable and size % ptr == 0:
            cmap = dict(cells)
            words = [cmap.get(r) or fmt_int(int.from_bytes(raw[r:r + ptr], self.endian), ptr, False)
                     for r in range(0, size, ptr)]
            while words and words[-1] == "0x0":
                words.pop()
            self._warn(f"{obj.name}: read-only blob with {len(cells)} pointer(s) emitted as "
                       f"uintptr_t[{size // ptr}] (element type changed to carry addresses)")
            return f"uintptr_t[{size // ptr}]", "{" + ", ".join(words) + "}" if words else "{0}"
        if obj.writable:
            for rel, e in cells:
                self._fix.append((rel, ptr, e))
            return f"{ctype}{dim}", hex_list(raw)
        self._warn(f"{obj.name}: read-only, unaligned blob with {len(cells)} pointer(s); literal kept")
        return f"{ctype}{dim}", hex_list(raw)

    def _emit(self, obj):
        self._fix = []
        data = obj.data
        if data is not None and data.isDefined() and not obj.blob:
            dt = data.getDataType()
            dlen = data.getLength()
            sdt = self.reg.strip(dt)
            if isinstance(sdt, AbstractStringDataType):
                ctype, dim, val = self._emit_string(obj, dt, dlen)
                gtype = f"{ctype}{dim}"
            elif sdt.getLength() <= 0:       # dynamic-length type we cannot model
                gtype, val = self._emit_untyped(obj)
            else:
                self.reg.register(dt)
                ctype, dim = self.reg.parse(dt)
                val = self._value(obj, dt, obj.start, dlen)
                if not obj.writable and ctype == "char" and dim:
                    ctype = "const char"     # read-only text stays read-only
                gtype = f"{ctype}{dim}"
        else:
            gtype, val = self._emit_untyped(obj)
        self.db.add_or_update_global(obj.name, gtype=gtype, value_or_expr=val, is_string=False)
        for rel, width, expr in self._fix:
            self.db.add_fixup(obj.name, rel, width, expr)
            self.stats["fixups"] += 1
        self.stats["objects"] += 1

    def _emit_safe(self, obj):
        """One bad object must not abort the whole run. Fall back to a plain
        byte image so references to `&name` elsewhere still compile."""
        try:
            self._emit(obj)
            return
        except Exception as e:
            self._warn(f"{obj.name} @ {hex(obj.start)}: {type(e).__name__}: {e}; "
                       f"falling back to raw bytes")
        try:
            size = obj.end - obj.start
            ctype, dim, scalar = self._untyped_decl(obj.start, size)
            raw = self._read(obj.start, size)
            val = "0" if (raw is None or not any(raw)) and scalar else (
                fmt_int(int.from_bytes(raw, self.endian), size, False) if scalar and raw
                else hex_list(raw or b""))
            self.db.add_or_update_global(obj.name, gtype=f"{ctype}{dim}", value_or_expr=val)
            self.stats["objects"] += 1
        except Exception as e2:
            self.stats["failed"] += 1
            self._warn(f"{obj.name}: raw fallback failed too ({e2}); object skipped")

    def extract_defined_and_bss_globals(self):
        """Passes 1+2 (defined data, BSS, named symbols) + pointer closure."""
        self._build_boundaries()
        self._build_evidence()
        for off in sorted(self._collect_roots()):
            a = self._addr(off)
            if a is not None:
                self._plan(a)
        while self.queue:                    # closure may append while we drain
            self._emit_safe(self.queue.popleft())
        print(f"Globals: {self.stats['objects']} emitted, "
              f"{self.stats['ptr_symbolic']} pointer cell(s) symbolized, "
              f"{self.stats['ptr_literal']} left literal, "
              f"{self.stats['fixups']} load-time fixup(s), {self.stats['failed']} failed.")

    # ---- passes 3 & 4: types seen only in signatures / locals ---------------------------------
    def _in_scope(self, func):
        if self.curated is not None:
            return func.getEntryPoint().getOffset() in self.curated
        return not is_noise_function_name(func.getName())

    def extract_function_signatures(self):
        """Pass 3: types appearing only in a function's own signature."""
        for func in self.fn_mgr.getFunctions(True):
            if not self._in_scope(func):
                continue
            try:
                self.reg.register(func.getReturnType())
                for param in func.getParameters():
                    self.reg.register(param.getDataType())
            except Exception as e:
                print(f"  [warn] Pass 3: {func.getName()}: {e}")

    def extract_local_variables(self):
        """Pass 4: types appearing only as local variables."""
        decomp = DecompInterface()
        decomp.openProgram(self.program)
        monitor = ConsoleTaskMonitor()
        done, before = 0, len(self.reg.seen)
        try:
            for func in self.fn_mgr.getFunctions(True):
                if not self._in_scope(func):
                    continue
                fname, fentry = func.getName(), func.getEntryPoint().toString()
                try:
                    result = decomp.decompileFunction(func, 60, monitor)
                except Exception as e:
                    print(f"  [warn] Pass 4: decompile raised for {fname} @ {fentry}: {e}")
                    continue
                if result is None:
                    print(f"  [warn] Pass 4: no decompile result for {fname} @ {fentry}")
                    continue
                if not result.decompileCompleted():
                    print(f"  [warn] Pass 4: decompile incomplete for {fname} @ {fentry}: "
                          f"{result.getErrorMessage()} -- attempting partial read anyway")
                high_func = result.getHighFunction()
                if high_func is None:
                    print(f"  [warn] Pass 4: no HighFunction for {fname} @ {fentry} -- skipped.")
                    continue
                done += 1
                for hv in high_func.getLocalSymbolMap().getSymbols():
                    try:
                        self.reg.register(hv.getDataType())
                    except Exception:
                        continue
        finally:
            decomp.dispose()
        print(f"Pass 4: decompiled {done} function(s) for local-variable types, "
              f"registered {len(self.reg.seen) - before} new type(s).")

    def write_missing_function_report(self, path):
        """Functions that globals point at but Stage 1 never extracted."""
        if not self.missing_funcs:
            return
        import json
        with open(path, "w", encoding="utf-8") as f:
            json.dump([{"address": hex(a), "name": n}
                       for a, n in sorted(self.missing_funcs.items())], f, indent=2)
        print(f"{len(self.missing_funcs)} function(s) are referenced from data but were not "
              f"extracted by Stage 1; see {path}")

    def write_rename_report(self, path):
        if not self.renames:
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write("ghidra_name\tc_name\taddress\n")
            for r in self.renames:
                f.write("\t".join(r) + "\n")
        print(f"{len(self.renames)} global(s) renamed vs. Ghidra; see {path}")


# --- Main entry point ----------------------------------------------------------------

def generate_global_files(path_to_binary, workspace_dir="."):
    project_location = os.path.join(workspace_dir, "ghidra_project")
    project_name = f"{os.path.basename(path_to_binary)}_ghidra"
    program_path = f"/{os.path.basename(path_to_binary)}"

    # FIX: validate BEFORE wiping the DB (a failed run used to leave it empty)
    if not os.path.isdir(project_location):
        raise RuntimeError(
            f"No shared Ghidra project found at {project_location}. Run Stage 1 "
            f"(function_extractor.py) on this binary first -- Stage 2 depends on "
            f"the already-analyzed program it produces."
        )

    db = SymbolDB(workspace_dir=workspace_dir)
    backup = db.db_path + ".bak"
    if os.path.exists(db.db_path):
        shutil.copy2(db.db_path, backup)
    db.reset_globals()
    db.reset_custom_types()

    curated = load_curated_function_entry_points(workspace_dir, path_to_binary)
    if curated is not None:
        print(f"Found {len(curated)} curated function(s) in extracted_functions/ -- "
              f"scoping global extraction to references from those functions only.")
    else:
        print("No curated extracted_functions/ folder found for this binary -- falling back to "
              "'referenced from any function in the binary'. Run function_extractor.py and prune "
              "it down to the functions you care about, then re-run this script for tighter results.")

    print(f"Initializing Ghidra and opening: {path_to_binary}")
    try:
        print(f"Opening shared Ghidra project: {project_location}/{project_name}")
        with pyghidra.open_project(project_location, project_name, create=False) as project:
            if project.getProjectData().getFile(program_path) is None:
                raise RuntimeError(f"{program_path} was not found in the shared project at {project_location}.")
            print(f"Opening already-analyzed program: {program_path}")
            with pyghidra.program_context(project, program_path) as program:
                # NOTE: the program is only read now; the old in-place array
                # collation (a write transaction on the shared project) is gone.
                extractor = GlobalValueExtractor(program, db, curated)
                extractor.extract_defined_and_bss_globals()
                extractor.extract_function_signatures()
                extractor.extract_local_variables()
                extractor.write_rename_report(os.path.join(workspace_dir, "global_name_map.tsv"))
                extractor.write_missing_function_report(
                    os.path.join(workspace_dir, "missing_function_targets.json"))
        db.export_header("data_globals.h")
        db.export_source("data_globals.c")
    except BaseException:
        if os.path.exists(backup):
            shutil.copy2(backup, db.db_path)
            print(f"Run failed; previous symbols.db restored from {backup}")
        raise