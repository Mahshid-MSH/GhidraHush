import sys, os
import pyghidra
import re
import warnings
import struct
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
        dt = underlying

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
            
        # Skip PE Structs by Data Type Name
        if dt_name.startswith("IMAGE_"):
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
                buf = bytearray(length)
                try:
                    program.getMemory().getBytes(data.getAddress(), buf)
                    return "{" + ", ".join([f"0x{b:02x}" for b in buf]) + "}"
                except: pass
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

        def process_global(addr, data, sym):
            if addr in processed_addrs:
                return

            mem_block = program.getMemory().getBlock(addr)
            # Do NOT skip uninitialized blocks (.bss)!
            if not mem_block or mem_block.isExecute():
                return
            
            block_name = mem_block.getName().lower()
            if any(sec in block_name for sec in ['.debug', '.pdata', '.xdata', '.eh_frame', '.reloc', '.rsrc', 'headers']):
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
                if is_string_data(data):
                    raw_str = str(data.getValue() or "")
                    val = escape_c_string(raw_str)
                    db.add_or_update_global(name, gtype="const char", value_or_expr=val, is_string=True)
                else:
                    dt = data.getDataType()
                    extract_and_store_type(dt, db, seen_types)
                    c_type, dim = parse_ghidra_type_and_dim(dt)
                    val_str = get_data_value_string(data, program)
                    db.add_or_update_global(name, gtype=f"{c_type}{dim}", value_or_expr=val_str, is_string=False)
            else:
                # Handle standard undefined global buffers or .bss variables
                db.add_or_update_global(name, gtype="uint8_t", value_or_expr="{ 0 }", is_string=False)

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