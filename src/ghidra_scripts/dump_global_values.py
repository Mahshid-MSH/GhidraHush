import sys, os
import pyghidra
import re
import warnings
from database.symbol_db import SymbolDB


C_KEYWORDS = {
    'auto', 'break', 'case', 'char', 'const', 'continue', 'default', 'do', 
    'double', 'else', 'enum', 'extern', 'float', 'for', 'goto', 'if', 'int', 
    'long', 'register', 'return', 'short', 'signed', 'sizeof', 'static', 
    'struct', 'switch', 'typedef', 'union', 'unsigned', 'void', 'volatile', 'while'
}
warnings.filterwarnings("ignore", category=DeprecationWarning)

def sanitize_name(name):
    name = re.sub(r'[^a-zA-Z0-9_]', '_', name)
    if name in C_KEYWORDS:
        name = '_' + name
    if name and name[0].isdigit():
        name = '_' + name
    return name

def is_string_data(data):
    if not data or not data.isDefined():
        return False
    dt_name = data.getDataType().getName().lower()
    return 'string' in dt_name or 'char' in dt_name

def map_ghidra_type_to_c(dt):
    """Maps Ghidra data types to standard C types."""
    if dt is None:
        return "uint8_t"   
    name = dt.getName().lower()
    # Standard scalar sizes
    if 'undefined1' in name or name == 'byte':
        return "uint8_t"
    elif 'undefined2' in name or name == 'word':
        return "uint16_t"
    elif 'undefined4' in name or name == 'dword':
        return "uint32_t"
    elif 'undefined8' in name or name == 'qword':
        return "uint64_t"
    elif 'float' in name:
        return "float"
    elif 'double' in name:
        return "double"
    elif 'pointer' in name or '*' in name:
        return "void*"
        
    # Arrays (e.g., "byte[16]" -> "uint8_t[16]")
    if '[' in name and ']' in name:
        base_type = name.split('[')[0]
        size_part = name[name.find('['):]
        if 'undefined' in base_type or 'byte' in base_type:
            return f"uint8_t{size_part}"
        elif 'word' in base_type:
            return f"uint16_t{size_part}"
        elif 'dword' in base_type:
            return f"uint32_t{size_part}"
        elif 'qword' in base_type:
            return f"uint64_t{size_part}"
        return f"{base_type}{size_part}"
        
    # Fallback for custom structs / raw undefined bytes
    return "uint8_t"


def generate_global_files(path_to_binary, workspace_dir="."):
    # Use workspace_dir to set up your output paths correctly
    header_path = os.path.join(workspace_dir, "LLM_globals.h")
    source_path = os.path.join(workspace_dir, "LLM_globals.c")
    db = SymbolDB(workspace_dir=workspace_dir)    
    TEB_PEB_IGNORE_LIST = [
        "ExceptionList", "LastError", "Tls", "Gdi", "Reserved", "StackBase", 
        "StackLimit", "ProcessEnvironmentBlock", "EnvironmentPointer", 
        "glDispatchTable", "TxnScope", "FiberData", "ArbitraryUserPointer", 
        "ThreadLocalStorage", "Win32ThreadInfo", "EtwTraceData", "DeallocationStack"
    ]
    
    print(f"Initializing Ghidra and opening: {path_to_binary}")
    
    with pyghidra.open_program(path_to_binary) as flat_api:
        from ghidra.program.model.symbol import SymbolType
        from ghidra.program.model.scalar import Scalar
        from ghidra.program.model.address import Address
        
        program = flat_api.currentProgram
        listing = program.getListing()
        symbol_table = program.getSymbolTable()
        symbols = symbol_table.getAllSymbols(True)
        
        seen_addresses = set()
        seen_names = set()
        
        for sym in symbols:
            if sym.getSymbolType() not in [SymbolType.LABEL, SymbolType.GLOBAL_VAR]:
                continue         
            addr = sym.getAddress()
            if not addr.isMemoryAddress() or addr in seen_addresses:
                continue
            raw_name = sym.getName()
            if any(ignored_item in raw_name for ignored_item in TEB_PEB_IGNORE_LIST):
                continue
            seen_addresses.add(addr)
            name = sanitize_name(raw_name)
            
            if name in seen_names:
                continue
            seen_names.add(name)
            
            data = listing.getDataAt(addr)
            
            # Handle completely undefined memory labels
            if not data or not data.isDefined():
                db.add_or_update_global(name, gtype="uintptr_t", value_or_expr="0", is_string=False)
                continue

            if is_string_data(data):
                val = data.getValue()
                escaped = ""
                if val:
                    escaped = str(val).replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
                db.add_or_update_global(name, gtype="const char[]", value_or_expr=escaped, is_string=True)
            else:
                # "What type are you?"
                dt = data.getDataType()
                c_type = map_ghidra_type_to_c(dt)
                
                # "What is your actual value?"
                val = data.getValue()
                value_expr = "0"
                
                if isinstance(val, Scalar):
                    # Unwrap the Ghidra Scalar object
                    value_expr = hex(val.getUnsignedValue())
                elif isinstance(val, Address):
                    # Format as a C pointer
                    value_expr = f"(void*){hex(val.getOffset())}"
                else:
                    # "Give me the raw bytes!" (The Fallback)
                    try:
                        raw_bytes = data.getBytes()
                        if raw_bytes:
                            # Java byte arrays in Jython are signed (-128 to 127). 
                            # (b & 0xFF) safely converts them to unsigned Python integers (0 to 255).
                            hex_bytes = [f"0x{(b & 0xFF):02X}" for b in raw_bytes]
                            value_expr = "{ " + ", ".join(hex_bytes) + " }"
                            # Ensure the C type becomes an array if we are outputting raw bytes
                            if '[' not in c_type:
                                length = data.getLength()
                                c_type = f"{c_type}[{length}]"
                    except Exception:
                        # Fallback if getBytes() fails on uninitialized memory segments
                        value_expr = "0"
                        
                db.add_or_update_global(name, gtype=c_type, value_or_expr=value_expr, is_string=False)

    db.export_header("LLM_globals.h")
    db.export_source("LLM_globals.c")
    print("Extraction complete! DB synced and header/source exported.")