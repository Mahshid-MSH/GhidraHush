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
    return "uintptr_t"


def generate_global_files(path_to_binary, workspace_dir="."):
    header_path = os.path.join(workspace_dir, "LLM_globals.h")
    source_path = os.path.join(workspace_dir, "LLM_globals.c")
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
    "calc_shellcode", "shellcode", "win_shellcode", "caseD_*"  # can use pattern
    }
    
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
            if program.getFunctionManager().getFunctionAt(addr) is not None:
                print(f" Skipping function symbol: {raw_name}")
                continue

            # Added '.', '?', and '<' to catch Ghidra section labels and C++ artifacts
            if raw_name.startswith(('_', '.', '?', '<')) or raw_name.startswith('FID_conflict:_') or raw_name.startswith('mingw')or raw_name.startswith('gcc:_') or raw_name.startswith('g++:_'):
                print(f" Skipping Runtime/Library Global: {raw_name}")
                continue

            if any(ignored_item in raw_name for ignored_item in TEB_PEB_IGNORE_LIST):
                continue
            seen_addresses.add(addr)
            name = sanitize_name(raw_name)
            
            if name in seen_names:
                continue
            seen_names.add(name)
            
            data = listing.getDataAt(addr)
            # Handle completely undefined memory labels
            # Handle completely undefined memory labels (or fragmented ones)
            if not data or not data.isDefined():
                mem_block = program.getMemory().getBlock(addr)
                if mem_block:
                    end_addr = mem_block.getEnd()
                    
                    # 1. Find the very next MEANINGFUL symbol address.
                    # We must IGNORE auto-generated labels so we don't prematurely chop up payloads containing strings.
                    sym_iter = symbol_table.getSymbolIterator(addr, True)
                    while sym_iter.hasNext():
                        s = sym_iter.next()
                        if s.getAddress().compareTo(addr) > 0:
                            next_name = s.getName()
                            
                            # Skip Ghidra's auto-generated data/string labels
                            if next_name.startswith("s_") or next_name.startswith("DAT_") or next_name.startswith("STRING_"):
                                continue
                                
                            if s.getAddress().compareTo(end_addr) < 0:
                                end_addr = s.getAddress()
                            break
                            
                    # Calculate the full size of the block
                    size = end_addr.subtract(addr)
                    
                    # 2. Forcibly read the raw bytes
                    if 0 < size < 1000000:
                        try:
                            mem = program.getMemory()
                            raw_bytes = []
                            for i in range(size):
                                raw_bytes.append(mem.getByte(addr.add(i)))
                                
                            hex_bytes = [f"0x{(b & 0xFF):02X}" for b in raw_bytes]
                            value_expr = "{ " + ", ".join(hex_bytes) + " }"
                            c_type = f"uint8_t[{size}]"
                            
                            db.add_or_update_global(name, gtype=c_type, value_or_expr=value_expr, is_string=False)
                            continue
                        except Exception as e:
                            print(f" [!] Warning: Failed to read raw bytes for {name}: {e}")

                # Ultimate fallback
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
                    # Assign raw hex to safely fit into uintptr_t or void*
                    value_expr = f"0x{val.getOffset():x}"
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