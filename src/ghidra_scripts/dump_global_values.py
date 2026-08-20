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

def extract_array_initializer(data, program):
    """Reads raw bytes from Ghidra memory to create a C array initializer string."""
    length = data.getLength()
    if length <= 0:
        return "{ 0 }"
        
    buf = bytearray(length)
    try:
        program.getMemory().getBytes(data.getAddress(), buf)
        hex_bytes = [f"0x{b & 0xff:02x}" for b in buf]
        return "{" + ", ".join(hex_bytes) + "}"
    except Exception:
        return "{ 0 }"

def parse_ghidra_type_and_dim(dt):
    """Splits Ghidra types into base C type and array dimension suffix."""
    if dt is None:
        return "uint8_t", ""
        
    name = dt.getName().lower()
    dim = ""
    
    if '[' in name and ']' in name:
        dim = name[name.find('['):]
        base_name = name.split('[')[0]
    else:
        base_name = name

    if 'undefined1' in base_name or 'byte' in base_name or 'char' in base_name:
        c_type = "uint8_t"
    elif 'undefined2' in base_name or 'word' in base_name:
        c_type = "uint16_t"
    elif 'undefined4' in base_name or 'dword' in base_name:
        c_type = "uint32_t"
    elif 'undefined8' in base_name or 'qword' in base_name:
        c_type = "uint64_t"
    elif 'float' in base_name:
        c_type = "float"
    elif 'double' in base_name:
        c_type = "double"
    elif 'pointer' in base_name or '*' in base_name:
        c_type = "void*"
    else:
        c_type = "uint8_t"

    return c_type, dim

def generate_global_files(path_to_binary, workspace_dir="."):
    db = SymbolDB(workspace_dir=workspace_dir)    
    
    TEB_PEB_IGNORE_LIST = [
        "ExceptionList", "LastError", "Tls", "Gdi", "Reserved", "StackBase", 
        "StackLimit", "ProcessEnvironmentBlock", "EnvironmentPointer", 
        "glDispatchTable", "TxnScope", "FiberData", "ArbitraryUserPointer", 
        "ThreadLocalStorage", "Win32ThreadInfo", "EtwTraceData", "DeallocationStack"
    ]
    # Added MSVC/MinGW CRT globals to prevent macro collisions with stdlib.h
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
        
        seen_names = set()
        
        data_iter = listing.getDefinedData(True)
        for data in data_iter:
            addr = data.getAddress()
            
            if fn_mgr.getFunctionContaining(addr) is not None:
                continue
            
            refs = ref_mgr.getReferencesTo(addr)
            is_used_in_function = False
            for ref in refs:
                from_addr = ref.getFromAddress()
                if fn_mgr.getFunctionContaining(from_addr) is not None:
                    is_used_in_function = True
                    break
            
            if not is_used_in_function:
                continue

            sym = symbol_table.getPrimarySymbol(addr)
            raw_name = sym.getName() if sym else f"DAT_{addr.toString()}"
            if raw_name in TEB_PEB_IGNORE_LIST or raw_name in RUNTIME_SYMBOLS:
                continue
            if raw_name.startswith(("__imp_", "_refptr_", "__xc_", "__xi_", "__xd_", "_CRT", "__mingw", "__native", "__lib64","_")):
                continue
            
            name = sanitize_name(raw_name)
            if name in seen_names:
                name = f"{name}_{addr.toString()}"
            seen_names.add(name)

            # --- STRING HANDLING ---
            if is_string_data(data):
                raw_str = str(data.getValue() or "")
                val = (raw_str.replace('\\', '\\\\')
                              .replace('"', '\\"')
                              .replace('\n', '\\n')
                              .replace('\r', '\\r')
                              .replace('\t', '\\t'))
                db.add_or_update_global(name, gtype="const char", value_or_expr=val, is_string=True)
            
            # --- NON-STRING HANDLING ---
            else:
                dt = data.getDataType()
                c_type, dim = parse_ghidra_type_and_dim(dt)

                if dim:  # Array Types
                    array_val = extract_array_initializer(data, program)
                    db.add_or_update_global(name, gtype=f"{c_type}[]", value_or_expr=array_val, is_string=False)
                
                else:  # Scalar Variables
                    val = data.getValue()
                    val_str = str(val) if val is not None else "0"
                
                    if val_str == "(null)":
                        val_str = "0"
                    elif hasattr(val, 'getOffset'):
                        val_str = f"({c_type})0x{val.getOffset():x}"
                    elif re.fullmatch(r'[0-9a-fA-F]+', val_str) and not val_str.isdigit():
                        val_str = f"0x{val_str}"

                    # Truncate hex values to fit scalar type bounds (prevents compiler overflow warnings)
                    if val_str.startswith("0x"):
                        try:
                            num_val = int(val_str, 16)
                            if c_type == "uint8_t":
                                val_str = f"0x{num_val & 0xFF:02x}"
                            elif c_type == "uint16_t":
                                val_str = f"0x{num_val & 0xFFFF:04x}"
                            elif c_type == "uint32_t":
                                val_str = f"0x{num_val & 0xFFFFFFFF:08x}"
                        except ValueError:
                            pass

                    db.add_or_update_global(name, gtype=c_type, value_or_expr=val_str, is_string=False)

    db.export_header("data_globals.h")
    db.export_source("data_globals.c")