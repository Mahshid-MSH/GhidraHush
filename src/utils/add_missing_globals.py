#!/usr/bin/env python3
"""
add_missing_globals.py
-----------------------
Scans all .c files in extracted_functions for global variable references
that are missing from data_globals.h and appends them via SymbolDB.
Includes a universal heuristic to auto-detect unstructured array boundaries.
"""

import os
import re
import sys
import struct
import pyghidra
from jpype import JArray, JByte
from database.symbol_db import SymbolDB


def parse_ghidra_type_and_dim(dt):
    if dt is None:
        return "uint32_t", ""
        
    name = dt.getName().lower()
    dim = ""
    
    if '[' in name and ']' in name:
        dim = name[name.find('['):]
        base_name = name[:name.find('[')]
    else:
        base_name = name

    if 'undefined1' in base_name or 'byte' in base_name or 'char' in base_name:
        c_type = "uint8_t"
    elif 'undefined2' in base_name or 'word' in base_name:
        c_type = "uint16_t"
    elif 'undefined4' in base_name or 'dword' in base_name or 'ulong' in base_name or 'long' in base_name:
        c_type = "uint32_t"
    elif 'undefined8' in base_name or 'qword' in base_name:
        c_type = "uint64_t"
    elif 'float' in base_name:
        c_type = "float"
    elif 'double' in base_name:
        c_type = "double"
    else:
        c_type = "uint32_t"

    return c_type, dim


def get_c_type_size(c_type):
    """Returns the byte size of standard C types."""
    if "64" in c_type or c_type == "double": return 8
    if "32" in c_type or c_type == "float": return 4
    if "16" in c_type: return 2
    return 1


def _is_incidental_marker(program, addr):
    """
    True if `addr` looks like an incidental label Ghidra placed on a byte
    the decompiler happened to dereference - NOT a real boundary between
    two separate globals.

    Two conditions both have to hold:
      1. The data type there is still Undefined (Ghidra never concluded
         this was the start of a distinct, independently-typed variable).
      2. Every symbol at that address has SourceType.DEFAULT - i.e. it's
         one of Ghidra's own auto-generated placeholder names (the
         DAT_xxxxxxxx / PTR_xxxxxxxx pattern), not something a person or
         a prior analysis pass deliberately identified as its own thing.

    This is what lets a large unstructured array (any size, any binary)
    stay intact: Ghidra typically auto-labels every individual offset
    that code touches inside such a blob, and without this check each of
    those labels would incorrectly look like "the next global starts
    here," fragmenting one real array into dozens of tiny ones.
    """
    from ghidra.program.model.symbol import SourceType
    from ghidra.program.model.data import Undefined

    data = program.getListing().getDataAt(addr)
    if data is not None and not Undefined.isUndefined(data.getDataType()):
        return False

    syms = program.getSymbolTable().getSymbols(addr)
    if len(syms) == 0:
        return True
    return all(s.getSource() == SourceType.DEFAULT for s in syms)


def get_data_boundary(program, addr):
    """
    UNIVERSAL HEURISTIC:
    Finds the exact byte size of an unknown data block by scanning forward
    until it hits a REAL boundary - either the end of the memory block, or
    a symbol/data item that Ghidra or a person has actually distinguished
    from a plain undefined byte. Incidental auto-labels sitting on still-
    Undefined data (see `_is_incidental_marker`) are skipped over rather
    than treated as boundaries, so one large unstructured array doesn't
    get sliced into fragments at every offset the decompiled code touches.

    Candidate boundaries are also only trusted if they fall inside the
    SAME memory block as `addr` - a symbol/data item that happens to sit
    further along in address order but lives in a different block (e.g.
    across a section gap, or in a block not actually backed by real
    bytes) is ignored, so the computed size can never reach past what
    Ghidra can actually read back.
    """
    mem_block = program.getMemory().getBlock(addr)
    if not mem_block:
        return 1

    end_offset = mem_block.getEnd().getOffset() + 1

    def _in_same_block(candidate_addr):
        try:
            return mem_block.contains(candidate_addr)
        except Exception:
            return False

    # 1. Walk forward through symbols, skipping incidental markers, until
    #    a genuine boundary or the end of the block is reached.
    next_sym_offset = end_offset
    sym_iter = program.getSymbolTable().getSymbolIterator(addr, True)
    for sym in sym_iter:
        sym_addr = sym.getAddress()
        if sym_addr.getOffset() <= addr.getOffset():
            continue
        if not _in_same_block(sym_addr):
            break
        if _is_incidental_marker(program, sym_addr):
            continue
        next_sym_offset = sym_addr.getOffset()
        break

    # 2. Same idea for defined data: skip past Undefined-typed data units
    #    (those are what incidental labels normally sit on) and only stop
    #    at data Ghidra actually gave a real type.
    from ghidra.program.model.data import Undefined
    listing = program.getListing()
    next_data_offset = end_offset
    next_data = listing.getDefinedDataAfter(addr)
    while next_data:
        nd_addr = next_data.getAddress()
        if nd_addr.getOffset() <= addr.getOffset() or not _in_same_block(nd_addr):
            break
        if Undefined.isUndefined(next_data.getDataType()):
            next_data = listing.getDefinedDataAfter(nd_addr)
            continue
        next_data_offset = nd_addr.getOffset()
        break

    # The true size is bounded by whatever real boundary comes first
    actual_size = min(next_sym_offset, next_data_offset, end_offset) - addr.getOffset()
    return actual_size if actual_size > 0 else 1


def _read_bytes_with_fallback(memory, addr, requested_len):
    """
    Reads `requested_len` bytes starting at `addr`. If the full-length read
    fails (MemoryAccessException), binary-searches for the longest prefix
    that Ghidra CAN actually deliver, and zero-pads the remainder rather
    than discarding the whole read. This matters most for large arrays:
    a single bad byte near the tail of a 32KB array shouldn't cost you
    the other 32KB of real data.

    Returns (bytes_buffer, num_real_bytes_recovered).
    """
    if requested_len <= 0:
        return b"", 0

    def _try_read(n):
        jbuf = JArray(JByte)(n)
        memory.getBytes(addr, jbuf)
        return bytes(b & 0xFF for b in jbuf)

    try:
        return _try_read(requested_len), requested_len
    except Exception:
        pass

    # Binary search for the longest readable prefix from `addr`.
    lo, hi, best = 0, requested_len, b""
    while lo < hi:
        mid = (lo + hi + 1) // 2
        try:
            best = _try_read(mid)
            lo = mid
        except Exception:
            hi = mid - 1

    return best + b"\x00" * (requested_len - len(best)), len(best)


def extract_generic_array(program, addr, c_type, byte_len):
    """Extracts arbitrary memory blocks and formats them into clean C arrays."""
    try:
        buf, real_bytes = _read_bytes_with_fallback(program.getMemory(), addr, byte_len)

        if real_bytes < byte_len:
            print(f"WARNING: only recovered {real_bytes}/{byte_len} real bytes at {addr}; "
                  f"remaining {byte_len - real_bytes} byte(s) zero-padded (array size preserved)")

        # MASSIVE ARRAY OPTIMIZATION: 
        # If the block is populated entirely with zeroes, return standard C zero-initializer.
        if not any(buf):
            return "{ 0 }"

        lines = []
        
        if "uint32_t" in c_type or "int32_t" in c_type:
            count = byte_len // 4
            vals = struct.unpack(f"<{count}I", buf[:count * 4])
            for i in range(0, len(vals), 8):
                lines.append("  " + ", ".join(f"0x{v:08X}L" for v in vals[i:i+8]))
                
        elif "uint16_t" in c_type or "int16_t" in c_type:
            count = byte_len // 2
            vals = struct.unpack(f"<{count}H", buf[:count * 2])
            for i in range(0, len(vals), 12):
                lines.append("  " + ", ".join(f"0x{v:04X}" for v in vals[i:i+12]))
                
        elif "uint64_t" in c_type or "int64_t" in c_type:
            count = byte_len // 8
            vals = struct.unpack(f"<{count}Q", buf[:count * 8])
            for i in range(0, len(vals), 4):
                lines.append("  " + ", ".join(f"0x{v:016X}ULL" for v in vals[i:i+4]))
                
        else:
            for i in range(0, len(buf), 16):
                lines.append("  " + ", ".join(f"0x{b & 0xff:02x}" for b in buf[i:i+16]))
                
        return "{\n" + ",\n".join(lines) + "\n}"
    except Exception as e:
        print(f"WARNING: failed to read {byte_len} bytes at {addr}: {e}")
        return "{ 0 }"


def append_missing_declarations(header_path, source_path, missing, workspace_dir, program=None):
    if not missing:
        print("No missing globals found.")
        return

    db = SymbolDB(workspace_dir=workspace_dir)

    if program is not None:
        symbol_table = program.getSymbolTable()
        listing = program.getListing()

        for name in missing:
            symbols = list(symbol_table.getSymbols(name))
            if not symbols:
                db.add_or_update_global(name, gtype="uintptr_t", value_or_expr="0", is_string=False)
                continue

            def _symbol_sort_key(sym):
                # Lower key = preferred. Primary symbols first, then symbols
                # whose address falls in a real, loaded/initialized memory
                # block (as opposed to an EXTERNAL/synthetic placeholder).
                blk = program.getMemory().getBlock(sym.getAddress())
                has_real_block = bool(blk) and blk.isInitialized()
                return (0 if sym.isPrimary() else 1, 0 if has_real_block else 1)

            symbols.sort(key=_symbol_sort_key)
            addr = symbols[0].getAddress()
            data = listing.getDefinedDataAt(addr) or listing.getDataAt(addr)
            
            c_type, dim = "uint8_t", ""
            is_ghidra_array = False
            
            if data:
                dt = data.getDataType()
                c_type, dim = parse_ghidra_type_and_dim(dt)
                is_ghidra_array = dim or data.isArray()
            
            # Universal Array Heuristic Trigger.
            # Never trust a Ghidra-typed array's own length as the upper bound:
            # Ghidra frequently only recognizes/types the LEADING slice of what
            # is really one much larger, mostly-undefined byte blob (an embedded
            # file, a resource, a partially-annotated lookup table, etc). Always
            # probe the real boundary and compare against what Ghidra typed.
            boundary_len = get_data_boundary(program, addr)
            ghidra_len = data.getLength() if data else 0

            if is_ghidra_array and boundary_len > ghidra_len:
                # Ghidra's own array type only covers part of a bigger
                # unstructured blob. Don't keep stretching its narrow element
                # type (e.g. uint32_t) across the whole extended region -
                # fall back to raw bytes for both type and size so every byte
                # in the true, larger region round-trips correctly.
                c_type = "uint8_t"
                byte_len = boundary_len
                is_ghidra_array = False  # force final_dim to be recomputed below
            elif is_ghidra_array:
                byte_len = ghidra_len
            else:
                byte_len = boundary_len

            c_size = get_c_type_size(c_type)

            if is_ghidra_array or byte_len > c_size:
                # 1. Maintain true array bounds for C code regardless of extraction size
                num_elements = byte_len // c_size if byte_len // c_size > 0 else 1
                final_dim = dim if is_ghidra_array else f"[{num_elements}]"
                
                # 2. Safely grab the memory block to check initialization
                mem_block = program.getMemory().getBlock(addr)
                is_init = mem_block.isInitialized() if mem_block else False
                
                if not is_init:
                    # 3. Unmapped or BSS section. Do not attempt a read.
                    init_val = "{ 0 }"
                else:
                    # 4. Cap extraction to 1MB to prevent Python OOM, but keep the full C array dimension above
                    extract_len = min(byte_len, 2048 * 2048)
                    init_val = extract_generic_array(program, addr, c_type, extract_len)
                
                db.add_or_update_global(name, gtype=f"{c_type}{final_dim}", value_or_expr=init_val, is_string=False)
            
            else:
                # Extract as a single scalar value
                val = data.getValue() if data else None
                if val is None:
                    val_str = "0"
                elif hasattr(val, 'getUnsignedValue'):
                    val_str = f"0x{val.getUnsignedValue():x}"
                elif hasattr(val, 'getOffset'):
                    val_str = f"0x{(val.getOffset() & 0xFFFFFFFFFFFFFFFF):x}"
                else:
                    val_str = str(val)

                # Clamp values safely
                if val_str.startswith("-0x") or val_str.startswith("0x"):
                    try:
                        num_val = int(val_str, 16)
                        if c_type == "uint8_t": val_str = f"0x{num_val & 0xFF:02x}"
                        elif c_type == "uint16_t": val_str = f"0x{num_val & 0xFFFF:04x}"
                        elif c_type == "uint32_t" or c_type == "int32_t": val_str = f"0x{num_val & 0xFFFFFFFF:08x}L"
                        elif c_type == "uint64_t" or c_type == "int64_t": val_str = f"0x{num_val & 0xFFFFFFFFFFFFFFFF:016x}ULL"
                    except ValueError:
                        pass

                db.add_or_update_global(name, gtype=c_type, value_or_expr=val_str, is_string=False)
    else:
        for name in missing:
            db.add_or_update_global(name, gtype="uintptr_t", value_or_expr="0", is_string=False)

    db.export_header(os.path.basename(header_path))
    db.export_source(os.path.basename(source_path))
    print(f"Added {len(missing)} missing global(s) with real binary values.")

# [Keep your existing DECLARED_RE, C_KEYWORDS, COMMENT_STR_RE, FUNC_RE, DECL_RE, IDENT_RE here]
DECLARED_RE = re.compile(r'extern\s+[\w_]+(?:\s*\*)*\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*;')

C_KEYWORDS = {
    'auto', 'break', 'case', 'char', 'const', 'continue', 'default', 'do',
    'double', 'else', 'enum', 'extern', 'float', 'for', 'goto', 'if',
    'inline', 'int', 'long', 'register', 'restrict', 'return', 'short',
    'signed', 'sizeof', 'static', 'struct', 'switch', 'typedef', 'union',
    'unsigned', 'void', 'volatile', 'while', 'bool', 'true', 'false',
    'NULL', 'uintptr_t', 'int8_t', 'int16_t', 'int32_t', 'int64_t',
    'uint8_t', 'uint16_t', 'uint32_t', 'uint64_t', 'size_t', 'byte',
    'undefined', 'undefined1', 'undefined2', 'undefined4', 'undefined8',
    'ulong', 'ushort', 'uint', 'longlong', 'ulonglong'
}

COMMENT_STR_RE = re.compile(r'//.*?$|/\*.*?\*/|"(?:\\.|[^\\"])*"', re.DOTALL | re.MULTILINE)
FUNC_RE = re.compile(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(')
DECL_RE = re.compile(r'\b(?:[a-zA-Z_][a-zA-Z0-9_]*\s+)+[*]*\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:[=;,\[\)])')
IDENT_RE = re.compile(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b')

def get_declared_globals(header_path):
    declared = set()
    if not os.path.exists(header_path):
        return declared
    with open(header_path, 'r', encoding='utf-8') as f:
        for line in f:
            match = DECLARED_RE.search(line)
            if match:
                declared.add(match.group(1))
    return declared

def find_used_globals(source_dir):
    used = set()
    for root, _, files in os.walk(source_dir):
        for file in files:
            if not file.endswith(('.c', '.cpp')): continue
            path = os.path.join(root, file)
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            clean_code = COMMENT_STR_RE.sub('', content)
            declared_locals = set(DECL_RE.findall(clean_code))
            func_names = set(FUNC_RE.findall(clean_code))

            for match in IDENT_RE.finditer(clean_code):
                name = match.group(1)
                if name not in C_KEYWORDS and name not in declared_locals and name not in func_names:
                    used.add(name)
    return used

def add_missing_values(workspace_dir=".", path_to_binary=None, program=None):
    header_file = os.path.join(workspace_dir, "data_globals.h")
    source_file = os.path.join(workspace_dir, "data_globals.c")
    target_dir = os.path.join(workspace_dir, "extracted_functions")

    if not os.path.isdir(target_dir): sys.exit(1)
    if not os.path.isfile(header_file): sys.exit(1)

    declared = get_declared_globals(header_file)
    used = find_used_globals(target_dir)
    missing = used - declared

    if missing and program is None and path_to_binary is not None:
        with pyghidra.open_program(path_to_binary) as flat_api:
            append_missing_declarations(header_file, source_file, missing, workspace_dir, flat_api.currentProgram)
    else:
        append_missing_declarations(header_file, source_file, missing, workspace_dir, program)

if __name__ == "__main__":
    add_missing_values()