#!/usr/bin/env python3
"""
add_missing_globals.py -- Stage 4 (Deterministic Symbol Completion).

DISCOVERY: The compiler is the oracle. Stage 3's compilation gates record exactly 
which identifiers failed to resolve (`compile_manifest.json` -> `missing_symbols`). 
Windows.h names, keywords, struct members, and calling conventions never appear 
in that list, so no text-scanning heuristics are needed—and none of the legacy scan's 
poisoning classes (globals named HANDLE/std/__stdcall, struct members like cFileName) 
can occur.

RESOLUTION LADDER per missing name:
  Rung 1: Exact symbol in Ghidra's memory space -> emit from the binary
          (function -> prototype; data -> typed/byte-array global).
  Rung 2: Decompiler overlap alias: '_X' over declared global 'X'
          (e.g., `strcpy(Status,"YES")` compiles to a dword store, which the
          decompiler renders as `_Status = 0x534559;`). Emitted as a
          cast-macro via `db.add_alias`: `#define _Status (*(uint32_t*)(Status))`.
  Rung 3: DAT_<hex> names encode their own address -> resolve directly.
  Rung 4: FUN_<hex> likewise -> emit the Ghidra-signature prototype
          (recovering prototypes that the text parser failed to extract).
  Else:   Recorded in `unresolved_symbols.json` and SKIPPED. Never fabricated: 
          a placeholder `uintptr_t foo = 0;` compiles cleanly while silently 
          redirecting program writes to dead memory.

SIZE PINNING: Call-site literals beat boundary inference (`&blob, 0xc2` 
means 194 bytes even if the boundary scan found 184; `(0x400, Drives)` 
means the buffer is >=1024 bytes even if typed as a scalar).

REUSE: Opens the ALREADY-ANALYZED Stage-1 shared Ghidra project. Never calls 
`pyghidra.open_program()` here, which would otherwise re-run a full analysis 
per function call.
"""

import os
import re
import sys
import json
import struct

import pyghidra
try:
    pyghidra.start()          # No-op if the PyGhidra JVM is already running
except Exception:
    pass

from jpype import JArray, JByte
from database.symbol_db import SymbolDB

WIDTH_TO_TYPE = {1: 'uint8_t', 2: 'uint16_t', 4: 'uint32_t', 8: 'uint64_t'}

_DAT_RE = re.compile(r'^DAT_([0-9A-Fa-f]+)$')
_FUN_RE = re.compile(r'^FUN_([0-9A-Fa-f]+)$')


# ======================================================================
# Type Helpers
# ======================================================================

def parse_ghidra_type_and_dim(dt):
    """
    Parses a Ghidra data type object and extracts its primitive C type and array dimensions.
    
    Why it's here: Ghidra data types (like `undefined1`, `dword`, or custom structs) 
    must be mapped cleanly to strict C99 primitives (`uint8_t`, `uint32_t`, etc.) 
    to ensure the generated headers compile without warnings.
    """
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
    elif ('undefined4' in base_name or 'dword' in base_name
          or 'ulong' in base_name or 'long' in base_name):
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
    """Returns the byte size for a given C primitive type."""
    if "64" in c_type or c_type == "double": 
        return 8
    if "32" in c_type or c_type == "float": 
        return 4
    if "16" in c_type: 
        return 2
    return 1


def _is_incidental_marker(program, addr):
    """
    Checks if an address is an incidental auto-label on undefined data 
    (Ghidra's own DAT_/PTR_ placeholder), NOT a real boundary between two globals.
    
    Why it's here: Skipping incidental markers keeps large unstructured byte arrays 
    intact rather than artificially fragmenting them.
    """
    from ghidra.program.model.symbol import SourceType
    from ghidra.program.model.data import Undefined
    
    data = program.getListing().getDataAt(addr)
    if data is not None and not Undefined.isUndefined(data.getDataType()):
        return False
    syms = list(program.getSymbolTable().getSymbols(addr))
    if not syms:
        return True
    return all(s.getSource() == SourceType.DEFAULT for s in syms)


def get_data_boundary(program, addr):
    """
    Scans forward to the next real memory boundary within the same memory block.
    """
    mem_block = program.getMemory().getBlock(addr)
    if not mem_block:
        return 1
    end_offset = mem_block.getEnd().getOffset() + 1

    def _in_same_block(candidate):
        try:
            return mem_block.contains(candidate)
        except Exception:
            return False

    from ghidra.program.model.data import Undefined
    listing = program.getListing()

    next_sym_offset = end_offset
    for sym in program.getSymbolTable().getSymbolIterator(addr, True):
        sym_addr = sym.getAddress()
        if sym_addr.getOffset() <= addr.getOffset():
            continue
        if not _in_same_block(sym_addr):
            break
        if _is_incidental_marker(program, sym_addr):
            continue
        next_sym_offset = sym_addr.getOffset()
        break

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

    actual = min(next_sym_offset, next_data_offset, end_offset) - addr.getOffset()
    return actual if actual > 0 else 1


def _read_bytes_with_fallback(memory, addr, requested_len):
    """
    Reads binary memory with a robust fallback. If the requested length causes a fault, 
    it binary-searches for the longest readable prefix and zero-pads the remainder.
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
    """
    Converts raw binary memory into a C array initializer block. 
    All-zero blocks automatically collapse to `{ 0 }`.
    """
    try:
        buf, real = _read_bytes_with_fallback(program.getMemory(), addr, byte_len)
        if real < byte_len:
            print(f"WARNING: recovered {real}/{byte_len} bytes at {addr}; "
                  f"{byte_len - real} zero-padded")
        if not any(buf):
            return "{ 0 }"
            
        lines = []
        if "uint32_t" in c_type or "int32_t" in c_type:
            vals = struct.unpack(f"<{byte_len // 4}I", buf[:(byte_len // 4) * 4])
            for i in range(0, len(vals), 8):
                lines.append("  " + ", ".join(f"0x{v:08X}L" for v in vals[i:i+8]))
        elif "uint16_t" in c_type or "int16_t" in c_type:
            vals = struct.unpack(f"<{byte_len // 2}H", buf[:(byte_len // 2) * 2])
            for i in range(0, len(vals), 12):
                lines.append("  " + ", ".join(f"0x{v:04X}" for v in vals[i:i+12]))
        elif "uint64_t" in c_type or "int64_t" in c_type:
            vals = struct.unpack(f"<{byte_len // 8}Q", buf[:(byte_len // 8) * 8])
            for i in range(0, len(vals), 4):
                lines.append("  " + ", ".join(f"0x{v:016X}ULL" for v in vals[i:i+4]))
        else:
            for i in range(0, len(buf), 16):
                lines.append("  " + ", ".join(f"0x{b:02x}" for b in buf[i:i+16]))
                
        return "{\n" + ",\n".join(lines) + "\n}"
    except Exception as e:
        print(f"WARNING: failed to read {byte_len} bytes at {addr}: {e}")
        return "{ 0 }"


# ======================================================================
# Call-Site Size Pinning
# ======================================================================

def pin_length_from_callsites(name, source_dir):
    """
    Performs deterministic size pinning by analyzing arguments passed at function call sites:
      - Pattern 1: `&name, <literal>` (blob passed with explicit byte length)
      - Pattern 2: `<literal>, name` (capacity-then-buffer APIs, e.g., `GetLogicalDriveStringsA(0x400, Drives)`)
    Returns the maximum literal size observed, or None.
    """
    best = None
    p1 = re.compile(rf'&{re.escape(name)}\b\s*,\s*(0x[0-9A-Fa-f]+|\d+)\b')
    p2 = re.compile(
        rf'(0x[0-9A-Fa-f]+|\d+)\s*,\s*(?:\([^()]*\)\s*)?&?{re.escape(name)}\s*[,)]')
        
    for root, _, files in os.walk(source_dir):
        for fname in files:
            if not fname.endswith(('.c', '.cpp')):
                continue
            try:
                with open(os.path.join(root, fname), errors='ignore') as fh:
                    text = fh.read()
            except OSError:
                continue
            for pat in (p1, p2):
                for m in pat.finditer(text):
                    tok = m.group(1)
                    val = int(tok, 16) if tok.lower().startswith('0x') else int(tok)
                    best = val if best is None else max(best, val)
    return best


# ======================================================================
# Core Resolution Ladder
# ======================================================================

def append_missing_declarations(header_path, source_path, missing,
                                workspace_dir, program):
    """
    Iterates through the missing symbol list and executes the 4-rung resolution ladder 
    to extract exact binary data or function prototypes from Ghidra.
    """
    if not missing:
        print("No missing globals found.")
        return
    if program is None:
        raise SystemExit(
            "ERROR: no Ghidra program available. Pass the binary path so the "
            "already-analyzed Stage-1 project can be opened:\n"
            "  python add_missing_globals.py <binary> [workspace_dir]\n"
            "Refusing to emit placeholder values for symbols we cannot read.")

    db = SymbolDB(workspace_dir=workspace_dir)
    symbol_table = program.getSymbolTable()
    listing = program.getListing()
    fn_mgr = program.getFunctionManager()
    extracted_dir = os.path.join(workspace_dir, "extracted_functions")
    unresolved = []

    def _sanitize(n):
        return re.sub(r'[^A-Za-z0-9_]', '_', n or 'param')

    for name in missing:
        all_syms = list(symbol_table.getSymbols(name))
        # Keep memory-space symbols only (filters out stack variables sharing global names)
        symbols = [s for s in all_syms
                   if s.getAddress().getAddressSpace().isMemorySpace()]

        # ---- Rung 2: Decompiler Overlap Alias ('_X' over declared 'X') ----
        if not symbols and name.startswith('_') and name[1:] in db.list_global_names():
            base = name[1:]
            width = 4                       # Default dword store assumption
            for s in all_syms:
                try:
                    w = s.getDataType().getLength()
                    if w in (1, 2, 4, 8):
                        width = w
                        break
                except Exception:
                    pass
            db.add_alias(name, base, width)
            print(f"  [resolve] '{name}' -> alias of '{base}' "
                  f"({WIDTH_TO_TYPE[width]} view)")
            continue

        # ---- Rungs 3 & 4: DAT_ / FUN_ Names Encoding Addresses ----
        m = _DAT_RE.match(name) or _FUN_RE.match(name)
        if not symbols and m:
            addr = (program.getAddressFactory().getDefaultAddressSpace()
                    .getAddress(int(m.group(1), 16)))
            func = fn_mgr.getFunctionAt(addr)
            if func is not None:
                if '::' in func.getName(True):
                    print(f"  [resolve] '{name}' is a C++ member function -- "
                          f"cannot be declared in the C header")
                    unresolved.append(name)
                    continue
                rt, _rd = parse_ghidra_type_and_dim(func.getReturnType())
                ps = []
                for p in func.getParameters():
                    pt, pd = parse_ghidra_type_and_dim(p.getDataType())
                    ps.append(f"{pt}{pd} {_sanitize(p.getName())}")
                if func.hasVarArgs():
                    ps.append("...")
                proto = (f"{rt} {_sanitize(func.getName())}"
                         f"({', '.join(ps) if ps else 'void'});")
                db.parse_and_upsert_prototype(proto)
                print(f"  [resolve] '{name}' -> prototype {proto}")
                continue
                
            blk = program.getMemory().getBlock(addr)
            if (blk and blk.isInitialized() and not blk.isExecute()
                    and fn_mgr.getFunctionContaining(addr) is None):
                size = max(get_data_boundary(program, addr), 1)
                init_val = extract_generic_array(program, addr, "uint8_t", size)
                db.add_or_update_global(name, gtype=f"uint8_t[{size}]",
                                        value_or_expr=init_val, is_string=False)
                print(f"  [resolve] '{name}' -> uint8_t[{size}] @ {addr}")
                continue
                
            print(f"  [resolve] '{name}': synthetic name but no resolvable "
                  f"data/function at encoded address")
            unresolved.append(name)
            continue

        # ---- Rung 1: Exact Memory-Space Symbol ----
        if not symbols:
            # Never fabricate silent placeholders; record as unresolved.
            print(f"  [resolve] '{name}': no memory-space symbol found -- "
                  f"NOT fabricating; recorded as unresolved")
            unresolved.append(name)
            continue

        def _sort_key(sym):
            blk = program.getMemory().getBlock(sym.getAddress())
            return (0 if sym.isPrimary() else 1,
                    0 if (blk and blk.isInitialized()) else 1)
                    
        symbols.sort(key=_sort_key)
        addr = symbols[0].getAddress()

        func = fn_mgr.getFunctionAt(addr)
        if func is not None:
            if '::' in func.getName(True):
                print(f"  [resolve] '{name}' is a C++ member function -- "
                      f"cannot be declared in the C header")
                unresolved.append(name)
                continue
            rt, _rd = parse_ghidra_type_and_dim(func.getReturnType())
            ps = []
            for p in func.getParameters():
                pt, pd = parse_ghidra_type_and_dim(p.getDataType())
                ps.append(f"{pt}{pd} {_sanitize(p.getName())}")
            if func.hasVarArgs():
                ps.append("...")
            proto = (f"{rt} {_sanitize(func.getName())}"
                     f"({', '.join(ps) if ps else 'void'});")
            db.parse_and_upsert_prototype(proto)
            print(f"  [resolve] '{name}' -> prototype {proto}")
            continue

        data = listing.getDefinedDataAt(addr) or listing.getDataAt(addr)
        c_type, dim = "uint8_t", ""
        is_ghidra_array = False
        if data:
            c_type, dim = parse_ghidra_type_and_dim(data.getDataType())
            is_ghidra_array = bool(dim or data.isArray())

        boundary_len = get_data_boundary(program, addr)
        ghidra_len = data.getLength() if data else 0
        byte_len = ghidra_len if is_ghidra_array else boundary_len

        # Call-site evidence overrides boundary inference.
        pinned = pin_length_from_callsites(name, extracted_dir)
        if pinned and pinned > byte_len:
            print(f"  [pin] '{name}': callsite passes {pinned} bytes "
                  f"(> inferred {byte_len}) -- extending at byte granularity")
            c_type, dim, is_ghidra_array = "uint8_t", "", False
            byte_len = pinned

        c_size = get_c_type_size(c_type)
        if is_ghidra_array or byte_len > c_size:
            num_elements = byte_len // c_size if byte_len // c_size > 0 else 1
            final_dim = dim if is_ghidra_array else f"[{num_elements}]"
            mem_block = program.getMemory().getBlock(addr)
            if not mem_block or not mem_block.isInitialized():
                init_val = "{ 0 }"
            else:
                init_val = extract_generic_array(
                    program, addr, c_type, min(byte_len, 2048 * 2048))
            db.add_or_update_global(name, gtype=f"{c_type}{final_dim}",
                                    value_or_expr=init_val, is_string=False)
        else:
            val = data.getValue() if data else None
            if val is None:
                val_str = "0"
            elif hasattr(val, 'getUnsignedValue'):
                val_str = f"0x{val.getUnsignedValue():x}"
            elif hasattr(val, 'getOffset'):
                val_str = f"0x{(val.getOffset() & 0xFFFFFFFFFFFFFFFF):x}"
            else:
                val_str = str(val)
            db.add_or_update_global(name, gtype=c_type,
                                    value_or_expr=val_str, is_string=False)

    # Export synchronized state back to header and source files
    db.export_header(os.path.basename(header_path))
    db.export_source(os.path.basename(source_path))
    print(f"Added {len(missing) - len(unresolved)} symbol(s) with real binary values.")
    
    if unresolved:
        path = os.path.join(workspace_dir, "unresolved_symbols.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(sorted(unresolved), f, indent=2)
        print(f"{len(unresolved)} unresolved name(s) -> {path}")


# ======================================================================
# Entry Points & Orchestration
# ======================================================================

def collect_missing_names(workspace_dir):
    """
    Discovers missing symbols directly from the compilation manifest (`compile_manifest.json`).
    
    Why it's here: The compiler acts as the absolute oracle. By reading compile errors 
    rather than scanning source text, we completely eliminate false positives like 
    system keywords or standard library headers.
    """
    manifest_path = os.path.join(workspace_dir, "compile_manifest.json")
    missing = set()
    if os.path.isfile(manifest_path):
        with open(manifest_path, encoding="utf-8") as f:
            for r in json.load(f).get("functions", []):
                missing.update(r.get("missing_symbols", []))
    return sorted(missing)


def add_missing_values(workspace_dir=".", path_to_binary=None, program=None, names=None):
    """
    Coordinates loading the Stage-1 shared Ghidra project and triggering symbol resolution.
    """
    header_file = os.path.join(workspace_dir, "data_globals.h")
    source_file = os.path.join(workspace_dir, "data_globals.c")
    path_to_binary = path_to_binary or os.environ.get("INPUT_EXE_PATH") or ""
    if path_to_binary:
        path_to_binary = os.path.basename(path_to_binary)
    if not path_to_binary:
        raise SystemExit("ERROR: binary name unknown -- pass path_to_binary "
                         "or set INPUT_EXE_PATH.")

    missing = (sorted(names) if names is not None
               else collect_missing_names(workspace_dir))
    db = SymbolDB(workspace_dir)
    
    if not missing:
        db.export_header(os.path.basename(header_file))
        db.export_source(os.path.basename(source_file))
        print("No missing globals -- header re-synced from DB.")
        return

    if program is not None:
        append_missing_declarations(header_file, source_file, missing,
                                    workspace_dir, program)
        return

    # Reuse the existing Stage-1 project to avoid expensive re-analysis
    binary_name = os.path.basename(path_to_binary)
    project_location = os.path.join(workspace_dir, "ghidra_project")
    project_name = f"{binary_name}_ghidra"
    
    with pyghidra.open_project(project_location, project_name,
                               create=False) as project:
        if project.getProjectData().getFile(f"/{binary_name}") is None:
            raise SystemExit(f"/{binary_name} not in the Ghidra project -- "
                             f"run Stage 1 first.")
        with pyghidra.program_context(project, f"/{binary_name}") as prog:
            append_missing_declarations(header_file, source_file, missing,
                                        workspace_dir, prog)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: add_missing_globals.py <binary_path> [workspace_dir]")
    add_missing_values(workspace_dir=sys.argv[2] if len(sys.argv) > 2 else ".",
                       path_to_binary=sys.argv[1])