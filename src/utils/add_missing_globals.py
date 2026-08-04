#!/usr/bin/env python3
"""
add_missing_globals.py
-----------------------
Scans all .c files in the extracted_functions directory for DAT_XXXXXXXX
references. If any are missing from LLM_globals.h, appends
'extern uintptr_t DAT_XXXXXXXX;' just before the #endif line.
"""

import os
import re
from database.symbol_db import SymbolDB
import sys

# Regex to extract already declared DAT_ names (assumes extern uintptr_t ...;)
DECLARED_RE = re.compile(r'extern\s+uintptr_t\s+(DAT_[0-9a-fA-F]+)\s*;')

# Regex to find DAT_ addresses in C source files (8 hex digits after underscore)
DAT_PATTERN = re.compile(r'\bDAT_([0-9a-fA-F]{8})\b')

def get_declared_globals(header_path):
    """Return set of DAT_ names already declared in the header."""
    declared = set()
    if not os.path.exists(header_path):
        print(f"Header not found: {header_path}")
        return declared
    with open(header_path, 'r', encoding='utf-8') as f:
        for line in f:
            match = DECLARED_RE.search(line)
            if match:
                declared.add(match.group(1))
    return declared

def find_used_dat_globals(source_dir):
    """Walk through .c files and collect all DAT_XXXXXXXX references."""
    used = set()
    for root, _, files in os.walk(source_dir):
        for file in files:
            if file.endswith('.c'):
                path = os.path.join(root, file)
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    for m in DAT_PATTERN.finditer(content):
                        used.add('DAT_' + m.group(1))
    return used

def append_missing_declarations(header_path, source_path, missing, workspace_dir):
    if not missing:
        print("No missing DAT_ globals found.")
        return

    # FIX: Pass the workspace_dir here as well
    db = SymbolDB(workspace_dir=workspace_dir)
    for name in missing:
        db.add_or_update_global(name, gtype="uintptr_t", value_or_expr="0", is_string=False)
    
    db.export_header(os.path.basename(header_path))
    db.export_source(os.path.basename(source_path))
    print(f"Added {len(missing)} missing DAT_ global(s) to Symbol DB and re-exported headers.")

def add_missing_values(workspace_dir="."):
    # Build workspace-aware paths
    header_file = os.path.join(workspace_dir, "LLM_globals.h")
    source_file = os.path.join(workspace_dir, "LLM_globals.c")
    default_source_dir = os.path.join(workspace_dir, "extracted_functions")

    # Read from CLI arguments if provided, otherwise fallback to workspace's extracted_functions
    target_dir = sys.argv[1] if len(sys.argv) > 1 else default_source_dir
    
    if not os.path.isdir(target_dir):
        print(f"Error: source directory '{target_dir}' not found.")
        sys.exit(1)
    if not os.path.isfile(header_file):
        print(f"Error: header file '{header_file}' not found.")
        sys.exit(1)

    print("Scanning for missing DAT_ globals...")
    declared = get_declared_globals(header_file)
    used = find_used_dat_globals(target_dir)

    missing = used - declared
    
    # FIX: Add the workspace_dir argument to this function call
    append_missing_declarations(header_file, source_file, missing, workspace_dir)
    
    print("Done. Header updated if necessary.")

if __name__ == "__main__":
    add_missing_values()