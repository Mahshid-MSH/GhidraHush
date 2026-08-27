#!/usr/bin/env python3
"""
symbol_db.py
------------
Centralized SQLite Symbol Database for tracking global variables and function prototypes.
Generates data_globals.h and data_globals.c directly from the database.
"""

import sqlite3
import os
import re

class SymbolDB:
    def __init__(self, workspace_dir=".", db_name="symbols.db"):
        self.workspace_dir = workspace_dir
        self.db_path = os.path.join(workspace_dir, db_name)
        self._init_db()

    def _get_conn(self):
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS globals (
                    name TEXT PRIMARY KEY,
                    type TEXT NOT NULL,
                    value_or_expr TEXT,
                    is_string INTEGER NOT NULL DEFAULT 0
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS functions (
                    name TEXT PRIMARY KEY,
                    return_type TEXT NOT NULL,
                    parameters TEXT NOT NULL,
                    is_variadic INTEGER NOT NULL DEFAULT 0
                )
            """)
            # NEW: Tracks custom struct/enum/union definitions maintaining dependency order
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS custom_types (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE,
                    definition TEXT NOT NULL
                )
            """)
            conn.commit()

    def add_custom_type(self, name, definition):
        """Inserts a custom type definition, ignoring if it already exists to maintain dependency order."""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR IGNORE INTO custom_types (name, definition)
                VALUES (?, ?)
            """, (name, definition))
            conn.commit()

    def add_or_update_global(self, name, gtype="uintptr_t", value_or_expr="0", is_string=False):
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO globals (name, type, value_or_expr, is_string)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    type=excluded.type,
                    value_or_expr=excluded.value_or_expr,
                    is_string=excluded.is_string
            """, (name, gtype, value_or_expr, 1 if is_string else 0))
            conn.commit()

    def parse_and_upsert_prototype(self, proto_str):
        """
        Parses a C function prototype string (e.g., 'int foo(char *bar, int baz);') 
        and upserts it into the functions table.
        """
        proto_str = proto_str.strip().rstrip(';')
        # Match return type, function name, and parameter block
        match = re.match(r'^(.*?)\s+([a-zA-Z_]\w*)\s*\((.*)\)$', proto_str, re.DOTALL)
        if not match:
            return False
            
        return_type, name, parameters = match.groups()
        return_type = return_type.strip()
        name = name.strip()
        parameters = parameters.strip()
        
        is_variadic = 1 if '...' in parameters else 0
        self.add_or_update_function(name, return_type, parameters, is_variadic)
        return True

    def add_or_update_function(self, name, return_type="void", parameters="void", is_variadic=False):
        parameters = " ".join(parameters.split()) if parameters else "void"
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO functions (name, return_type, parameters, is_variadic)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    return_type=excluded.return_type,
                    parameters=excluded.parameters,
                    is_variadic=excluded.is_variadic
            """, (name, return_type, parameters, 1 if is_variadic else 0))
            conn.commit()

    def export_header(self, header_name="data_globals.h"):
        header_path = os.path.join(self.workspace_dir, header_name)
        with self._get_conn() as conn:
            cursor = conn.cursor()
            # Fetch custom types ordered by ID so nested dependencies are declared correctly!
            cursor.execute("SELECT definition FROM custom_types ORDER BY id ASC")
            custom_types_list = cursor.fetchall()

            cursor.execute("SELECT name, type, is_string FROM globals ORDER BY name")
            globals_list = cursor.fetchall()

            cursor.execute("SELECT name, return_type, parameters FROM functions ORDER BY name")
            functions_list = cursor.fetchall()

        lines = [
            "/* Auto-generated Header from Symbol Database */",
            "#ifndef DATA_GLOBALS_H",
            "#define DATA_GLOBALS_H\n",
            "#ifndef WIN32_LEAN_AND_MEAN",
            "#define WIN32_LEAN_AND_MEAN",
            "#endif\n",
            "#include <stdint.h>",
            "#include <windows.h>\n",
            "// --- GHIDRA DECOMPILER SHIM ---",
            "typedef unsigned char      undefined1;",
            "typedef unsigned short     undefined2;",
            "typedef uint32_t           undefined4;",
            "typedef uint64_t           undefined8;",
            "typedef unsigned char      byte;",
            "typedef unsigned int       uint;",
            "typedef unsigned short     ushort;",
            "typedef unsigned long      ulong;",
            "typedef void               code;\n",
            "// --- CUSTOM DATA TYPES ---"
        ]

        # Inject definitions directly before globals
        for (definition,) in custom_types_list:
            lines.append(definition)

        lines.append("\n// --- GLOBAL VARIABLES ---")
        for name, gtype, is_string in globals_list:
            if is_string:
                lines.append(f"extern const char {name}[];")
            else:
                if '[' in gtype:
                    base_type, array_part = gtype.split('[', 1)
                    lines.append(f"extern {base_type.strip()} {name}[{array_part};")
                else:
                    lines.append(f"extern {gtype} {name};")

        lines.append("\n// --- REFACTORED FUNCTION PROTOTYPES ---")
        for name, return_type, parameters in functions_list:
            lines.append(f"{return_type} {name}({parameters});")

        # Safely pad the endif to guarantee nothing is appended afterwards
        lines.append("\n#endif // DATA_GLOBALS_H\n")

        with open(header_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    def update_function_return_type(self, name, return_type):
        """Updates just the return type of a function, preserving its parameters."""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO functions (name, return_type, parameters, is_variadic)
                VALUES (?, ?, 'void', 0)
                ON CONFLICT(name) DO UPDATE SET
                    return_type=excluded.return_type
            """, (name, return_type))
            conn.commit()

    def export_source(self, source_name="data_globals.c", header_name="data_globals.h"):
        source_path = os.path.join(self.workspace_dir, source_name)
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name, type, value_or_expr, is_string FROM globals ORDER BY name")
            globals_list = cursor.fetchall()

        lines = [
            "/* Auto-generated Global Variables Source from Symbol Database */",
            f'#include "{header_name}"\n'
        ]

        for name, gtype, value_or_expr, is_string in globals_list:
            if is_string:
                escaped = value_or_expr if value_or_expr is not None else ""
                lines.append(f'const char {name}[] = "{escaped}";')
            else:
                val = value_or_expr if value_or_expr is not None else "0"
                if '[' in gtype:
                    base_type, array_part = gtype.split('[', 1)
                    lines.append(f"{base_type.strip()} {name}[{array_part} = {val};")
                else:
                    lines.append(f"{gtype} {name} = {val};")

        with open(source_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")