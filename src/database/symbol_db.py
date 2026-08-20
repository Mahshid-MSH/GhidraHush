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
        """Creates the required tables if they do not exist."""
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
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS call_sites (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    caller TEXT NOT NULL,
                    callee TEXT NOT NULL,
                    arg_count INTEGER NOT NULL,
                    arg_types TEXT
                )
            """)
            conn.commit()

    def add_or_update_global(self, name, gtype="uintptr_t", value_or_expr="0", is_string=False):
        """Inserts or updates a global variable entry."""
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

    def add_or_update_function(self, name, return_type="void", parameters="void", is_variadic=False):
        """Inserts or updates a function signature entry."""
        # Clean up parameters formatting
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

    def update_function_return_type(self, name, return_type):
        """Updates the return type of an existing function while keeping parameters intact."""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT parameters FROM functions WHERE name = ?", (name,))
            row = cursor.fetchone()
            if row:
                cursor.execute("UPDATE functions SET return_type = ? WHERE name = ?", (return_type, name))
            else:
                cursor.execute("INSERT INTO functions (name, return_type, parameters) VALUES (?, ?, ?)", 
                               (name, return_type, "void"))
            conn.commit()

    def parse_and_upsert_prototype(self, prototype_str):
        """Helper to parse a raw prototype string 'int FindProcessId(char *a);' and insert into DB."""
        clean = prototype_str.strip().rstrip(';')
        # Matches return_type function_name(args) for any valid C identifier
        match = re.search(r'([\w\s\*]+)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)', clean)
        if match:
            return_type = match.group(1).strip()
            func_name = match.group(2).strip()
            args = match.group(3).strip() or "void"
            self.add_or_update_function(func_name, return_type, args)
            return True
        return False

    def export_header(self, header_name="data_globals.h"):
        """Generates the clean data_globals.h file directly from the database."""
        header_path = os.path.join(self.workspace_dir, header_name)
        with self._get_conn() as conn:
            cursor = conn.cursor()
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
            "#include <windows.h>",
            "// --- GHIDRA DECOMPILER SHIM ---",
            "typedef unsigned char      undefined1;",
            "typedef unsigned short     undefined2;",
            "typedef uint32_t           undefined4;",
            "typedef uint64_t           undefined8;",
            "typedef unsigned char      byte;",
            "typedef unsigned int       uint;",
            "typedef unsigned short     ushort;",
            "typedef unsigned long      ulong;",
            "typedef void               code;\n"
            #"// --- GLOBAL VARIABLES ---"
        ]

        for name, gtype, is_string in globals_list:
            if is_string:
                lines.append(f"extern const char {name}[];")
            else:
                if '[' in gtype:
                    # Split 'uint8_t[16]' into 'uint8_t' and '16]'
                    base_type, array_part = gtype.split('[', 1)
                    lines.append(f"extern {base_type.strip()} {name}[{array_part};")
                else:
                    lines.append(f"extern {gtype} {name};")

        lines.append("\n// --- REFACTORED FUNCTION PROTOTYPES ---")
        for name, return_type, parameters in functions_list:
            lines.append(f"{return_type} {name}({parameters});")

        lines.append("\n#endif // DATA_GLOBALS_H\n")    # This line generates errors, because some stuff get added after it!

        with open(header_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    def export_source(self, source_name="data_globals.c", header_name="data_globals.h"):
        """Generates the clean data_globals.c file directly from the database."""
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


    def remove_function(self, name):
        """Remove a function entry from the database."""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            # Check if the function exists
            cursor.execute("SELECT 1 FROM functions WHERE name = ?", (name,))
            if cursor.fetchone():
                # Delete it from the SQL database
                cursor.execute("DELETE FROM functions WHERE name = ?", (name,))
                conn.commit()
                return True
            return False