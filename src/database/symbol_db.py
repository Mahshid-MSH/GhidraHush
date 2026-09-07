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
                    func_id TEXT,
                    return_type TEXT NOT NULL,
                    parameters TEXT NOT NULL,
                    is_variadic INTEGER NOT NULL DEFAULT 0
                )
            """)
            try:
                cursor.execute("ALTER TABLE functions ADD COLUMN func_id TEXT")
            except sqlite3.OperationalError:
                pass  # column already exists
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_functions_func_id ON functions(func_id)")
            # NEW: Tracks custom struct/enum/union definitions maintaining dependency order
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS custom_types (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE,
                    definition TEXT NOT NULL
                )
            """)
            # NEW: Permanent denylists. Unlike `globals`/`custom_types`
            # (which reset_globals()/reset_custom_types() wipe clean at the
            # start of every dump_global_values.py run, so stale entries
            # from older/looser filter versions can't linger forever),
            # these persist across runs -- once a name is marked excluded
            # via exclude_global()/exclude_custom_type(), it stays excluded
            # even though Ghidra will keep finding it on every future pass.
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS excluded_globals (
                    name TEXT PRIMARY KEY
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS excluded_custom_types (
                    name TEXT PRIMARY KEY
                )
            """)
            conn.commit()

    def add_custom_type(self, name, definition):
        """Inserts a custom type definition, ignoring if it already exists to maintain dependency order."""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM excluded_custom_types WHERE name = ?", (name,))
            if cursor.fetchone():
                return  # permanently denylisted, see exclude_custom_type()
            cursor.execute("""
                INSERT OR IGNORE INTO custom_types (name, definition)
                VALUES (?, ?)
            """, (name, definition))
            conn.commit()

    def add_or_update_global(self, name, gtype="uintptr_t", value_or_expr="0", is_string=False):
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM excluded_globals WHERE name = ?", (name,))
            if cursor.fetchone():
                return  # permanently denylisted, see exclude_global()
            cursor.execute("""
                INSERT INTO globals (name, type, value_or_expr, is_string)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    type=excluded.type,
                    value_or_expr=excluded.value_or_expr,
                    is_string=excluded.is_string
            """, (name, gtype, value_or_expr, 1 if is_string else 0))
            conn.commit()

    def exclude_global(self, name):
        """Permanently blacklists a global by name: deletes it from
        `globals` right now, and remembers the exclusion so future
        dump_global_values.py runs won't silently re-add it even though
        Ghidra still considers it a legitimate, function-referenced symbol."""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT OR IGNORE INTO excluded_globals (name) VALUES (?)", (name,))
            cursor.execute("DELETE FROM globals WHERE name = ?", (name,))
            conn.commit()

    def unexclude_global(self, name):
        """Reverses exclude_global(); the symbol can be re-added on the next run."""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM excluded_globals WHERE name = ?", (name,))
            conn.commit()

    def is_global_excluded(self, name):
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM excluded_globals WHERE name = ?", (name,))
            return cursor.fetchone() is not None

    def list_excluded_globals(self):
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM excluded_globals ORDER BY name")
            return [row[0] for row in cursor.fetchall()]

    def exclude_custom_type(self, name):
        """Same as exclude_global() but for a custom_types entry (a
        struct/enum/union/typedef tag name)."""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT OR IGNORE INTO excluded_custom_types (name) VALUES (?)", (name,))
            cursor.execute("DELETE FROM custom_types WHERE name = ?", (name,))
            conn.commit()

    def unexclude_custom_type(self, name):
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM excluded_custom_types WHERE name = ?", (name,))
            conn.commit()

    def is_custom_type_excluded(self, name):
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM excluded_custom_types WHERE name = ?", (name,))
            return cursor.fetchone() is not None

    def list_excluded_custom_types(self):
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM excluded_custom_types ORDER BY name")
            return [row[0] for row in cursor.fetchall()]

    def reset_globals(self):
        """Wipes the `globals` table so a fresh Ghidra analysis run reflects
        only what THIS run's filters currently decide to keep, instead of
        accumulating every symbol any past (possibly looser) version of the
        extractor ever inserted. Does not touch `excluded_globals` (that
        denylist is meant to persist) or `functions` (those accumulate
        across incremental per-function enhancement runs on purpose)."""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM globals")
            conn.commit()

    def reset_custom_types(self):
        """Same as reset_globals(), for the `custom_types` table."""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM custom_types")
            conn.commit()

    def list_global_names(self):
        """All global names currently in the DB (for diffing against a
        hand-edited header -- see manage_symbols.py's `sync` command)."""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM globals ORDER BY name")
            return [row[0] for row in cursor.fetchall()]

    def list_custom_type_names(self):
        """All custom type names currently in the DB (for diffing against a
        hand-edited header -- see manage_symbols.py's `sync` command)."""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM custom_types ORDER BY name")
            return [row[0] for row in cursor.fetchall()]

    def parse_and_upsert_prototype(self, proto_str, func_id=None):
        """
        Parses a C/C++ function prototype string (e.g., 'int foo(char *bar, int baz);'
        """
        proto_str = proto_str.strip().rstrip(';')
        match = re.match(r'^(.*?)\s+([A-Za-z_~][A-Za-z0-9_:~]*)\s*\((.*)\)$', proto_str, re.DOTALL)
        if not match:
            # Constructors/destructors have no return type at all (e.g.
            # "MyClass::MyClass(MyClass *this);"), so also accept a prototype
            # with nothing before the name.
            match = re.match(r'^()([A-Za-z_~][A-Za-z0-9_:~]*)\s*\((.*)\)$', proto_str, re.DOTALL)
        if not match:
            return False

        return_type, name, parameters = match.groups()
        return_type = return_type.strip() or "void"
        name = name.strip()
        parameters = parameters.strip()

        is_variadic = 1 if '...' in parameters else 0
        self.add_or_update_function(name, return_type, parameters, is_variadic, func_id=func_id)
        return True

    def add_or_update_function(self, name, return_type="void", parameters="void", is_variadic=False, func_id=None):
        parameters = " ".join(parameters.split()) if parameters else "void"
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO functions (name, func_id, return_type, parameters, is_variadic)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    func_id=excluded.func_id,
                    return_type=excluded.return_type,
                    parameters=excluded.parameters,
                    is_variadic=excluded.is_variadic
            """, (name, func_id, return_type, parameters, 1 if is_variadic else 0))
            conn.commit()

    def get_function_by_func_id(self, func_id):
        """Look up a synced prototype by its stable Ghidra-address-based id
        rather than by display name. Display names can repeat across a
        binary (overloads, same-named methods in different classes, same-
        named statics across translation units), so they aren't a safe join
        key -- func_id (derived from the function's entry point) is."""
        if not func_id:
            return None
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT return_type, name, parameters FROM functions WHERE func_id = ?",
                (func_id,)
            )
            return cursor.fetchone()

    def export_header(self, header_name="data_globals.h"):
        """Renders data_globals.h purely from the DB: Ghidra's decompiler
        shim typedefs, then custom_types (user-defined structs/unions/
        enums/typedefs only -- see dump_global_values.py's
        is_windows_provided_type()), then extern globals, then function
        prototypes.

        Deliberately does NOT define WIN32_LEAN_AND_MEAN before
        `#include <windows.h>`. Lean mode excludes whole subsystems
        (winsock, wincrypt, shell, RPC/COM, ...) that malware samples
        routinely touch -- so a binary using sockets or crypto APIs would
        hit "unknown type"/"implicit declaration" for perfectly real
        WinAPI names, defeating the entire point of trusting windows.h
        instead of hand-defining things. Since Stage 4's compile-check is
        `-fsyntax-only` (see c_code_enhancer.py) and never links, the
        extra parse time from the full, non-lean windows.h costs nothing
        that matters here.
        """
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