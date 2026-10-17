#!/usr/bin/env python3
"""
centralized SQLite symbol database; renders
data_globals.h / data_globals.c.
"""

import sqlite3
import os
import re
import shutil
from contextlib import contextmanager


class SymbolDB:
    # Decompiler overlap-alias widths -> C types.
    WIDTH_TO_TYPE = {1: 'uint8_t', 2: 'uint16_t', 4: 'uint32_t', 8: 'uint64_t'}

    def __init__(self, workspace_dir=".", db_name="symbols.db"):
        self.workspace_dir = workspace_dir
        self.db_path = os.path.join(workspace_dir, db_name)
        self._init_db()

    def array_global_names(self):
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT name FROM globals WHERE type LIKE '%[%'").fetchall()
        return [r[0] for r in rows]

    def _get_conn(self):
        return sqlite3.connect(self.db_path)

    @contextmanager
    def _conn(self):
        """Commit-and-CLOSE connection scope. (`with sqlite3.connect(...)` only
        commits; it never closes, so every helper call used to leak a handle.)"""
        conn = sqlite3.connect(self.db_path)
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self):
        with self._conn() as conn:
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
            # Persistent compiler-probe results: is this type name already provided by the SDK headers? Keyed by toolchain identity.
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sdk_type_probes (
                    probe_key TEXT PRIMARY KEY,
                    status TEXT NOT NULL
                )
            """)
            # Decompiler overlap aliases ('_Status' over 'Status'): emitted as cast-macros, NOT as second global objects -- two objects cannot legally share an address in C.
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS global_aliases (
                    alias  TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    width  INTEGER NOT NULL DEFAULT 4
                )
            """)
            # Extern declarations for functions that data initialisers point at but that have no
            # prototype in `functions` (rendered into data_globals.c only; skipped once a real prototype exists).
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS source_predecls (
                    name TEXT PRIMARY KEY,
                    decl TEXT NOT NULL
                )
            """)
            # Load-time "relocations" for pointer cells inside byte blobs whose declared type must stay uint8_t[]
            # (an address constant cannot be written into a byte array initialiser).
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS data_fixups (
                    obj         TEXT NOT NULL,
                    byte_offset INTEGER NOT NULL,
                    width       INTEGER NOT NULL,
                    expr        TEXT NOT NULL,
                    PRIMARY KEY (obj, byte_offset)
                )
            """)
            try:
                cursor.execute("ALTER TABLE functions ADD COLUMN func_id TEXT")
            except sqlite3.OperationalError:
                pass  # column already exists
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_functions_func_id "
                           "ON functions(func_id)")
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS custom_types (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE,
                    definition TEXT NOT NULL
                )
            """)
            # Permanent denylists: persist across runs (unlike globals custom_types, which reset_* wipes each Stage-2 run).
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

    # ------------------------------------------------------------------
    # SDK type probe cache (compiler-oracle elision)
    # ------------------------------------------------------------------

    def get_probe_statuses_by_key(self, keys):
        with self._conn() as conn:
            cursor = conn.cursor()
            out = {}
            for key in keys:
                cursor.execute("SELECT status FROM sdk_type_probes "
                               "WHERE probe_key = ?", (key,))
                row = cursor.fetchone()
                if row:
                    out[key] = row[0]
            return out

    def set_probe_statuses(self, mapping):
        if not mapping:
            return
        with self._conn() as conn:
            conn.executemany(
                "INSERT OR REPLACE INTO sdk_type_probes (probe_key, status) "
                "VALUES (?, ?)", list(mapping.items()))
            conn.commit()

    @staticmethod
    def _custom_type_kind(definition, name):
        """'struct'/'union'/'enum' if the definition defines that tag, else 'type'."""
        m = re.search(r'^\s*typedef\s+(struct|union|enum)\s+' + re.escape(name)
                      + r'\b\s*\{', definition, re.MULTILINE)
        return m.group(1) if m else "type"

    # ------------------------------------------------------------------
    # Overlap aliases
    # ------------------------------------------------------------------

    def add_alias(self, alias, target, width=4):
        """Decompiler overlap alias ('_Status' over 'Status'): same address,
        narrower view. Emitted as a cast-macro in export_header."""
        if alias == target:
            return
        with self._conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM excluded_globals WHERE name = ?",
                           (alias,))
            if cursor.fetchone():
                return
            cursor.execute("""
                INSERT INTO global_aliases (alias, target, width)
                VALUES (?, ?, ?)
                ON CONFLICT(alias) DO UPDATE SET
                    target=excluded.target, width=excluded.width
            """, (alias, target, width))
            conn.commit()

    # ------------------------------------------------------------------
    # Custom types
    # ------------------------------------------------------------------

    def add_custom_type(self, name, definition):
        """Inserts a custom type definition, ignoring if it already exists
        to maintain dependency order."""
        with self._conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM excluded_custom_types WHERE name = ?",
                           (name,))
            if cursor.fetchone():
                return  # permanently denylisted
            cursor.execute("""
                INSERT OR IGNORE INTO custom_types (name, definition)
                VALUES (?, ?)
            """, (name, definition))
            conn.commit()

    # ------------------------------------------------------------------
    # Globals
    # ------------------------------------------------------------------

    def add_or_update_global(self, name, gtype="uintptr_t",
                             value_or_expr="0", is_string=False):
        with self._conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM excluded_globals WHERE name = ?",
                           (name,))
            if cursor.fetchone():
                return  # permanently denylisted
            cursor.execute("""
                INSERT INTO globals (name, type, value_or_expr, is_string)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    type=excluded.type,
                    value_or_expr=excluded.value_or_expr,
                    is_string=excluded.is_string
            """, (name, gtype, value_or_expr, 1 if is_string else 0))
            conn.commit()

    def add_predeclaration(self, name, decl):
        """Extern declaration emitted into data_globals.c (never the header)."""
        with self._conn() as conn:
            conn.execute("INSERT OR IGNORE INTO source_predecls (name, decl) "
                         "VALUES (?, ?)", (name, decl))

    def add_fixup(self, obj, byte_offset, width, expr):
        """Pointer cell inside `obj` patched at load time with `expr`."""
        with self._conn() as conn:
            conn.execute("INSERT OR REPLACE INTO data_fixups "
                         "(obj, byte_offset, width, expr) VALUES (?, ?, ?, ?)",
                         (obj, byte_offset, width, expr))

    def exclude_global(self, name):
        """Permanently blacklists a global by name."""
        with self._conn() as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT OR IGNORE INTO excluded_globals (name) "
                           "VALUES (?)", (name,))
            cursor.execute("DELETE FROM globals WHERE name = ?", (name,))
            conn.commit()

    def unexclude_global(self, name):
        with self._conn() as conn:
            conn.execute("DELETE FROM excluded_globals WHERE name = ?", (name,))
            conn.commit()

    def is_global_excluded(self, name):
        with self._conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM excluded_globals WHERE name = ?",
                           (name,))
            return cursor.fetchone() is not None

    def list_excluded_globals(self):
        with self._conn() as conn:
            return [r[0] for r in conn.execute(
                "SELECT name FROM excluded_globals ORDER BY name").fetchall()]

    def exclude_custom_type(self, name):
        with self._conn() as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT OR IGNORE INTO excluded_custom_types (name) "
                           "VALUES (?)", (name,))
            cursor.execute("DELETE FROM custom_types WHERE name = ?", (name,))
            conn.commit()

    def unexclude_custom_type(self, name):
        with self._conn() as conn:
            conn.execute("DELETE FROM excluded_custom_types WHERE name = ?",
                         (name,))
            conn.commit()

    def is_custom_type_excluded(self, name):
        with self._conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM excluded_custom_types WHERE name = ?",
                           (name,))
            return cursor.fetchone() is not None

    def list_excluded_custom_types(self):
        with self._conn() as conn:
            return [r[0] for r in conn.execute(
                "SELECT name FROM excluded_custom_types ORDER BY name"
            ).fetchall()]

    def reset_globals(self):
        """Wipes `globals` so a fresh Stage-2 run reflects only what THIS
        run's filters keep. Does not touch excluded_globals (persistent
        denylist) or functions (accumulate on purpose)."""
        with self._conn() as conn:
            conn.execute("DELETE FROM globals")
            conn.execute("DELETE FROM source_predecls")
            conn.execute("DELETE FROM data_fixups")
            conn.commit()

    def reset_custom_types(self):
        with self._conn() as conn:
            conn.execute("DELETE FROM custom_types")
            conn.commit()

    def list_global_names(self):
        with self._conn() as conn:
            return [r[0] for r in conn.execute(
                "SELECT name FROM globals ORDER BY name").fetchall()]

    def list_custom_type_names(self):
        with self._conn() as conn:
            return [r[0] for r in conn.execute(
                "SELECT name FROM custom_types ORDER BY name").fetchall()]

    # ------------------------------------------------------------------
    # Functions / prototypes
    # ------------------------------------------------------------------

    def has_function(self, name):
        with self._conn() as conn:
            return conn.execute("SELECT 1 FROM functions WHERE name = ?",
                                (name,)).fetchone() is not None

    def get_function_by_name(self, name):
        """Full row, for backup-before-patch / revert logic."""
        with self._conn() as conn:
            return conn.execute(
                "SELECT name, return_type, parameters FROM functions "
                "WHERE name = ?", (name,)).fetchone()

    def delete_function(self, name):
        with self._conn() as conn:
            conn.execute("DELETE FROM functions WHERE name = ?", (name,))
            conn.commit()

    def parse_and_upsert_prototype(self, proto_str, func_id=None):
        """Parses a C prototype string and upserts it."""
        proto_str = proto_str.strip().rstrip(';')
        # The return type may end in '*' with no space: 'char *foo(int)'.
        match = re.match(r'^(.*?[\s\*])([A-Za-z_~][A-Za-z0-9_:~]*)\s*\((.*)\)$',
                         proto_str, re.DOTALL)
        if not match:
            match = re.match(r'^()([A-Za-z_~][A-Za-z0-9_:~]*)\s*\((.*)\)$',
                             proto_str, re.DOTALL)
        if not match:
            return False
        return_type, name, parameters = match.groups()
        return_type = return_type.strip() or "void"
        name = name.strip()
        parameters = parameters.strip()
        is_variadic = 1 if '...' in parameters else 0
        self.add_or_update_function(name, return_type, parameters,
                                    is_variadic, func_id=func_id)
        return True

    def add_or_update_function(self, name, return_type="void",
                               parameters="void", is_variadic=False,
                               func_id=None):
        parameters = " ".join(parameters.split()) if parameters else "void"
        with self._conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO functions (name, func_id, return_type, parameters,
                                       is_variadic)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    func_id=excluded.func_id,
                    return_type=excluded.return_type,
                    parameters=excluded.parameters,
                    is_variadic=excluded.is_variadic
            """, (name, func_id, return_type, parameters,
                  1 if is_variadic else 0))
            conn.commit()

    def get_function_by_func_id(self, func_id):
        if not func_id:
            return None
        with self._conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT return_type, name, parameters FROM functions "
                "WHERE func_id = ?", (func_id,))
            return cursor.fetchone()

    # ------------------------------------------------------------------
    # Header / source rendering
    # ------------------------------------------------------------------

    def export_header(self, header_name="data_globals.h", probe_compiler=None):
        """
        Renders data_globals.h from the DB. Custom types that the SDK
        headers already provide are elided (compiler-oracle probe) so our
        definitions can never conflict with <windows.h>. Deliberately does
        NOT define WIN32_LEAN_AND_MEAN: lean mode excludes subsystems
        (winsock, crypto, shell) malware routinely touches.
        """
        header_path = os.path.join(self.workspace_dir, header_name)
        with self._conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name, definition FROM custom_types "
                           "ORDER BY id ASC")
            custom_types = cursor.fetchall()
            cursor.execute("SELECT name, type, is_string FROM globals "
                           "ORDER BY name")
            globals_list = cursor.fetchall()
            cursor.execute("SELECT name, return_type, parameters FROM functions "
                           "ORDER BY name")
            functions_list = cursor.fetchall()

        # Single source of truth for the shim; the probe reuses the same
        # preamble so the probe environment matches the real header.
        shim_lines = [
            "// --- GHIDRA DECOMPILER SHIM ---",
            "#ifdef __cplusplus",                     # .cpp files are compiled with g++, which
            "#define GH_STATIC_ASSERT(c, m) static_assert(c, m)",   # rejects _Static_assert
            "#else",
            "#define GH_STATIC_ASSERT(c, m) _Static_assert(c, m)",
            "#endif",
            "typedef unsigned char      undefined1;",
            "typedef unsigned short     undefined2;",
            "typedef uint32_t           undefined4;",
            "typedef uint64_t           undefined8;",
            "typedef unsigned char      byte;",
            "typedef unsigned int       uint;",
            "typedef unsigned short     ushort;",
            "typedef unsigned long      ulong;",
            "typedef int64_t            longlong;",   # Ghidra 64-bit names
            "typedef uint64_t           ulonglong;",  # (previously unmapped)
            "typedef signed char        sbyte;",
            "typedef uint8_t            uchar;",
            "typedef void               code;",
        ]

        # --- SDK-conflict elision (compiler oracle) ---
        elisions = {}
        if custom_types:
            probe_compiler = (probe_compiler
                              or os.environ.get("SDK_PROBE_COMPILER",
                                                "i686-w64-mingw32-gcc"))
            if shutil.which(probe_compiler):
                preamble = ["#include <stdint.h>", "#include <windows.h>",
                            "#include <string.h>", "#include <stdlib.h>",
                            "#include <time.h>", "#include <stdio.h>",
                            "#include <math.h>", ""]
                try:
                    try:
                        from database.type_probe import probe_type_names
                    except ImportError:
                        from type_probe import probe_type_names
                    candidates = [(n, self._custom_type_kind(d, n))
                                  for n, d in custom_types]
                    elisions = probe_type_names(
                        candidates, probe_compiler, preamble,
                        cache_get=self.get_probe_statuses_by_key,
                        cache_set=self.set_probe_statuses)
                except Exception as e:
                    print(f"  [warn] SDK type probe failed ({e}); emitting all "
                          f"custom types -- header may conflict with windows.h")
            else:
                print(f"  [warn] probe compiler '{probe_compiler}' not found; "
                      f"emitting all custom types -- header may conflict "
                      f"with windows.h")

        lines = [
            "/* Auto-generated Header from Symbol Database */",
            "#ifndef DATA_GLOBALS_H",
            "#define DATA_GLOBALS_H\n",
            "#include <stdint.h>",
            "#include <windows.h>\n",
            "#include <string.h>",    # strncpy/memcpy/strcmp (Ghidra __builtin_*)
            "#include <stddef.h>",    # offsetof (layout _Static_asserts), uintptr_t
            "#include <stdlib.h>",    # srand/rand/_itoa
            "#include <time.h>",      # time()
            "#include <stdio.h>",     # FILE, used by CRT-internal prototypes
            "#include <math.h>",      # struct _exception (_matherr etc.)
        ]
        lines += shim_lines
        lines.append("\n// --- CUSTOM DATA TYPES ---")

        elided_count = 0
        for name, definition in custom_types:
            status = elisions.get((name, self._custom_type_kind(definition, name)))
            if status in ("sdk", "macro"):
                kind = self._custom_type_kind(definition, name)
                if status == "sdk" and kind in ("struct", "union", "enum"):
                    # Tag-only identity alias: keeps bare-name usage legal
                    # while deferring the layout to the SDK. Identical
                    # typedef redefinition is legal in C11/GNU.
                    lines.append(f"typedef {kind} {name} {name}; "
                                 f"/* deferred to <windows.h> */")
                else:
                    lines.append(f"/* elided '{name}': already provided by "
                                 f"SDK headers ({status}) */")
                elided_count += 1
                continue
            lines.append(definition)
        if elided_count:
            print(f"  Elided {elided_count} SDK-provided type definition(s) "
                  f"from {header_name}")

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

        # Decompiler overlap aliases, as cast-macros.
        with self._conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT alias, target, width FROM global_aliases "
                           "ORDER BY alias")
            aliases = cursor.fetchall()
        if aliases:
            lines.append("\n// --- DECOMPILER OVERLAP ALIASES ---")
            for alias, target, width in aliases:
                t = self.WIDTH_TO_TYPE.get(width, 'uint32_t')
                lines.append(f"#define {alias} (*({t} *)({target}))")

        lines.append("\n// --- REFACTORED FUNCTION PROTOTYPES ---")
        for name, return_type, parameters in functions_list:
            lines.append(f"{return_type} {name}({parameters});")

        lines.append("\n#endif // DATA_GLOBALS_H\n")

        with open(header_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    def update_function_return_type(self, name, return_type):
        """Updates just the return type, preserving parameters."""
        with self._conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO functions (name, return_type, parameters,
                                       is_variadic)
                VALUES (?, ?, 'void', 0)
                ON CONFLICT(name) DO UPDATE SET
                    return_type=excluded.return_type
            """, (name, return_type))
            conn.commit()

    def export_source(self, source_name="data_globals.c",
                      header_name="data_globals.h"):
        source_path = os.path.join(self.workspace_dir, source_name)
        with self._conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name, type, value_or_expr, is_string "
                           "FROM globals ORDER BY name")
            globals_list = cursor.fetchall()
            cursor.execute("SELECT name, decl FROM source_predecls ORDER BY name")
            predecls = cursor.fetchall()
            cursor.execute("SELECT name FROM functions")
            known_funcs = {r[0] for r in cursor.fetchall()}
            cursor.execute("SELECT obj, byte_offset, width, expr FROM data_fixups "
                           "ORDER BY obj, byte_offset")
            fixups = cursor.fetchall()
        global_names = {g[0] for g in globals_list}

        lines = [
            "/* Auto-generated Global Variables Source from Symbol Database */",
            f'#include "{header_name}"\n'
        ]

        # Functions that data initialisers point at but that have no prototype
        # in the header. Skipped if a real prototype appeared in the meantime,
        # because `void f();` would then conflict with it.
        emitted_predecl = False
        for name, decl in predecls:
            if name in known_funcs or name in global_names:
                continue
            if not emitted_predecl:
                lines.append("/* --- functions referenced by data initialisers --- */")
                emitted_predecl = True
            lines.append(decl)
        if emitted_predecl:
            lines.append("")

        for name, gtype, value_or_expr, is_string in globals_list:
            if is_string:
                escaped = value_or_expr if value_or_expr is not None else ""
                lines.append(f'const char {name}[] = "{escaped}";')
            else:
                val = value_or_expr if value_or_expr is not None else "0"
                if '[' in gtype:
                    base_type, array_part = gtype.split('[', 1)
                    lines.append(f"{base_type.strip()} {name}[{array_part} "
                                 f"= {val};")
                else:
                    lines.append(f"{gtype} {name} = {val};")

        fixups = [f for f in fixups if f[0] in global_names]
        if fixups:
            lines.append("")
            lines.append("/* Pointer cells inside byte blobs: the object keeps its recovered")
            lines.append(" * uint8_t[] type (so indexing stays byte-granular) and the address")
            lines.append(" * constants are patched in at load time, like a relocation table. */")
            lines.append("static void __attribute__((constructor)) data_globals_apply_fixups(void)")
            lines.append("{")
            for obj, off, width, expr in fixups:
                lines.append(f"    {{ uintptr_t v = (uintptr_t)({expr}); "
                             f"memcpy((char *)&{obj} + {off}, &v, {width}); }}")
            lines.append("}")

        with open(source_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")