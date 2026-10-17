#!/usr/bin/env python3
"""
ast_patcher.py
--------------
Parses C source code using `pycparser` to detect functions whose return values 
are assigned to typed variables, but are incorrectly declared as 'void' in `data_globals.h`. 
Also strips Ghidra cast artifacts and simplifies complex pointer arithmetic.

NOTE: `pycparser` is a pure C parser with no preprocessor and no knowledge of system 
headers. To prevent parsing failures on Windows APIs or custom types, this module 
injects dynamic parser scaffolding (mock typedefs) and strips them before code generation.
"""

import os
import re
from pycparser import c_parser, c_ast, c_generator
from database.symbol_db import SymbolDB


# Console styling constants for rich logging output (if needed)
DIM, RED, GREEN, YELLOW, CYAN, RESET = (
    '\033[2m', '\033[91m', '\033[92m', '\033[93m', '\033[96m', '\033[0m'
)


def ast_tools_applicable(filepath):
    """
    Determines whether AST tools can be applied to the target file.
    
    Why it's here: `pycparser` only understands standard C99 syntax. C++ constructs 
    (`std::`, templates, `new`/`delete`, `::` scope resolution) will break the parser. 
    Thus, AST tools are strictly restricted to `.c` files.
    """
    return filepath.endswith(".c")


# Functions whose declarations are owned by system headers. AST return-type inference 
# must NEVER patch these: writing custom return types for standard library/Windows 
# functions creates conflicting-prototype errors against <string.h>, <stdlib.h>, or windows.h.
CRT_PROVIDED = frozenset({
    'strlen', 'strncpy', 'strcpy', 'strcat', 'strcmp', 'strncmp', 'strstr',
    'memcpy', 'memmove', 'memset', 'memcmp', 'malloc', 'calloc', 'realloc',
    'free', 'printf', 'sprintf', 'snprintf', 'puts', 'exit', 'rand', 'srand',
    'time', '_itoa', 'itoa', 'atoi', 'atol', 'tolower', 'toupper',
})


# Static seed for parser scaffolding. These types allow `pycparser` to successfully 
# parse decompiled binary bodies without requiring full SDK header inclusion.
FAKE_TYPE_SEED = {
    # stdint/stddef stand-ins
    'uintptr_t', 'intptr_t', 'uint8_t', 'uint16_t', 'uint32_t', 'uint64_t',
    'int8_t', 'int16_t', 'int32_t', 'int64_t', 'size_t', 'ssize_t',
    'SIZE_T', 'SSIZE_T', 'ULONG_PTR', 'bool', 'uint', 'ulong', 'ushort',
    'uchar', 'qword', 'longlong', 'ulonglong',
    # Ghidra primitives
    'undefined', 'undefined1', 'undefined2', 'undefined4', 'undefined8',
    # Common Windows SDK names appearing in decompiled bodies
    'HANDLE', 'LPVOID', 'PVOID', 'LPCSTR', 'LPSTR', 'LPCWSTR', 'LPWSTR',
    'LPCTSTR', 'LPTSTR', 'DWORD', 'WORD', 'BYTE', 'BOOL', 'CHAR', 'WCHAR',
    'TCHAR', 'FARPROC', 'HMODULE', 'HINSTANCE', 'HWND', 'HKEY', 'HDC',
    'HGLOBAL', 'HINTERNET', 'NTSTATUS', 'WPARAM', 'LPARAM', 'LRESULT',
    'UINT', 'ULONG', 'USHORT', 'PWSTR', 'PHANDLE', 'LPBYTE', 'LPDWORD',
    'LSTATUS', 'SC_HANDLE', 'SERVICE_STATUS_HANDLE', 'HCRYPTPROV',
    'HCRYPTHASH', 'HCRYPTKEY', 'SOCKET', 'ATOM',
    # Structures frequently referenced in decompiled binaries
    'WIN32_FIND_DATAA', 'WIN32_FIND_DATAW', 'STARTUPINFOA', 'STARTUPINFOW',
    'PROCESS_INFORMATION', 'SYSTEM_INFO', 'WSADATA', 'MSG', 'PAINTSTRUCT',
    'WNDCLASSEXA', 'sockaddr', 'sockaddr_in', 'hostent',
}


def _collect_fake_types(header_path=None):
    """
    Combines static seed types with every typedef and struct tag defined in `data_globals.h`.
    
    Why it's here: Ensures custom function pointers, malware structures, and project-specific 
    types parse cleanly through `pycparser` with zero manual list maintenance.
    """
    names = set(FAKE_TYPE_SEED)
    tags = set()
    
    if header_path and os.path.isfile(header_path):
        with open(header_path, encoding="utf-8", errors="ignore") as f:
            text = f.read()
            
        for m in re.finditer(r'\btypedef\b[^;]*;', text, re.DOTALL):
            decl = m.group(0)
            if '{' in decl:
                # E.g., 'typedef struct X {...} NAME, *PNAME;' -> typedef names follow closing brace
                after = decl.split('}', 1)[1]
                for mm in re.finditer(r'([A-Za-z_]\w*)', after):
                    names.add(mm.group(1))
                continue
                
            # Bodyless typedef: name is inside '(*X)' (function pointers) or is the trailing identifier
            mm = re.search(r'\(\s*\*\s*([A-Za-z_]\w*)\s*\)', decl)
            if not mm:
                mm = re.search(r'([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*;\s*$', decl)
            if mm:
                names.add(mm.group(1))
                
        for m in re.finditer(r'\b(?:struct|union|enum)\s+([A-Za-z_]\w*)', text):
            tags.add(m.group(1))
            
    return names, tags


def _fake_prelude(header_path=None):
    """
    Generates a mock prelude string of dummy `typedef` and `struct` declarations 
    to prepend during AST parsing, along with a set of names to strip later.
    """
    names, tags = _collect_fake_types(header_path)
    parts = [f"typedef int {n};" for n in sorted(names)]
    parts += [f"struct {t} {{ int _m; }};" for t in sorted(tags)]
    return "\n".join(parts) + "\n", (names | tags)


def _strip_fake_externals(ast, strip_names):
    """
    Removes every mock declaration from the parsed top-level AST before code generation.
    
    Why it's here: Prevents parser scaffolding (`typedef int HANDLE;`, etc.) from 
    leaking into regenerated code and conflicting with real system headers.
    """
    def is_fake(node):
        if isinstance(node, c_ast.Typedef) and node.name in strip_names:
            return True
        if isinstance(node, c_ast.Decl) and node.name is None:
            t = node.type
            if isinstance(t, (c_ast.Struct, c_ast.Union)) and t.name in strip_names:
                return True
        return False
        
    if hasattr(ast, 'ext'):
        ast.ext = [n for n in ast.ext if not is_fake(n)]


def sanitize_code_for_pycparser(c_code):
    """
    Strips compiler attributes, comments, placeholder statements, and preprocessor 
    directives that `pycparser` cannot parse.
    """
    # 1. Strip non-breaking spaces
    clean = c_code.replace('\xa0', ' ')

    # 2. Remove single-line (//) and block (/* */) comments
    clean = re.sub(r'//.*?$', '', clean, flags=re.MULTILINE)
    clean = re.sub(r'/\*.*?\*/', '', clean, flags=re.DOTALL)

    # 3. Remove placeholder statements like "original_statement_1;"
    clean = re.sub(r'\boriginal_statement_\d+\s*;', '', clean)

    # 4. Strip ALL preprocessor directives (#include, #pragma, #line, #if, etc.)
    clean = re.sub(r'^\s*#.*?$', '', clean, flags=re.MULTILINE)

    # 5. Strip standard Ghidra and Windows compiler attributes/macros
    clean = re.sub(r'\b(__stdcall|__cdecl|__fastcall|__thiscall|WINAPI|APIENTRY|CALLBACK|NTAPI)\b', '', clean)
    clean = re.sub(r'\b__declspec\([^)]*\)', '', clean)

    # 6. Convert MSVC integer primitives to standard C primitives
    clean = re.sub(r'\b__int64\b', 'long long', clean)
    clean = re.sub(r'\b__int32\b', 'int', clean)
    clean = re.sub(r'\b__int16\b', 'short', clean)
    clean = re.sub(r'\b__int8\b', 'char', clean)
    clean = re.sub(r'\b__forceinline\b', 'inline', clean)

    # 7. Remove stray backslashes at line ends (common in Ghidra output)
    clean = re.sub(r'\\\n', '\n', clean)

    return clean


# ======================================================================
# AST Visitors for Analysis & Cleaning
# ======================================================================

class AssignmentVisitor(c_ast.NodeVisitor):
    """
    Traverses the AST to trace function return values assigned to typed variables 
    or declared with explicit types.
    """
    def __init__(self):
        self.function_calls = []
        self.var_types = {}
        self.generator = c_generator.CGenerator()

    def _get_type_str(self, decl_node):
        try:
            return self.generator.visit(decl_node.type).strip()
        except Exception:
            return "unknown"

    def _get_func_name(self, func_call_node):
        if isinstance(func_call_node.name, c_ast.ID):
            return func_call_node.name.name
        return None

    def visit_Decl(self, node):
        if node.name and node.type:
            type_str = self._get_type_str(node)
            self.var_types[node.name] = type_str

            if isinstance(node.init, c_ast.FuncCall):
                func_name = self._get_func_name(node.init)
                if func_name:
                    self.function_calls.append({
                        "func_name": func_name,
                        "required_return_type": type_str
                    })

        self.generic_visit(node)

    def visit_Assignment(self, node):
        if isinstance(node.rvalue, c_ast.FuncCall):
            func_name = self._get_func_name(node.rvalue)
            if func_name:
                lvalue_type = "unknown"
                if isinstance(node.lvalue, c_ast.ID):
                    lvalue_type = self.var_types.get(node.lvalue.name, "unknown")
                
                if lvalue_type != "unknown":
                    self.function_calls.append({
                        "func_name": func_name,
                        "required_return_type": lvalue_type
                    })

        self.generic_visit(node)


class CodeCleaner(c_ast.NodeVisitor):
    """
    AST cleaner that simplifies verbose pointer arithmetic into clean array
    subscript notation (`ptr[offset]`). It no longer strips casts or injects
    (void*) casts: both changed program behaviour (verified by compiling + running).
    """
    def visit_Assignment(self, node):
        # NOTE: this used to wrap every `x = <int literal>` in (void*)(uintptr_t)...
        # The cleaner knows nothing about the type of `x`, so that turned
        # `double d; d = 5;` into a compile error and added pointer round-trips to
        # every integer store. Removed: no information => no rewrite.
        self.generic_visit(node)

    def clean_node(self, node):
        """Rewrites *(a + b) -> a[b]: identical by definition in C (E1[E2] == *(E1+E2)),
        so it is purely cosmetic. Casts are deliberately KEPT -- stripping them silently
        changed arithmetic and memory-access semantics (see class docstring)."""
        def rewrite(child):
            if (isinstance(child, c_ast.UnaryOp) and child.op == '*'
                    and isinstance(child.expr, c_ast.BinaryOp) and child.expr.op == '+'):
                return c_ast.ArrayRef(name=child.expr.left, subscript=child.expr.right)
            return child

        for attr_name in getattr(node, '__slots__', []):
            attr = getattr(node, attr_name)
            if attr is None:
                continue
            if isinstance(attr, list):
                for i, child in enumerate(attr):
                    if isinstance(child, c_ast.Node):
                        self.clean_node(child)
                        attr[i] = rewrite(child)
            elif isinstance(attr, c_ast.Node):
                self.clean_node(attr)
                setattr(node, attr_name, rewrite(attr))


# ======================================================================
# Public Orchestration Functions
# ======================================================================

def proactive_header_patch(header_path, ast_analysis, workspace_dir="."):
    """
    Applies return-type discoveries from AST analysis back to `SymbolDB` and updates 
    the global header file.
    """
    if not ast_analysis:
        return False

    db = SymbolDB(workspace_dir)
    modified = False

    for item in ast_analysis:
        func_name = item["func_name"]
        new_type = item["required_return_type"]
        
        if new_type in ("unknown", "void"):
            continue                       # Void-to-void changes nothing
        if func_name in CRT_PROVIDED:
            continue                       # System headers own these declarations
        if not db.has_function(func_name):
            continue                       # Never invent arbitrary prototypes
            
        db.update_function_return_type(func_name, new_type)
        print(f"[AST] return type of '{func_name}' -> {new_type}")
        modified = True

    if modified:
        db.export_header(os.path.basename(header_path))
        return True
    return False


def analyze_ast_types(c_code, header_path=None):
    """
    Performs assignment-site return-type inference by parsing C code into an AST 
    and executing the `AssignmentVisitor`.
    """
    code_no_directives = re.sub(r'#include\s*[<"].*?[>"]', '', c_code)
    clean_code = sanitize_code_for_pycparser(code_no_directives)

    prelude, _ = _fake_prelude(header_path)
    parser = c_parser.CParser()
    try:
        ast = parser.parse(prelude + clean_code)
        visitor = AssignmentVisitor()
        visitor.visit(ast)
        return visitor.function_calls
    except Exception as e:
        print(f"[AST Analysis Error] {e}")
        return []


_CALLCONV_RE = re.compile(r'\b(__stdcall|__cdecl|__fastcall|__thiscall|WINAPI|APIENTRY|CALLBACK|NTAPI)\b')


def clean_decompiled_code(c_code, header_path=None):
    """
    Parses decompiled C bodies, strips Ghidra cast artifacts, simplifies pointer 
    arithmetic, and regenerates clean C code. All parser scaffolding is stripped before output.
    """
    # pycparser cannot parse calling conventions, so they are stripped before parsing --
    # and the regenerated text would permanently lack them. A stdcall callback
    # (ThreadProc, WndProc...) compiled as cdecl corrupts the stack on x86 when
    # Windows calls it. The cleanup is cosmetic, so skip such files entirely.
    if _CALLCONV_RE.search(c_code):
        return c_code

    preprocessor_lines = []
    body_lines = []
    
    for line in c_code.split('\n'):
        if line.strip().startswith('#'):
            preprocessor_lines.append(line)
        else:
            body_lines.append(line)

    body_code = '\n'.join(body_lines)
    clean_body = sanitize_code_for_pycparser(body_code)

    prelude, strip_names = _fake_prelude(header_path)
    parser = c_parser.CParser()
    try:
        ast = parser.parse(prelude + clean_body)
    except Exception as e:
        print(f"[AST Cleaner] Skipping cast cleanup due to parse error: {e}")
        return c_code

    # Strip parser scaffolding so it never leaks into shipped files
    _strip_fake_externals(ast, strip_names)

    # Clean AST nodes (casts, pointer math)
    cleaner = CodeCleaner()
    cleaner.clean_node(ast)
    cleaner.visit(ast)

    regenerated = c_generator.CGenerator().visit(ast)
    return '\n'.join(preprocessor_lines) + '\n\n' + regenerated