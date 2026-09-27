import os
import re
import subprocess
import tempfile

_PROTO_NAME_RE = re.compile(r'([A-Za-z_~][A-Za-z0-9_:~]*)\s*\(')
_PROTO_CTRL_KEYWORDS = {'if', 'for', 'while', 'switch', 'return', 'catch', 'sizeof'}


def pre_process_ghidra_types(c_code):
    """
    Standardizes Ghidra-specific data types and artifacts before the LLM sees them.
    
    Why it's here: Ghidra outputs non-standard primitive names like `undefined8`, 
    `undefined4`, or compiler-injected stack cookies (`_RTC_CheckStackVars`) that 
    cause modern C compilers to throw immediate syntax errors. Normalizing these 
    to standard C99/C++ types (`uint64_t`, `uint32_t`, `uintptr_t`) gives the LLM 
    a cleaner, standard-compliant starting point.
    """
    replacements = {
        r'\bunsigned\s+long\s+long\b': 'uint64_t',
        r'\bsigned\s+long\s+long\b': 'int64_t',
        r'\bunsigned\s+long\b': 'uint32_t',
        r'\bsigned\s+long\b': 'int32_t',
        r'\bundefined8\b': 'uintptr_t',      
        r'\bundefined4\b': 'uint32_t',
        r'\bundefined2\b': 'uint16_t',
        r'\bundefined1\b': 'uint8_t',
        r'\bundefined\b': 'void',             
        r'\blonglong\b': 'int64_t',          
        r'\bulonglong\b': 'uint64_t',        
        r'\blong\b': 'int32_t',              
        r'\bushort\b': 'uint16_t',
        r'\bdword\b': 'uint32_t',
        r'\bword\b': 'uint16_t',
        r'\bbyte\b': 'uint8_t',
        r'\buint\b': 'uint32_t',
        r'_RTC_CheckStackVars\(.*?\);': '',
        r'__CheckForDebuggerJustMyCode\(.*?\);': '',
        r'__RTC_CheckEsp\(\);': '',
        r'__security_check_cookie\(.*?\);': '',
        r'\b__builtin_([a-zA-Z_]\w*)\b': r'\1',   # Clean up Ghidra __builtin intrinsics
        r'\s*__main\(\);': '',                    # Remove MinGW CRT init call    
    }
    for pattern, replacement in replacements.items():
        c_code = re.sub(pattern, replacement, c_code)
    return c_code


def build_name_to_id_map(call_graph):
    """
    Maps each function's display name to its real unique node ID in the call graph.
    
    Why it's here: Ghidra call graphs often index functions with long internal hashes 
    or memory addresses (e.g., `FUN_00401200`). This helper maps human-friendly names 
    back to their internal IDs so the dependency graph can resolve them accurately.
    """
    name_to_id = {}
    for node_id, entry in call_graph.items():
        name = entry.get("name") if isinstance(entry, dict) else None
        if name is None:
            name = node_id.rsplit('_', 1)[0]
        name_to_id.setdefault(name, node_id)
    return name_to_id


def resolve_callee_id(raw_id, call_graph, name_to_id):
    """
    Normalizes a callee ID from `call_graph.json` to the standard node ID format.
    """
    raw_id = raw_id.strip()
    if raw_id in call_graph:
        return raw_id
    base_name = raw_id.rsplit('_', 1)[0]
    return name_to_id.get(base_name, raw_id)


def find_matching_paren(text, open_idx):
    """
    Scans a string to find the closing parenthesis matching an opening parenthesis at `open_idx`,
    correctly skipping over string literals and nested scopes.
    """
    depth = 0
    i = open_idx
    in_string = None
    while i < len(text):
        ch = text[i]
        if in_string:
            if ch == '\\':
                i += 1
            elif ch == in_string:
                in_string = None
        elif ch in ('"', "'"):
            in_string = ch
        elif ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def is_ctor_or_dtor(func_name):
    """Checks if a C++ function name corresponds to a class constructor or destructor."""
    parts = func_name.split('::')
    if len(parts) < 2:
        return func_name.startswith('~')
    last, prev = parts[-1], parts[-2]
    return last == prev or last == '~' + prev


def extract_prototype(text):
    """
    Parses a function definition string and extracts its clean C/C++ prototype declaration.
    
    Why it's here: As each function is successfully beautified, we extract its 
    signature (prototype) and append it to `data_globals.h`. This allows downstream 
    functions that call it to reference accurate type definitions.
    """
    if not text:
        return None
    # Strip leading/trailing markdown blocks if present
    text = re.sub(r'^```[a-zA-Z0-9_+]*\s*\n?', '', text.strip())
    text = re.sub(r'\n?```\s*$', '', text)

    for m in _PROTO_NAME_RE.finditer(text):
        name_start, name_end = m.span(1)
        paren_open = m.end() - 1
        paren_close = find_matching_paren(text, paren_open)
        if paren_close is None:
            continue

        func_name = text[name_start:name_end].strip()
        if func_name in _PROTO_CTRL_KEYWORDS:
            continue

        after = text[paren_close + 1:].lstrip()
        after = re.sub(r'^(const|noexcept|override|final)\b\s*', '', after)
        if not after.startswith('{'):
            continue

        args = " ".join(text[paren_open + 1:paren_close].split())
        head = text[:name_start]
        last_hash_end = -1
        for pp in re.finditer(r'^#.*$', head, re.MULTILINE):
            last_hash_end = pp.end()
        boundary = max(head.rfind(';'), head.rfind('}'), last_hash_end)
        return_type = head[boundary + 1:].strip()
        if not return_type and not is_ctor_or_dtor(func_name):
            continue

        prefix = f"{return_type} " if return_type else ""
        return f"{prefix}{func_name}({args});"
    return None


def find_code_files(directory):
    """Recursively finds all `.c` and `.cpp` files in the specified directory."""
    code_files = []
    if not os.path.exists(directory):
        return code_files
        
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith((".c", ".cpp")):
                code_files.append(os.path.join(root, file))
    
    code_files.sort()
    return code_files


def syntax_check(code, workspace_dir, is_cpp=False, timeout=120):
    """
    The Compile Gate: Performs a fast syntax validation using GCC/Clang (`-fsyntax-only`).
    
    Why it's here: Instead of blindly trusting that the LLM's refactored code compiles, 
    this function writes the code to a temporary file, forces-includes `data_globals.h`, 
    and invokes a cross-compiler (like MinGW). If the compiler returns code 0, we know 
    with absolute mathematical certainty that the code is syntactically valid C/C++.
    """
    compiler = os.environ.get("SDK_PROBE_COMPILER", "i686-w64-mingw32-gcc")
    if is_cpp:
        compiler = compiler.replace("gcc", "g++")
        
    header = os.path.abspath(os.path.join(workspace_dir, "data_globals.h"))
    if not os.path.isfile(header):
        return False, "data_globals.h not found"
        
    # Quick structural check before invoking the heavy compiler process
    if code.count("{") != code.count("}") or code.count("(") != code.count(")"):
        return False, "unbalanced braces/parens (truncated output?)"
        
    suffix = ".cpp" if is_cpp else ".c"
    with tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False,
                                     encoding="utf-8") as f:
        f.write(code)
        path = f.name
        
    try:
        cmd = [compiler, "-fsyntax-only", "-w", "-include", header,
               "-I", os.path.abspath(workspace_dir)]
        if is_cpp:
            cmd.append("-fpermissive")
        cmd.append(path)
        
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout)
        return proc.returncode == 0, proc.stderr or ""
    except FileNotFoundError:
        return False, f"compiler not found: {compiler}"
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def append_prototype_to_header(prototype, header_path="data_globals.h"):
    """
    Safely appends a function prototype inside the header guard of `data_globals.h`.
    
    Why it's here: Prevents duplicate entries and ensures declarations are safely 
    injected right before the closing preprocessor `#endif` directive.
    """
    if not prototype:
        return
    try:
        with open(header_path, "r", encoding="utf-8") as f:
            content = f.read()
            
        # Deduplication check
        if f"\n{prototype}" in content or f"\n{prototype}\n" in content:
            return                       
            
        idx = content.rfind("#endif")
        if idx == -1:
            print("Failed: header has no #endif guard -- not appending")
            return
            
        content = (content[:idx] + f"\n{prototype}\n\n" + content[idx:])
        with open(header_path, "w", encoding="utf-8") as f:
            f.write(content)
            
        print(f"Appended prototype inside guard: {prototype}")
    except Exception as e:
        print(f"Failed to append prototype to header: {e}")