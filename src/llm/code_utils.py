import os
import re

_PROTO_NAME_RE = re.compile(r'([A-Za-z_~][A-Za-z0-9_:~]*)\s*\(')
_PROTO_CTRL_KEYWORDS = {'if', 'for', 'while', 'switch', 'return', 'catch', 'sizeof'}


def pre_process_ghidra_types(c_code):
    """Standardize Ghidra types via Python before the LLM sees them."""
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
        r'__security_check_cookie\(.*?\);': ''    
    }
    for pattern, replacement in replacements.items():
        c_code = re.sub(pattern, replacement, c_code)
    return c_code


def build_name_to_id_map(call_graph):
    """Maps each function's name to that entry's real func_id."""
    name_to_id = {}
    for node_id, entry in call_graph.items():
        name = entry.get("name") if isinstance(entry, dict) else None
        if name is None:
            name = node_id.rsplit('_', 1)[0]
        name_to_id.setdefault(name, node_id)
    return name_to_id


def resolve_callee_id(raw_id, call_graph, name_to_id):
    """Normalizes a callee id from call_graph.json to the id that
    callee's own top-level entry actually uses."""
    raw_id = raw_id.strip()
    if raw_id in call_graph:
        return raw_id
    base_name = raw_id.rsplit('_', 1)[0]
    return name_to_id.get(base_name, raw_id)


def find_matching_paren(text, open_idx):
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
    parts = func_name.split('::')
    if len(parts) < 2:
        return func_name.startswith('~')
    last, prev = parts[-1], parts[-2]
    return last == prev or last == '~' + prev


def extract_prototype(text):
    if not text:
        return None
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
    """Recursively find all .c and .cpp files in the specified directory."""
    code_files = []
    if not os.path.exists(directory):
        return code_files
        
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith((".c", ".cpp")):
                code_files.append(os.path.join(root, file))
    
    code_files.sort()
    return code_files


def append_prototype_to_header(prototype, header_path="data_globals.h"):
    """Directly append updates to the header file."""
    if not prototype:
        return
    try:
        with open(header_path, "a", encoding="utf-8") as f:
            f.write(f"\n{prototype}\n")
        print(f"Appended prototype to Header: {prototype}")
    except Exception as e:
        print(f"Failed to append prototype to header: {e}")