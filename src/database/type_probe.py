#!/usr/bin/env python3
"""
Dynamic Type Collision Resolver (Compiler Oracle).
Automates the deduplication of recovered C types (from PDBs/Ghidra) against standard platform SDK headers. 
Emitting recovered standard types (e.g., _FILETIME, HINSTANCE__) alongside platform headers like <windows.h> causes fatal type redefinition errors. 
Rather than relying on an incomplete, manually curated denylist, this script generates temporary C probe files and parses the target compiler's syntax errors 
to dynamically classify which types are already provided by the SDK, which are macros, and which are genuinely absent and must be emitted.
"""

import hashlib
import os
import re
import subprocess
import tempfile

_ERROR_LINE_RE_TPL = r"^{path}:(\d+):\d+:\s*(?:fatal )?error:"


def _compiler_id(compiler, extra_flags):
    """
    Generates a unique SHA-1 fingerprint of the current compiler version and flags.
    
    Why it's here: If the build environment changes (e.g., switching from GCC 11 
    to Clang 14), the types supported by the SDK might change. This fingerprint 
    acts as a cache key to ensure the script doesn't accidentally reuse cached 
    results from a completely different compiler setup.
    """
    try:
        out = subprocess.run([compiler, "--version"], capture_output=True,
                             text=True, timeout=60).stdout
        ver = out.strip().splitlines()[0] if out.strip() else "unknown"
    except Exception:
        ver = "unknown"
    return hashlib.sha1(f"{compiler}|{ver}|{extra_flags}".encode()).hexdigest()[:16]


def build_probe_source(preamble, candidates):
    """
    Generates the text for a temporary C source file testing all candidate types.
    candidates: list of (name, kind); kind in {'type','struct','union','enum'}.
    
    Why it's here: The compiler needs valid C code to evaluate. By wrapping each 
    variable declaration in its own scope `{ ... }` and casting it to `(void)`, 
    we ensure two things: a syntax error on one line doesn't halt the compilation 
    of the subsequent lines, and the compiler doesn't throw "unused variable" warnings.
    """
    lines = list(preamble)
    lines.append("static void __type_probe_all(void) {")
    for i, (name, kind) in enumerate(candidates):
        qualified = f"{kind} {name}" if kind in ("struct", "union", "enum") else name
        lines.append(f"    {{ {qualified} __probe_var_{i}; (void)__probe_var_{i}; }}")
    lines.append("}")
    return "\n".join(lines) + "\n"


def _compile_probe(src, compiler, extra_flags, timeout=300):
    """
    Writes the C code to disk, runs a syntax check, and captures the errors.
    
    Why it's here: This is the execution engine. It safely runs the "oracle" query 
    against the compiler using the `-fsyntax-only` flag (checking for errors without 
    building an executable). It also handles writing and deleting the temporary 
    C files so your file system isn't cluttered with dummy files.
    """
    with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False,
                                     encoding="utf-8") as f:
        f.write(src)
        path = f.name
    try:
        proc = subprocess.run(
            [compiler, "-fsyntax-only", *(extra_flags or []), path],
            capture_output=True, text=True, timeout=timeout)
        return proc.stderr or "", path
    finally:
        os.unlink(path)


def _error_lines(stderr, path):
    """
    Parses the compiler's stderr to extract line numbers that caused fatal errors.
    
    Why it's here: Standard headers like <windows.h> can generate hundreds of 
    deep, cascading internal errors when a type conflicts. This regex filters out 
    the noise, matching strictly against the exact file path of our temporary 
    script to find exactly which of *our* generated lines the compiler rejected.
    """
    pat = re.compile(_ERROR_LINE_RE_TPL.format(path=re.escape(path)), re.MULTILINE)
    return {int(m.group(1)) for m in pat.finditer(stderr)}


def probe_type_names(candidates, compiler, preamble, extra_flags=None,
                     cache_get=None, cache_set=None):
    """
    The main orchestrator that coordinates the 2-pass compiler tests.
    
    Why it's here: It manages the entire deduplication workflow:
      1. Cache Check: Skips previously tested types to save processing time.
      2. Pass 1: Tests all pending types. If a type compiles without error, 
         it is marked as 'sdk' (it already exists in the platform headers).
      3. Pass 2: For types that failed, it injects `#undef` and tests again. 
         If the error disappears, the name was a 'macro' collision. If it 
         still fails, the type is truly 'absent' and must be emitted by Ghidra.

    Returns {(name, kind): status}:
      'sdk'    -> provided by the SDK as a type   -> elide
      'macro'  -> SDK preprocessor macro          -> elide
      'absent' -> not provided                    -> caller emits its definition
    """
    cid = _compiler_id(compiler, extra_flags)
    keys = {c: f"{cid}|{c[1]}|{c[0]}" for c in candidates}

    results, pending = {}, list(candidates)
    if cache_get is not None:
        cached = cache_get([keys[c] for c in pending])
        pending = [c for c in pending if keys[c] not in cached]
        for c in candidates:
            if keys[c] in cached:
                results[c] = cached[keys[c]]

    if pending:
        # Pass 1: which names does the SDK already provide?
        stderr, path = _compile_probe(build_probe_source(preamble, pending),
                                      compiler, extra_flags)
        err_lines = _error_lines(stderr, path)
        start = len(preamble) + 2          # first probe line (1-based)
        missing = []
        for i, cand in enumerate(pending):
            if (start + i) in err_lines:
                missing.append(cand)
            else:
                results[cand] = "sdk"

        # Pass 2: absent vs macro (only for the missing minority)
        if missing:
            preamble2 = list(preamble) + [f"#undef {n}" for n, _ in missing] + [""]
            stderr2, path2 = _compile_probe(
                build_probe_source(preamble2, missing), compiler, extra_flags)
            err2 = _error_lines(stderr2, path2)
            start2 = len(preamble2) + 2
            for j, cand in enumerate(missing):
                results[cand] = "absent" if (start2 + j) in err2 else "macro"

        if cache_set is not None:
            cache_set({keys[c]: results[c] for c in pending})

    return results