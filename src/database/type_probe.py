#!/usr/bin/env python3
"""
Dynamic Type Collision Resolver (Compiler Oracle).
Automates the deduplication of recovered C types (from PDBs/Ghidra) against standard platform SDK headers.
Emitting recovered standard types (e.g., _FILETIME, HINSTANCE__) alongside platform headers like <windows.h> causes fatal type redefinition errors.
Rather than relying on an incomplete, manually curated denylist, this script generates temporary C probe files and parses the target compiler's syntax errors
to dynamically classify which types are already provided by the SDK, which are macros, and which are genuinely absent and must be emitted.

Why a compiler oracle at all?  Recompilable decompilation is *defined* by "the
output is accepted by a standard C compiler" (see the definition used in
"Refining Decompiled C Code with Large Language Models", arXiv 2310.06530).
Asking the real compiler is the only check that is exact for the real SDK.

Fixes relative to the first version
-----------------------------------
1.  A failing *preamble* (e.g. <windows.h> not found) used to be invisible: the
    compiler stops at the fatal error, no probe line reports an error, and
    every candidate was classified 'sdk' -> the header silently lost ALL type
    definitions.  The preamble is now checked and a ProbeError is raised.
2.  A non-zero exit status with no parsable error line (wrong path form,
    compiler crash, unsupported flag) is also a ProbeError instead of "all sdk".
3.  clang stops after 20 errors by default, which would classify every later
    candidate as 'sdk'.  -ferror-limit=0 / -fmax-errors=0 is now passed.
4.  The cache key now includes a hash of the preamble: changing the includes or
    -D flags no longer reuses stale results.
5.  The first probe line is computed from the real newline count, not from
    len(preamble), so preamble entries that contain '\\n' cannot shift the
    line mapping.
"""

import hashlib
import os
import re
import subprocess
import tempfile

_ERROR_LINE_RE_TPL = r"^{path}:(\d+):\d+:\s*(?:fatal )?error:"


class ProbeError(RuntimeError):
    """The oracle itself is broken (not 'the type is absent')."""


def _compiler_id(compiler, extra_flags, preamble=()):
    """
    Generates a unique SHA-1 fingerprint of the current compiler version, flags
    and preamble.

    Why it's here: If the build environment changes (e.g., switching from GCC 11
    to Clang 14, or adding -D_WIN32_WINNT), the types supported by the SDK might
    change. This fingerprint acts as a cache key to ensure the script doesn't
    accidentally reuse cached results from a completely different setup.
    """
    try:
        out = subprocess.run([compiler, "--version"], capture_output=True,
                             text=True, timeout=60).stdout
        ver = out.strip().splitlines()[0] if out.strip() else "unknown"
    except Exception:
        ver = "unknown"
    pre = hashlib.sha1("\n".join(preamble).encode()).hexdigest()[:8]
    return hashlib.sha1(
        f"{compiler}|{ver}|{extra_flags}|{pre}".encode()).hexdigest()[:16]


def _first_probe_line(preamble):
    """1-based line number of the first candidate line in the probe source."""
    return sum(p.count("\n") + 1 for p in preamble) + 2


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


def _probe_flags(compiler, extra_flags):
    flags = list(extra_flags or [])
    if "clang" in os.path.basename(compiler).lower():
        flags.append("-ferror-limit=0")      # clang default is 20
    else:
        flags.append("-fmax-errors=0")       # gcc: 0 == unlimited
    return flags


def _compile_probe(src, compiler, extra_flags, timeout=300):
    """
    Writes the C code to disk, runs a syntax check, and captures the errors.

    Why it's here: This is the execution engine. It safely runs the "oracle" query
    against the compiler using the `-fsyntax-only` flag (checking for errors without
    building an executable). It also handles writing and deleting the temporary
    C files so your file system isn't cluttered with dummy files.

    Returns (stderr, path, returncode).
    """
    with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False,
                                     encoding="utf-8") as f:
        f.write(src)
        path = f.name
    try:
        proc = subprocess.run(
            [compiler, "-fsyntax-only", *_probe_flags(compiler, extra_flags), path],
            capture_output=True, text=True, timeout=timeout)
        return proc.stderr or "", path, proc.returncode
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


def _checked_error_lines(stderr, path, rc, first_probe_line, what):
    """Error lines of the probe body; raises ProbeError if the oracle is unsound."""
    err_lines = _error_lines(stderr, path)
    bad_preamble = sorted(l for l in err_lines if l < first_probe_line)
    if bad_preamble:
        head = "\n".join(stderr.splitlines()[:5])
        raise ProbeError(f"{what}: preamble does not compile "
                         f"(line(s) {bad_preamble[:5]}):\n{head}")
    if rc != 0 and not err_lines:
        head = "\n".join(stderr.splitlines()[:5])
        raise ProbeError(f"{what}: compiler exited with status {rc} but no "
                         f"error line could be attributed to the probe file:\n{head}")
    return err_lines


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

    Raises ProbeError if the oracle cannot be trusted (see module docstring);
    callers should then emit every type rather than elide anything.
    """
    cid = _compiler_id(compiler, extra_flags, preamble)
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
        stderr, path, rc = _compile_probe(build_probe_source(preamble, pending),
                                          compiler, extra_flags)
        start = _first_probe_line(preamble)
        err_lines = _checked_error_lines(stderr, path, rc, start, "pass 1")
        missing = []
        for i, cand in enumerate(pending):
            if (start + i) in err_lines:
                missing.append(cand)
            else:
                results[cand] = "sdk"

        # Pass 2: absent vs macro (only for the missing minority)
        if missing:
            preamble2 = list(preamble) + [f"#undef {n}" for n, _ in missing] + [""]
            stderr2, path2, rc2 = _compile_probe(
                build_probe_source(preamble2, missing), compiler, extra_flags)
            start2 = _first_probe_line(preamble2)
            err2 = _checked_error_lines(stderr2, path2, rc2, start2, "pass 2")
            for j, cand in enumerate(missing):
                results[cand] = "absent" if (start2 + j) in err2 else "macro"

        if cache_set is not None:
            cache_set({keys[c]: results[c] for c in pending})

    return results