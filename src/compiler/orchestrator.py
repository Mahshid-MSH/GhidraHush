"""
orchestrator.py -- compile-fix loop over extracted functions.
Per file: preprocess (AST-clean for .c, regex-only for .cpp) -> compile
(gcc/g++ chosen by extension) -> on failure, LLM repair with prioritized
errors + relevant header context -> on success, sync the prototype back
into data_globals.h. Non-interactive by default (AUTO_APPROVE=0 restores
the approval prompt for single-sample debugging sessions).
"""
import os
import shutil
import json
import re
from database.symbol_db import SymbolDB
from compiler.compiler_service import CompilerService   # the merged service
from compiler.compilation_order import compilation_order    # the fixed topo sort
from llm.patch_agent import PatchAgent
from pathlib import Path


from Auxiliary.reports import compilation_report
from utils.ast_patcher import (
    analyze_ast_types, proactive_header_patch,
    clean_decompiled_code, ast_tools_applicable,
)
from llm.code_utils import pre_process_ghidra_types, extract_prototype

DIM, RED, GREEN, YELLOW, CYAN, RESET = (
    '\033[2m', '\033[91m', '\033[92m', '\033[93m', '\033[96m', '\033[0m')


def say(label, text, color=DIM, max_lines=14):
    """Echo multi-line evidence (compiler errors, LLM context) to the console
    with a colored tag. Truncated but never silent."""
    lines = text.strip().splitlines()
    print(f"{color}{label}{RESET}")
    for line in lines[:max_lines]:
        print(f"{color}  | {line}{RESET}")
    if len(lines) > max_lines:
        print(f"{color}  | ... ({len(lines)} total lines){RESET}")



class CompilerOrchestrator:
    def __init__(self, model_name, base_url, max_retries, workspace_dir=".",binary_name=""):
        self.workspace = os.path.abspath(workspace_dir)
        self.compiler = CompilerService(self.workspace)
        self.agent = PatchAgent(model_name, base_url)
        self.max_retries = max_retries
        self.dir_success = os.path.join(self.workspace, "compiled_successfully")
        self.dir_failed = os.path.join(self.workspace, "failed_functions")
        self.dir_output = os.path.join(self.workspace, "output_objects")
        self.dir_logs = os.path.join(self.workspace, "llm_responses")
        self.header_path = os.path.join(self.workspace, "data_globals.h")
        self.auto_approve = os.environ.get("AUTO_APPROVE", "1") == "1"
        self.stats = {"success": 0, "failed": 0}
        self._binary_name = binary_name or os.path.basename(os.environ.get("INPUT_EXE_PATH", ""))
        self.per_function = []
        


    # ------------------------------------------------------------------

    def _preflight_header(self, want_cpp=False):
        """
        Compile one-line TUs against data_globals.h ONLY, then data_globals.c itself.
        If the header is broken, every function fails for fake reasons and repairs
        are wasted -- halt the stage instead.

        Checks beyond the original: (1) data_globals.c is compiled and its result is
        no longer ignored (compile_globals() returned a bool nobody read, so a broken
        data_globals.c only surfaced at link time); (2) when .cpp files are present the
        header is also compiled with g++, since constructs that are fine in C
        (e.g. _Static_assert) can be rejected there.
        """
        def _check(name, text, label):
            probe = os.path.join(self.workspace, name)
            with open(probe, "w", encoding="utf-8") as f:
                f.write(text)
            try:
                ok, errors = self.compiler.compile(probe, self.dir_output)
            finally:
                try: os.unlink(probe)
                except OSError: pass
            if not ok:
                raise RuntimeError(
                    f"P0 preflight FAILED ({label}) -- fix the generator "
                    f"(symbol_db/dump_global_values) first.\n" + errors[:3000])

        _check("__hdr_probe__.c", "int __gh_probe__(void);\n", "data_globals.h as C")
        if want_cpp:
            _check("__hdr_probe__.cpp", 'extern "C" int __gh_probe__(void);\n',
                   "data_globals.h as C++")
        src = os.path.join(self.workspace, "data_globals.c")
        if os.path.isfile(src):
            ok, errors = self.compiler.compile(src, self.dir_output)
            if not ok:
                raise RuntimeError("P0 preflight FAILED (data_globals.c does not "
                                   "compile)\n" + errors[:3000])

    def process_directory(self, target_dir):
        for d in (self.dir_success, self.dir_output, self.dir_logs,
                  self.dir_failed):
            os.makedirs(d, exist_ok=True)
        files = [os.path.join(target_dir, f) for f in os.listdir(target_dir)
                 if f.endswith((".c", ".cpp"))]
        self._preflight_header(want_cpp=any(f.endswith(".cpp") for f in files))  # ONCE
        if not files:
            print(f"No .c/.cpp files found in {target_dir}")
            return

        ordered = compilation_order(target_dir, files)

        for filepath in ordered:
            self._process_one(filepath)

        print(f"\n{CYAN}{'=' * 60}{RESET}")
        print(f"{BOLD if False else ''}Compile stage summary:{RESET}")
        print(f"  {GREEN}compiled:  {self.stats['success']}{RESET}")
        print(f"  {RED}failed:    {self.stats['failed']}{RESET}")
        print(f"  artifacts: compiled_successfully/ failed_functions/ "
              f"output_objects/ llm_responses/")
        print(f"{CYAN}{'=' * 60}{RESET}")
        
        with open(os.path.join(self.workspace, "compile_stats.json"), "w",
                  encoding="utf-8") as f:
            json.dump({
                "binary": self._binary_name,
                "totals": dict(self.stats),
                "functions": self.per_function,
            }, f, indent=2)

        # Inside orchestrator.py, where compile_stats.json is saved:
        total_repairs = sum(f.get("repairs", 0) for f in self.per_function)
        summary_payload = {
            "binary": self._binary_name,
            "success": self.stats['success'],
            "failed": self.stats['failed'],
            "total_repairs": total_repairs,
            "functions": self.per_function,
        }
        
        # Save JSON as before
        with open(os.path.join(self.workspace, "compile_stats.json"), "w", encoding="utf-8") as f:
            json.dump(summary_payload, f, indent=2)

        # Resolve project root (two levels up from orchestrator.py if located in a subfolder, 
        # or adjust according to your actual folder layout)
        project_root = Path(__file__).resolve().parent.parent
        
        total_repairs = sum(f.get("repairs", 0) for f in self.per_function)
        summary_payload = {
            "binary": self._binary_name,
            "totals": dict(self.stats),
            "success": self.stats['success'],
            "failed": self.stats['failed'],
            "total_repairs": total_repairs,
            "functions": self.per_function,
        }
        
        # Save JSON once cleanly
        stats_path = os.path.join(self.workspace, "compile_stats.json")
        with open(stats_path, "w", encoding="utf-8") as f:
            json.dump(summary_payload, f, indent=2)

        # Append to Excel Report sheet if available
        try:
       
            report_path = project_root / "Results" / "comparisons.xlsx"
            rep = compilation_report(str(report_path))
            if hasattr(rep, "add_compilation_stats"):
                rep.add_compilation_stats([summary_payload])
        except Exception as e:
            print(f"[xlsx warning] Could not write compilation stats to Excel: {e}")
            
        print(f"[stats] compile_stats.json written "
              f"({self.stats['success']}/{self.stats['success'] + self.stats['failed']} compiled)")
    # ------------------------------------------------------------------
    def _process_one(self, filepath):
        filename = os.path.basename(filepath)
        is_cpp = filename.endswith(".cpp")
        print(f"\n{'-' * 50}\nProcessing: {filename}")
        repairs = 0
        resolved_already = set()
        attempt = 0
        errors = ""
        while attempt < self.max_retries:
            if attempt == 0:
                self._preprocess(filepath, is_cpp)

            ok, errors = self.compiler.compile(filepath, self.dir_output)
            if ok:
                print(f"Success! {filename} compiled cleanly.")
                self._sync_prototype(filepath)
                shutil.move(filepath, os.path.join(self.dir_success, filename))
                self.stats["success"] += 1
                self.per_function.append({
                "name": filename, "ok": True, "repairs": repairs,
                "lang": ".cpp" if is_cpp else ".c",
            })
                return

            # Demand-driven resolution: does NOT consume an attempt.
            prog_missing = set(re.findall(
                r"[‘'\"]((?:DAT_|FUN_)[0-9A-Fa-f]+)[’'\"]", errors))
            prog_missing |= {n for n in re.findall(
                r"[‘'\"](_[A-Za-z]\w*)[’'\"] was not declared", errors)
                if n[1:] in SymbolDB(self.workspace).list_global_names()}
            prog_missing -= resolved_already          # loop guard
            if prog_missing:
                resolved_already |= prog_missing
                print(f"{YELLOW}[resolve] resolving {sorted(prog_missing)} "
                      f"inline{RESET}")
                from utils.add_missing_globals import add_missing_values
                add_missing_values(workspace_dir=self.workspace,
                                   path_to_binary=self._binary_name,
                                   names=sorted(prog_missing))
                continue                              # recompile; free

            # From here on, every cycle consumes an attempt (LLM repair).
            attempt += 1

            err_lines = [l for l in errors.splitlines() if "error:" in l]
            if any("data_globals.h" in l for l in err_lines):
                print(f"{RED}Errors in data_globals.h -- the function is NOT "
                      f"at fault. Not sending to the LLM.{RESET}")
                self._retire_failed(filepath, errors, filename)
                raise RuntimeError("header blocked compilation -- fix the "
                                   "generator, then re-run the stage")

            print(f"{YELLOW}Compilation failed (repair {attempt}): "
                  f"{errors.count('error:')} error(s){RESET}")
            say("compiler stderr:", errors, RED, max_lines=12)
            if attempt >= self.max_retries:
                break
            repairs += 1 
            if not self._repair_cycle(filepath, errors, filename, attempt,
                                      is_cpp):
                self._repair_cycle(filepath, errors, filename, attempt, is_cpp)
        self.per_function.append({                        # <-- NEW (both exits)
            "name": filename,
            "ok": False,                                  # reached here = failed
            "repairs": repairs,
            "lang": ".cpp" if is_cpp else ".c",
        })
        self._retire_failed(filepath, errors, filename)
    # ------------------------------------------------------------------
    def _preprocess(self, filepath, is_cpp):
        """C: pycparser AST clean + proactive return-type patching.
        C++: regex preprocessing only (pycparser cannot parse std::)."""
        try:
            with open(filepath, encoding="utf-8", errors="ignore") as f:
                code = f.read()
            if is_cpp:
                cleaned = pre_process_ghidra_types(code)
            else:
                cleaned = clean_decompiled_code(code, header_path=self.header_path)
                ast_calls = analyze_ast_types(cleaned, header_path=self.header_path)
                if proactive_header_patch(self.header_path, ast_calls,
                                          workspace_dir=self.workspace):
                    self.compiler.compile_globals()
            cleaned = self._deterministic_normalize(cleaned)   # <-- NEW
            if cleaned != code:
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(cleaned)
                print(f"[preprocess] cleaned {os.path.basename(filepath)}")
        except Exception as e:
            print(f"[preprocess] skipped for {filepath}: {e}")

    # ------------------------------------------------------------------
    def _deterministic_normalize(self, code):
        """Fixes that never need an LLM:
        - builtin_strncpy -> strncpy (Ghidra emits __builtin_X; earlier LLM
          passes wrote builtin_X into processed files)
        - &ArrayGlobal -> ArrayGlobal (numerically identical address; kills
          the uint8_t(*)[N] -> char* error class entirely)"""
        code = re.sub(r'\b_{0,2}builtin_', '', code)
        for name in SymbolDB(self.workspace).array_global_names():
            # (?<![&\w]) keeps `a && arr` intact; (?!\s*\[) keeps `&arr[i]` (a pointer to
            # element i) from being turned into `arr[i]` (the element's VALUE).
            code = re.sub(rf'(?<![&\w])&{re.escape(name)}\b(?!\s*\[)', name, code)
        return code

    # ------------------------------------------------------------------
    def _apply_repair(self, filepath, response, broken_code, error_block):
        """
        Atomic application: prototype patch (if evidence-backed) + code
        are verified TOGETHER; both roll back or both land.
        """
        fixed_code = response.get("full_fixed_code", "")
        patches = response.get("header_patches", [])
        db = SymbolDB(self.workspace)

        pending_protos = []
        implicated = set(re.findall(r'\b[A-Za-z_]\w*\b', error_block or ""))
        for patch in patches:
            proto = str(patch.get("replace", "")).strip()
            m = re.search(r'([A-Za-z_~][\w:]*)\s*\(', proto)
            if m and m.group(1).split('::')[-1] in implicated:
                pending_protos.append((m.group(1).split('::')[-1], proto))
            else:
                print(f"[DB patch] SKIPPED (no compiler error names this "
                      f"function -- guess, not evidence): {proto}")
        if not fixed_code.strip() and not pending_protos:
            return False

        # Snapshot everything we might have to roll back.
        prev_header = open(self.header_path, encoding="utf-8").read()
        prev_rows = {n: db.get_function_by_name(n) for n, _ in pending_protos}

        # Fabrication check FIRST -- reject before touching DB or header.
        if fixed_code.strip():
            fabricated = re.findall(
                r'^\s*(?:const\s+)?\w+[\w\s*]*\b((?:DAT_|FUN_)[0-9A-Fa-f]+)\s*(?:=|\[|;)',
                fixed_code, re.MULTILINE)
            if fabricated:
                print(f"{RED}[repair] REJECTED: LLM fabricated declaration(s) "
                      f"for {sorted(set(fabricated))} -- resolver-only names."
                      f"{RESET}")
                return False
        applied_protos = []
        try:
            for name, proto in pending_protos:
                db.parse_and_upsert_prototype(proto)
                applied_protos.append(name)
            db.export_header(os.path.basename(self.header_path))
            if fixed_code.strip():
                fabricated = re.findall(
                    r'^\s*(?:const\s+)?\w+[\w\s*]*\b((?:DAT_|FUN_)[0-9A-Fa-f]+)\s*(?:=|\[|;)',
                    fixed_code, re.MULTILINE)
                if fabricated:
                    print(f"{RED}[repair] REJECTED: LLM fabricated declaration(s) "
                          f"for binary symbol(s) {sorted(set(fabricated))} -- "
                          f"these may only be declared by the resolver{RESET}")
                    return False
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(fixed_code)
            # THE gate: the (patched header, new code) pair must compile.
            ok, errors = self.compiler.compile(filepath, self.dir_output)
            if ok:
                if applied_protos:
                    print(f"[DB patch] verified with caller: "
                          f"{[p for _, p in pending_protos]}")
                self.compiler.compile_globals()
                return True
            # Failed -> full rollback: DB, header, AND caller code.
            for name in applied_protos:
                if prev_rows.get(name):
                    db.add_or_update_function(*prev_rows[name])
                else:
                    db.delete_function(name)
            with open(self.header_path, "w", encoding="utf-8") as f:
                f.write(prev_header)
            if fixed_code.strip():
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(broken_code)
            print("[repair] patch+code rejected by compiler -- fully rolled back")
            return False
        except Exception as e:
            # Crash safety: same rollback path.
            for name in applied_protos:
                if prev_rows.get(name):
                    db.add_or_update_function(*prev_rows[name])
                else:
                    db.delete_function(name)
            with open(self.header_path, "w", encoding="utf-8") as f:
                f.write(prev_header)
            if fixed_code.strip():
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(broken_code)
            print(f"[repair] exception during apply, rolled back: {e}")
            return False
        
    def _repair_cycle(self, filepath, errors, filename, attempt, is_cpp):
        with open(filepath, encoding="utf-8") as f:
            broken_code = f.read()

        response = self.agent.fix_with_llm(broken_code, errors,
                                           self.header_path, attempt,
                                           is_cpp=is_cpp)
        log_path = os.path.join(self.dir_logs,
                                f"{filename}_attempt_{attempt}.log")
        with open(log_path, "w", encoding="utf-8") as lf:
            lf.write(f"=== COMPILER ERRORS ===\n{errors}\n\n"
                     f"=== LLM RESPONSE ===\n{json.dumps(response, indent=2)}")

        print(f"\n[{filename}] reasoning: "
              f"{response.get('reasoning', 'none')[:200]}")

        # All disk writes (header + code) are owned by _apply_repair, so
        # the (header, code) pair can be verified and rolled back together.
        return self._apply_repair(filepath, response, broken_code, errors)


    # ------------------------------------------------------------------
    def _sync_prototype(self, filepath):
        """Prototype of a file that COMPILED is ground truth -- record it."""
        with open(filepath, encoding="utf-8") as f:
            proto = extract_prototype(f.read())
        if not proto:
            return
        db = SymbolDB(self.workspace)
        if db.parse_and_upsert_prototype(proto):
            db.export_header(os.path.basename(self.header_path))
            print(f"[sync] {proto}")

    # ------------------------------------------------------------------
    def _retire_failed(self, filepath, errors, filename):
        stem, ext = os.path.splitext(filename)
        print(f"!!!! Exhausted retries for {filename} !!!!")
        with open(os.path.join(self.dir_failed, stem + ".err"),
                  "w", encoding="utf-8") as f:
            f.write(errors)
        shutil.move(filepath, os.path.join(self.dir_failed, filename))
        self.stats["failed"] += 1