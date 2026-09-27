"""
compiler_service.py -- one service, both languages.
.c -> gcc, .cpp -> g++ (+ -fpermissive: decompiler cast artifacts become
warnings, real errors stay errors). Compiles to objects; never links.
"""
import os
import subprocess


class CompilerService:
    def __init__(self, workspace_dir="."):
        self.workspace_dir = os.path.abspath(workspace_dir)
        base = os.environ.get("SDK_PROBE_COMPILER", "i686-w64-mingw32-gcc")
        self._compilers = {".c": base, ".cpp": base.replace("gcc", "g++")}
        self.header = os.path.join(self.workspace_dir, "data_globals.h")

    def _cmd(self, filepath, obj_path):
        ext = ".cpp" if filepath.endswith(".cpp") else ".c"
        cmd = [self._compilers[ext], "-c", "-w",
               "-I", self.workspace_dir, "-include", self.header]
        if ext == ".cpp":
            cmd.append("-fpermissive")
        return cmd + [os.path.abspath(filepath), "-o", obj_path]

    def compile(self, filepath, output_dir):
        os.makedirs(output_dir, exist_ok=True)
        stem = os.path.splitext(os.path.basename(filepath))[0]
        obj_path = os.path.join(output_dir, stem + ".o")
        try:
            proc = subprocess.run(self._cmd(filepath, obj_path),
                                  capture_output=True, text=True, timeout=120)
        except FileNotFoundError:
            raise RuntimeError(f"compiler not found: {self._compilers}")
        return proc.returncode == 0, proc.stderr

    def compile_globals(self):
        src = os.path.join(self.workspace_dir, "data_globals.c")
        return self.compile(src, self.workspace_dir)[0]