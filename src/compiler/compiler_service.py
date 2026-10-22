"""Compile C and C++ translation units to object files without linking."""
import os
import subprocess


class CompilerService:
    def __init__(self, workspace_dir: str = ".") -> None:
        self.workspace_dir = os.path.abspath(workspace_dir)
        base = os.environ.get("SDK_PROBE_COMPILER", "i686-w64-mingw32-gcc")
        self._compilers = {".c": base, ".cpp": base.replace("gcc", "g++")}
        self.header = os.path.join(self.workspace_dir, "data_globals.h")

    def _cmd(self, filepath: str, obj_path: str) -> list[str]:
        ext = ".cpp" if filepath.endswith(".cpp") else ".c"
        cmd = [
            self._compilers[ext], "-c", "-w",
            "-I", self.workspace_dir, "-include", self.header,
        ]
        if ext == ".cpp":
            cmd.append("-fpermissive")
        return cmd + [os.path.abspath(filepath), "-o", obj_path]

    def compile(self, filepath: str, output_dir: str) -> tuple[bool, str]:
        os.makedirs(output_dir, exist_ok=True)
        stem = os.path.splitext(os.path.basename(filepath))[0]
        obj_path = os.path.join(output_dir, stem + ".o")
        try:
            proc = subprocess.run(
                self._cmd(filepath, obj_path),
                capture_output=True,
                text=True,
                timeout=120,
            )
        except FileNotFoundError:
            raise RuntimeError(f"compiler not found: {self._compilers}")
        return proc.returncode == 0, proc.stderr

    def compile_globals(self) -> bool:
        src = os.path.join(self.workspace_dir, "data_globals.c")
        return self.compile(src, self.workspace_dir)[0]