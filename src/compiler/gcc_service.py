import os
import sys
import subprocess
class GCCService:
    def __init__(self, compiler="i686-w64-mingw32-gcc", workspace_dir="."):
        self.compiler = compiler
        self.workspace_dir = workspace_dir

    def compile_file(self, filepath, output_dir):
        os.makedirs(output_dir, exist_ok=True)
        filename = os.path.basename(filepath)
        obj_name = filename.replace('.c', '.o')
        obj_path = os.path.join(output_dir, obj_name)
        
        # Force include the global header using GCC's -include flag
        header_path = os.path.join(self.workspace_dir, "LLM_globals.h")
        cmd = [self.compiler, f"-I{self.workspace_dir}", "-include", header_path, "-c", "-w", filepath, "-o", obj_path]
        
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.returncode == 0, result.stderr

    def recompile_globals(self):
        source_path = os.path.join(self.workspace_dir, "LLM_globals.c")
        obj_path = os.path.join(self.workspace_dir, "globals.o")
        
        cmd = [self.compiler, f"-I{self.workspace_dir}", "-c", "-w", source_path, "-o", obj_path]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.returncode == 0