import os
import shutil
import json
import re
from database.symbol_db import SymbolDB
from src.compiler.gcc_service import GCCService
from src.compiler.dependency_graph import DependencyGraph
from src.llm.patch_agent import PatchAgent
from llm.c_code_enhancer import get_ignored_functions
from src.utils.ast_patcher import analyze_ast_types, proactive_header_patch, clean_decompiled_code

class CompilerOrchestrator:
    def __init__(self, model_name, base_url, max_retries, compiler, workspace_dir="."):
        self.gcc = GCCService(compiler)
        self.agent = PatchAgent(model_name, base_url)
        self.max_retries = max_retries
        self.workspace_dir = workspace_dir

        self.dir_success = os.path.join(workspace_dir, "compiled_successfully")
        self.dir_failed = os.path.join(workspace_dir, "failed_functions")
        self.dir_output = os.path.join(workspace_dir, "output_objects")
        self.dir_logs = os.path.join(workspace_dir, "llm_responses")
        self.header_path = os.path.join(workspace_dir, "LLM_globals.h")
        self.stats = {"success": 0, "failed": 0}


    def process_directory(self, target_dir):
        os.makedirs(self.dir_success, exist_ok=True)
        os.makedirs(self.dir_output, exist_ok=True)
        os.makedirs(self.dir_logs, exist_ok=True)

        raw_c_files = [f for f in os.listdir(target_dir) if f.endswith('.c')]
        if not raw_c_files:
            print(f"No C files found in {target_dir}")
            return
        
        c_files = DependencyGraph.get_compilation_order(target_dir, raw_c_files)

        for filename in c_files:
            filepath = os.path.join(target_dir, filename)
            print(f"\n{'-'*50}\nProcessing: {filename}")

            success = False
            for attempt in range(1, self.max_retries + 1):

                if attempt == 1:
                    try:
                        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                            raw_code = f.read()
                        
                        # --- NEW: Clean the code and save it back to disk ---
                        cleaned_code = clean_decompiled_code(raw_code)
                        if cleaned_code != raw_code:
                            with open(filepath, "w", encoding="utf-8") as f:
                                f.write(cleaned_code)
                            print(f"[AST Cleaner] Simplified casts and pointers for {filename}")
                            # Update raw_code so the next step analyzes the cleaned version
                            raw_code = cleaned_code 
                        
                        # --- EXISTING: Proactive Header Patching ---
                        ast_calls = analyze_ast_types(raw_code)
                        if proactive_header_patch(self.header_path, ast_calls):
                            self.gcc.recompile_globals()
                            
                    except Exception as e:
                        print(f"Proactive AST check/clean skipped for {filename}: {e}")

                # Proceed to compile the (now cleaned) file
                is_compiled, errors = self.gcc.compile_file(filepath, self.dir_output)

                if is_compiled:
                    print(f"Success! {filename} compiled cleanly.")
                    self.sync_prototype_to_header(filepath, self.header_path)
                    
                    try:
                        shutil.move(filepath, os.path.join(self.dir_success, filename))
                    except Exception as e:
                        print(f"Warning: Failed to move {filename} to success folder: {e}")

                    self.stats["success"] += 1
                    success = True
                    break

                else:
                    print(f"Compilation failed (Attempt {attempt}).")
                    if attempt < self.max_retries:
                        with open(filepath, "r", encoding="utf-8") as f:
                            broken_code = f.read()
                        
                        llm_response = self.agent.fix_with_llm(filepath, broken_code, errors, self.header_path, attempt)
                        
                        log_path = os.path.join(self.dir_logs, f"{filename}_attempt_{attempt}.log")                            
                        with open(log_path, "w", encoding="utf-8") as lf:
                            lf.write(f"=== COMPILER ERRORS ===\n{errors}\n\n=== LLM JSON RESPONSE ===\n{json.dumps(llm_response, indent=2)}")
                        
                        # --- INTERACTIVE PROMPT ---
                        print(f"\n[{filename} - LLM Proposed Fix]")
                        print(f"Reasoning: {llm_response.get('reasoning', 'No reasoning provided')}")
                        
                        print(json.dumps(llm_response, indent=2))
                        
                        user_choice = input("\nApprove and apply this patch? (y)es / (n)o (manual edit): ").strip().lower()

                        if user_choice == 'y':
                            header_patches = llm_response.get("header_patches", [])
                            if self.apply_header_patch(self.header_path, header_patches):
                                self.gcc.recompile_globals()
                                
                            func_patches = llm_response.get("function_patches", [])
                            fixed_code, function_patched = self.agent.apply_function_patch(broken_code, func_patches)
                            if function_patched:
                                with open(filepath, "w", encoding="utf-8") as f:
                                    f.write(fixed_code)
                            else:
                                print(f"No valid function patches successfully applied.")
                        else:
                            print(f"\n[!] Paused. The automated patch was rejected.")
                            print(f"You can now manually edit the file in your workspace:")
                            print(f"  -> {filepath}")
                            
                            input("\nPress ENTER to resume compilation once you have saved your manual changes...")
                    else:
                        # Fixed indentation matching 'if attempt < self.max_retries:'
                        print(f"!!!!Exhausted retries for {filename}!!!!")
                        os.makedirs(self.dir_failed, exist_ok=True)
                        err_path = os.path.join(self.dir_failed, filename.replace('.c', '.err'))
                        with open(err_path, "w", encoding="utf-8") as f:
                            f.write(errors)
                        
                        try:
                            shutil.move(filepath, os.path.join(self.dir_failed, filename))
                        except Exception as e:
                            print(f"[-] Warning: Failed to move {filename} to failed folder: {e}")
                        
                        self.stats["failed"] += 1

        print(f"\nProcessing Complete. Stats: {self.stats}")

    def apply_header_patch(self, header_path, header_patches):
        if not header_patches:
            return False
        db = SymbolDB()
        applied = False

        for patch in header_patches:
            replace_with = patch.get("replace", "").strip()
            if not replace_with:
                continue
            match = re.search(r'([\w\s\*]+)\s+(\w+)\s*\(', replace_with)
            if match:
                func_name = match.group(2).strip()
                ALL_IGNORED_FUNCTIONS = get_ignored_functions()
                
                if func_name in ALL_IGNORED_FUNCTIONS:
                    print(f"Purging system/libc function from database: {func_name}") 
                    db.remove_function(func_name)
                    db.export_header(header_path) 
                    return True 
            if db.parse_and_upsert_prototype(replace_with):
                applied = True
                print(f"[DB Patch] Header patch registered in DB: {replace_with}")
            else:
                print(f"Failed to parse header replacement as prototype: {replace_with}")

        if applied:
            db.export_header(header_path)

        return applied

    def sync_prototype_to_header(self, filepath, header_path="LLM_globals.h"):
        """Extracts the compiled function prototype and updates it in the symbol DB."""
        if not os.path.exists(filepath):
            return

        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        pattern = r'([\w\s\*]+)\s+((?:FUN_|My_|thunk_)[0-9a-fA-F_a-zA-Z]+|entry)\s*\(([^)]*)\)\s*\{'
        match = re.search(pattern, content)
        if not match:
            return

        return_type = match.group(1).strip()
        func_name = match.group(2).strip()
        args = match.group(3).strip()

        db = SymbolDB()
        db.add_or_update_function(func_name, return_type, args)
        db.export_header(header_path)
        print(f"Synced compiled function '{func_name}' prototype to Symbol DB.")