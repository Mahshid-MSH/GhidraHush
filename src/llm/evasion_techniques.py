import os
import re
import glob
import json
import math
from base_agent import BaseLLMAgent
from prompts import (
    JUNK_CODE_PROMPT,
    STACK_STRING_PROMPT,
    VARIABLE_ALIASING_PROMPT,
    CONTROL_FLOW_PROMPT,
    LOCAL_CONTEXT_STRUCT_PROMPT
)


class DefensiveEvasion(BaseLLMAgent):
    def __init__(self, model_name=None, base_url=None, arch="x86", workspace_dir="."):
        self.workspace_dir = workspace_dir
        self.arch = arch
        super().__init__(model_name, base_url)
        print(f"DefensiveEvasion initialized with {self.model_name} at {self.base_url} for architecture: {self.arch}")

    @staticmethod
    def get_language_from_filename(filename):
        ext = os.path.splitext(filename)[1].lower()
        if ext in ('.c',):
            return 'c'
        elif ext == '.cpp':
            return 'cpp'
        else:
            return 'c'

    def call_llm(self, prompt, original_code, base_name="unknown", tech_name="unknown", language='c'):
        """Send prompt to LLM and extract raw C/C++ code utilizing the base agent."""
        print(f"Sending request to LLM for {tech_name} ({language})...")
        return self.process_llm_task(
            prompt=prompt,
            original_code=original_code,
            workspace_dir=self.workspace_dir,
            log_prefix=f"evasion_{tech_name}",
            base_name=base_name,
            options={
                'temperature': 0.0,
                'num_ctx': 8192,
                'top_k': 10,
                'top_p': 0.5,
                'repeat_penalty': 1.1,
                'seed': 42
            }
        )

    # ------------------------------------------------------------
    # apply_junk_code_insertion
    # ------------------------------------------------------------
    def apply_junk_code_insertion(self, c_code, base_name="unknown", language='c'):
        lang_word = "C++" if language == "cpp" else "C"
        code_fence = "cpp" if language == "cpp" else "c"
        prompt = JUNK_CODE_PROMPT.format(
            lang_word=lang_word,
            arch=self.arch,
            code_fence=code_fence,
            c_code=c_code
        )
        return self.call_llm(prompt, c_code, base_name, "junk_code", language=language)

    # ------------------------------------------------------------
    # apply_stack_string_xor_obfuscation
    # ------------------------------------------------------------
    def apply_stack_string_xor_obfuscation(self, c_code, base_name="unknown", language='c'):
        lang_word = "C++" if language == "cpp" else "C"
        code_fence = "cpp" if language == "cpp" else "c"
        prompt = STACK_STRING_PROMPT.format(
            lang_word=lang_word,
            code_fence=code_fence,
            c_code=c_code
        )
        return self.call_llm(prompt, c_code, base_name, "stack_string_obfuscation", language=language)

    # ------------------------------------------------------------
    # apply_aggressive_variable_aliasing
    # ------------------------------------------------------------
    def apply_aggressive_variable_aliasing(self, c_code, base_name="unknown", language='c'):
        lang_word = "C++" if language == "cpp" else "C"
        code_fence = "cpp" if language == "cpp" else "c"
        prompt = VARIABLE_ALIASING_PROMPT.format(
            lang_word=lang_word,
            code_fence=code_fence,
            c_code=c_code
        )
        return self.call_llm(prompt, c_code, base_name, "variable_aliasing", language=language)

    # ------------------------------------------------------------
    # apply_control_flow_obfuscation
    # ------------------------------------------------------------
    def apply_control_flow_obfuscation(self, c_code, base_name="unknown", language='c'):
        lang_word = "C++" if language == "cpp" else "C"
        code_fence = "cpp" if language == "cpp" else "c"
        prompt = CONTROL_FLOW_PROMPT.format(
            lang_word=lang_word,
            arch=self.arch,
            code_fence=code_fence,
            c_code=c_code
        )
        return self.call_llm(prompt, c_code, base_name, "control_flow_Obfuscation", language=language)

    # ------------------------------------------------------------
    # apply_local_context_struct_packaging
    # ------------------------------------------------------------
    def apply_local_context_struct_packaging(self, c_code, base_name="unknown", language='c'):
        lang_word = "C++" if language == "cpp" else "C"
        code_fence = "cpp" if language == "cpp" else "c"
        prompt = LOCAL_CONTEXT_STRUCT_PROMPT.format(
            lang_word=lang_word,
            code_fence=code_fence,
            c_code=c_code
        )
        return self.call_llm(prompt, c_code, base_name, "local_context_struct", language=language)

    # ------------------------------------------------------------
    # apply_all_techniques
    # ------------------------------------------------------------
    def apply_all_techniques(self, c_code, techniques=None, base_name="unknown", language='c'):
        """Apply a list of techniques in order."""
        if techniques is None:
            techniques = [
                'junk_code_insertion',
                'stack_string_xor_obfuscation',
                'aggressive_variable_aliasing',
                'control_flow_obfuscation',
                'local_context_struct_packaging'
            ]
        code = c_code
        for tech in techniques:
            method = getattr(self, f"apply_{tech}", None)
            if method:
                print(f"Applying {tech} ({language})...")
                code = method(code, base_name=base_name, language=language)
            else:
                print(f"Unknown technique: {tech}")
        return code

    # ------------------------------------------------------------
    # process_directory_with_scoring
    # ------------------------------------------------------------
    def process_directory_with_scoring(self, processed_dir, workspace_dir, exe_name, techniques=None):
        """Scores functions, filters external APIs, and creates a separate directory per technique."""
        if techniques is None:
            techniques = [
                'junk_code_insertion',
                'stack_string_xor_obfuscation',
                'aggressive_variable_aliasing',
                'control_flow_obfuscation',
                'local_context_struct_packaging'
            ]

        graph_path = os.path.join(workspace_dir, "extracted_functions", exe_name, "call_graph.json")
        call_graph = {}
        if os.path.exists(graph_path):
            with open(graph_path, "r", encoding="utf-8") as f:
                call_graph = json.load(f)
        else:
            print(f"Warning: Call graph not found at {graph_path}")
            
        c_files = glob.glob(os.path.join(processed_dir, "*.c"))
        cpp_files = glob.glob(os.path.join(processed_dir, "*.cpp"))
        cpp_files += glob.glob(os.path.join(processed_dir, "*.cc"))
        cpp_files += glob.glob(os.path.join(processed_dir, "*.cxx"))
        all_files = c_files + cpp_files
        
        scored_functions = []
        
        for file_path in all_files:
            base_name = os.path.splitext(os.path.basename(file_path))[0]   
            with open(file_path, 'r', encoding='utf-8') as f:
                loc = len(f.readlines()) 
                
            api_count = len(call_graph.get(base_name, []))
            score = (loc / 10.0) + (api_count * 2.0)
            
            scored_functions.append({
                'file_path': file_path,
                'name': base_name,
                'score': score
            })
            
        total_functions = len(scored_functions)
        if total_functions == 0:
            print("No valid internal functions found for scoring.")
            return

        if total_functions < 10:
            percentage = 1.00
        elif 10 <= total_functions <= 20:
            percentage = 0.80
        elif 21 <= total_functions <= 40:
            percentage = 0.50
        elif 41 <= total_functions <= 70:
            percentage = 0.30
        else:
            percentage = 0.15

        target_count = math.ceil(total_functions * percentage)
        print(f"\n--- Selection Criteria ---")
        print(f"Total Internal Functions: {total_functions}")
        print(f"Target Modification Rate: {percentage * 100}%")
        print(f"Target Function Count: {target_count}")
        print(f"--------------------------\n")

        scored_functions.sort(key=lambda x: x['score'], reverse=True)
        worthy_function_names = set(f['name'] for f in scored_functions[:target_count])
        binary_name = os.path.splitext(exe_name)[0]
        
        for tech in techniques:
            tech_dir = os.path.join(workspace_dir, "processed_functions", f"{binary_name}_{tech}")
            os.makedirs(tech_dir, exist_ok=True)
            
            print(f"\n--- Generating Variant Directory: {tech_dir} ---")
            
            for file_path in all_files:
                base_name = os.path.splitext(os.path.basename(file_path))[0]
                language = self.get_language_from_filename(file_path)
                dest_path = os.path.join(tech_dir, os.path.basename(file_path))
                
                with open(file_path, 'r', encoding='utf-8') as f:
                    code = f.read()

                if base_name in worthy_function_names:
                    method = getattr(self, f"apply_{tech}", None)
                    if method:
                        print(f"Applying {tech} to: {base_name} ({language})")
                        modified_code = method(code, base_name=base_name, language=language)
                    else:
                        print(f"Unknown technique method for {tech}, passing unchanged.")
                        modified_code = code
                    with open(dest_path, 'w', encoding='utf-8') as f:
                        f.write(modified_code)
                else:
                    with open(dest_path, 'w', encoding='utf-8') as f:
                        f.write(code)