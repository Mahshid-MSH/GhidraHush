import os
import json
import re
from ollama import Client

class PatchAgent:
    def __init__(self, model_name, base_url):
        self.client = Client(host=base_url)
        self.model_name = model_name

    def extract_highest_priority_error(self, full_error_log):
        """
        Parses GCC output into isolated blocks, groups them by the referenced function,
        and prioritizes structural errors over type warnings for each function sequentially.
        """
        lines = full_error_log.strip().split('\n')
        blocks = []
        current_block = []
        preamble = []
        
        start_of_block = re.compile(r'^[^:]+:\d+:\d+: (error|warning):')

        for line in lines:
            if start_of_block.search(line):
                if current_block:
                    blocks.append('\n'.join(current_block))
                    current_block = []
                if not blocks and preamble:
                    current_block.extend(preamble)
                current_block.append(line)
            else:
                if current_block:
                    current_block.append(line)
                else:
                    preamble.append(line)
                    
        if current_block:
            blocks.append('\n'.join(current_block))

        if not blocks:
            return full_error_log

        def get_target_function(block_text):
            match = re.search(r'(?:function|of)\s+‘([^’]+)’', block_text)
            if match:
                return match.group(1)
            match = re.search(r'\b((?:FUN_|My_|thunk_)[0-9a-zA-Z_]+)\b', block_text)
            if match:
                return match.group(1)
            return "unknown_func"

        target_funcs = []
        block_func_map = []
        
        for block in blocks:
            func = get_target_function(block)
            if func not in target_funcs:
                target_funcs.append(func)
            block_func_map.append((func, block))

        structural_keywords = ["too many arguments", "too few arguments", "undeclared", "implicit declaration", "conflicting types"]

        for target_func in target_funcs:
            func_blocks = [b for f, b in block_func_map if f == target_func]
            for block in func_blocks:
                if any(keyword in block.lower() for keyword in structural_keywords):
                    return block 
            if func_blocks:
                return func_blocks[0]

        return blocks[0]

    def retrieve_header_context(self, header_path, c_code, error_log):
        """Extracts only header declarations relevant to symbols referenced in code or errors."""
        if not os.path.exists(header_path):
            return "// LLM_globals.h not found"

        tokens = set(re.findall(r'\b[a-zA-Z_]\w*\b', c_code + "\n" + error_log))
        c_keywords = {
            'if', 'else', 'for', 'while', 'return', 'int', 'char', 'void', 
            'struct', 'typedef', 'const', 'unsigned', 'uintptr_t', 'sizeof'
        }
        search_tokens = tokens - c_keywords

        relevant_lines = []
        with open(header_path, 'r', encoding='utf-8') as f:
            for line in f:
                line_str = line.strip()
                if not line_str or line_str.startswith('//'):
                    continue
                    
                if line_str.startswith('#include') or line_str.startswith('#define'):
                    relevant_lines.append(line_str)
                    continue

                for token in search_tokens:
                    if re.search(rf'\b{re.escape(token)}\b', line_str):
                        relevant_lines.append(line_str)
                        break

        seen = set()
        deduped_lines = [x for x in relevant_lines if not (x in seen or seen.add(x))]
        return "\n".join(deduped_lines)

    def build_whole_function_prompt(self, c_code, error_log, retrieved_header_context, attempt=1):
        prompt = f"""You are a C/C++ bug-fixing assistant.
        Your task is to fix compiler errors by outputting the ENTIRE corrected source code.

        ### RELEVANT GLOBAL HEADER CONTEXT (LLM_globals.h):
        {retrieved_header_context}

        ### COMPILER ERRORS:
        {error_log}

        ### BROKEN SOURCE CODE:
        {c_code}

        ### INSTRUCTIONS:
        1. IDENTIFY THE ERROR TYPE: Is this a structural error (too many/few arguments, undeclared) or a type error?
        2. HEADER PATCHES: If the error involves an invalid cast from a function returning `void`, or mismatched arguments, you MUST write a new prototype in `header_patches` to fix the return type or signature. 
        3. TYPES SECOND: Explicitly cast all global variables, raw memory addresses, and DAT_... variables to the exact types expected.
        4. UNDECLARED VARIABLES & SCOPE: If an error states a variable is undeclared, you MUST add its declaration at the VERY TOP of the function block. NEVER declare variables inside `if` blocks, `for` loops, or `do-while` loops, as they will lose scope.
        5. RETURN COMPLETE CODE: You must return the entirety of the C code provided above, with your fixes seamlessly integrated. Do not truncate the code.

        ### REQUIRED JSON FORMAT:
        You must respond ONLY with a valid JSON object matching this exact schema. If no header patch is needed, leave the list empty [].
        {{
            "reasoning": "Explain whether this is a structural or type error, and exactly what you changed.",
            "full_fixed_code": "The complete, fully corrected C code string, including all includes and the full function block.",
            "header_patches": [
                {{
                    "replace": "int FUN_00401000(char *a);" 
                }}
            ]
        }}
        """
        return prompt

    def build_surgical_prompt(self, c_code, error_log, retrieved_header_context, attempt=1):
        lines = c_code.split('\n')
        line_numbered_code = "\n".join(f"{i+1:3d} | {line}" for i, line in enumerate(lines))

        prompt = f"""You are a C/C++ bug-fixing assistant. DO NOT rewrite the entire function.
        Your task is to fix compiler errors by outputting SURGICAL LINE REPLACEMENTS in JSON format.

        ### RELEVANT GLOBAL HEADER CONTEXT (LLM_globals.h):
        {retrieved_header_context}

        ### COMPILER ERRORS:
        {error_log}

        ### BROKEN FUNCTION SOURCE CODE:
        {line_numbered_code}

        ### INSTRUCTIONS:
        1. IDENTIFY THE ERROR TYPE: Is this a structural error (too many/few arguments, undeclared) or a type error (cast warning, pointer mismatch)?
        2. SIGNATURES FIRST: If the error is "too many/few arguments" OR "invalid use of void expression", Ghidra guessed the global signature incorrectly. The call site inside the function is the absolute source of truth. You MUST issue a "header_patches" replacement to make the global header match the call site.
        - If it's called with zero arguments, change the header to accept `(void)`.
        - If it's called with more arguments than the header has, change the header to a variadic function `(char *format, ...)` or add generic `uintptr_t` parameters.
        - If the code tries to assign a void function to a typed variable, change the header's return type from void to match the exact type of the variable it is being assigned to or cast to.        
        - If a function is called with zero arguments in the body, you MUST rewrite its header patch to accept (void).
        3. TYPES SECOND: Only if the error is specifically about incompatible pointers or typecasts should you issue a "function_patches" replacement to add things like `(WCHAR *)` or `&`.
        4. ONE FIX AT A TIME: Do not attempt to fix unmentioned errors. Address ONLY the compiler error provided.
        5. Do NOT declare or redefine standard C library functions (such as strlen, strncpy, malloc, etc.). Assume all necessary standard headers (like <string.h>, <windows.h>) are already included. If the decompiled code contains a custom implementation of a standard function, you MUST rename it by adding a custom_ prefix (e.g., custom_strlen, custom_strncpy) to avoid conflicts with the standard library
        6. Treat all C warnings as errors. You must explicitly cast all global variables, raw memory addresses, and DAT_... variables to the exact types expected by the function signatures. When calling Windows API functions, explicitly cast arguments to Windows data types (e.g., cast to (LPSTR) or (LPCSTR) for strings, (LPDWORD) for pointer-to-DWORD, (LPVOID) for generic pointers). Do NOT rely on implicit conversions between integers and pointers, or between different pointer types. Always write the explicit cast (e.g., GetUserNameA((LPSTR)DAT_00409f8c, (LPDWORD)&DAT_004099e0);).
        ### REQUIRED JSON FORMAT:
        ### REQUIRED JSON FORMAT:
        You must respond ONLY with a valid JSON object matching this exact schema:
        {{
        "reasoning": "Explain whether this is a structural or type error, and what needs fixing.",
        "function_patches": [
            {{
            "line_number": <integer line number from the provided code>,
            "old_line": "<exact current line of code>",
            "new_line": "<corrected line of code>"
            }}
        ],
        "header_patches": [
            {{
            "replace": "<the fully corrected prototype, e.g., int FUN_00401000(char *a);>"
            }}
        ]
        }}
        """
        return prompt


    def apply_function_patch(self, c_code, full_fixed_code):
        """Replaces the entire broken code with the LLM's generated whole function."""
        if not full_fixed_code or full_fixed_code.strip() == "":
            print("Function Patch Failed: LLM returned empty code.")
            return c_code, False

        print(" Applied Whole-Function Patch successfully.")
        return full_fixed_code, True

    """

    def apply_function_patch(self, c_code, function_patches):
        #Applies string replacements based on JSON patch definitions.
        if not function_patches:
            return c_code, False

        modified_code = c_code
        applied_count = 0

        for patch in function_patches:
            # Use the keys that the LLM actually returns
            old_line = patch.get("old_line", "").strip()
            new_line = patch.get("new_line", "").strip()

            if not old_line:
                continue

            # In case the LLM accidentally included line numbers, strip them
            old_line = re.sub(r'^\d+\s*\|\s*', '', old_line)
            new_line = re.sub(r'^\d+\s*\|\s*', '', new_line)

            if old_line in modified_code:
                modified_code = modified_code.replace(old_line, new_line, 1)
                applied_count += 1
                print(f" Applied Function Patch: '{old_line}' -> '{new_line}'")
            else:
                print(f"Function Patch Failed (Line not found): '{old_line}'")

        return modified_code, applied_count > 0

    """

    def fix_with_llm(self, filepath, c_code, error_log, header_path, attempt):
        # FIXED: Pass header_path explicitly into this method from the orchestrator
        isolated_error = self.extract_highest_priority_error(error_log)
        header_context = self.retrieve_header_context(header_path, c_code, isolated_error)
        prompt = self.build_whole_function_prompt(c_code, isolated_error, header_context, attempt)
        
        print(f"Asking LLM for JSON patches for {os.path.basename(filepath)} (Attempt {attempt})...")
                
        current_temp = 0.0 if attempt == 1 else 0.2 * (attempt - 1)
        response = ""
        
        for chunk in self.client.generate(
            model=self.model_name, 
            prompt=prompt, 
            stream=True, 
            format='json',
            options={'temperature': current_temp, 'num_predict': 2048}
        ):
            response += chunk['response']         
            
        try:
            return json.loads(response)
        except json.JSONDecodeError as e:
            print(f"Failed to parse LLM JSON response: {e}")
            return {"reasoning": "JSON parse error", "header_patches": [], "function_patches": []}