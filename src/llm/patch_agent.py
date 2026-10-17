import os
import json
import re
from base_agent import BaseLLMAgent
from prompts import get_whole_function_prompt, get_surgical_prompt

# Console styling constants for rich logging output
DIM, RED, GREEN, YELLOW, CYAN, RESET = (
    '\033[2m', '\033[91m', '\033[92m', '\033[93m', '\033[96m', '\033[0m'
)


class PatchAgent(BaseLLMAgent):
    """
    Automated Compiler Error Correction Agent.
    
    Why this exists: Even after multi-pass beautification, decompiled code often 
    fails compilation due to subtle type mismatches, missing declarations, or 
    syntax errors. When the compiler (`gcc`/`g++`) throws an error log, this agent 
    reads the log, isolates the core issue, and queries the LLM to patch the code 
    until it compiles cleanly.
    """

    def extract_highest_priority_error(self, full_error_log):
        """
        Parses compiler output into isolated blocks, groups them by function, 
        and prioritizes structural errors over minor warnings.
        
        Why it's here: If a C file has 50 compiler errors, feeding all of them 
        to an LLM simultaneously causes it to hallucinate or get confused. This method 
        hunts down the *root-cause* error (like an undeclared identifier or conflicting 
        types) and targets that first.
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
            """Extracts the function name referenced in the compiler error block."""
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

        # Structural errors that break compilation flow entirely
        structural_keywords = [
            "too many arguments", "too few arguments", "undeclared",
            "implicit declaration", "conflicting types",
            "was not declared in this scope", "conflicting declaration"
        ]

        # Prioritize structural errors over minor warnings for the target function
        for target_func in target_funcs:
            func_blocks = [b for f, b in block_func_map if f == target_func]
            for block in func_blocks:
                if any(keyword in block.lower() for keyword in structural_keywords):
                    return block 
            if func_blocks:
                return func_blocks[0]

        return blocks[0]

    def retrieve_header_context(self, header_path, c_code, error_log):
        """
        Extracts only header declarations from `data_globals.h` that are relevant 
        to symbols referenced in the code or error logs.
        
        Why it's here: `data_globals.h` can grow to thousands of lines as functions 
        are processed. Injecting the entire file into every prompt wastes context 
        tokens. This scanner filters the header down to only the exact variables 
        and prototypes needed to fix the current error.
        """
        if not os.path.exists(header_path):
            return "// data_globals.h not found"

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
                    
                # Layout checks exist for the compiler, not the model: every one mentions the
                # struct name, so they matched on nearly every token and bloated the prompt.
                if line_str.startswith(('GH_STATIC_ASSERT', '_Static_assert')):
                    continue

                if line_str.startswith('#include') or line_str.startswith('#define'):
                    relevant_lines.append(line_str)
                    continue

                for token in search_tokens:
                    if re.search(rf'\b{re.escape(token)}\b', line_str):
                        relevant_lines.append(line_str)
                        break

        # Deduplicate and preserve order
        seen = set()
        deduped_lines = [x for x in relevant_lines if not (x in seen or seen.add(x))]
        return "\n".join(deduped_lines)

    def build_whole_function_prompt(self, c_code, error_log, retrieved_header_context, attempt=1, lang="C"):
        """
        Constructs the comprehensive prompt instructing the LLM to fix the broken function 
        while adhering to strict C/C++ language rules.
        """
        lang_rules = (
            "LANGUAGE RULES (C++ / g++ -fpermissive):\n"
            "- reinterpret_cast ONLY between pointer and integer types; "
            "static_cast for integer<->integer and openmode/enum OR-combines.\n"
            "- Never write &arrayName where char*/const char* is expected; "
            "arrays decay -- cast the array itself, e.g. (LPCSTR)Virus.\n"
            "- Do not add #include lines; windows.h and data_globals.h are "
            "force-included. Program prototypes live in extern \"C\" in "
            "data_globals.h -- never redeclare them.\n"
        ) if lang == "C++" else (
            "LANGUAGE RULES (C / gcc): Do not add #include lines; windows.h "
            "and data_globals.h are force-included. Never redeclare program "
            "functions declared in data_globals.h.\n"
        )
        base = get_whole_function_prompt(c_code, error_log, retrieved_header_context)
        return f"{lang_rules}\n\n{base}"

    def build_surgical_prompt(self, c_code, error_log, retrieved_header_context, attempt=1):
        """Prepares line-numbered code for localized bug fixes."""
        lines = c_code.split('\n')
        line_numbered_code = "\n".join(f"{i+1:3d} | {line}" for i, line in enumerate(lines))
        return get_surgical_prompt(line_numbered_code, error_log, retrieved_header_context)

    def apply_function_patch(self, c_code, full_fixed_code):
        """Applies the whole-function replacement patch generated by the LLM."""
        if not full_fixed_code or full_fixed_code.strip() == "":
            print("Function Patch Failed: LLM returned empty code.")
            return c_code, False

        print(" Applied Whole-Function Patch successfully.")
        return full_fixed_code, True

    def _coerce_response(self, raw):
        """
        Safely parses LLM output into a structured dictionary, with robust fallbacks 
        if the model fails to return valid JSON.
        
        Why it's here: LLMs frequently ignore instructions to "respond in valid JSON" 
        and instead output raw markdown code blocks. This method attempts to extract 
        JSON; if that fails, it gracefully intercepts bare code and wraps it in the expected format.
        """
        text = self._strip_fences(raw).strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
            
        # Fallback: Hunt for JSON braces inside conversational text
        start, end = text.find("{"), text.rfind("}")
        if start != -1 and end > start:
            try:
                return json.loads(text[start:end + 1])
            except json.JSONDecodeError:
                pass
                
        # Fallback: Model answered with bare code instead of JSON -- accept it.
        if text.lstrip().startswith(("{", "int ", "void ", "#include")):
            return {
                "reasoning": "non-JSON response accepted as code",
                "full_fixed_code": text, 
                "header_patches": []
            }
            
        return {
            "reasoning": f"unparseable: {text[:200]}",
            "full_fixed_code": "", 
            "header_patches": []
        }

    def _strip_fences(self, text):
        """Strips markdown code fences from a response string."""
        m = re.search(r"```(?:json)?\s*\n(.*?)```", text, re.DOTALL)
        return m.group(1) if m else text

    def fix_with_llm(self, c_code, error_log, header_path, attempt, is_cpp=False):
        """
        Orchestrates the error-fixing workflow by assembling the prompt, setting 
        adaptive temperatures, and invoking the LLM.
        
        Why it's here: On the first attempt, temperature is set to `0.0` for deterministic 
        corrections. If the fix fails, temperature increases incrementally (`0.2`, `0.4`, etc.) 
        on subsequent attempts to encourage creative problem-solving for stubborn compilation errors.
        """
        lang = "C++" if is_cpp else "C"
        isolated = self.extract_highest_priority_error(error_log)   # Priority focus
        header_ctx = self.retrieve_header_context(header_path, c_code, error_log)

        # Compact full error list: one line per error, capped to avoid context bloat
        all_errors = "\n".join(
            l.strip() for l in error_log.splitlines() if "error:" in l
        )[:3500]

        prompt = self.build_whole_function_prompt(
            c_code, 
            f"PRIORITY ERROR (fix first):\n{isolated}\n\n"
            f"ALL OTHER ERRORS (must also be fixed; the file must "
            f"compile completely):\n{all_errors}",
            header_ctx, 
            attempt, 
            lang=lang
        )
        
        # Adaptive temperature scaling per retry attempt
        temp = 0.0 if attempt == 1 else 0.2 * (attempt - 1)
        print(f"{CYAN}[llm] attempt {attempt}, temperature={temp}{RESET}")
        
        response = self.stream_prompt(prompt, options={"temperature": temp})
        try:
            return self._coerce_response(response)
        except json.JSONDecodeError:
            return {
                "reasoning": "JSON parse error", 
                "header_patches": []
            }