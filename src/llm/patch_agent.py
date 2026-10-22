import re
import json
import os
from base_agent import BaseLLMAgent
from prompts import get_whole_function_prompt, get_surgical_prompt

# Console styling constants for rich logging output
DIM, RED, GREEN, YELLOW, CYAN, RESET = (
    '\033[2m', '\033[91m', '\033[92m', '\033[93m', '\033[96m', '\033[0m'
)


class PatchAgent(BaseLLMAgent):
    """Repair compiler errors by prioritizing diagnostics and querying an LLM."""

    def extract_highest_priority_error(self, full_error_log):
        """Group diagnostics and select the highest-priority compiler error."""
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
        if not os.path.exists(header_path):
            return "// data_globals.h not found"

        with open(header_path, 'r', encoding='utf-8') as f:
            header_content = f.read()

        # Include the full header when it fits comfortably in the prompt.
        if len(header_content) < 12000:
            return header_content

        # Truncate very large headers to keep prompt size bounded.
        return header_content[:12000] + "\n// ... (truncated)"

    def build_whole_function_prompt(self, c_code, error_log, retrieved_header_context, attempt=1, lang="C"):
        """Build the language-specific whole-function repair prompt."""
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
        line_numbered_code = "\n".join(
            f"{index + 1:3d} | {line}" for index, line in enumerate(lines)
        )
        return get_surgical_prompt(line_numbered_code, error_log, retrieved_header_context)

    def apply_function_patch(self, c_code, full_fixed_code):
        """Applies the whole-function replacement patch generated by the LLM."""
        if not full_fixed_code or full_fixed_code.strip() == "":
            print("Function Patch Failed: LLM returned empty code.")
            return c_code, False

        print(" Applied Whole-Function Patch successfully.")
        return full_fixed_code, True

    def _coerce_response(self, raw):
        """Parse structured LLM output, with a fallback for bare source code."""
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
                "header_patches": [],
            }
            
        return {
            "reasoning": f"unparseable: {text[:200]}",
            "full_fixed_code": "",
            "header_patches": [],
        }

    def _strip_fences(self, text):
        """Strips markdown code fences from a response string."""
        m = re.search(r"```(?:json)?\s*\n(.*?)```", text, re.DOTALL)
        return m.group(1) if m else text

    def fix_with_llm(self, c_code, error_log, header_path, attempt, is_cpp=False):
        """Request a repair, increasing temperature on later attempts."""
        lang = "C++" if is_cpp else "C"
        isolated = self.extract_highest_priority_error(error_log)   # Priority focus
        header_ctx = self.retrieve_header_context(header_path, c_code, error_log)

        # Compact full error list: one line per error, capped to avoid context bloat
        all_errors = "\n".join(
            line.strip() for line in error_log.splitlines() if "error:" in line
        )[:3500]

        prompt = self.build_whole_function_prompt(
            c_code,
            f"PRIORITY ERROR (fix first):\n{isolated}\n\n"
            f"ALL OTHER ERRORS (must also be fixed; the file must "
            f"compile completely):\n{all_errors}",
            header_ctx,
            attempt,
            lang=lang,
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