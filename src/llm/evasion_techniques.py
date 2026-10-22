import os
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


# ------------------------------------------------------------
# Parameter tables: one entry per technique, each value maps to the
# token text that gets substituted into the prompt via .replace().
# ------------------------------------------------------------

JUNK_DENSITY_PARAMS = {
    "sparse": {
        "branch_count": "2",
        "min_lines": "8",
        "allowed_patterns": "Pattern A (Math Invariant) only",
    },
    "medium": {
        "branch_count": "2",
        "min_lines": "10",
        "allowed_patterns": "Pattern A (Math Invariant) and Pattern B (System Query)",
    },
    "dense": {
        "branch_count": "3",
        "min_lines": "15",
        "allowed_patterns": "Pattern A (Math Invariant), Pattern B (System Query), and Pattern C (Combination)",
    },
}

STACK_STRING_COVERAGE_PARAMS = {
    "api_names_only": (
        "Target ONLY DLL names and Win32 API/function name strings passed to "
        "Get/Load-style calls. Leave file paths, registry keys, and network "
        "endpoints alone."
    ),
    "sensitive_only": (
        "Target prominent or sensitive string literals (DLL names, API names, "
        "file paths, registry keys, network endpoints). Leave minor formatting "
        "strings (`\"%s\"`, `\"\\n\"`) alone."
    ),
    "all": (
        "Target EVERY string literal of length 3 characters or more, including "
        "minor formatting strings, excluding single-character literals."
    ),
}

STACK_STRING_KEY_SCHEME_PARAMS = {
    "single_byte": (
        "Assign a DIFFERENT, unique 1-byte XOR key (e.g., `0x3E`, `0x7A`, `0x1F`) "
        "to each target string literal across the function."
    ),
    "rotating": (
        "Assign each target string a short multi-byte rotating key (3-4 bytes, "
        "e.g., `{0x3E,0x7A,0x1F}`), XOR-ing each character with "
        "`key[i % key_len]` instead of a single byte."
    ),
}

VARIABLE_ALIASING_SCOPE_PARAMS = {
    "all_scalars": {
        "scalar_rule": (
            "Target EVERY eligible local scalar variable in the function "
            "(e.g., `int`, `DWORD`, `HANDLE`, `size_t`, `char`, `LPVOID`, `HMODULE`)."
        ),
        "loop_counter_rule": "Target loop counters (e.g., the `i` in `for (int i = 0; ...)`).",
    },
    "loop_counters_only": {
        "scalar_rule": "Do NOT target general local scalar variables; leave them untouched.",
        "loop_counter_rule": (
            "Target ONLY loop counters (e.g., the `i` in `for (int i = 0; ...)`) "
            "and no other variables."
        ),
    },
    "pointers_only": {
        "scalar_rule": (
            "Target ONLY local variables that are already pointer types "
            "(e.g., `char*`, `HANDLE`, `LPVOID`, `HMODULE`). Leave plain scalars "
            "(`int`, `DWORD`, `size_t`) untouched."
        ),
        "loop_counter_rule": "Do NOT target loop counters unless they are pointer-typed.",
    },
}

CF_DISPATCH_PARAMS = {
    "goto_flattening": (
        "Control Flow Flattening using a volatile state variable and a "
        "goto-based dispatcher (NO switch statements). Follow the STRUCTURAL "
        "PATTERN below exactly."
    ),
    "opaque_jump": (
        "Opaque conditional jump using MSVC __asm blocks and volatile condition "
        "checks (x86 only) or memory-read/intrinsic-based opaque branches (x64). "
        "Do NOT flatten control flow into a state machine for this variant."
    ),
}

STRUCT_PACKING_GROUPING_PARAMS = {
    "by_declaration_order": {
        "selection_rule": (
            "Target EVERY locally declared variable (e.g., scalars, pointers, "
            "arrays, handles), in the same order they were originally declared."
        ),
        "grouping_rule": (
            "Move all targeted variable declarations into the `struct _LocalCtx` "
            "definition, preserving original declaration order."
        ),
    },
    "by_type": {
        "selection_rule": "Target EVERY locally declared variable (e.g., scalars, pointers, arrays, handles).",
        "grouping_rule": (
            "Move all targeted variable declarations into the `struct _LocalCtx` "
            "definition, GROUPED BY TYPE (all HANDLE-type fields together, then "
            "all integer-type fields, then all pointer-type fields, etc.), "
            "regardless of original declaration order."
        ),
    },
    "by_access_frequency": {
        "selection_rule": "Target EVERY locally declared variable (e.g., scalars, pointers, arrays, handles).",
        "grouping_rule": (
            "Move all targeted variable declarations into the `struct _LocalCtx` "
            "definition, ordering fields by how frequently each variable is "
            "read/written in the function body (most-accessed variable declared "
            "first in the struct)."
        ),
    },
}

TECHNIQUE_PARAM_SPACES = {
    "junk_code_insertion": [{"density": d} for d in JUNK_DENSITY_PARAMS.keys()],
    "stack_string_xor_obfuscation": [
        {"coverage": c, "key_scheme": k}
        for c in STACK_STRING_COVERAGE_PARAMS.keys()
        for k in STACK_STRING_KEY_SCHEME_PARAMS.keys()
    ],
    "aggressive_variable_aliasing": [{"scope": s} for s in VARIABLE_ALIASING_SCOPE_PARAMS.keys()],
    "control_flow_obfuscation": [{"dispatch": d} for d in CF_DISPATCH_PARAMS.keys()],
    "local_context_struct_packaging": [{"grouping": g} for g in STRUCT_PACKING_GROUPING_PARAMS.keys()],
}


def validate_technique_parameters(technique, params):
    """Validate a single technique configuration before prompt generation."""
    parameter_space = TECHNIQUE_PARAM_SPACES.get(technique)
    if parameter_space is None:
        raise ValueError(f"Unknown evasion technique: {technique}")
    if isinstance(params, list):
        if not params:
            raise ValueError(f"At least one configuration is required for {technique}")
        return [validate_technique_parameters(technique, item) for item in params]
    if not isinstance(params, dict):
        raise ValueError(f"Parameters for {technique} must be an object or a list of objects")

    allowed_values = {}
    for combination in parameter_space:
        for key, value in combination.items():
            allowed_values.setdefault(key, set()).add(value)

    for key, value in params.items():
        if key not in allowed_values:
            raise ValueError(f"Unknown parameter '{key}' for {technique}")
        if value not in allowed_values[key]:
            choices = ", ".join(sorted(allowed_values[key]))
            raise ValueError(
                f"Invalid {key} '{value}' for {technique}; choose from: {choices}"
            )
    return params


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
    def apply_junk_code_insertion(self, c_code, base_name="unknown", language='c', params=None):
        params = params or {}
        density = params.get("density", "medium")
        cfg = JUNK_DENSITY_PARAMS[density]

        lang_word = "C++" if language == "cpp" else "C"
        code_fence = "cpp" if language == "cpp" else "c"

        prompt = JUNK_CODE_PROMPT.format(
            lang_word=lang_word,
            arch=self.arch,
            code_fence=code_fence,
            c_code=c_code
        )
        prompt = (prompt
                  .replace("___BRANCH_COUNT___", cfg["branch_count"])
                  .replace("___MIN_LINES___", cfg["min_lines"])
                  .replace("___ALLOWED_PATTERNS___", cfg["allowed_patterns"]))

        tech_name = f"junk_code_{density}"
        return self.call_llm(prompt, c_code, base_name, tech_name, language=language)

    # ------------------------------------------------------------
    # apply_stack_string_xor_obfuscation
    # ------------------------------------------------------------
    def apply_stack_string_xor_obfuscation(self, c_code, base_name="unknown", language='c', params=None):
        params = params or {}
        coverage = params.get("coverage", "sensitive_only")
        key_scheme = params.get("key_scheme", "single_byte")

        lang_word = "C++" if language == "cpp" else "C"
        code_fence = "cpp" if language == "cpp" else "c"

        prompt = STACK_STRING_PROMPT.format(
            lang_word=lang_word,
            code_fence=code_fence,
            c_code=c_code
        )
        prompt = (prompt
                  .replace("___SELECTION_RULE___", STACK_STRING_COVERAGE_PARAMS[coverage])
                  .replace("___KEY_SCHEME_RULE___", STACK_STRING_KEY_SCHEME_PARAMS[key_scheme]))

        tech_name = f"stack_string_{coverage}_{key_scheme}"
        return self.call_llm(prompt, c_code, base_name, tech_name, language=language)

    # ------------------------------------------------------------
    # apply_aggressive_variable_aliasing
    # ------------------------------------------------------------
    def apply_aggressive_variable_aliasing(self, c_code, base_name="unknown", language='c', params=None):
        params = params or {}
        scope = params.get("scope", "all_scalars")
        cfg = VARIABLE_ALIASING_SCOPE_PARAMS[scope]

        lang_word = "C++" if language == "cpp" else "C"
        code_fence = "cpp" if language == "cpp" else "c"

        prompt = VARIABLE_ALIASING_PROMPT.format(
            lang_word=lang_word,
            code_fence=code_fence,
            c_code=c_code
        )
        prompt = (prompt
                  .replace("___SCALAR_RULE___", cfg["scalar_rule"])
                  .replace("___LOOP_COUNTER_RULE___", cfg["loop_counter_rule"]))

        tech_name = f"variable_aliasing_{scope}"
        return self.call_llm(prompt, c_code, base_name, tech_name, language=language)

    # ------------------------------------------------------------
    # apply_control_flow_obfuscation
    # ------------------------------------------------------------
    def apply_control_flow_obfuscation(self, c_code, base_name="unknown", language='c', params=None):
        params = params or {}
        dispatch = params.get("dispatch", "goto_flattening")

        lang_word = "C++" if language == "cpp" else "C"
        code_fence = "cpp" if language == "cpp" else "c"

        prompt = CONTROL_FLOW_PROMPT.format(
            lang_word=lang_word,
            arch=self.arch,
            code_fence=code_fence,
            c_code=c_code
        )
        prompt = prompt.replace("___DISPATCH_INSTRUCTION___", CF_DISPATCH_PARAMS[dispatch])

        tech_name = f"control_flow_{dispatch}"
        return self.call_llm(prompt, c_code, base_name, tech_name, language=language)

    # ------------------------------------------------------------
    # apply_local_context_struct_packaging
    # ------------------------------------------------------------
    def apply_local_context_struct_packaging(self, c_code, base_name="unknown", language='c', params=None):
        params = params or {}
        grouping = params.get("grouping", "by_declaration_order")
        cfg = STRUCT_PACKING_GROUPING_PARAMS[grouping]

        lang_word = "C++" if language == "cpp" else "C"
        code_fence = "cpp" if language == "cpp" else "c"

        prompt = LOCAL_CONTEXT_STRUCT_PROMPT.format(
            lang_word=lang_word,
            code_fence=code_fence,
            c_code=c_code
        )
        prompt = (prompt
                  .replace("___SELECTION_RULE___", cfg["selection_rule"])
                  .replace("___GROUPING_RULE___", cfg["grouping_rule"]))

        tech_name = f"struct_packing_{grouping}"
        return self.call_llm(prompt, c_code, base_name, tech_name, language=language)

    # ------------------------------------------------------------
    # apply_all_techniques
    # ------------------------------------------------------------
    def apply_all_techniques(self, c_code, techniques=None, base_name="unknown", language='c', param_map=None):
        """
        Apply a list of techniques in order. param_map optionally supplies
        per-technique params, e.g. {"junk_code_insertion": {"density": "dense"}}.
        """
        if techniques is None:
            techniques = [
                'junk_code_insertion',
                'stack_string_xor_obfuscation',
                'aggressive_variable_aliasing',
                'control_flow_obfuscation',
                'local_context_struct_packaging'
            ]
        param_map = param_map or {}
        code = c_code
        for tech in techniques:
            method = getattr(self, f"apply_{tech}", None)
            if method:
                print(f"Applying {tech} ({language})...")
                code = method(code, base_name=base_name, language=language, params=param_map.get(tech))
            else:
                print(f"Unknown technique: {tech}")
        return code

    # ------------------------------------------------------------
    # process_directory_with_scoring
    # ------------------------------------------------------------
    def process_directory_with_scoring(self, processed_dir, workspace_dir, exe_name,
                                        techniques=None, param_map=None):
        """
        Scores functions, filters external APIs, and automatically generates variants
        per technique configuration using the top-scored function subset (no subset variants).
        """
        if techniques is None:
            techniques = [
                'junk_code_insertion',
                'stack_string_xor_obfuscation',
                'aggressive_variable_aliasing',
                'control_flow_obfuscation',
                'local_context_struct_packaging'
            ]
        param_map = param_map or {}

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
            if base_name == "data_globals":
                continue
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
        print("\n--- Selection Criteria ---")
        print(f"Total Internal Functions: {total_functions}")
        print(f"Target Modification Rate: {percentage * 100}%")
        print(f"Target Function Count: {target_count}")
        print("--------------------------\n")

        scored_functions.sort(key=lambda x: x['score'], reverse=True)
        binary_name = os.path.splitext(exe_name)[0]

        # Use a single deterministic subset of top-scored functions
        worthy_function_names = {f['name'] for f in scored_functions[:target_count]}

        for tech in techniques:
            param_combinations = param_map.get(tech) if param_map and tech in param_map else TECHNIQUE_PARAM_SPACES.get(tech, [{}])
            if isinstance(param_combinations, dict):
                param_combinations = [param_combinations]

            for params in param_combinations:
                if tech in TECHNIQUE_PARAM_SPACES:
                    validate_technique_parameters(tech, params)
                param_str = "_".join([f"{k}_{v}" for k, v in params.items()])
                variant_tag = f"_{param_str}" if param_str else ""
                
                tech_dir = os.path.join(
                    workspace_dir, "compiled_successfully", f"{binary_name}_{tech}{variant_tag}"
                )
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
                            print(f"Applying {tech} ({params}) to: {base_name} ({language})")
                            modified_code = method(
                                code, base_name=base_name, language=language,
                                params=params
                            )
                        else:
                            print(f"Unknown technique method for {tech}, passing unchanged.")
                            modified_code = code
                        with open(dest_path, 'w', encoding='utf-8') as f:
                            f.write(modified_code)
                    else:
                        with open(dest_path, 'w', encoding='utf-8') as f:
                            f.write(code)