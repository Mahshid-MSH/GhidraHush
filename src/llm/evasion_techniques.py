import os
import re, glob
from ollama import Client
import json, math
from base_agent import BaseLLMAgent


class DefensiveEvasion(BaseLLMAgent):
    def __init__(self, model_name=None, base_url=None, arch="x86", workspace_dir="."):
        self.workspace_dir = workspace_dir
        self.arch = arch
        super().__init__(model_name, base_url)
        print(f"DefensiveEvasion initialized with {self.model_name} at {self.base_url} for architecture: {self.arch}")

    # Helper to detect language from filename
    @staticmethod
    def get_language_from_filename(filename):
        ext = os.path.splitext(filename)[1].lower()
        if ext in ('.c',):
            return 'c'
        elif ext  == 'cpp':
            return 'cpp'
        else:
            # Fallback: assume C, could also try to inspect content
            return 'c'

    def call_llm(self, prompt, original_code, base_name="unknown", tech_name="unknown", language='c'):
        """Send prompt to LLM and extract raw C/C++ code utilizing the base agent."""
        print(f"Sending request to LLM for {tech_name} ({language})...")
        # The base agent (process_llm_task) should already handle code extraction.
        # If not, adjust its regex to accept both ```c and ```cpp fences.
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
    # apply_junk_code_insertion (updated for language awareness)
    # ------------------------------------------------------------
    def apply_junk_code_insertion(self, c_code, base_name="unknown", language='c'):
        lang_word = "C++" if language == "cpp" else "C"
        code_fence = "cpp" if language == "cpp" else "c"
        prompt = f"""
            You are an expert {lang_word} developer generating synthesized code variants.
            Target architecture: {self.arch}

            ### CRITICAL TRANSFORMATION RULE: ADDITIVE-ONLY
            - DO NOT MOVE, MODIFY, OR WRAP ANY EXISTING CODE INSIDE A DEAD BRANCH.
            - All original code statements MUST remain outside the `if` block in the live execution path.
            - Dead branches (`if (opaque_false_condition) {{ ... }}`) must contain ONLY newly generated, self-contained dummy logic.
            - The dummy logic may READ existing local variables (those declared before the branch), but it MUST NOT modify any original variable, global state, or function argument.
            - You may add required `#include` directives at the beginning of the file only if needed; do not remove or modify existing includes.

            ### MANDATORY VOLUME AND PLACEMENT
            - Insert **at least 2 dead branches** in the given function.
            - Place them at **different locations**: after variable declarations, before loops, inside loops (but not around original statements), and before return statements.
            - Each dead branch must contain **at least 10 lines** of dummy code.
            - Each dead branch must use a **different opaque predicate pattern** from the list below.
            - Each dead branch must use a **different category** from the list below.

            ### OPAQUE PREDICATE REQUIREMENTS
            Use only the following patterns, one per branch. Do NOT use `if (0)` or `volatile int v = 0; if (v)`.
            Do NOT use registry APIs in dead branches.

            Pattern A (Math Invariant):
            volatile int dummy_x = 7;
            if ((dummy_x * (dummy_x + 1)) % 2 != 0) {{
                // Dead branch
            }}

            Pattern B (System Query):
            if (GetPriorityClass(GetCurrentProcess()) == 0xFFFFFFFF) {{
                // Dead branch
            }}

            Pattern C (Combination):
            volatile DWORD dummy_tick = GetTickCount();
            if ((dummy_tick ^ 0x5A5A5A5A) == 0xFFFFFFFF && (dummy_tick & 0x80000000) != 0) {{
                // Dead branch
            }}

            ### DEAD BRANCH BODY REQUIREMENTS
            - The body must be self-contained and **may not use variables declared outside the branch** except for reading already‑declared local variables (parameters or locals).
            - **All variables used inside the branch must be either:**
            1. Declared inside the branch (e.g., `char local_buf[64];`), or
            2. Already declared in the function’s outer scope **before** the branch (and you only read them).
            - **Do not use variables declared in one dead branch inside another dead branch** – each branch is an independent scope.
            - Declare all dummy variables with `volatile` where possible to prevent compiler elimination.
            - Use at least 2 different Windows/C runtime API or standard C functions in each body.
            - Include dummy loops with at least 2 iterations that compute a dummy result and then discard it.
            - End each body with `memset` or `SecureZeroMemory` on dummy buffers to appear realistic.
            - Ensure no variable shadowing or redefinition.

            CATEGORIES (choose one per branch, no repeats within the same function)

            A: System info queries
            GetSystemInfo, GetLocalTime, GetUserNameA, GetComputerNameA
            → **You must use proper struct types**: SYSTEM_INFO, SYSTEMTIME, and declare them correctly (e.g., `SYSTEM_INFO si; GetSystemInfo(&si);`).

            B: Memory & String operations
            malloc, sprintf_s, strlen, memcpy, memset, free
            → If you use sprintf_s, you MUST add `#include <stdio.h>` at the top of the file (you are allowed to add includes).
            In C++, you may use `<cstdio>` instead.

            C: Bitwise/Math loops
            XOR loops over local dummy array, polynomial hash (use fixed constants like 0x811C9DC5 for FNV‑1a, not undeclared ones).

            ### STRUCTURAL PATTERN TO FOLLOW

            // --- ORIGINAL CODE STATEMENT ---
            original_statement_1;

            // --- INSERTED DEAD BRANCH 1 (ADDITIVE ONLY) ---
            volatile int dummy_x_1 = 7;
            if ((dummy_x_1 * (dummy_x_1 + 1)) % 2 != 0) {{
                // NEW DUMMY LOGIC HERE (Category A, at least 15 lines)
                // ... all variables declared inside this branch ...
            }}

            // --- ORIGINAL CODE STATEMENT CONTINUES ---
            original_statement_2;

            // --- INSERTED DEAD BRANCH 2 (ADDITIVE ONLY) ---
            volatile DWORD dummy_tick_2 = GetTickCount();
            if ((dummy_tick_2 ^ 0x5A5A5A5A) == 0xFFFFFFFF && (dummy_tick_2 & 0x80000000) != 0) {{
                // NEW DUMMY LOGIC HERE (Category B, at least 15 lines)
                // ... all variables declared inside this branch ...
            }}

            // --- ORIGINAL CODE STATEMENT CONTINUES ---
            original_statement_3;

            // --- INSERTED DEAD BRANCH 3 (ADDITIVE ONLY) ---
            if (GetPriorityClass(GetCurrentProcess()) == 0xFFFFFFFF) {{
                // NEW DUMMY LOGIC HERE (Category C, at least 15 lines)
                // ... all variables declared inside this branch ...
            }}

            INPUT CODE:
            {c_code}

            Return ONLY the complete, modified source code inside a single markdown code block.
            Use ```{code_fence} according to the detected input language.

            """
        return self.call_llm(prompt, c_code, base_name, "junk_code", language=language)

    # ------------------------------------------------------------
    # apply_stack_string_xor_obfuscation (updated)
    # ------------------------------------------------------------
    def apply_stack_string_xor_obfuscation(self, c_code, base_name="unknown", language='c'):
        lang_word = "C++" if language == "cpp" else "C"
        code_fence = "cpp" if language == "cpp" else "c"
        prompt = f"""
        You are an expert {lang_word} developer generating synthesized code variants.

        ### YOUR OBJECTIVE
        Apply "Stack-String XOR Obfuscation" to the provided {lang_word} function. You must eliminate human-readable ASCII and Unicode string literals by converting them into stack-allocated character arrays decoded lazily right before usage. 
        To ensure MSVC does not optimize this away via constant folding, you MUST use `volatile` arrays and disable optimizations.

        ### STRICT SELECTION CRITERIA
        1. **SELECTIVE TARGETING:** Target prominent or sensitive string literals (e.g., DLL names, API names, file paths, registry keys, network endpoints). Leave minor formatting strings (e.g., `"%s"`, `"\\n"`) alone.
        2. DO NOT target `#include` directives.
        3. DO NOT target single character literals (e.g., `'A'`).

        ### TRANSFORMATION RULES
        1. **DISABLE OPTIMIZATIONS:** You MUST insert `#pragma optimize("", off)` before the helper function, and `#pragma optimize("", on)` after the main function closes.
        2. **CENTRALIZED DECRYPTION HELPER:** Define a static decryption helper function above the target function that accepts a `volatile char*`:
        `static void xor_decrypt(volatile char *buf, size_t len, unsigned char key) {{ for (size_t i = 0; i < len; i++) {{ buf[i] ^= key; }} }}`
        3. **PER-STRING KEY ROTATION:** Assign a DIFFERENT, unique 1-byte XOR key (e.g., `0x3E`, `0x7A`, `0x1F`) to each target string literal across the function to eliminate single-key signatures.
        4. **VOLATILE CHARACTER LITERAL INITIALIZATION:** For each selected string, initialize a stack array using `volatile char` and XORed characters: `volatile char sz_str_1[] = {{'c'^KEY, ...}};`
        5. **NULL TERMINATION:** Always include the null terminator as the final element, written as `0x00 ^ KEY`.
        6. **LAZY JUST-IN-TIME DECRYPTION:** Call `xor_decrypt(sz_str, sizeof(sz_str), KEY);` immediately before the string is passed into an API call.
        7. **API CASTING:** When passing the `volatile char` array into a standard function or Windows API, you MUST cast it back to `(char*)` (or `reinterpret_cast<char*>` in C++) to avoid strict volatile qualifier compiler warnings.

        ### STRUCTURAL EXAMPLE (MIMIC THIS EXACTLY)

        **Original Code:**
        ```{code_fence}
        HMODULE hMod = GetModuleHandleA("kernel32.dll");
        if (hMod) {{
            CopyFileA("C:\\\\test.txt", "C:\\\\Windows\\\\Temp\\\\test.txt", FALSE);
            return 1;
        }}
        ```

        **Transformed Code:**
        ```{code_fence}
        #pragma optimize("", off)
        static void xor_decrypt(volatile char *buf, size_t len, unsigned char key) {{
            for (size_t i = 0; i < len; i++) {{
                buf[i] ^= key;
            }}
        }}

        HMODULE get_module_example(void) {{
            // "kernel32.dll" XOR'd with key 0x3E
            volatile char sz_str_1[] = {{ 'k'^0x3E, 'e'^0x3E, 'r'^0x3E, 'n'^0x3E, 'e'^0x3E, 'l'^0x3E, '3'^0x3E, '2'^0x3E, '.'^0x3E, 'd'^0x3E, 'l'^0x3E, 'l'^0x3E, 0x00^0x3E }};
            xor_decrypt(sz_str_1, sizeof(sz_str_1), 0x3E);
            HMODULE hMod = GetModuleHandleA((char*)sz_str_1); // C-style cast (works in both C and C++)
            // In C++ you may also use reinterpret_cast<char*>(sz_str_1)

            if (hMod) {{
                // Lazy initialization and decryption using distinct keys (0x7A, 0x1F)
                volatile char sz_str_2[] = {{ 'C'^0x7A, ':'^0x7A, '\\\\'^0x7A, 't'^0x7A, 'e'^0x7A, 's'^0x7A, 't'^0x7A, '.'^0x7A, 't'^0x7A, 'x'^0x7A, 't'^0x7A, 0x00^0x7A }};
                volatile char sz_str_3[] = {{ 'C'^0x1F, ':'^0x1F, '\\\\'^0x1F, 'W'^0x1F, 'i'^0x1F, 'n'^0x1F, 'd'^0x1F, 'o'^0x1F, 'w'^0x1F, 's'^0x1F, '\\\\'^0x1F, 'T'^0x1F, 'e'^0x1F, 'm'^0x1F, 'p'^0x1F, '\\\\'^0x1F, 't'^0x1F, 'e'^0x1F, 's'^0x1F, 't'^0x1F, '.'^0x1F, 't'^0x1F, 'x'^0x1F, 't'^0x1F, 0x00^0x1F }};
                
                xor_decrypt(sz_str_2, sizeof(sz_str_2), 0x7A);
                xor_decrypt(sz_str_3, sizeof(sz_str_3), 0x1F);
                
                CopyFileA((char*)sz_str_2, (char*)sz_str_3, FALSE);
                return 1;
            }}
            return 0;
        }}
        #pragma optimize("", on)
        ```

        ### OUTPUT CONSTRAINTS (CRITICAL)
        - You MUST wrap all generated code in `#pragma optimize("", off)` and `#pragma optimize("", on)`.
        - You MUST use `volatile char` for the stack arrays and `volatile char *` for the helper function argument.
        - You MUST cast the array to `(char*)` (or `reinterpret_cast<char*>` in C++) when using it in standard functions or APIs.
        - Generate a UNIQUE 1-byte XOR key for each string transformed in the function.
        - Decrypt strings lazily right before they are used.
        - DO NOT OUTPUT ANY EXPLANATION, ANALYSIS, OR CONVERSATIONAL TEXT.
        - Return ONLY the exact, modified source code inside a single markdown code block (```{code_fence} ... ```).
        - If no prominent string literals exist, return the original code wrapped in the markdown block without any changes.

        INPUT CODE:
        {c_code}
        """
        return self.call_llm(prompt, c_code, base_name, "stack_string_obfuscation", language=language)

    # ------------------------------------------------------------
    # apply_aggressive_variable_aliasing (updated)
    # ------------------------------------------------------------
    def apply_aggressive_variable_aliasing(self, c_code, base_name="unknown", language='c'):
        lang_word = "C++" if language == "cpp" else "C"
        code_fence = "cpp" if language == "cpp" else "c"
        prompt = f"""
        You are an expert {lang_word} developer generating synthesized code variants.

        ### YOUR OBJECTIVE
        Apply "Aggressive Variable Aliasing via Pointer Indirection" to the provided {lang_word} function. 
        You must heavily mutate the Data Flow Graph (DFG) by transforming EVERY eligible local variable into a heap-style pointer abstraction on the stack. 
        To ensure MSVC does not optimize away these indirections, you MUST wrap the function in optimization pragmas and use the `volatile` keyword.

        ### STRICT SELECTION CRITERIA
        1. Target some local scalar variables in the function (e.g., `int`, `DWORD`, `HANDLE`, `size_t`, `char`, `LPVOID`, `HMODULE`).
        2. Target loop counters (e.g., the `i` in `for (int i = 0; ...)`). 
        3. DO NOT target function parameters.
        4. DO NOT target arrays (e.g., `char buf[256]`), structs (e.g., `SYSTEM_INFO si`), or globally scoped variables.

        ### TRANSFORMATION RULES
        1. **DISABLE OPTIMIZATIONS:** You MUST insert `#pragma optimize("", off)` immediately before the function signature, and `#pragma optimize("", on)` immediately after the function closes.
        For each selected variable:
        2. **Uninitialized Variables:** `TYPE var;` becomes `volatile TYPE var_buf[2] = {{0, (TYPE)0}}; volatile TYPE *p_var = (volatile TYPE *)&var_buf[0];`
        3. **Initialized Variables:** `TYPE var = val;` becomes `volatile TYPE var_buf[2] = {{val, (TYPE)0}}; volatile TYPE *p_var = (volatile TYPE *)&var_buf[0];`
        4. **Loop Variables:** Extract inline loop declarations (`for(int i=0;)`) to the outer scope before the loop, initialize the volatile buffer/pointer, and use the dereference inside the loop parameters.
        5. **Substitution:** Substitute EVERY subsequent read or write of the variable within the function scope with the parenthesized dereferenced pointer `(*p_var)`.
        6. **Pointer Preservation:** If the original variable was already a pointer (e.g., `char* pStr`), ensure the pointer itself is marked volatile (e.g., `char* volatile pStr_buf...`).

        ### STRUCTURAL VARIANTS (MIMIC THESE EXACTLY)

        **Variant 1: Standard Initialization**
        Original: `HANDLE hProc = NULL;`
        Transformed: 
        ```{code_fence}
        volatile HANDLE hProc_buf[2] = {{NULL, (HANDLE)0}};
        volatile HANDLE *p_hProc = (volatile HANDLE *)&hProc_buf[0];
        ```

        **Variant 2: Uninitialized Declaration**
        Original: `DWORD bytesWritten;`
        Transformed:
        ```{code_fence}
        volatile DWORD bytesWritten_buf[2] = {{0, (DWORD)0}};
        volatile DWORD *p_bytesWritten = (volatile DWORD *)&bytesWritten_buf[0];
        ```

        **Variant 3: Inline Loop Counters**
        Original:
        ```{code_fence}
        for (int i = 0; i < max_len; i++) {{ ... }}
        ```
        Transformed:
        ```{code_fence}
        volatile int i_buf[2] = {{0, (int)0}};
        volatile int *p_i = (volatile int *)&i_buf[0];
        for ((*p_i) = 0; (*p_i) < (*p_max_len); (*p_i)++) {{ ... }}
        ```

        **Variant 4: Existing Pointers**
        Original: `char* pStr = "test";`
        Transformed:
        ```{code_fence}
        char* volatile pStr_buf[2] = {{"test", (char*)0}};
        char* volatile *p_pStr = &pStr_buf[0];
        ```

        ### OUTPUT CONSTRAINTS (CRITICAL)
        - You MUST wrap the function in `#pragma optimize("", off)` and `#pragma optimize("", on)`.
        - DO NOT OUTPUT ANY EXPLANATION, ANALYSIS, OR CONVERSATIONAL TEXT.
        - Return ONLY the exact, modified source code inside a single markdown code block (```{code_fence} ... ```).
        - Transform as many variables as structurally possible without breaking standard {lang_word} syntax.

        INPUT CODE:
        {c_code}
        """
        return self.call_llm(prompt, c_code, base_name, "variable_aliasing", language=language)

    # ------------------------------------------------------------
    # apply_control_flow_obfuscation (updated)
    # ------------------------------------------------------------
    def apply_control_flow_obfuscation(self, c_code, base_name="unknown", language='c'):
        lang_word = "C++" if language == "cpp" else "C"
        code_fence = "cpp" if language == "cpp" else "c"
        prompt = f"""
        You are an expert {lang_word} developer generating synthesized code variants.
        Target architecture: {self.arch}

        ### TASK
        Inject a single control-flow obfuscation transformation into the provided function.
        To ensure MSVC does not unflatten the control flow via block reordering or constant propagation, you MUST disable optimizations for the target function.

        ### CONSTRAINTS
        1. FEATURE ISOLATION: Implement EXACTLY ONE of the following techniques matching the target architecture rules.

        Target architecture rules:
        - Opaque conditional jump using MSVC __asm blocks and volatile condition checks (x86 only; not available on x64).
        - Control Flow Flattening using a volatile state variable and a goto-based dispatcher (NO switch statements).

        2. DISABLE OPTIMIZATIONS: You MUST insert `#pragma optimize("", off)` immediately before the function signature, and `#pragma optimize("", on)` immediately after the function closes.

        3. NO NEW FUNCTIONS: You are strictly forbidden from creating helper functions or separate function bodies.
        All logic must reside entirely inside the existing function.

        4. PRESERVE EXECUTION FLOW & LOGIC:
        - All original logic, side effects, and return values must execute in the exact same sequence as the original code.
        - You may restructure the existing code only for the selected obfuscation technique.
        - Do not add new side effects, change return values, or alter error handling.

        5. ISOLATED SCOPING:
        Use localized, uniquely named variables (e.g. `dummy_state`, `dummy_cond`) to prevent variable shadowing. Ensure no variable redefinition occurs.

        6. COMPILER COMPATIBILITY:
        - MSVC DOES NOT support the GNU "Labels as Values" extension (`&&label`). You MUST use standard C/C++ `goto` syntax.

        ### STRUCTURAL PATTERN TO FOLLOW

        If using **Control Flow Flattening**, restructure the original block sequence into a `goto`-based state machine. 
        DO NOT use a `while-switch` loop. Mimic this exact layout:

        ```{code_fence}
        #pragma optimize("", off)
        int target_function(void) {{
            volatile int dummy_state = 1;

        dummy_dispatcher:
            if (dummy_state == 1) goto dummy_state_1;
            if (dummy_state == 2) goto dummy_state_2;
            if (dummy_state == 0) goto dummy_end;

        dummy_state_1:
            // Original block 1
            ...
            dummy_state = 2;
            goto dummy_dispatcher;

        dummy_state_2:
            // Original block 2
            ...
            dummy_state = 0; // terminate state loop
            goto dummy_dispatcher;

        dummy_end:
            // Return statements here
            return 0;
        }}
        #pragma optimize("", on)
        ```

        Rules for Control Flow Flattening:
        - Split the original function body into logical blocks while preserving exact execution order.
        - Ensure all original return statements are converted to `dummy_state = 0; goto dummy_dispatcher;` plus a final return at the end.
        - If the function returns a value, store it in a local variable and return it after the state machine ends.

        If using **Opaque Conditional Jump**, follow the architecture-specific rule:
        - x86: Use MSVC inline assembly or volatile checks to create an opaque branch.
        - x64: Use memory reads and intrinsics (no inline assembly).

        ### OUTPUT CONSTRAINTS (CRITICAL)
        - You MUST wrap the generated function in `#pragma optimize("", off)` and `#pragma optimize("", on)`.
        - DO NOT OUTPUT ANY EXPLANATION, ANALYSIS, OR CONVERSATIONAL TEXT.
        - Return ONLY the exact, modified source code inside a single markdown code block (```{code_fence} ... ```).

        INPUT CODE:
        {c_code}
        """
        return self.call_llm(prompt, c_code, base_name, "control_flow_Obfuscation", language=language)

    # ------------------------------------------------------------
    # apply_local_context_struct_packaging (updated)
    # ------------------------------------------------------------
    def apply_local_context_struct_packaging(self, c_code, base_name="unknown", language='c'):
        lang_word = "C++" if language == "cpp" else "C"
        code_fence = "cpp" if language == "cpp" else "c"
        prompt = f"""
            You are an expert {lang_word} developer generating synthesized code variants.

            ### YOUR OBJECTIVE
            Apply "Local Context Struct Packaging" to the provided {lang_word} function. You must bundle all locally scoped variables into a single, locally defined structure. To ensure the compiler does not optimize this structure away, you must wrap the function in MSVC optimization pragmas and declare the structure instance as `volatile`. 
            ### STRICT SELECTION CRITERIA
            1. Target **EVERY** locally declared variable (e.g., scalars, pointers, arrays, handles).
            2. Target inline loop counters (e.g., the `i` in `for(int i = 0; ...)`).
            3. DO NOT target function parameters (arguments passed into the function).
            4. DO NOT target `static` variables or globally scoped variables.

            ### TRANSFORMATION RULES (CRITICAL C SYNTAX)
            1. **DISABLE OPTIMIZATIONS:** You MUST insert `#pragma optimize("", off)` immediately before the function signature, and `#pragma optimize("", on)` immediately after the function closes.
            2. **STRUCT DEFINITION:** At the very beginning of the function body, define a structure named `struct _LocalCtx`.
            3. **VOLATILE INSTANTIATION:** You MUST instantiate the structure with the `volatile` keyword as `volatile struct _LocalCtx ctx;`.
            4. Move all targeted variable declarations into the `struct _LocalCtx` definition.
            5. **CRITICAL:** C structures do NOT allow inline initialization. You MUST separate the declaration (inside the struct) from the assignment (after the struct instantiation).
            6. For variables that were initialized at declaration (e.g., `int count = 10;`), move `int count;` into the struct, and write `ctx.count = 10;` immediately after the struct is instantiated.
            7. For inline loop counters (`for(int i = 0;)`), move `int i;` into the struct, and update the loop to `for(ctx.i = 0; ...)`.
            8. Substitute EVERY subsequent usage of the variables in the function with the `ctx.` prefix (e.g., `var_name` becomes `ctx.var_name`).

            ### STRUCTURAL EXAMPLE (MIMIC THIS EXACTLY)

            **Original Code:**
            ```{code_fence}
            int parse_data(char* input, DWORD size) {{
                HANDLE hHeap = GetProcessHeap();
                int count = 0;
                
                if (input == NULL) {{ return -1; }}
                
                for (int i = 0; i < size; i++) {{
                    count += 1;
                }}
                return count;
            }}
            ```
            
            **Transformed Code:**
            ```{code_fence}
            #pragma optimize("", off)
            int parse_data(char* input, DWORD size) {{
                volatile struct _LocalCtx {{
                    HANDLE hHeap;
                    int count;
                    int i;
                }} ctx;
                
                // Initializations moved outside the struct definition
                ctx.hHeap = GetProcessHeap();
                ctx.count = 0;
                
                if (input == NULL) {{ return -1; }}
                
                for (ctx.i = 0; ctx.i < size; ctx.i++) {{
                    ctx.count += 1;
                }}
                return ctx.count;
            }}
            #pragma optimize("", on)
            ```

            ### OUTPUT CONSTRAINTS (CRITICAL)
            You MUST wrap the function in #pragma optimize("", off) and #pragma optimize("", on).
            You MUST declare the struct instance as volatile.
            NEVER assign a value inside the struct _LocalCtx {{ ... }}; block.
            DO NOT alter function parameters (input and size in the example remain untouched).
            DO NOT OUTPUT ANY EXPLANATION, ANALYSIS, OR CONVERSATIONAL TEXT.
            Return ONLY the exact, modified source code inside a single markdown code block (```{code_fence} ... ```).
            If the function contains no local variables to pack, return the original code wrapped in the markdown block without any changes.

            INPUT CODE:
            {c_code}
            """
        return self.call_llm(prompt, c_code, base_name, "local_context_struct", language=language)

    # ------------------------------------------------------------
    # apply_all_techniques (updated to propagate language)
    # ------------------------------------------------------------
    def apply_all_techniques(self, c_code, techniques=None, base_name="unknown", language='c'):
        """Apply a list of techniques in order.
        techniques: list of strings, e.g., ['junk_code_insertion', 'string_encryption', ...]
        If None, apply all.
        """
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
    # process_directory_with_scoring (updated to handle .c and .cpp)
    # ------------------------------------------------------------
    def process_directory_with_scoring(self, processed_dir, workspace_dir, exe_name, techniques=None):
        """Scores functions, filters external APIs, and creates a separate binary+technique directory per technique containing all functions."""
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
            
        # Discover both C and C++ source files
        c_files = glob.glob(os.path.join(processed_dir, "*.c"))
        cpp_files = glob.glob(os.path.join(processed_dir, "*.cpp"))
        cpp_files += glob.glob(os.path.join(processed_dir, "*.cc"))
        cpp_files += glob.glob(os.path.join(processed_dir, "*.cxx"))
        all_files = c_files + cpp_files
        
        scored_functions = []
        
        # Score all internal functions
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

        # Determine target selection threshold
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
        
        # Process per technique: Create directory named <binary_name>_<technique>
        for tech in techniques:
            tech_dir = os.path.join(workspace_dir, "processed_functions", f"{binary_name}_{tech}")
            os.makedirs(tech_dir, exist_ok=True)
            
            print(f"\n--- Generating Variant Directory: {tech_dir} ---")
            
            for file_path in all_files:
                base_name = os.path.splitext(os.path.basename(file_path))[0]
                language = self.get_language_from_filename(file_path)  # Detect language
                # Preserve original extension in output
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
                    # Pass through non-selected functions unchanged
                    with open(dest_path, 'w', encoding='utf-8') as f:
                        f.write(code)

