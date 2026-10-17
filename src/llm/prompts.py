PASS_1_PROMPT_C = """You are an expert C programmer refactoring Ghidra pseudo-code for compilation.

### STRICT RULES

1. **FUNCTION NAME & SIGNATURE**: Retain exact function name, parameters, and return type (after standard type adjustments).
2. **LOCAL VARIABLES**: Rename cryptic Ghidra variables (`local_1c`, `uVar1`, `iVar2`) to meaningful names based on usage context.
{var_rule}
4. **TYPE REPLACEMENT**: Use standard types from `<stdint.h>` (`uint8_t`, `uint32_t`, `int32_t`, `uintptr_t`, etc.). Replace Ghidra primitives (`undefined`, `undefined4`, `ulong`, `byte`, `dword`).
5. **REMOVE COMPILER & STACK ARTIFACTS**:
- Strip calling conventions (`__cdecl`, `__stdcall`, `__fastcall`).
- Remove stack cookies and compiler checks (`___security_cookie`, `__security_check_cookie`, `__RTC_CheckEsp`, `__RTC_CheckStackVars`, `ExceptionList`).
- Delete associated stack canary variables and initializers.
6. **PRESERVE LOGIC & SIDE EFFECTS**: Never remove statements with side effects (API calls, assignments, control flow). Only prune unread intermediate variables that hold no side-effecting expressions.
7. **GLOBAL SYMBOLS**: Keep external/global names (`DAT_`, `s_`, `string_`) unchanged. Do NOT re-declare structs, unions, or enums locally.
8. **STRING LITERALS**: Keep all string literals verbatim.
9. **OUTPUT**: Return ONLY valid C code wrapped in ```c backticks. No commentary.

### INPUT CODE
___C_CODE_PLACEHOLDER___
"""

PASS_1_PROMPT_CPP = """You are an expert C++ programmer refactoring Ghidra pseudo-code for compilation.

### STRICT RULES

1. **FUNCTION NAME & SIGNATURE**: Retain exact function name, parameters, and return type.
2. **LOCAL VARIABLES**: Rename cryptic Ghidra variables (`local_1c`, `uVar1`) to clear, descriptive names.
{var_rule}
4. **TYPE REPLACEMENT**: Use standard `<cstdint>` types (`uint8_t`, `uint32_t`, `uintptr_t`, etc.).
5. **REMOVE COMPILER ARTIFACTS**: Strip `__stdcall`, `ExceptionList`, `__security_cookie`, stack-check loops, and dead canary variables.
6. **PRESERVE LOGIC**: Maintain all side effects and logical flow.
7. **GLOBAL SYMBOLS**: Keep global names intact (`DAT_`, `s_`). Do NOT define structs or auxiliary types locally.
9. ** GLOBAL REDEFINITION**: ALL the global data are already defined elsewhere. You shall not define them again inside the file.
8. **DEFER C++ RECONSTRUCTION**: Do not transform explicit `this` pointer arithmetic into high-level class abstractions during this pass.
9. **OUTPUT**: Return ONLY valid C++ code wrapped in ```cpp backticks. No commentary.

### INPUT CODE
___C_CODE_PLACEHOLDER___
"""

JUNK_CODE_PROMPT = """
            You are an expert {lang_word} developer generating synthesized code variants.
            Target architecture: {arch}

            ### CRITICAL TRANSFORMATION RULE: ADDITIVE-ONLY
            - DO NOT MOVE, MODIFY, OR WRAP ANY EXISTING CODE INSIDE A DEAD BRANCH.
            - All original code statements MUST remain outside the `if` block in the live execution path.
            - Dead branches (`if (opaque_false_condition) {{ ... }}`) must contain ONLY newly generated, self-contained dummy logic.
            - The dummy logic may READ existing local variables (those declared before the branch), but it MUST NOT modify any original variable, global state, or function argument.
            - You may add required `#include` directives at the beginning of the file only if needed; do not remove or modify existing includes.

            ### MANDATORY VOLUME AND PLACEMENT
            - Insert ___BRANCH_COUNT___ dead branches in the given function.
            - Place them at **different locations**: after variable declarations, before loops, inside loops (but not around original statements), and before return statements.
            - Each dead branch must contain **at least ___MIN_LINES___ lines** of dummy code.
            - Each dead branch must use a **different opaque predicate pattern** from the list below.
            - Restrict opaque predicates to this allowed set only: ___ALLOWED_PATTERNS___.

            ### OPAQUE PREDICATE REQUIREMENTS
            Use only the patterns listed in ___ALLOWED_PATTERNS___ above, one per branch. Do NOT use `if (0)` or `volatile int v = 0; if (v)`.
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

            CATEGORIES (choose only from the allowed set in ___ALLOWED_PATTERNS___, no repeats within the same function)

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
            ### INPUT CODE:
            {c_code}
            Return ONLY the complete, modified source code inside a single markdown code block.
            Use ```{code_fence} according to the detected input language. 
            """

STACK_STRING_PROMPT = """
        You are an expert {lang_word} developer generating synthesized code variants.

        ### YOUR OBJECTIVE
        Apply "Stack-String XOR Obfuscation" to the provided {lang_word} function. You must eliminate human-readable ASCII and Unicode string literals by converting them into stack-allocated character arrays decoded lazily right before usage. 
        To ensure MSVC does not optimize this away via constant folding, you MUST use `volatile` arrays and disable optimizations.

        ### STRICT SELECTION CRITERIA
        1. **SELECTIVE TARGETING:** ___SELECTION_RULE___
        2. DO NOT target `#include` directives.
        3. DO NOT target single character literals (e.g., `'A'`).

        ### TRANSFORMATION RULES
        1. **DISABLE OPTIMIZATIONS:** You MUST insert `#pragma optimize("", off)` before the helper function, and `#pragma optimize("", on)` after the main function closes.
        2. **CENTRALIZED DECRYPTION HELPER:** Define a static decryption helper function above the target function that accepts a `volatile char*`:
        `static void xor_decrypt(volatile char *buf, size_t len, unsigned char key) {{ for (size_t i = 0; i < len; i++) {{ buf[i] ^= key; }} }}`
        3. **KEY SCHEME:** ___KEY_SCHEME_RULE___
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
        - Follow the key scheme described above for each string transformed in the function.
        - Decrypt strings lazily right before they are used.
        - DO NOT OUTPUT ANY EXPLANATION, ANALYSIS, OR CONVERSATIONAL TEXT.
        - Return ONLY the exact, modified source code inside a single markdown code block (```{code_fence} ... ```).
        - If no prominent string literals exist, return the original code wrapped in the markdown block without any changes.

        INPUT CODE:
        {c_code}
        """

VARIABLE_ALIASING_PROMPT = """
        You are an expert {lang_word} developer generating synthesized code variants.

        ### YOUR OBJECTIVE
        Apply "Aggressive Variable Aliasing via Pointer Indirection" to the provided {lang_word} function. 
        You must heavily mutate the Data Flow Graph (DFG) by transforming eligible local variables into a heap-style pointer abstraction on the stack. 
        To ensure MSVC does not optimize away these indirections, you MUST wrap the function in optimization pragmas and use the `volatile` keyword.

        ### STRICT SELECTION CRITERIA
        1. ___SCALAR_RULE___
        2. ___LOOP_COUNTER_RULE___
        3. DO NOT target function parameters.
        4. DO NOT target arrays (e.g., `char buf[256]`), structs (e.g., `SYSTEM_INFO si`), or globally scoped variables.

        ### TRANSFORMATION RULES
        1. **DISABLE OPTIMIZATIONS:** You MUST insert `#pragma optimize("", off)` immediately before the function signature, and `#pragma optimize("", on)` immediately after the function closes.
        For each selected variable:
        2. **Uninitialized Variables:** `TYPE var;` becomes `volatile TYPE var_buf[2] = {{0, (TYPE)0}}; volatile TYPE *p_var = (volatile TYPE *)&var_buf[0];`
        3. **Initialized Variables:** `TYPE var = val;` becomes `volatile TYPE var_buf[2] = {{val, (TYPE)0}}; volatile TYPE *p_var = (volatile TYPE *)&var_buf[0];`
        4. **Loop Variables:** Extract inline loop declarations (`for(int i=0;)`) to the outer scope before the loop, initialize the volatile buffer/pointer, and use the dereference inside the loop parameters.
        5. **Substitution:** Substitute EVERY subsequent read or write of a targeted variable within the function scope with the parenthesized dereferenced pointer `(*p_var)`.
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
        - Transform variables strictly according to the selection criteria above, without breaking standard {lang_word} syntax.

        INPUT CODE:
        {c_code}
        """

CONTROL_FLOW_PROMPT = """
        You are an expert {lang_word} developer generating synthesized code variants.
        Target architecture: {arch}

        ### TASK
        Inject a single control-flow obfuscation transformation into the provided function.
        To ensure MSVC does not unflatten the control flow via block reordering or constant propagation, you MUST disable optimizations for the target function.

        ### CONSTRAINTS
        1. FEATURE ISOLATION: Implement EXACTLY the following technique: ___DISPATCH_INSTRUCTION___

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
        #include <windows.h>
        
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

LOCAL_CONTEXT_STRUCT_PROMPT = """
            You are an expert {lang_word} developer generating synthesized code variants.

            ### YOUR OBJECTIVE
            Apply "Local Context Struct Packaging" to the provided {lang_word} function. You must bundle locally scoped variables into a single, locally defined structure. To ensure the compiler does not optimize this structure away, you must wrap the function in MSVC optimization pragmas and declare the structure instance as `volatile`. 
            ### STRICT SELECTION CRITERIA
            1. ___SELECTION_RULE___
            2. Target inline loop counters (e.g., the `i` in `for(int i = 0; ...)`).
            3. DO NOT target function parameters (arguments passed into the function).
            4. DO NOT target `static` variables or globally scoped variables.

            ### TRANSFORMATION RULES (CRITICAL C SYNTAX)
            1. **DISABLE OPTIMIZATIONS:** You MUST insert `#pragma optimize("", off)` immediately before the function signature, and `#pragma optimize("", on)` immediately after the function closes.
            2. **STRUCT DEFINITION:** At the very beginning of the function body, define a structure named `struct _LocalCtx`.
            3. **VOLATILE INSTANTIATION:** You MUST instantiate the structure with the `volatile` keyword as `volatile struct _LocalCtx ctx;`.
            4. ___GROUPING_RULE___
            5. **CRITICAL:** C structures do NOT allow inline initialization. You MUST separate the declaration (inside the struct) from the assignment (after the struct instantiation).
            6. For variables that were initialized at declaration (e.g., `int count = 10;`), move `int count;` into the struct, and write `ctx.count = 10;` immediately after the struct is instantiated.
            7. For inline loop counters (`for(int i = 0;)`), move `int i;` into the struct, and update the loop to `for(ctx.i = 0; ...)`.
            8. Substitute EVERY subsequent usage of the targeted variables in the function with the `ctx.` prefix (e.g., `var_name` becomes `ctx.var_name`).

            ### STRUCTURAL EXAMPLE (MIMIC THIS EXACTLY)

            **Original Code:**
```{code_fence}
            #include <windows.h>
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
            #include <windows.h>
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

WHOLE_FUNCTION_PATCH_PROMPT = """You are a C/C++ bug-fixing assistant.
Your task is to fix compiler errors by outputting the ENTIRE corrected source code.

### RELEVANT GLOBAL HEADER CONTEXT (data_globals.h):
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
{
    "reasoning": "Explain whether this is a structural or type error, and exactly what you changed.",
    "full_fixed_code": "The complete, fully corrected C code string, including all includes and the full function block.",
    "header_patches": [
        {
            "replace": "int FUN_00401000(char *a);" 
        }
    ]
}
"""

SURGICAL_PATCH_PROMPT = """You are a C/C++ bug-fixing assistant. DO NOT rewrite the entire function.
Your task is to fix compiler errors by outputting SURGICAL LINE REPLACEMENTS in JSON format.

### RELEVANT GLOBAL HEADER CONTEXT (data_globals.h):
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
7. If a #include of a POSIX header (netdb.h, unistd.h, sys/socket.h, ...) fails with 'No such file or directory', that header does not exist on Windows:
REMOVE the include line entirely, and rely on data_globals.h/windows.h
(already force-included) for the same-named functions -- most POSIX network functions (gethostname, gethostbyname, socket, connect, send, recv) exist with identical names in winsock2.h.

### REQUIRED JSON FORMAT:
You must respond ONLY with a valid JSON object matching this exact schema:
{
"reasoning": "Explain whether this is a structural or type error, and what needs fixing.",
"function_patches": [
    {
    "line_number": <integer line number from the provided code>,
    "old_line": "<exact current line of code>",
    "new_line": "<corrected line of code>"
    }
],
"header_patches": [
    {
    "replace": "<the fully corrected prototype, e.g., int FUN_00401000(char *a);>"
    }
]
}
"""

def get_whole_function_prompt(c_code: str, error_log: str, retrieved_header_context: str) -> str:
    return WHOLE_FUNCTION_PATCH_PROMPT.replace("{c_code}", c_code)\
                                      .replace("{error_log}", error_log)\
                                      .replace("{retrieved_header_context}", retrieved_header_context)

def get_surgical_prompt(line_numbered_code: str, error_log: str, retrieved_header_context: str) -> str:
    return SURGICAL_PATCH_PROMPT.replace("{line_numbered_code}", line_numbered_code)\
                                .replace("{error_log}", error_log)\
                                .replace("{retrieved_header_context}", retrieved_header_context)


def get_pass_1_prompt(is_cpp: bool, var_rule: str) -> str:
    template = PASS_1_PROMPT_CPP if is_cpp else PASS_1_PROMPT_C
    return template.replace("{var_rule}", var_rule)

