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
8. **DEFER C++ RECONSTRUCTION**: Do not transform explicit `this` pointer arithmetic into high-level class abstractions during this pass.
9. **OUTPUT**: Return ONLY valid C++ code wrapped in ```cpp backticks. No commentary.

### INPUT CODE
___C_CODE_PLACEHOLDER___
"""

PASS_2_PROMPT_C = """You are an expert C programmer fixing memory pointers, casts, and API calls in Ghidra pseudo-code.

### STRICT RULES

1. **POINTER RECOVERY**: Cast integer types used as address offsets to appropriate pointer types.
2. **ARRAY & BUFFER INDEXING**: Convert expressions like `*(char *)((uintptr_t)i + Buffer)` to `Buffer[i]`.
3. **GLOBAL ADDRESSES**: Cast fixed numeric addresses to appropriate pointer types (e.g., `(const char *)0x140008164`).
4. **WIN32 CONSTANTS & MACROS**:
- Replace registry handle magic numbers: `(HKEY)0x80000000` -> `HKEY_CLASSES_ROOT`, `(HKEY)0x80000001` -> `HKEY_CURRENT_USER`, `(HKEY)0x80000002` -> `HKEY_LOCAL_MACHINE`.
- Replace Win32 access masks: `0xf003f` -> `KEY_ALL_ACCESS`, `0x20019` -> `KEY_READ`.
5. **CRT FUNCTION NORMALIZATION**:
- Replace non-standard MSVC function aliases with ISO C standards (e.g., replace `_snprintf` with `snprintf`, `_stricmp` with `stricmp`/`strcasecmp`).
6. **CONST CORRECTNESS**: Apply `const char *` where string literals are assigned.
7. **FUNCTION POINTERS**: Properly cast function pointer calls before invocation.
{context_block}
8. **NO LOCAL TYPE DEFINITIONS**: Do NOT define structs, unions, enums, or function prototypes locally.
9. **OUTPUT**: Return ONLY valid C code inside ```c backticks.

### INPUT CODE
___C_CODE_PLACEHOLDER___
"""

PASS_2_PROMPT_CPP = """You are an expert C++ programmer fixing memory references, C++ style casts (`static_cast`, `reinterpret_cast`), and API calls.

### STRICT RULES

1. **C++ CASTS**: Replace raw C-style pointer casts with `reinterpret_cast` or `static_cast`.
2. **WIN32 CONSTANTS & MACROS**: Convert raw hex literals for registry keys/access masks (`0x80000002` -> `HKEY_LOCAL_MACHINE`, `0xf003f` -> `KEY_ALL_ACCESS`).
3. **CRT FUNCTION NORMALIZATION**: Replace MSVC specific aliases like `_snprintf` with standard `snprintf` or `std::snprintf`.
4. **NO LOCAL TYPES**: Do NOT define external structs or function prototypes locally.
{context_block}
5. **OUTPUT**: Return ONLY valid C++ code inside ```cpp backticks.

### INPUT CODE
___C_CODE_PLACEHOLDER___
"""

PASS_3_PROMPT_C = """You are an expert C reverse engineer ensuring decompiled code compiles cleanly.

### HARD REQUIREMENTS

1. **HEADER INCLUSIONS**:
- `#include "data_globals.h"` MUST be the very first line.
- Include standard system headers directly after `data_globals.h` based on APIs used in the body:
    * If Win32 APIs/types (`HKEY`, `DWORD`, `CHAR`, `GetUserNameA`, `RegCreateKeyExA`) are present: `#include <windows.h>`
    * If string functions (`memcpy`, `strncpy`, `strstr`) are present: `#include <string.h>`
    * If formatting functions (`snprintf`, `printf`) are present: `#include <stdio.h>`
    * If memory/utility functions (`malloc`, `free`, `exit`) are present: `#include <stdlib.h>`
    * If x86 intrinsics (`__inword`, `__rdtsc`, `__cpuid`) are present: `#include <intrin.h>`
2. **NO STRUCT OR PROTOTYPE DEFINITIONS**: NEVER define structs, unions, enums, or function prototypes locally. Assume they exist in `data_globals.h` or included system headers.
3. **TRANSLATE GHIDRA ARTIFACTS**:
- `CONCATxy(hi, lo)`: Convert to explicit bitwise shifts and masks: `(((uint64_t)(hi) << 32) | (uint32_t)(lo))`.
- `SUBxy(val, n)`: Convert to shift and cast: `(uint<y*8>_t)((val) >> (n * 8))`.
- `local_X._0_1_`: Convert to explicit bitwise shift/mask operations on `local_X`.
- `goto`/`LAB_xxx`: Restructure into clean loops/conditionals ONLY if flow equivalence is guaranteed. Keep `goto` if non-trivial or irreducible.
4. **EXCEPTION HANDLING COMPATIBILITY**:
- Do NOT mix C++ `try/catch` and MSVC Structured Exception Handling (`__try` / `__except`) in the same block. For Win32 hardware exception checking (like `__inword`), use SEH (`__try / __except`) exclusively without C++ `try/catch`.
5. **ONE FUNCTION ONLY**: Output only the `#include` directives and the target function inside ```c backticks.

### INPUT CODE
___C_CODE_PLACEHOLDER___
"""

PASS_3_PROMPT_CPP = """You are an expert C++ reverse engineer ensuring decompiled C++ code compiles cleanly (C++17 standard).

### HARD REQUIREMENTS

1. **HEADER INCLUSIONS**:
- `#include "data_globals.h"` MUST be the very first line.
- Include required headers immediately following `data_globals.h`:
    * Win32 types (`HKEY`, `DWORD`, `CHAR`, `GetUserNameA`, etc.): `#include <windows.h>`
    * Formatting (`snprintf`): `#include <cstdio>`
    * String ops (`strstr`, `strncpy`): `#include <cstring>`
    * Standard containers/strings: `#include <string>`, `#include <vector>`
    * MSVC/x86 Intrinsics (`__inword`, `__readfsdword`): `#include <intrin.h>`
2. **NO STRUCT OR PROTOTYPE DEFINITIONS**: NEVER define custom structs, classes, enums, or external prototypes locally.
3. **EXCEPTION HANDLING COMPATIBILITY**:
- NEVER nest MSVC SEH blocks (`__try` / `__except`) inside C++ `try` / `catch` blocks. If SEH is used for hardware checks (e.g., `__inword`), remove the redundant outer C++ `try / catch` structure.
4. **TRANSLATE GHIDRA ARTIFACTS**: Rewrite bitwise macros (`CONCATxy`, `SUBxy`) into explicit C++ arithmetic masks.
5. **ONE FUNCTION ONLY**: Output only the `#include` directives and the target function inside ```cpp backticks.

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

VARIABLE_ALIASING_PROMPT = """
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

CONTROL_FLOW_PROMPT = """
        You are an expert {lang_word} developer generating synthesized code variants.
        Target architecture: {arch}

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

LOCAL_CONTEXT_STRUCT_PROMPT = """
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


def get_pass_1_prompt(is_cpp: bool, var_rule: str) -> str:
    template = PASS_1_PROMPT_CPP if is_cpp else PASS_1_PROMPT_C
    return template.replace("{var_rule}", var_rule)


def get_pass_2_prompt(is_cpp: bool, context_block: str) -> str:
    template = PASS_2_PROMPT_CPP if is_cpp else PASS_2_PROMPT_C
    return template.replace("{context_block}", context_block)


def get_pass_3_prompt(is_cpp: bool) -> str:
    return PASS_3_PROMPT_CPP if is_cpp else PASS_3_PROMPT_C