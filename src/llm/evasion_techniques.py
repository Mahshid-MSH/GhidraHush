#!/usr/bin/env python3
"""
defensive_evasion_techniques.py
--------------------------------
Provides methods to apply various code obfuscation and defensive evasion techniques
to C functions using an LLM.
"""

import os
import re, glob
from ollama import Client
import json, math
from base_agent import BaseLLMAgent


class DefensiveEvasion(BaseLLMAgent):
    def __init__(self, model_name=None, base_url=None, arch="x86",workspace_dir="."):
        self.workspace_dir = workspace_dir
        self.arch = arch               # e.g., "x86 (32-bit)" or "x86_64 (64-bit)"
        super().__init__(model_name, base_url)
        print(f"DefensiveEvasion initialized with {self.model_name} at {self.base_url} for architecture: {self.arch}")

    def call_llm(self, prompt, original_code, base_name="unknown", tech_name="unknown"):
        """Send prompt to LLM and extract raw C code utilizing the base agent."""
        print(f"Sending request to LLM for {tech_name}...")
        
        return self.process_llm_task(
            prompt=prompt,
            original_code=original_code,
            workspace_dir=self.workspace_dir,
            log_prefix=f"evasion_{tech_name}",
            base_name=base_name,
            options={'temperature': 0.6, 'num_ctx': 16384}
        )

# improved
    def apply_junk_code_insertion(self, c_code, base_name="unknown"):
        prompt = f"""
            You are an expert C developer generating synthesized code variants for AV evasion research.
            Target architecture: {self.arch}
            Source language: C (preserve the input language; do not convert C to C++ or C++ to C).

            ### CRITICAL TRANSFORMATION RULE: ADDITIVE-ONLY
            - DO NOT MOVE, MODIFY, OR WRAP ANY EXISTING CODE INSIDE A DEAD BRANCH.
            - All original code statements MUST remain outside the `if` block in the live execution path.
            - Dead branches (`if (opaque_false_condition) {{ ... }}`) must contain ONLY newly generated, self-contained dummy logic.
            - The dummy logic may READ existing local variables (those declared before the branch), but it MUST NOT modify any original variable, global state, or function argument.
            - You may add required `#include` directives at the beginning of the file only if needed; do not remove or modify existing includes.

            ### MANDATORY VOLUME AND PLACEMENT
            - Insert **at least 3 dead branches** in the given function.
            - Place them at **different locations**: after variable declarations, before loops, inside loops (but not around original statements), and before return statements.
            - Each dead branch must contain **at least 15 lines** of dummy code.
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
            - Use at least 3 different Windows/C runtime API or standard C functions in each body.
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
            Use ```c according to the detected input language.

            """
        return self.call_llm(prompt, c_code, base_name, "junk_code")

#improved
    def apply_api_call_substitution(self, c_code, base_name="unknown"):
        """Replace common Windows API calls with alternative NT API calls."""
        prompt = f"""
            You are an expert C developer generating synthesized code variants.
            Target architecture: {self.arch}
            Compiler: Microsoft Visual Studio (MSVC)

            ### CRITICAL TRANSFORMATION RULES
            1. NO NEW FUNCTIONS: All translations must happen inline inside the existing function body.
            2. ALLOWED NT API SUBSTITUTION MAP (use ONLY these documented ntdll.dll exports):
            - VirtualAlloc       -> NtAllocateVirtualMemory
            - VirtualProtect     -> NtProtectVirtualMemory
            - WriteProcessMemory -> NtWriteVirtualMemory
            - OpenProcess        -> NtOpenProcess
            - CreateFileA/W      -> NtCreateFile
            - ReadFile           -> NtReadFile
            - CloseHandle        -> NtClose

            You may also use the following REAL NT APIs if the original code already uses related functionality:
            - NtQueryInformationProcess
            - NtQuerySystemInformation
            - NtTerminateProcess
            - NtReadVirtualMemory
            - NtWriteVirtualMemory

            3. DO NOT replace any API that is NOT in the map above.
            Especially leave these unchanged:
            - CreateToolhelp32Snapshot
            - Process32First
            - Process32Next
            - Module32First
            - Module32Next
            - _stricmp, strcmp, memcpy, printf, etc.
            - Any function for which you are not 100% sure a real ntdll export exists.

            NEVER invent NT names such as:
            NtCreateToolhelp32Snapshot, NtProcess32First, NtProcess32Next, NtModule32First, NtCreateProcess, etc.
            These DO NOT exist in ntdll.dll and will cause the program to fail or crash.

            4. DYNAMIC RESOLUTION:
            For each allowed API substitution, inline:
            - `GetModuleHandleA("ntdll.dll")`
            - `GetProcAddress`
            Do not use static `ntdll.lib` linkage.

            5. TYPE CONVERSION:
            Inline the necessary NT structures as local definitions inside the relevant block.
            Use unique names where needed to avoid conflicts.

            For `OBJECT_ATTRIBUTES`, use the correct `PUNICODE_STRING` type for `ObjectName`, not `void*`.
            Define `UNICODE_STRING` locally if any substituted API requires it:

            ```c
            typedef struct _UNICODE_STRING {{
                USHORT Length;
                USHORT MaximumLength;
                PWSTR  Buffer;
            }} UNICODE_STRING, *PUNICODE_STRING;

            typedef struct _OBJECT_ATTRIBUTES {{
                ULONG           Length;
                HANDLE          RootDirectory;
                PUNICODE_STRING ObjectName;
                ULONG           Attributes;
                PVOID           SecurityDescriptor;
                PVOID           SecurityQualityOfService;
            }} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

            typedef struct _CLIENT_ID {{
                HANDLE UniqueProcess;
                HANDLE UniqueThread;
            }} CLIENT_ID, *PCLIENT_ID;
            ```
            If replacing CreateFileA/W with NtCreateFile, you must correctly build a UNICODE_STRING from the original path.
            If you are not confident about the conversion, leave the original CreateFile call unchanged.

            ### BEHAVIOR PRESERVATION:
                The transformed code must have the same external behavior, return values, error handling, and control flow as the original.
                For NTSTATUS success checks, use if (status == 0) for STATUS_SUCCESS.
                If the original call fails, set the resulting HANDLE/pointer to an appropriate error value (NULL, INVALID_HANDLE_VALUE, etc.) to mimic the original behavior.

            ### ADDITIVE-ONLY:
                Do NOT remove or modify existing code that is not being substituted.
                If an API is unsupported, leave the original call exactly as is.

            ### STRUCTURAL PATTERN TO FOLLOW
            For a call to OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid):

            // --- TRANSFORMED CODE ---
            HANDLE dummy_hProcess = NULL;
            HMODULE dummy_ntdll = GetModuleHandleA("ntdll.dll");
            if (dummy_ntdll) {{
                typedef struct _UNICODE_STRING {{
                    USHORT Length;
                    USHORT MaximumLength;
                    PWSTR  Buffer;
                }} UNICODE_STRING, *PUNICODE_STRING;

                typedef struct _OBJECT_ATTRIBUTES {{
                    ULONG           Length;
                    HANDLE          RootDirectory;
                    PUNICODE_STRING ObjectName;
                    ULONG           Attributes;
                    PVOID           SecurityDescriptor;
                    PVOID           SecurityQualityOfService;
                }} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

                typedef struct _CLIENT_ID {{
                    HANDLE UniqueProcess;
                    HANDLE UniqueThread;
                }} CLIENT_ID, *PCLIENT_ID;

                typedef NTSTATUS (WINAPI *PNT_OPEN_PROCESS)(
                    PHANDLE,
                    ACCESS_MASK,
                    POBJECT_ATTRIBUTES,
                    PCLIENT_ID
                );

                PNT_OPEN_PROCESS dummy_NtOpenProcess =
                    (PNT_OPEN_PROCESS)GetProcAddress(dummy_ntdll, "NtOpenProcess");

                if (dummy_NtOpenProcess) {{
                    CLIENT_ID dummy_cid;
                    dummy_cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
                    dummy_cid.UniqueThread = 0;

                    OBJECT_ATTRIBUTES dummy_oa;
                    memset(&dummy_oa, 0, sizeof(dummy_oa));
                    dummy_oa.Length = sizeof(dummy_oa);

                    NTSTATUS dummy_status = dummy_NtOpenProcess(
                        &dummy_hProcess,
                        PROCESS_ALL_ACCESS,
                        &dummy_oa,
                        &dummy_cid
                    );
                    if (dummy_status != 0) dummy_hProcess = NULL;
                }}
            }}

            ### EXAMPLE OF UNSUPPORTED API (DO NOT REPLACE)
            HANDLE snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            // This must be left unchanged because no NT equivalent exists.

            INPUT CODE:
            {c_code}

        Return ONLY the complete, modified source code inside a single markdown code block. Use c or cpp according to the detected input language.
        """
        return self.call_llm(prompt, c_code, base_name, "api_call_substitution")

    def apply_anti_debugging(self, c_code,base_name="unknown"):
        """Insert anti-debugging checks inline."""
        prompt = f"""
            You are an expert C reverse engineer and compiler-aware code generator.  
            Your task is to insert **context-aware anti-debugging instrumentation** into a single existing C function, for authorized defensive/red-team security testing only.

            Target Architecture: {self.arch}
            Compiler: Microsoft Visual Studio (MSVC)

            ---

            ### MANDATORY CONTEXT ANALYSIS

            Before generating any code, perform a full semantic analysis of the provided function:

            1. Determine its:
            - Return type and calling convention.
            - Existing local variable declarations and their naming style.
            - Existing control flow: early returns, `goto cleanup`, `__try/__except`, loops, switch statements.
            - Existing error-handling conventions: return codes, `NULL`, `FALSE`, etc.
            - Existing macro usage and typedef style.
            - Existing comments and formatting/indentation style.

            2. Choose the best injection point:
            - Choose the injection point after all resources that would need to be freed on early exit have been allocated. 
            - If the function allocates memory or opens handles before the check, you must either place the check after those allocations and use a goto cleanup (if available) to free them, or add a cleanup block yourself. Never place the check before allocations that would be leaked on early return.

            3. Select anti-debugging technique(s) from the categories below. Do **not** default to the most common checks. Choose a technique that blends with the function's existing operations and does not introduce obvious API calls:
            - Manual PEB inspection: `PEB.BeingDebugged`, `NtGlobalFlag`, Heap Flags.
            - Native API via dynamic resolution: `NtQueryInformationProcess` with `ProcessDebugFlags`, `ProcessDebugPort`, `ProcessDebugObjectHandle`; resolve using `GetModuleHandleA("ntdll.dll")` + `GetProcAddress`.
            - Exception-based checks: `INT 2D`, `INT 3`, `DebugBreak`, `ICE`, combined with existing or new `__try/__except` handlers.
            - Timing checks: `__rdtsc` + `__cpuid`, `QueryPerformanceCounter`, `GetTickCount64`, but only if the function already performs loops or computational work. 
            - Memory scans: scan a small portion of the current function or a known DLL export for `0xCC`; use checksums on a local code region if the function is stable.
            - Direct debugger interaction: `NtSetInformationThread(ThreadHideFromDebugger)`, `NtQueryObject` for `DebugObject`, parent process check.

            4. Use **multiple independent checks** only if you can combine them via arithmetic/boolean logic that does not look like a debugger check.  
            Example: `if (((peb_flags ^ heap_flags) + timing_delta) > threshold) { ... }`  
            Avoid a single variable named `is_debugged`, `dummy_is_debugged`, `anti_debug`, etc.

            ---

            ### STRICT GENERATION RULES

            - **NO NEW FUNCTIONS**: All logic must be injected inline inside the existing function body. Do not create helper functions, static functions, inline functions, or new file-scope typedefs/globals.
            - **NO UNINITIALIZED READS**: Do not read from local variables that have not been assigned a value. If you need to use a field of a structure, ensure that the structure has been allocated and initialized.
            - **CONSISTENT EXIT**: If the function has a cleanup section, use a goto to that section; otherwise, return an appropriate error value. Ensure that the returned value matches the original function’s error semantics (e.g., `NULL` for pointers, `FALSE` for `BOOL`, `-1` for `int`).
            
            - **VARIABLE NAMING**:
            - Generate unique local variable names that match the style of the surrounding code.
            - If the surrounding code uses Hungarian notation, follow it: `dwValue`, `pPeb`, `bResult`, etc.
            - If the surrounding code uses lowercase snake_case, follow that.
            - **Never** include strings like `debug`, `dbg`, `anti`, `trace`, `check`, `detect`, `is_debugged`, or similar in variable names.

            - **OBFUSCATION & BLENDING**:
            - Use compile-time constant expressions instead of raw magic numbers when possible. For example, use `((0x10 | 0x20 | 0x40) ^ 0x70) == 0` instead of `0x70`.
            - Use arithmetic identities and opaque predicates, e.g. `if ((x * 2 + 1) % 2 == 1)`.
            - Introduce a small number of meaningless local variables that are used in the anti-debug calculation. These should look like normal temporary variables, not debugger indicators.
            - Do not add comments that mention anti-debug, debugger, detection, or evasion. If the original code has comments, mimic their tone; if it has no comments, add none or only neutral comments.
            - If the function uses `__try/__except`, integrate exception-based checks with the existing exception style. Do not create a separate handler that stands out.

            ### REAL DETECTION
            - Use only reliable techniques such as:
            - PEB.BeingDebugged (via `__readfsdword(0x30)` or `__readgsqword(0x60)`)
            - NtGlobalFlag (PEB offset 0x68/0xBC)
            - NtQueryInformationProcess(ProcessDebugFlags)
            - You may combine these with timing checks, but the timing threshold must be derived from a loop that is guaranteed to take a consistent number of cycles under normal execution.

            - **ARCHITECTURE ADAPTATION**:
            - use `__readfsdword(0x30)` and 32-bit PEB offsets.
            - Adjust heap offsets and structure sizes accordingly.

            - **VARIANT UNIQUENESS**:
            - Every generated response must be a **new variant**. Even for the same input function, the generated anti-debugging logic must differ in at least:
                - Chosen technique(s)
                - Variable names
                - Logic arrangement
                - Constant encoding
                - Injection point
            - Do not output the same snippet twice.

            - **COMPILATION GUARANTEE**:
            - The final output must compile cleanly with MSVC for the target architecture.
            - If inline assembly is used, ensure it is valid for the target architecture.
            - If `__try/__except` is used, ensure it is inside a function and does not cross variable initialization boundaries.

            ---

            ### STRUCTURAL EXAMPLE

            Do **not** copy this exact code. It only shows the required structure and blending style:

            ```c
            void target_function(int *out_value) {{
                int local_status = 0;
                unsigned int ctx_a = 0;

                // Original variable declarations continue...
                // --- INSERTED CONTEXT-AWARE LOGIC START ---
                PEB *peb = (PEB*)__readfsdword(0x30);
                if (peb->BeingDebugged) {{
                    local_status = 1;
                }}
                // (If using NtGlobalFlag: check peb->NtGlobalFlag)
                if (local_status) {{
                    return; // or goto cleanup if resources are allocated
                }}
                // --- INSERTED CONTEXT-AWARE LOGIC END ---

                // Original code continues...
            }}
            ```

            ### Notice:
            No variable named debug or is_debugged.
            No direct debug API call.
            The early return matches the function's void return type.
            The logic uses a plausible timing check with __rdtsc and __cpuid, not a raw IsDebuggerPresent.

            INPUT FUNCTION
            {c_code}

            Return ONLY the complete, modified C source code inside a single markdown code block (c ... ).
            """
        return self.call_llm(prompt, c_code,base_name, "anti_debugging")

    def apply_control_flow_obfuscation(self, c_code,base_name="unknown"):
        """Obfuscate control flow using opaque predicates or state-machine dispatchers."""   
        # Architecture-specific technique isolation
        if self.arch == "x86":
            tech_rules = """
            - Opaque conditional jump using MSVC __asm blocks and volatile condition checks.
            - Control Flow Flattening using a volatile state variable inside a while-switch loop."""
        else: # x64
            tech_rules = """
            - Opaque conditional jump using volatile global/memory reads to create an unreachable branch containing MSVC intrinsics (__nop()).
            - Control Flow Flattening using a volatile state variable inside a while-switch loop.
            - Do NOT use inline assembly (__asm) or _emit directives on x64."""

        prompt = f"""
            You are an expert C/C++ developer generating synthesized code variants.
            Target architecture: {self.arch}
            Compiler: Microsoft Visual Studio (MSVC)
            Source language: C or C++ (preserve the input language; do not convert C to C++ or C++ to C).

            ### TASK
            Inject a single control-flow obfuscation transformation into the provided function.

            ### CONSTRAINTS
            1. FEATURE ISOLATION: Implement EXACTLY ONE of the following techniques matching the target architecture rules.

            Target architecture rules:
            {tech_rules}

            2. NO NEW FUNCTIONS: You are strictly forbidden from creating helper functions or separate function bodies.
            All logic must reside entirely inside the existing function.

            3. PRESERVE EXECUTION FLOW & LOGIC:
            - All original logic, side effects, and return values must execute in the exact same sequence as the original code.
            - You may restructure the existing code only for the selected obfuscation technique.
            - Do not add new side effects, change return values, or alter error handling.

            4. ISOLATED SCOPING:
            Use localized, uniquely named variables, e.g. `dummy_state`, `dummy_cond`, `dummy_volatile`, to prevent variable shadowing.
            Ensure no variable redefinition or name conflict with existing variables.

            5. LANGUAGE PRESERVATION:
            - If the input is C, the output must remain valid C.
            - If the input is C++, the output must remain valid C++.
            - Use C++ features only when the input is already C++.

            ### STRUCTURAL PATTERN TO FOLLOW

            If using **Control Flow Flattening**, restructure the original block sequence into a state machine similar to this layout, but adapt it to the actual code:

            volatile int dummy_state = 1;
            while (dummy_state != 0) {{
                switch (dummy_state) {{
                    case 1:
                        // Original statements / block 1
                        ...
                        dummy_state = 2;
                        break;
                    case 2:
                        // Original statements / block 2
                        ...
                        dummy_state = 0; // terminate state loop
                        break;
                    default:
                        dummy_state = 0;
                        break;
                }}
            }}

            Rules for Control Flow Flattening:

                Split the original function body into logical blocks while preserving exact execution order.

                If the function already contains loops or conditionals, you may integrate them as blocks inside the state machine, but do not alter their semantics.

                Ensure all original return statements are converted to dummy_state = 0; plus a final return at the end if needed, preserving the return value.

                If the original function returns a value, store it in a local variable and return it after the state machine ends.

            If using Opaque Conditional Jump, follow the architecture-specific rule:
                x86: Use MSVC inline assembly or volatile checks to create an opaque branch.

            Do not copy the example code literally; use it only as a structural guide.

            INPUT CODE:
            {c_code}

            Return ONLY the complete, modified source code inside a single markdown code block.
            Use c or cpp according to the detected input language.
            """
        return self.call_llm(prompt, c_code,base_name, "control_flow_Obfuscation")
    
    def apply_anti_disassembly(self, c_code, base_name="unknown"):
        """
        Leverages the LLM's semantic understanding to inject context-aware 
        x86 anti-disassembly techniques natively into the code.
        """   
        prompt = f"""
            You are an elite malware analyst generating synthetic, highly contextualized obfuscation datasets for machine learning training.
            Target Architecture: x86 ONLY
            Compiler: Microsoft Visual Studio (MSVC)

            ### YOUR OBJECTIVE: SEMANTIC ENTANGLEMENT
            Do not use generic top-level opaque predicates in C, and DO NOT declare new dummy variables. 
            Your task is to understand the semantic purpose of the provided C code and weave MSVC x86 anti-disassembly tricks directly into existing function bodies using the function's natural variables.

            ### X86 INLINE ASSEMBLY TECHNIQUES (SELECT ONE):
            1. Rogue Byte Injection: Safely guard a junk byte (e.g., `_emit 0xE8`) inside an `__asm` block using an opaque predicate.
            2. Misaligned Jump: Use an `__asm` block to jump 1 byte into a multi-byte instruction to confuse recursive descent disassemblers.
            3. Call/Pop Stack Tampering: Manually manipulate stack frames using `__asm` push/pop sequences to obscure function call flow.

            ### CRITICAL JUNK BYTE & TAUTOLOGY RULES (MUST FOLLOW EXACTLY):
            1. NO C-LEVEL CONDITIONALS: Never use C-level `if` or `else` blocks to guard assembly junk bytes. The MSVC optimizer will strip them.
            2. ALL-IN-ASM SCOPING: The predicate, conditional jump, junk byte, and jump target label MUST reside entirely within a single `__asm {{ ... }}` block.
            3. NO TRIVIAL ZEROING: Do not use `xor reg, reg` to create your zero flag. Use non-trivial arithmetic on an existing variable (e.g., `and reg, 0` or `imul reg, 0`).
            4. LABEL INSIDE BRACKETS: The target label MUST be inside the `__asm` block to prevent C-compiler optimization errors.

            ### ANTI-PATTERN WARNING & DIVERSITY RULES:
            1. NO BLIND COPYING: Do not reuse the exact same mathematical instruction sequence. You must vary the instructions across injections (e.g., use bitwise shifts `shl`, additions `add`, or bitwise `xor` with constants instead of always using `imul`).
            2. SPAM LIMIT: Inject **only ONE** well-crafted anti-disassembly block per function. Do not spam them after every single line of code.

           ### X86 INLINE ASSEMBLY TECHNIQUES & EXAMPLES (CHOOSE ONE PER FUNCTION):

                1. ROGUE BYTE INJECTION (Guarded Junk Byte):
                Use ANY local variable existing in the target function to create a non-trivial tautology, jumping over a junk byte.
                EXAMPLE (Substitute 'some_local_var' with a real variable from the function):
                __asm {{
                    mov ecx, dword ptr [some_local_var]
                    add ecx, 10
                    sub ecx, 10
                    cmp ecx, dword ptr [some_local_var]
                    jne skip_byte
                    _emit 0xE8
                skip_byte:
                }}

                2. MISALIGNED JUMP (Instruction Stream Confusion):
                Use an unconditional or conditional jump combined with a `_emit` byte sequence to force linear sweep disassemblers into misinterpreting instruction boundaries.
                EXAMPLE:
                __asm {{
                    jmp clean_path
                    _emit 0x89 // Decoy opcode byte that desynchronizes linear disassembly
                clean_path:
                    nop
                }}

                3. CALL/POP CONTROL FLOW TAMPERING (Stack/EIP Obfuscation):
                Leverage a local `call` and `pop` sequence (classic position-independent code idiom) to dynamically calculate execution offsets and skip embedded decoy bytes.
                EXAMPLE:
                __asm {{
                    call get_position
                    _emit 0x90 // Decoy/junk byte embedded in the code stream
                get_position:
                    pop edx
                    add edx, 1 // Advance past the junk byte
                    jmp edx    // Resume normal execution flow
                }}

            ### BAD (Will crash or be optimized away):
            - `if (bytes_read == -1)` -> C-level condition; state depends on runtime and can fall through to junk.
            - `if ((bytes_read * 0) == 0)` -> C-level condition; MSVC optimizer will remove it.

            ### OUTPUT FORMAT:
            Output exactly two sections:
            1. <analysis>: 
            - State the function's domain purpose.
            - Name the existing variable used.
            - Provide a brief mathematical proof showing why the conditional jump is a guaranteed tautology.
            2. <code>: The complete, modified C source code inside a single markdown code block (```c ... ```).

            ### INPUT CODE:
            {c_code}
            """
        response = self.call_llm(prompt, c_code,base_name, "anti_disassembly")
        
        # Simple parser to extract just the code block, ignoring the analysis phase
        import re
        match = re.search(r'```c\n(.*?)\n```', response, re.DOTALL)
        if match:
            return match.group(1).strip()
        return response # Fallback

    # I put it here just in case, a method to apply a list of techniques sequentially
    def apply_all_techniques(self, c_code, techniques=None, base_name="unknown"):
        """Apply a list of techniques in order.
        techniques: list of strings, e.g., ['junk_code_insertion', 'string_encryption', ...]
        If None, apply all.
        """
        if techniques is None:
            techniques = [
                'junk_code_insertion',
                'api_call_substitution',
                'anti_debugging',
                'control_flow_obfuscation',
                'anti_disassembly'
            ]
        code = c_code
        for tech in techniques:
            method = getattr(self, f"apply_{tech}", None)
            if method:
                print(f"Applying {tech}...")
                code = method(code, base_name=base_name)
            else:
                print(f"Unknown technique: {tech}")
        return code

    def process_directory_with_scoring(self, processed_dir, workspace_dir, exe_name, techniques=None):
        """Scores functions, filters external APIs, and creates a separate binary+technique directory per technique containing all functions."""
        if techniques is None:
            techniques = [
                'junk_code_insertion',
                'api_call_substitution',
                'anti_debugging',
                'control_flow_obfuscation',
                'anti_disassembly'
            ]

        graph_path = os.path.join(workspace_dir, "extracted_functions", exe_name, "call_graph.json")
        call_graph = {}
        if os.path.exists(graph_path):
            with open(graph_path, "r", encoding="utf-8") as f:
                call_graph = json.load(f)
        else:
            print(f"Warning: Call graph not found at {graph_path}")
            
        c_files = glob.glob(os.path.join(processed_dir, "*.c"))
        scored_functions = []
        
        # 1. Score all internal functions
        for file_path in c_files:
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

        # 2. Determine target selection threshold
        if total_functions < 10:
            percentage = 1.00
        elif 10 <= total_functions <= 20:
            percentage = 0.60
        elif 21 <= total_functions <= 40:
            percentage = 0.30
        elif 41 <= total_functions <= 70:
            percentage = 0.20
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
        
        # 3. Process per technique: Create directory named <binary_name>_<technique>
        for tech in techniques:
            tech_dir = os.path.join(workspace_dir, "processed_functions", f"{binary_name}_{tech}")
            os.makedirs(tech_dir, exist_ok=True)
            
            print(f"\n--- Generating Variant Directory: {tech_dir} ---")
            
            for file_path in c_files:
                base_name = os.path.splitext(os.path.basename(file_path))[0]
                dest_path = os.path.join(tech_dir, f"{base_name}.c")
                
                with open(file_path, 'r', encoding='utf-8') as f:
                    code = f.read()

                if base_name in worthy_function_names:
                    method = getattr(self, f"apply_{tech}", None)
                    if method:
                        print(f"Applying {tech} to: {base_name}")
                        modified_code = method(code, base_name=base_name)
                    else:
                        print(f"Unknown technique method for {tech}, passing unchanged.")
                        modified_code = code
                    with open(dest_path, 'w', encoding='utf-8') as f:
                        f.write(modified_code)
                else:
                    # Pass through non-selected functions unchanged
                    with open(dest_path, 'w', encoding='utf-8') as f:
                        f.write(code)