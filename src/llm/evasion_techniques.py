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


class DefensiveEvasion:
    def __init__(self, model_name=None, base_url=None, arch="x86"):
        self.base_url = base_url or os.environ.get('OLLAMA_HOST', 'http://ollama:11434')
        self.model_name = model_name or os.environ.get('LLM_MODEL', 'deepseek-coder-v2')
        self.client = Client(host=self.base_url)
        self.arch = arch               # e.g., "x86 (32-bit)" or "x86_64 (64-bit)"
        print(f"DefensiveEvasion initialized with {self.model_name} at {self.base_url} for architecture: {self.arch}")

    def call_llm(self, prompt, original_code):
        """Send prompt to LLM and extract raw C code from response."""
        print("Sending request to LLM...")
        response = ""
        for chunk in self.client.generate(
            model=self.model_name,
            prompt=prompt,
            stream=True,
            options={'temperature': 0.3, 'num_ctx': 16384}
        ):
            response += chunk['response']
        return self.extract_code(response, original_code)

    def extract_code(self, llm_output, original_code):
        """Extract C code from markdown block, or fallback to original."""
        match = re.search(r"```[cC]?\s*\n(.*?)```", llm_output, re.DOTALL)
        if match:
            return match.group(1).strip()
        # Fallback: if the output itself looks like C code
        if "#include" in llm_output or "void" in llm_output or "int" in llm_output:
            return llm_output.strip()
        return original_code

    def apply_junk_code_insertion(self, c_code):
        """Insert dead code / junk instructions that do not affect logic."""
        prompt = f"""
        You are an expert C developer generating synthesized code variants.
        Target Architecture: {self.arch}
        Compiler: Microsoft Visual Studio (MSVC)

        ### CRITICAL TRANSFORMATION RULE: ADDITIVE-ONLY
        - DO NOT MOVE, MODIFY, OR WRAP ANY EXISTING CODE INSIDE A DEAD BRANCH.
        - All original code statements MUST remain outside the `if` block in the live execution path.
        - Dead branches (`if (opaque_false_condition) {{ ... }}`) must contain ONLY newly generated, self-contained dummy logic.

        ### STRICT COMPILATION & LOGIC RULES
        1. NO NEW FUNCTIONS: All inserted logic must reside entirely inside existing function bodies.
        2. PRESERVE ORIGINAL BEHAVIOR: The execution outcome, return values, side effects, and active control flow of the original code must remain 100% identical.
        3. ISOLATED DUMMY SCOPING: All variables declared inside a dead branch MUST be given unique names prefixed with `dummy_` (e.g., `dummy_buf`, `dummy_status`) to prevent variable shadowing or redefinition errors.
        4. SELF-CONTAINED HEADERS: Ensure any APIs used in the dead branch are supported by standard Windows/C headers (`<windows.h>`, `<stdio.h>`, `<stdlib.h>`).

        ### OPAQUE PREDICATE REQUIREMENTS
        Drive the dead branch using a mathematical invariant that statically looks complex but dynamically evaluates to FALSE at runtime:
        - Pattern A (Math Invariant): `volatile int dummy_x = 7; if ((dummy_x * (dummy_x + 1)) % 2 != 0) {{ ... }}` (Always False)
        - Pattern B (System Query): `if (GetPriorityClass(GetCurrentProcess()) == 0xFFFFFFFF) {{ ... }}` (Always False under normal execution)
        Do NOT use simple `volatile int v = 0; if (v)` or `if (0)`.

        ### VARIETY REQUIREMENT FOR DEAD BRANCH BODY
        Select ONE random category below for the newly generated dead branch body:
        - Category A: System info queries (e.g., GetSystemInfo, GetLocalTime, GetUserNameA into dummy buffers).
        - Category B: Memory & String operations (e.g., malloc dummy buffer, sprintf_s, strlen, free).
        - Category C: Bitwise/Math loops (e.g., multi-iteration XOR loops over a local dummy array).
        - Category D: Registry queries (e.g., RegOpenKeyExA on a non-existent key with local cleanup).

        ### STRUCTURAL PATTERN TO FOLLOW:
        ```c
        // --- ORIGINAL CODE STATEMENT ---
        original_statement_1;

        // --- INSERTED DEAD BRANCH (ADDITIVE ONLY) ---
        volatile int dummy_seed = 12;
        if ((dummy_seed * dummy_seed + dummy_seed) % 2 != 0) {{
            // NEW DUMMY LOGIC HERE (Category A, B, C, or D)
            char dummy_buf[32];
            memset(dummy_buf, 0, sizeof(dummy_buf));
        }}

        // --- ORIGINAL CODE STATEMENT CONTINUES ---
        original_statement_2;
        ### INPUT CODE:
        {c_code}

        Return ONLY the complete, modified C source code inside a single markdown code block (```c ... ```).
        """
        return self.call_llm(prompt, c_code)


    def apply_string_encryption(self, c_code):
        """Encrypt string literals and add inline runtime decryption."""
        prompt = f"""
            You are an expert C developer generating synthesized code variants.
            Target Architecture: {self.arch}
            Compiler: Microsoft Visual Studio (MSVC)

            ### STRICT COMPILATION & LOGIC RULES
            1. NO NEW FUNCTIONS: You are strictly forbidden from creating any decryption helper functions. ALL decryption loops must be 100% inline where the string is needed.
            2. PRESERVE EXECUTION FLOW: The decrypted string at runtime MUST exactly match the original string literal. Do not change the logic of the host application.
            3. INLINE DECRYPTION: Decrypt strings in-place within stack-allocated byte arrays directly in the local scope. If a string is passed directly into a function call (e.g., `printf("hello")`), you must hoist the string declaration and decryption loop BEFORE the function call.
            4. ISOLATED NAMING: Use randomized variable names for local buffers, keys, and loop counters (e.g., `enc_buf_1`, `dec_key_a`) to prevent classifier overfitting. 
            5. DETERMINISTIC KEYING: Use a simple XOR key (e.g., single-byte or multi-byte).

            ### STRUCTURAL PATTERN TO FOLLOW:
            Do not use this exact code, but follow this structural layout for every string you replace:

            ```c
            // --- ORIGINAL CODE STATEMENT ---
            // CreateFileA("C:\\secret.txt", ...);

            // --- TRANSFORMED CODE ---
            unsigned char enc_str_1[] = {{ 0x01, 0x18, 0x11, 0x17, 0x07, 0x06, 0x4c, 0x16, 0x1a, 0x16, 0x5e, 0x00 }};
            unsigned char dec_key_1 = 0x42;
            for (int i_1 = 0; i_1 < sizeof(enc_str_1) - 1; i_1++) {{
                enc_str_1[i_1] ^= dec_key_1;
            }}
            CreateFileA((char*)enc_str_1, ...);
            memset(enc_str_1, 0, sizeof(enc_str_1)); // Cleanup immediately after use

            ```
            ### TASK
            Identify all string literals in the C function below. Replace each string literal with the inline stack-buffer setup, decryption loop, and cleanup exactly as shown in the structural pattern. Ensure necessary headers (`<string.h>`) are present.

            ### INPUT CODE:

            {c_code}

            Return ONLY the complete, modified C source code inside a single markdown code block (`c ... `).
            """
        return self.call_llm(prompt, c_code)


    def apply_api_call_substitution(self, c_code):
        """Replace common Windows API calls with alternative NT API calls."""
        prompt = f"""
        You are an expert C developer generating synthesized code variants.
        Target Architecture: {self.arch}
        Compiler: Microsoft Visual Studio (MSVC)

        ### CRITICAL TRANSFORMATION RULES
        1. NO NEW FUNCTIONS: All translations must happen inline. Do not create wrapper functions for the NT APIs.
        2. NATIVE API TRANSLATION: Identify high-level Win32 API calls (e.g., `VirtualAlloc`, `CreateFile`, `OpenProcess`) and replace them with their Native API equivalents (`NtAllocateVirtualMemory`, `NtCreateFile`, `NtOpenProcess`).
        3. DYNAMIC RESOLUTION: Do not rely on static linking to `ntdll.lib`. Dynamically resolve the function pointers inline using `GetModuleHandleA("ntdll.dll")` and `GetProcAddress`.
        4. TYPE CONVERSION: Inline the necessary setup for NT structures (e.g., `OBJECT_ATTRIBUTES`, `CLIENT_ID`, `UNICODE_STRING`) and change return type checks to handle `NTSTATUS` (e.g., checking if `status == 0` for `STATUS_SUCCESS`).
        5. NO INLINE ASM ON X64: Keep all logic in standard C. Do not use `__asm` or fake syscall intrinsics.

        ### STRUCTURAL PATTERN TO FOLLOW
        Do not copy this exact code, but follow this structural layout for API substitutions:

        ```c
        // --- ORIGINAL CODE STATEMENT ---
        // HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

        // --- TRANSFORMED CODE ---
        HANDLE dummy_hProcess = NULL;
        HMODULE dummy_ntdll = GetModuleHandleA("ntdll.dll");
        if (dummy_ntdll) {{
            typedef NTSTATUS(WINAPI* PNT_OPEN_PROCESS)(PHANDLE, ACCESS_MASK, PVOID, PVOID);
            PNT_OPEN_PROCESS dummy_NtOpenProcess = (PNT_OPEN_PROCESS)GetProcAddress(dummy_ntdll, "NtOpenProcess");
            
            if (dummy_NtOpenProcess) {{
                // Inline setup of required NT structures
                struct _CLIENT_ID {{
                    HANDLE UniqueProcess;
                    HANDLE UniqueThread;
                }} dummy_cid;
                dummy_cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
                dummy_cid.UniqueThread = 0;

                struct _OBJECT_ATTRIBUTES {{
                    ULONG Length;
                    HANDLE RootDirectory;
                    void* ObjectName;
                    ULONG Attributes;
                    void* SecurityDescriptor;
                    void* SecurityQualityOfService;
                }} dummy_oa;
                memset(&dummy_oa, 0, sizeof(dummy_oa));
                dummy_oa.Length = sizeof(dummy_oa);

                // Native API Call
                NTSTATUS dummy_status = dummy_NtOpenProcess(&dummy_hProcess, PROCESS_ALL_ACCESS, &dummy_oa, &dummy_cid);
            }}
        }}
        INPUT CODE:
        {c_code}

        Return ONLY the complete, modified C source code inside a single markdown code block (c ... ).
        """
        return self.call_llm(prompt, c_code)

    def apply_anti_debugging(self, c_code):
        """Insert anti-debugging checks inline."""
        prompt = f"""
            You are an expert C developer generating synthesized code variants.
            Target Architecture: {self.arch}
            Compiler: Microsoft Visual Studio (MSVC)

            ### CRITICAL TRANSFORMATION RULE: ADDITIVE-ONLY
            - DO NOT MOVE, MODIFY, OR WRAP ANY EXISTING CODE.
            - All original code statements MUST remain intact in the live execution path.

            ### STRICT COMPILATION & LOGIC RULES
            1. FEATURE ISOLATION: Implement exactly ONE of the following anti-debugging techniques:
            - PEB.BeingDebugged inspection (using __readfsdword or __readgsqword).
            - NtGlobalFlag inspection.
            - Timing check (__rdtsc and __cpuid).
            - OutputDebugStringA error check.
            2. NO NEW FUNCTIONS: All logic must be injected directly into the existing function body. Do not create static, inline, or helper functions.
            3. SAFE EVASION: Do NOT attempt to corrupt existing variables. Define a unique local flag (e.g., `dummy_is_debugged`). If a debugger is detected, gracefully return from the function (e.g., `return 0;` or `return NULL;`) to prevent crashes.
            4. DEPENDENCIES: Ensure required headers (`<windows.h>`, `<intrin.h>`) are included at the top of the file.

            ### STRUCTURAL PATTERN TO FOLLOW:
            Do not copy this exact code, but follow this structural layout for the anti-debugging injection:

            ```c
            // --- ORIGINAL CODE HEADERS ---
            #include <windows.h>
            #include <intrin.h> // Ensure this is present for rdtsc

            void original_function() {{
                // --- INSERTED ANTI-DEBUGGING (ADDITIVE ONLY) ---
                int dummy_is_debugged = 0;
                
                // Example: Timing check
                unsigned __int64 dummy_tsc1 = __rdtsc();
                Sleep(0); 
                unsigned __int64 dummy_tsc2 = __rdtsc();
                if ((dummy_tsc2 - dummy_tsc1) > 0xFFFFF) {{
                    dummy_is_debugged = 1;
                }}

                if (dummy_is_debugged) {{
                    return; // Safe, silent exit. No ExitProcess, no variable corruption.
                }}

                // --- ORIGINAL CODE CONTINUES ---
                original_statement_1;
                original_statement_2;
            }}
            INPUT CODE:
            {c_code}

            Return ONLY the complete, modified C source code inside a single markdown code block (c ... ).
            """
        return self.call_llm(prompt, c_code)

    def apply_control_flow_Obfuscation(self, c_code):
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
            You are an expert C developer generating synthesized code variants.
            Target Architecture: {self.arch}
            Compiler: Microsoft Visual Studio (MSVC)

            ### TASK
            Inject a single control-flow obfuscation transformation into the provided C function.

            ### CONSTRAINTS
            1. FEATURE ISOLATION: Implement EXACTLY ONE of the following techniques matching target rules:{tech_rules}
            2. NO NEW FUNCTIONS: You are strictly forbidden from creating helper functions or separate function bodies. All logic must reside entirely inside the existing function.
            3. PRESERVE EXECUTION FLOW & LOGIC: All original logic, side effects, and return values must execute in the exact same sequence as the original code.
            4. ISOLATED SCOPING: Use localized, uniquely named variables (e.g., `dummy_state`, `dummy_cond`) to prevent variable shadowing.

            ### STRUCTURAL PATTERN TO FOLLOW (CONTROL FLOW FLATTENING EXAMPLE):
            Do not copy this exact code, but follow this structural layout if flattening control flow:

            ```c
            // --- TRANSFORMED CONTROL FLOW STRUCTURE ---
            int dummy_state = 1;
            while (dummy_state != 0) {{
                switch (dummy_state) {{
                    case 1:
                        // Original Block 1
                        original_statement_1;
                        dummy_state = 2;
                        break;
                    case 2:
                        // Original Block 2
                        original_statement_2;
                        dummy_state = 0; // Terminate state loop
                        break;
                    default:
                        dummy_state = 0;
                        break;
                }}
            }}
            INPUT CODE:
            {c_code}

            Return ONLY the complete, modified C source code inside a single markdown code block (c ... ).
            """
        return self.call_llm(prompt, c_code)
    
    def apply_anti_disassembly(self, c_code):
        """Insert architecture-aware anti-disassembly tricks inline."""
        # Define architecture-specific rules in Python
        if self.arch == "x86":
            arch_rules = """
                Use exactly ONE of the following x86 MSVC-compatible techniques:
                - Insert junk bytes inside a dead/unreachable branch using `__asm { _emit 0x66 }`.
                - Use misaligned jumps (e.g., jumping 1 byte into a multi-byte instruction) using `__asm { jmp ... }`.
                - Obfuscate immediate values with complex, dummy arithmetic using volatile variables."""
        elif self.arch == "x64":
            arch_rules = """
                Use exactly ONE of the following x64 MSVC-compatible techniques:
                - Create opaque conditional branches (using volatile variables or __rdtsc()) where the dead branch contains MSVC intrinsics like __nop().
                - Obfuscate immediate values with complex, dummy arithmetic using volatile variables.
                - Do NOT use inline assembly, _emit, or __debugbreak(). Keep the control flow strictly in C."""
        else:
            raise ValueError("Unsupported architecture")
        # Build the strict prompt
        prompt = f"""
            You are an expert C developer generating synthesized code variants. 
            Target Architecture: {self.arch}
            Compiler: Microsoft Visual Studio (MSVC)

            ### CRITICAL TRANSFORMATION RULE: ADDITIVE-ONLY
            - DO NOT MOVE, MODIFY, OR WRAP ANY EXISTING CODE INSIDE A DEAD BRANCH.
            - All original code statements MUST remain outside the `if` block in the live execution path.

            ### STRICT COMPILATION & LOGIC RULES
            1. FEATURE ISOLATION: {arch_rules}
            2. NO NEW FUNCTIONS: All inserted logic must reside entirely inside existing function bodies. Do NOT create helper functions.
            3. PRESERVE ORIGINAL BEHAVIOR: The execution outcome, return values, and side effects of the original code must remain 100% identical.
            4. ISOLATED DUMMY SCOPING: All variables declared for opaque predicates or dummy arithmetic MUST be given unique names prefixed with `dummy_` (e.g., `dummy_cond`, `dummy_junk`) to prevent variable shadowing.
            5. SELF-CONTAINED HEADERS: Ensure any APIs used are supported by standard Windows/C headers (`<windows.h>`, `<intrin.h>`).

            ### STRUCTURAL PATTERN TO FOLLOW (OPAQUE PREDICATE EXAMPLE):
            Do not copy this exact code, but follow this structural layout for inserting dead branches:

            ```c
            // --- ORIGINAL CODE STATEMENT ---
            original_statement_1;

            // --- INSERTED ANTI-DISASSEMBLY (ADDITIVE ONLY) ---
            volatile int dummy_seed = 12;
            if ((dummy_seed * dummy_seed + dummy_seed) % 2 != 0) {{
                // JUNK INSTRUCTIONS HERE (e.g., __nop() for x64, or __asm {{ _emit 0x66 }} for x86)
            }}

            // --- ORIGINAL CODE STATEMENT CONTINUES ---
            original_statement_2;
                    INPUT CODE:
            {c_code}

            Return ONLY the complete, modified C source code inside a single markdown code block (c ... ).
            """
        return self.call_llm(prompt, c_code)

    # I put it here just in case, a method to apply a list of techniques sequentially
    def apply_all_techniques(self, c_code, techniques=None):
        """Apply a list of techniques in order.
        techniques: list of strings, e.g., ['junk_code_insertion', 'string_encryption', ...]
        If None, apply all.
        """
        if techniques is None:
            techniques = [
                'junk_code_insertion',
                'string_encryption',
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
                code = method(code)
            else:
                print(f"Unknown technique: {tech}")
        return code

    def process_directory_with_scoring(self, processed_dir, workspace_dir, exe_name, techniques=None):
        """Scores functions, filters external APIs, and applies evasion to the top %."""
        
        graph_path = os.path.join(workspace_dir, "extracted_functions", exe_name, "call_graph.json")
        call_graph = {}
        if os.path.exists(graph_path):
            with open(graph_path, "r", encoding="utf-8") as f:
                call_graph = json.load(f)
        else:
            print(f"Warning: Call graph not found at {graph_path}")
        c_files = glob.glob(os.path.join(processed_dir, "*.c"))
        scored_functions = []
        
        # First Pass: Score all valid internal functions
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

        # Selection Criteria
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
        
        # Second Pass: Apply evasion and save to the current directory
        dest_dir = os.path.join(workspace_dir, "processed_functions")
        os.makedirs(dest_dir, exist_ok=True)
        for file_path in c_files:
            base_name = os.path.splitext(os.path.basename(file_path))[0]
            dest_path = os.path.join(dest_dir, f"{base_name}.c")
            
            with open(file_path, 'r', encoding='utf-8') as f:
                code = f.read()

            if base_name in worthy_function_names:
                print(f"Applying evasion to highly scored function: {base_name}")
                modified_code = self.apply_all_techniques(code, techniques=techniques)
                with open(dest_path, 'w', encoding='utf-8') as f:
                    f.write(modified_code)
            else:
                # Pass through non-selected functions unchanged to maintain compilation integrity
                with open(dest_path, 'w', encoding='utf-8') as f:
                    f.write(code)