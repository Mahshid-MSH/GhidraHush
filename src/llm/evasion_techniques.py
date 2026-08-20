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
    def __init__(self, model_name=None, base_url=None, arch="x86",workspace_dir="."):
        self.base_url = base_url or os.environ.get('OLLAMA_HOST', 'http://ollama:11434')
        self.model_name = model_name or os.environ.get('LLM_MODEL', 'deepseek-coder-v2')
        self.client = Client(host=self.base_url)
        self.workspace_dir = workspace_dir
        self.arch = arch               # e.g., "x86 (32-bit)" or "x86_64 (64-bit)"
        print(f"DefensiveEvasion initialized with {self.model_name} at {self.base_url} for architecture: {self.arch}")

    def call_llm(self, prompt, original_code, base_name="unknown", tech_name="unknown"):
        """Send prompt to LLM and extract raw C code from response."""
        print("Sending request to LLM...")
        response = ""
        for chunk in self.client.generate(
            model=self.model_name,
            prompt=prompt,
            stream=True,
            options={'temperature': 0.6, 'num_ctx': 16384}
        ):
            response += chunk['response']
        log_dir = os.path.join(self.workspace_dir, "llm_logs")
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, f"evasion_{base_name}_{tech_name}.log")
        with open(log_file, "w", encoding="utf-8") as f:
            f.write(response)
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

# improved
    def apply_junk_code_insertion(self, c_code, base_name="unknown"):
        prompt = f"""
            You are an expert C/C++ developer generating synthesized code variants for AV evasion research.
            Target architecture: {self.arch}
            Compiler: Microsoft Visual Studio (MSVC)
            Source language: C or C++ (preserve the input language; do not convert C to C++ or C++ to C).

            ### CRITICAL TRANSFORMATION RULE: ADDITIVE-ONLY
            - DO NOT MOVE, MODIFY, OR WRAP ANY EXISTING CODE INSIDE A DEAD BRANCH.
            - All original code statements MUST remain outside the `if` block in the live execution path.
            - Dead branches (`if (opaque_false_condition) { ... }`) must contain ONLY newly generated, self-contained dummy logic.
            - The dummy logic may READ existing local variables, but it MUST NOT modify any original variable, global state, or function argument.
            - You may add required `#include` directives at file scope only if needed; do not remove or modify existing includes.

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
            if ((dummy_x * (dummy_x + 1)) % 2 != 0) {
                // Dead branch
            }

            Pattern B (System Query):
            if (GetPriorityClass(GetCurrentProcess()) == 0xFFFFFFFF) {
                // Dead branch
            }

            Pattern C (Combination):
            volatile DWORD dummy_tick = GetTickCount();
            if ((dummy_tick ^ 0x5A5A5A5A) == 0xFFFFFFFF && (dummy_tick & 0x80000000) != 0) {
                // Dead branch
            }

            ### DEAD BRANCH BODY REQUIREMENTS
            - The body must be self-contained but may read existing local variables; do not modify them.
            - Declare all dummy variables with `volatile` where possible to prevent compiler elimination.
            - Use at least 3 different Windows/C runtime API or standard C/C++ functions in each body.
            - Include dummy loops with at least 2 iterations that compute a dummy result and then discard it.
            - End each body with `memset` or `SecureZeroMemory` on dummy buffers to appear realistic.
            - Ensure no variable shadowing or redefinition.
            - Keep dummy code valid for the detected input language. If the input is C, use only C-compatible code. If the input is C++, you may use C++ constructs, but do not alter the original code.

            CATEGORIES (choose one per branch, no repeats within the same function)

            A: System info queries
            GetSystemInfo, GetLocalTime, GetUserNameA, GetComputerNameA

            B: Memory & String operations
            malloc, sprintf_s, strlen, memcpy, memset, free

            C: Bitwise/Math loops
            XOR loops over local dummy array, polynomial hash

            ### STRUCTURAL PATTERN TO FOLLOW

            // --- ORIGINAL CODE STATEMENT ---
            original_statement_1;

            // --- INSERTED DEAD BRANCH 1 (ADDITIVE ONLY) ---
            volatile int dummy_x_1 = 7;
            if ((dummy_x_1 * (dummy_x_1 + 1)) % 2 != 0) {
                // NEW DUMMY LOGIC HERE (Category A, at least 15 lines)
                ...
            }

            // --- ORIGINAL CODE STATEMENT CONTINUES ---
            original_statement_2;

            // --- INSERTED DEAD BRANCH 2 (ADDITIVE ONLY) ---
            volatile DWORD dummy_tick_2 = GetTickCount();
            if ((dummy_tick_2 ^ 0x5A5A5A5A) == 0xFFFFFFFF && (dummy_tick_2 & 0x80000000) != 0) {
                // NEW DUMMY LOGIC HERE (Category B, at least 15 lines)
                ...
            }

            // --- ORIGINAL CODE STATEMENT CONTINUES ---
            original_statement_3;

            // --- INSERTED DEAD BRANCH 3 (ADDITIVE ONLY) ---
            if (GetPriorityClass(GetCurrentProcess()) == 0xFFFFFFFF) {
                // NEW DUMMY LOGIC HERE (Category C, at least 15 lines)
                ...
            }

            INPUT CODE:
            {c_code}

            Return ONLY the complete, modified source code inside a single markdown code block.
            Use ```c or ```cpp according to the detected input language.
            """
        return self.call_llm(prompt, c_code, base_name, "junk_code")


    def apply_string_encryption(self, c_code, base_name="unknown"):
        """Encrypt string literals and add global runtime decryption helper functions."""
        prompt = f"""
            You are an expert C developer generating synthesized code variants.
            Target Architecture: {self.arch}
            Compiler: Microsoft Visual Studio (MSVC)

            ### STRICT COMPILATION & LOGIC RULES
            1. USE HELPER FUNCTIONS: Do not use inline decryption loops. You must write dedicated encryption/decryption helper functions ABOVE the main function (or at the global scope).
            2. PRESERVE EXECUTION FLOW: The decrypted string at runtime MUST exactly match the original string literal. Do not change the underlying logic of the host application.
            3. OBFUSCATE STRINGS: The LLM must statically encrypt the plaintext strings. Replace original string literals in the target code with these encrypted byte arrays.
            4. CALL THE HELPER: Wherever the original string was used, pass your encrypted byte array to your decryption helper function before use.
            5. ISOLATED NAMING: Use randomized or inconspicuous variable names for local buffers, keys, and the helper functions themselves (e.g., `init_data_buffer`, `transform_buffer`) to avoid obvious "decrypt" signatures. 
            6. DETERMINISTIC KEYING: Implement a reliable cipher in your helper function (e.g., XOR, simple substitution, or custom rolling key).

            ### STRUCTURAL PATTERN TO FOLLOW:
            Do not use this exact code, but follow this structural layout for every string you replace:

            ```c
            #include <string.h>

            // --- HELPER FUNCTIONS DECLARED ABOVE MAIN ---
            void transform_string_helper(unsigned char* buffer, size_t len, unsigned char key) {{
                for (size_t i = 0; i < len; i++) {{
                    buffer[i] ^= key;
                }}
            }}

            // ... other code ...

            void some_function() {{
                // --- ORIGINAL CODE STATEMENT ---
                // CreateFileA("C:\\secret.txt", ...);

                // --- TRANSFORMED CODE ---
                unsigned char enc_str_1[] = {{ 0x01, 0x18, 0x11, 0x17, 0x07, 0x06, 0x4c, 0x16, 0x1a, 0x16, 0x5e, 0x00 }};
                transform_string_helper(enc_str_1, sizeof(enc_str_1) - 1, 0x42);
                
                CreateFileA((char*)enc_str_1, ...);
                memset(enc_str_1, 0, sizeof(enc_str_1)); // Cleanup immediately after use
            }}
            ```

            ### TASK
            Identify all string literals in the C function below. Generate the necessary decryption helper functions at the global scope. Replace each string literal with an encrypted stack-buffer setup, a call to your decryption helper, and cleanup exactly as shown in the structural pattern. Ensure necessary headers (`<string.h>`) are present.

            ### INPUT CODE:

            {c_code}

            Return ONLY the complete, modified C source code inside a single markdown code block (`c ... `).
            """
        return self.call_llm(prompt, c_code, base_name, "string_encryption")

#improved
    def apply_api_call_substitution(self, c_code, base_name="unknown"):
        """Replace common Windows API calls with alternative NT API calls."""
        prompt = f"""
            You are an expert C developer generating synthesized code variants.
            Target Architecture: {self.arch}
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
            Inline the necessary NT structures as local definitions, e.g.:
            - `OBJECT_ATTRIBUTES`
            - `CLIENT_ID`
            - `UNICODE_STRING`
            - `NTSTATUS`
            Keep all definitions inside the function to avoid conflicts.

            6. BEHAVIOR PRESERVATION:
            The transformed code must have the same external behavior, return values, error handling, and control flow as the original. For NTSTATUS success checks, use `if (status == 0)` for `STATUS_SUCCESS`.
            If the original call fails, set the resulting HANDLE/pointer to an appropriate error value (`NULL`, `INVALID_HANDLE_VALUE`, etc.) to mimic the original behavior.

            7. ADDITIVE-ONLY:
            Do NOT remove or modify existing code that is not being substituted. If an API is unsupported, leave the original call exactly as is.

            ### STRUCTURAL PATTERN TO FOLLOW
            For a call to `OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid)`:

            ```c
            // --- TRANSFORMED CODE ---
            HANDLE dummy_hProcess = NULL;
            HMODULE dummy_ntdll = GetModuleHandleA("ntdll.dll");
            if (dummy_ntdll) {{
                typedef NTSTATUS(WINAPI* PNT_OPEN_PROCESS)(PHANDLE, ACCESS_MASK, PVOID, PVOID);
                PNT_OPEN_PROCESS dummy_NtOpenProcess = (PNT_OPEN_PROCESS)GetProcAddress(dummy_ntdll, "NtOpenProcess");
                if (dummy_NtOpenProcess) {{
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

                    NTSTATUS dummy_status = dummy_NtOpenProcess(&dummy_hProcess, PROCESS_ALL_ACCESS, &dummy_oa, &dummy_cid);
                    if (dummy_status != 0) dummy_hProcess = NULL;
                }}
            }}

        ### EXAMPLE OF UNSUPPORTED API (DO NOT REPLACE)
            Original:

            ```
            HANDLE snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            This must be left unchanged because no NT equivalent exists.
            ```

            INPUT CODE:
            {c_code}

            Return ONLY the complete, modified C source code inside a single markdown code block (c ...).
            """
        return self.call_llm(prompt, c_code, base_name, "api_call_substitution")

    def apply_anti_debugging(self, c_code,base_name="unknown"):
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
        return self.call_llm(prompt, c_code,base_name, "control_flow_Obfuscation")
    
    def apply_anti_disassembly(self, c_code,base_name="unknown"):
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
        return self.call_llm(prompt, c_code,base_name, "anti_disassembly")

    # I put it here just in case, a method to apply a list of techniques sequentially
    def apply_all_techniques(self, c_code, techniques=None, base_name="unknown"):
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
                code = method(code, base_name=base_name)
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
                modified_code = self.apply_all_techniques(code, techniques=techniques, base_name=base_name)
                with open(dest_path, 'w', encoding='utf-8') as f:
                    f.write(modified_code)
            else:
                # Pass through non-selected functions unchanged to maintain compilation integrity
                with open(dest_path, 'w', encoding='utf-8') as f:
                    f.write(code)