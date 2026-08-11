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
    def __init__(self, model_name=None, base_url=None):
        self.base_url = base_url or os.environ.get('OLLAMA_HOST', 'http://ollama:11434')
        self.model_name = model_name or os.environ.get('LLM_MODEL', 'deepseek-coder-v2')
        self.client = Client(host=self.base_url)
        print(f"DefensiveEvasion initialized with {self.model_name} at {self.base_url}")

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
            You are a red‑team developer crafting stealthy C code that must pass static analysis.  
            The code will be compiled with **Microsoft Visual Studio (MSVC)**. Use MSVC-compatible syntax.  
            Insert **junk code** into the function below using realistic-looking dead logic.  
            Requirements:
                - Use **opaque predicates** that always evaluate to TRUE or FALSE but are hard to statically determine, e.g., based on `__rdtsc()`, a CPUID leaf, or a PEB field that is always set.
                - Emit **fake Windows API calls** that are never executed because the predicate jumps over them, e.g., `CreateFileW`, `RegOpenKeyExW` inside an always‑false branch.  
                - Include **dummy error handling** blocks (like calls to `SetLastError` or `FormatMessage`) that are unreachable but look plausible.  
                - Do NOT use trivial operations such as `int x = 1+1;` or simple constant comparisons.
                - The function’s original behaviour and side effects must be unchanged.
                - Avoid adding large static arrays or loops that would inflame size‑based heuristics.

            CRITICAL RULE: Every variable, buffer, handle, or pointer you reference MUST be declared 
                and initialized before use. Do NOT use variables that aren't declared in the current scope.
                If you add junk code that references API functions, you MUST:
                1. Declare all variables at the top of the function or block
                2. Initialize them appropriately (even if the code path is never executed)
                3. #include any required headers for types like HKEY, LPVOID, etc.
                Never reference undeclared variables like 'buffer', 'lpMsgBuf', or 'lpBuffer' without 
                first declaring them with proper types.
            Additionally, if you introduce any **new helper functions** (e.g., custom predicates), their complete definition must appear **before** they are first called.

            ### INPUT CODE:
            {c_code}

            Return only the modified C code in a markdown code block.
        """
        return self.call_llm(prompt, c_code)

    def apply_string_encryption(self, c_code):
        """Encrypt/obfuscate string literals and add runtime decryption."""
        prompt = f"""
        You are a red‑team developer writing production evasion code.  
        The code will be compiled with **Microsoft Visual Studio (MSVC)**. Use MSVC-compatible syntax.  
        Obfuscate **all string literals** in the given function by encrypting them at compile time and decrypting at runtime.  
        Detailed requirements:
        - Use a **randomised algorithm**: choose between XOR‑ADD‑ROL chaining, a 32‑bit LCG‑based stream cipher, or a tiny RC4 implemented inline. Do NOT use a single static XOR key.
        - Derive the decryption key from a **dynamic value** available at runtime, e.g., the low 32 bits of the tick count (`GetTickCount()`) XORed with a constant, so the key changes every execution.
        - Store the encrypted strings as `unsigned char[]` arrays.  
        - Add an inline `decrypt_string(char *buf, size_t len, DWORD key)` function that performs the reverse operations.
        - **Define the full implementation of `decrypt_string` before it is first called** – do not only declare it.
        - Replace every original string literal with a call to `decrypt_string` before use.
        - Ensure the decrypted buffer is cleaned immediately after use to avoid memory‑forensics artefacts (you may overwrite it with zeros).
        - Do NOT call `malloc` – use stack buffers.

        ### INPUT CODE:
        {c_code}

        Return only the modified C code in a markdown code block.
        """
        return self.call_llm(prompt, c_code)

    def apply_api_call_substitution(self, c_code):
        """Replace common Windows API calls with alternative (e.g., syscall or NT API)."""
        prompt = f"""
        You are a red‑team developer implementing a Windows implant that must evade EDR user‑land hooks.  
        The code will be compiled with **Microsoft Visual Studio (MSVC)**. Use MSVC-compatible syntax.  
        Replace **every high‑level API call** (e.g., `VirtualAlloc`, `WriteFile`, `CreateThread`) with a **direct syscall**.  
        Implementation details:
        - Write an inline assembly syscall stub that sets `eax` to the SSN, sets `r10` (x64) appropriately, and issues `syscall`. On x86, use `int 0x2E` or `sysenter`. For MSVC, use `__asm` blocks on x86 only; for x64 use a separate .asm file or a wrapper that invokes a syscall stub via a manually crafted jump (e.g., using `_syscall` intrinsic if available). Adapt to what MSVC supports.
        - Retrieve the SSN **dynamically** from a clean ntdll.dll mapped from disk (Hell’s Gate / Halos Gate technique). Briefly explain the resolution in code comments.  
        - If you cannot fit the full dynamic resolution, fall back to a **fixed SSN** but XOR it with a constant to avoid static signatures, and note that in a comment.
        - Adjust the function signature and error handling to match the NTSTATUS style.
        - If the original function uses a handle from a Win32 API, you may need to first obtain a handle via the corresponding NT path (e.g., `NtOpenProcess` instead of `OpenProcess`).
        - Ensure that stack alignment (16‑byte) is preserved before the syscall.
        - Any new functions you create (like a helper to resolve SSNs or a generic syscall stub) must be **completely defined before they are called**.

        ### INPUT CODE:
        {c_code}

        Return only the modified C code in a markdown code block.
        """
        return self.call_llm(prompt, c_code)

    def apply_anti_debugging(self, c_code):
        """Insert anti-debugging checks (e.g., IsDebuggerPresent, NtQueryInformationProcess)."""
        prompt = f"""
        You are a red‑team developer adding anti‑analysis safeguards to a function.  
        The code will be compiled with **Microsoft Visual Studio (MSVC)**. Use MSVC-compatible syntax.  
        Insert **multiple, varied anti‑debugging checks** that, if triggered, silently corrupt a critical variable rather than terminating (to mislead the analyst).  
        Include at least three of the following techniques, implemented in a way that is not trivially signatured:
        1. **PEB.BeingDebugged** – read it directly from the PEB via `__readfsdword(0x30) + 2` (x86) or `__readgsqword(0x60) + 2` (x64).  
        2. **NtGlobalFlag** – check for `0x70` mask at PEB+0x68 (32‑bit) or PEB+0xBC (64‑bit).  
        3. **Heap flags** – read `HeapFlags` and `ForceFlags` from the default process heap.  
        4. **Hardware breakpoint detection** – use `GetThreadContext` to check `Dr0`–`Dr3` registers.  
        5. **Timing check** – use `__rdtsc()` and `CPUID` to measure a small section and compare with expected time.  
        6. **OutputDebugString** trick – call `OutputDebugStringA` with a known string and then call `GetLastError`; if no error is set, a debugger is present.  

        On detection, do **not** call `ExitProcess`. Instead, modify an internal variable that will subtly alter the function’s behaviour later (e.g., change a flag so that subsequent decryption produces garbage).  
        Make the checks look like normal error‑handling code.  
        If you add any **helper functions** (e.g., a custom detection routine), provide their full definition before they are invoked.

        ### INPUT CODE:
        {c_code}

        Return only the modified C code in a markdown code block.
        """
        return self.call_llm(prompt, c_code)

    def apply_control_flow_Obfuscation(self, c_code):
        """Obfuscate control flow using opaque predicates and jump tables."""
        prompt = f"""
        You are a red‑team developer implementing **anti‑disassembly** tricks that break linear sweep and recursive disassemblers.  
        The code will be compiled with **Microsoft Visual Studio (MSVC)**. Use MSVC-compatible syntax.  
        Insert at least **three different techniques** into the function.  
        Use the following approaches, adapted for MSVC:
        1. **Opaque conditional jump** – use a predicate that is hard to determine statically (based on `__rdtsc()` or a PEB value) to create a conditional jump that always goes one way. The “dead” branch contains junk bytes or confusing instructions.
        2. **Overlapping instructions** – if targeting x86, you may use `__asm` blocks with `_emit` to craft overlapping instructions. For x64, simulate the effect with dummy `__noop()` sequences and misaligned labels that confuse linear disassemblers.
        3. **False return** – on x86, use `__asm` to push a fake return address and execute `ret`, but ensure the address points to the next real instruction. For x64, simulate with a call to a helper that adjusts the stack.
        4. **`EB FF` trick** – on x86, place a 2‑byte `jmp` that lands inside another instruction. On x64, mimic with `__nop()` sleds that look like other opcodes.
        5. **Insert junk prefixes** – use MSVC’s `__nop()`, `_emit(0x66)`, `_emit(0x67)`, etc., where applicable.

        Make sure the function still compiles and runs correctly, and that the tricks are commented in the source with `// anti‑disasm`.  
        Any introduced helper functions (e.g., a wrapper for `_emit`) must be fully defined before use.

        ### INPUT CODE:
        {c_code}

        Return only the modified C code in a markdown code block.
        """
        return self.call_llm(prompt, c_code)

    def apply_anti_disassembly(self, c_code):
        """Insert junk bytes or misalign instructions to confuse disassemblers."""
        prompt = f"""You are an expert in anti-disassembly techniques.
        The code will be compiled with **Microsoft Visual Studio (MSVC)**. Use MSVC-compatible syntax.
        Insert anti-disassembly tricks into the given C function. Use methods such as:
        - Inserting junk bytes via `__asm _emit 0x66` (x86) or `_emit` in a separate `__asm` block.
        - Using misaligned jumps or call instructions (x86 `__asm` with `jmp`, `call`).
        - Obfuscating immediate values with dummy arithmetic.
        - For x64, avoid architecture‑dependent inline assembly and instead use compiler intrinsics like `__noop()`, `__debugbreak()`, or opaque conditionals based on runtime checks.
        The function must still compile and execute correctly under MSVC.
        Any new function you add (e.g., a small wrapper for `_emit`) must be defined in full before it is used.

        ### INPUT CODE:
        {c_code}

        Return only the modified C code in a markdown code block.
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