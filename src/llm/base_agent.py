import os
import re
import time
import json
import openai
from openai import OpenAI


class BaseLLMAgent:
    """
    Core LLM Orchestration Wrapper.
    
    Why this exists: When building an automated pipeline that talks to LLMs 
    (like DeepSeek, local Ollama, Groq, or vLLM), we need a robust layer that 
    handles rate-limiting, network failures, empty responses, and context-window 
    configurations invisibly. This class abstracts away those API quirks so the 
    rest of our codebase can just say "process this prompt" and reliably get code back.
    """

    # Default context window. Hardcoded to 16k because local models (like Ollama) 
    # often default to 4k if VRAM is low. This silently truncates large Ghidra 
    # decompilation inputs, leading to broken outputs. Forcing 16k prevents this.
    DEFAULT_NUM_CTX = 16384
    BASE_AGENT_VERSION = "v3-numctx-16384"

    def __init__(self, model_name=None, base_url=None, delay_between_requests=0):
        """
        Initializes the API client with graceful fallbacks.
        
        Why it's here: Allows the tool to seamlessly switch between local inference 
        (e.g., Ollama at localhost:11434) and cloud APIs (DeepSeek) using environment 
        variables, without changing the source code.
        """
        self.base_url = (base_url
                         or os.environ.get("LLM_BASE_URL")
                         or os.environ.get("DEEPSEEK_BASE_URL")
                         or "https://api.deepseek.com")
        self.model_name = (model_name
                           or os.environ.get("LLM_MODEL", "deepseek-chat"))
        self.api_key = (os.environ.get("LLM_API_KEY")
                        or os.environ.get("DEEPSEEK_API_KEY")
                        or "unused")
        
        # Pacing prevents rate-limit bans when processing hundreds of functions.
        self.delay_between_requests = (
            delay_between_requests
            if delay_between_requests is not None
            else float(os.environ.get("LLM_PACING_SECONDS", "2")))
            
        self.client = OpenAI(base_url=self.base_url, api_key=self.api_key)
        print(f"Connected to {self.base_url} using model {self.model_name} "
              f"[base_agent {self.BASE_AGENT_VERSION}, num_ctx={self.DEFAULT_NUM_CTX}]")

    def extract_raw_c_code(self, llm_output, original_code):
        """
        Strips conversational "fluff" from the LLM response to isolate the C code.
        
        Why it's here: LLMs often wrap code in Markdown (```c ... ```) or add 
        sentences like "Here is the refactored code:". This breaks automated 
        compilation. This regex hunts down the actual code block. If it fails, 
        it falls back to the original Ghidra code so the pipeline doesn't crash.
        """
        # Attempt 1: Look for Markdown code fences
        match = re.search(r"```[a-zA-Z]*\s*\n(.*?)```", llm_output, re.DOTALL)
        if match:
            return match.group(1).strip()
            
        # Attempt 2: Heuristic check for raw C code without markdown fences
        if any(k in llm_output for k in ["#include", "void", "int", "struct"]):
            return llm_output.strip()
            
        # Fallback: Return original code to ensure pipeline continuity
        return original_code

    def _completion_kwargs(self, prompt, temperature, options):
        """
        Constructs the payload sent to the OpenAI-compatible API.
        
        Why it's here: Standard OpenAI endpoints only expect standard arguments. 
        However, local runners like Ollama require specific hardware/inference 
        tweaks (like `num_ctx`, `seed`, `repeat_penalty`). The `extra_body` field 
        allows us to sneak these custom parameters through the official OpenAI SDK 
        without it throwing validation errors.
        """
        opts = options or {}
        kw = {
            "model": self.model_name,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature,
        }
        
        # Force num_ctx to prevent silent truncation on Ollama
        extra = {
            "num_ctx": int(opts.get("num_ctx") or self.DEFAULT_NUM_CTX),
        }
        
        # Safely map optional inference parameters
        if opts.get("num_predict"):
            extra["num_predict"] = int(opts["num_predict"])
        if opts.get("seed") is not None:
            extra["seed"] = int(opts["seed"])
        if opts.get("top_k"):
            extra["top_k"] = int(opts["top_k"])
        if opts.get("repeat_penalty"):
            extra["repeat_penalty"] = float(opts["repeat_penalty"])
        if opts.get("top_p"):
            extra["top_p"] = float(opts["top_p"])
            
        kw["extra_body"] = extra
        return kw

    def stream_prompt(self, prompt, options=None, max_retries=5):
        """
        Executes the LLM request with heavy fault tolerance and exponential backoff.
        
        Why it's here: Network calls fail, APIs get overloaded, and sometimes LLMs 
        just return empty responses. This method wraps the actual API call in a 
        retry loop. If streaming fails (common with some proxy servers), it 
        automatically attempts a fallback non-streaming request.
        """
        options = options or {}
        temperature = options.get("temperature", 0)

        for attempt in range(max_retries):
            try:
                result, finish = self._stream_once(prompt, temperature, options)

                # Empty responses are treated as failures
                if not result.strip():
                    print(f"\n[LLM] EMPTY response (attempt {attempt + 1}/"
                          f"{max_retries}, finish_reason={finish})")
                    
                    # Fallback for proxies that break Server-Sent Events (SSE) streaming
                    if attempt >= 1:          
                        try:
                            result, finish = self._nonstream_once(
                                prompt, temperature, options)
                            if result.strip():
                                print("[LLM] non-streaming fallback succeeded")
                                break
                        except Exception:
                            pass
                    time.sleep(min(2 ** attempt, 30)) # Exponential backoff
                    continue

                if self.delay_between_requests > 0:
                    time.sleep(self.delay_between_requests)
                    
                # Save metadata for auditing
                self._last_meta = {"finish_reason": finish,
                                   "attempts": attempt + 1,
                                   "response_chars": len(result)}
                return result

            except (openai.RateLimitError, openai.APIConnectionError,
                    openai.InternalServerError) as e:
                wait_time = (2 ** attempt) + 1
                print(f"\nAPI error: {e}. Retrying in {wait_time}s "
                      f"(attempt {attempt+1}/{max_retries})...")
                time.sleep(wait_time)

        raise RuntimeError(
            f"LLM returned no usable content after {max_retries} attempts "
            f"(model={self.model_name}, base_url={self.base_url}). "
            f"Check llm_logs/ META sections and provider account/quota.")

    def _stream_once(self, prompt, temperature, options=None):
        """
        Makes a single streaming API request, yielding tokens as they arrive.
        Why it's here: Streaming prevents connection timeouts on massive generations.
        """
        resp = self.client.chat.completions.create(
            **self._completion_kwargs(prompt, temperature, options),
            stream=True)
        result, finish = "", None
        for chunk in resp:
            if not chunk.choices:
                continue
            content = getattr(chunk.choices[0].delta, "content", None)
            if content:
                result += content
            if chunk.choices[0].finish_reason:
                finish = chunk.choices[0].finish_reason
        return result, finish

    def _nonstream_once(self, prompt, temperature, options=None):
        """
        Makes a standard blocking API request. 
        Why it's here: Used exclusively as a fallback if the streaming API is broken.
        """
        resp = self.client.chat.completions.create(
            **self._completion_kwargs(prompt, temperature, options),
            stream=False)
        return (resp.choices[0].message.content or ""), resp.choices[0].finish_reason

    def process_llm_task(self, prompt, original_code, workspace_dir, log_prefix,
                         base_name, options=None):
        """
        High-level orchestrator that runs the prompt, logs the result, and extracts the code.
        
        Why it's here: When debugging LLM prompt engineering, you MUST know exactly 
        what you sent to the model and exactly what it sent back before the regex 
        stripped it. This function ensures every single LLM interaction is saved to disk 
        (`llm_logs/`) alongside its metadata, providing a perfect audit trail.
        """
        response = self.stream_prompt(prompt, options=options)
        
        # Ensure log directory exists
        log_dir = os.path.join(workspace_dir, "llm_logs")
        os.makedirs(log_dir, exist_ok=True)
        
        # Write audit log
        log_file = os.path.join(log_dir, f"{log_prefix}_{base_name}.log")
        with open(log_file, "w", encoding="utf-8") as f:
            f.write(f"=== META ===\n{json.dumps(getattr(self, '_last_meta', {}), indent=2)}\n\n")
            f.write(f"=== PROMPT ({len(prompt)} chars) ===\n{prompt}\n\n")
            f.write(f"=== RESPONSE ({len(response)} chars) ===\n{response}\n")
            
        # Return only the actionable code
        return self.extract_raw_c_code(response, original_code)