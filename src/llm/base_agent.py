import os
import re
import time
import json
import openai
from openai import OpenAI
import httpx 


class BaseLLMAgent:
    """
    Core LLM Orchestration Wrapper.
    """

    BASE_AGENT_VERSION = "v4-fixed-options"

    def __init__(self, model_name=None, base_url=None, delay_between_requests=100):
        """
        Initializes the API client with graceful fallbacks.
        Supports Groq, DeepSeek, Ollama, etc. via arguments or env vars.
        """
        self.base_url = (base_url or os.environ.get("LLM_BASE_URL"))
        
        self.model_name = (model_name or os.environ.get("LLM_MODEL"))
        
        self.api_key = (os.environ.get("LLM_API_KEY"))
        
        self.delay_between_requests = (
            delay_between_requests
            if delay_between_requests is not None
            else float(os.environ.get("LLM_PACING_SECONDS", "2")))
            
        self.client = OpenAI(base_url=self.base_url, api_key=self.api_key)
        print(f"Connected to {self.base_url} using model {self.model_name} "
              f"[base_agent {self.BASE_AGENT_VERSION}]")

    def extract_raw_c_code(self, llm_output, original_code):
        """Strips conversational markdown fences to isolate the C code."""
        match = re.search(r"```[a-zA-Z]*\s*\n(.*?)```", llm_output, re.DOTALL)
        if match:
            return match.group(1).strip()
            
        if any(k in llm_output for k in ["#include", "void", "int", "struct"]):
            return llm_output.strip()
            
        return original_code

    def _completion_kwargs(self, prompt, temperature, options):
        """
        Constructs the payload sent to the OpenAI-compatible API,
        properly respecting passed options (like max_tokens).
        """
        opts = options or {}
        kw = {
            "model": self.model_name,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature,
        }

        # Allow overriding max_tokens safely (defaulting to a safer 4096 for code)
        max_tokens = opts.get("max_tokens", 4096)
        if max_tokens:
            kw["max_tokens"] = max_tokens

        return kw

    def stream_prompt(self, prompt, options=None, max_retries=5):
        """Executes LLM request with fault tolerance and exponential backoff."""
        options = options or {}
        temperature = options.get("temperature", 0)

        for attempt in range(max_retries):
            try:
                result, finish = self._stream_once(prompt, temperature, options)

                if not result.strip():
                    print(f"\n[LLM] EMPTY response (attempt {attempt + 1}/"
                          f"{max_retries}, finish_reason={finish})")
                    
                    if attempt >= 1:          
                        try:
                            result, finish = self._nonstream_once(
                                prompt, temperature, options)
                            if result.strip():
                                print("[LLM] non-streaming fallback succeeded")
                                break
                        except Exception:
                            pass
                    time.sleep(min(2 ** attempt, 30))
                    continue

                if self.delay_between_requests > 0:
                    time.sleep(self.delay_between_requests)
                    
                self._last_meta = {"finish_reason": finish,
                                   "attempts": attempt + 1,
                                   "response_chars": len(result)}
                return result

            except (
                openai.RateLimitError,
                openai.APIConnectionError,
                openai.InternalServerError,
            ) as e:
                print(f"\n[LLM ERROR] {type(e).__name__}: {e}")
                wait_time = (2 ** attempt) + 1
                print(f"Retrying in {wait_time}s (attempt {attempt + 1}/{max_retries})...")
                time.sleep(wait_time)

        raise RuntimeError(
            f"LLM returned no usable content after {max_retries} attempts "
            f"(model={self.model_name}, base_url={self.base_url}).")

    def _stream_once(self, prompt, temperature, options=None):
        """Makes a single streaming API request."""
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
        """Makes a standard blocking API request as a fallback."""
        resp = self.client.chat.completions.create(
            **self._completion_kwargs(prompt, temperature, options),
            stream=False)
        return (resp.choices[0].message.content or ""), resp.choices[0].finish_reason

    def process_llm_task(self, prompt, original_code, workspace_dir, log_prefix,
                         base_name, options=None):
        """Orchestrator that runs prompt, logs result, and extracts code."""
        response = self.stream_prompt(prompt, options=options)
        
        log_dir = os.path.join(workspace_dir, "llm_logs")
        os.makedirs(log_dir, exist_ok=True)
        
        log_file = os.path.join(log_dir, f"{log_prefix}_{base_name}.log")
        with open(log_file, "w", encoding="utf-8") as f:
            f.write(f"=== META ===\n{json.dumps(getattr(self, '_last_meta', {}), indent=2)}\n\n")
            f.write(f"=== PROMPT ({len(prompt)} chars) ===\n{prompt}\n\n")
            f.write(f"=== RESPONSE ({len(response)} chars) ===\n{response}\n")
            
        return self.extract_raw_c_code(response, original_code)