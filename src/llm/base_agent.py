import os
import re
import time
import openai
from openai import OpenAI


class BaseLLMAgent:
    """Core class to handle DeepSeek connections, streaming, code extraction, and logging."""

    def __init__(self, model_name=None, base_url=None, delay_between_requests=40):
        # 1. Ensure the base URL includes the /v1 path required by the OpenAI-compatible router
        self.base_url = base_url or os.environ.get(
    "DEEPSEEK_BASE_URL", "https://api.deepseek.com"
        )
        
        # 2. Use a standard model name supported by the wrapper (e.g., "deepseek-chat")
        self.model_name = model_name or os.environ.get(
            "LLM_MODEL", "deepseek-chat"
        )
        
        # Local proxy handles session authentication via cookies, so api_key can be anything/unused
        self.api_key = os.environ.get("DEEPSEEK_API_KEY", "unused")
        
        # Pacing delay in seconds to prevent hitting RPM limits
        self.delay_between_requests = delay_between_requests

        self.client = OpenAI(
            base_url=self.base_url,
            api_key=self.api_key
        )

        print(
            f"Connected to DeepSeek API at {self.base_url} "
            f"using model {self.model_name}"
        )

    def stream_prompt(self, prompt, options=None, max_retries=5):
        """Send a prompt with retry backoff and rate-limit delay."""
        options = options or {}
        temperature = options.get("temperature", 0)

        for attempt in range(max_retries):
            try:
                response = self.client.chat.completions.create(
                    model=self.model_name,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=temperature,
                    stream=True
                )

                result = ""
                for chunk in response:
                    if chunk.choices and chunk.choices[0].delta.content:
                        result += chunk.choices[0].delta.content

                # Enforce pacing delay after successful request
                if self.delay_between_requests > 0:
                    time.sleep(self.delay_between_requests)

                return result

            except (openai.RateLimitError, openai.APIConnectionError, openai.InternalServerError) as e:
                wait_time = (2 ** attempt) + 1
                print(f"\nAPI Error/Rate Limit encountered: {e}. Retrying in {wait_time}s (Attempt {attempt+1}/{max_retries})...")
                time.sleep(wait_time)
            except Exception as e:
                print(f"\nUnexpected error: {e}")
                raise e

        raise RuntimeError("Exceeded maximum API retries due to rate limits or connection failures.")

    def extract_raw_c_code(self, llm_output, original_code):
        """Extract code enclosed in markdown backticks or return entire response if raw code."""
        match = re.search(r"```[a-zA-Z]*\s*\n(.*?)```", llm_output, re.DOTALL)
        if match:
            return match.group(1).strip()

        if any(keyword in llm_output for keyword in ["#include", "void", "int", "struct"]):
            return llm_output.strip()

        return original_code

    def process_llm_task(self, prompt, original_code, workspace_dir, log_prefix, base_name, options=None):
        """Run the prompt, log the response, and extract code."""
        response = self.stream_prompt(prompt, options=options)

        log_dir = os.path.join(workspace_dir, "llm_logs")
        os.makedirs(log_dir, exist_ok=True)

        log_file = os.path.join(log_dir, f"{log_prefix}_{base_name}.log")
        with open(log_file, "w", encoding="utf-8") as f:
            f.write(response)

        return self.extract_raw_c_code(response, original_code)