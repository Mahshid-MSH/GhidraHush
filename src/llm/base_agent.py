import os
import re
from ollama import Client

class BaseLLMAgent:
    """Core class to handle LLM connections, streaming, and code extraction."""
    def __init__(self, model_name=None, base_url=None):
        self.base_url = base_url or os.environ.get('OLLAMA_HOST', 'http://ollama:11434')
        self.model_name = model_name or os.environ.get('LLM_MODEL', 'deepseek-coder-v2')
        self.client = Client(host=self.base_url)
        print(f"Connected to Ollama at {self.base_url} using {self.model_name}")

    def stream_prompt(self, prompt, options=None, format=None):
        """Standardized generator for LLM responses."""
        default_options = {'temperature': 0, 'num_ctx': 8192}
        if options:
            default_options.update(options)
            
        response = ""
        for chunk in self.client.generate(
            model=self.model_name, 
            prompt=prompt, 
            stream=True, 
            options=default_options,
            format=format
        ):
            response += chunk['response']
        return response

    def extract_raw_c_code(self, llm_output, original_code):
        """Standardized extraction logic."""
        match = re.search(r"```[a-zA-Z]*\s*\n(.*?)```", llm_output, re.DOTALL)
        if match:
            return match.group(1).strip()
        if "#include" in llm_output or "void" in llm_output or "int" in llm_output:
            return llm_output.strip()
        return original_code