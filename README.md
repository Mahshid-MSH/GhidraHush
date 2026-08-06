```markdown
# GhidraDeforger

```
                                                                                                                             
              ,,          ,,        ,,                                            ,...                                       
  .g8"""bgd `7MM          db      `7MM                   `7MM"""Yb.             .d' ""                                       
.dP'     `M   MM                    MM                     MM    `Yb.           dM`                                          
dM'       `   MMpMMMb.  `7MM   ,M""bMM  `7Mb,od8 ,6"Yb.    MM     `Mb  .gP"Ya  mMMmm,pW"Wq.`7Mb,od8 .P"Ybmmm .gP"Ya `7Mb,od8 
MM            MM    MM    MM ,AP    MM    MM' "'8)   MM    MM      MM ,M'   Yb  MM 6W'   `Wb MM' "':MI  I8  ,M'   Yb  MM' "' 
MM.    `7MMF' MM    MM    MM 8MI    MM    MM     ,pm9MM    MM     ,MP 8M""""""  MM 8M     M8 MM     WmmmP"  8M""""""  MM     
`Mb.     MM   MM    MM    MM `Mb    MM    MM    8M   MM    MM    ,dP' YM.    ,  MM YA.   ,A9 MM    8M       YM.    ,  MM     
  `"bmmmdPY .JMML  JMML..JMML.`Wbmd"MML..JMML.  `Moo9^Yo..JMMmmmdP'    `Mbmmd'.JMML.`Ybmd9'.JMML.   YMMMMMb  `Mbmmd'.JMML.   
                                                                                                   6'     dP                 
                                                                                                   Ybmmmd'                   
```

GhidraDeforger is an automated binary reverse engineering and orchestration toolchain. Designed for security researchers, it leverages the Ghidra decompiler API and Large Language Models (LLMs) to automatically extract, refactor, patch, and recompile C code. This creates a powerful framework for malware analysis, threat hunting, and executing structural mutation and robustness testing on compiled binaries.

## 🏗️ Project Architecture

The repository is structured to cleanly separate orchestration infrastructure from application logic:

* **`/` (Root):** Contains all infrastructure and configuration (`docker-compose.yaml`[cite: 1], `Dockerfile`[cite: 2], `.env`, and `GhidraReforger.sh`[cite: 3]).
* **`src/`:** Contains the core Python toolchain, including the LLM agents, compiler orchestrators, and Ghidra Python scripts[cite: 4].
* **`workspace/`:** A dynamically generated I/O directory (ignored by version control) where target binaries are copied, analyzed, and recompiled into isolated `run_X` folders[cite: 3].

## 🛠️ Prerequisites

Ensure you have the following installed on your host system:
* [Docker](https://docs.docker.com/get-docker/)
* [Docker Compose](https://docs.docker.com/compose/install/)

## 🚀 First-Time Setup

Before running the pipeline for the first time, you must build the environment and pull the required LLM into the Ollama service.

1. **Start the containers in detached mode:**

```bash
   docker compose up -d
```

2. **Pull the LLM model into Ollama:**
*Note: Do this only the first time you want to use the program or if you need to update the model.*
```bash
docker compose exec ollama ollama run [the LLM of your choice]

```

3. **Verify the application container builds successfully (Optional):**
```bash
docker compose run --rm app

```

## 💻 Usage

The entire pipeline is controlled via an interactive Bash wrapper that handles workspace allocation, environment variable tracking, and Docker execution.

1. **Launch the interactive menu:**
```bash
./GhidraReforger.sh

```

2. **Provide the target executable:**
When prompted, provide the absolute or relative path to the `.exe` you want to decompile and mutate. The script will automatically allocate a new `workspace/run_X/` directory and copy the binary into it.


3. **Select a pipeline stage:**
You can run the pipeline sequentially from the beginning, or resume from any specific stage. The script tracks your progress via a `.env` file.



## ⚙️ Pipeline Stages

The orchestration pipeline (`src/entry.py`) consists of 8 distinct phases:

1. **Extract functions from binary (Ghidra):** Automates the Ghidra headless analyzer to dump target functions.


2. **Extract global variables & data (Ghidra):** Extracts `.data` and `.bss` segments for state preservation.


3. **Beautify & refactor extracted C code (LLM):** Prompts the LLM agent to clean up decompiled pseudocode into standard C syntax.


4. **Resolve & add missing global declarations:** Stitches dependencies back into the refactored code.


5. **Generate main wrapper script:** Generates a dynamic `main.c` wrapper for execution.


6. **Compile LLM_globals.c & main.c:** Uses `i686-w64-mingw32-gcc` to compile the baseline object files.


7. **Agentic compilation loop & patching (LLM):** An autonomous LLM-driven loop that attempts to compile the refactored functions, reads GCC error logs, and patches the source code until compilation succeeds.


8. **Link output objects into final executable:** Links all generated `.o` files into the final `binary_reconstructed.exe`.



## 📝 Notes

* Any changes made to Python files inside `src/` are instantly reflected in the container via volume mounts. You do not need to rebuild the Docker image when modifying application logic.


* You only need to run `docker compose build` if you modify system-level dependencies in the `Dockerfile` or `requirements.txt`.

