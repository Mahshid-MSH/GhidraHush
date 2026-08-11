#!/bin/bash

# --- Pin Working Directory ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

# --- Configuration ---
COMPOSE_FILE="docker-compose.yaml"
ENV_FILE=".env"
WORKSPACE_BASE_DIR="workspace"
WORKSPACE_PREFIX="run"

# --- Colors ---
CYAN='\033[96m'
GREEN='\033[92m'
YELLOW='\033[93m'
RED='\033[91m'
RESET='\033[0m'
BOLD='\033[1m'
DIM='\033[2m'



if [[ ! -f "$COMPOSE_FILE" ]]; then
    echo -e "${RED}${BOLD}Error:${RESET} ${RED}'$COMPOSE_FILE' not found.${RESET}"
    exit 1
fi

update_env_var() {
    local key="$1"
    local value="$2"
    
    if [ ! -f "$ENV_FILE" ]; then
        touch "$ENV_FILE"
    fi

    if grep -q "^${key}=" "$ENV_FILE"; then
        sed -i "s|^${key}=.*|${key}='${value}'|" "$ENV_FILE"
    else
        echo "${key}='${value}'" >> "$ENV_FILE"
    fi
}

# --- Read Completed Stage from .env ---
check_stage() {
    local stage="$1"
    
    local completed
    completed=$(grep "^LAST_COMPLETED_STAGE=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2 | tr -d "'\"")
    completed=${completed:-0}

    if [ "$stage" -le "$completed" ]; then
        return 0
    else
        return 1
    fi
}

get_or_create_workspace() {
    mkdir -p "$WORKSPACE_BASE_DIR"
    
    local target_path="${WORKSPACE_BASE_DIR}/${WORKSPACE_PREFIX}"
    if [[ ! -d "$target_path" ]]; then
        mkdir -p "$target_path"
        echo "$target_path"
        return
    fi

    local counter=1
    while true; do
        target_path="${WORKSPACE_BASE_DIR}/${WORKSPACE_PREFIX}_${counter}"
        if [[ ! -d "$target_path" ]]; then
            mkdir -p "$target_path"
            echo "$target_path"
            return
        fi
        ((counter++))
    done
}

show_banner() {
    cat << "EOF" 
  ______   __        __        __                     __    __                      __       
 /      \ |  \      |  \      |  \                   |  \  |  \                    |  \      
|  $$$$$$\| $$____   \$$  ____| $$  ______   ______  | $$  | $$ __    __   _______ | $$____  
| $$ __\$$| $$    \ |  \ /      $$ /      \ |      \ | $$__| $$|  \  |  \ /       \| $$    \ 
| $$|    \| $$$$$$$\| $$|  $$$$$$$|  $$$$$$\ \$$$$$$\| $$    $$| $$  | $$|  $$$$$$$| $$$$$$$\
| $$ \$$$$| $$  | $$| $$| $$  | $$| $$   \$$/      $$| $$$$$$$$| $$  | $$ \$$    \ | $$  | $$
| $$__| $$| $$  | $$| $$| $$__| $$| $$     |  $$$$$$$| $$  | $$| $$__/ $$ _\$$$$$$\| $$  | $$
 \$$    $$| $$  | $$| $$ \$$    $$| $$      \$$    $$| $$  | $$ \$$    $$|       $$| $$  | $$
  \$$$$$$  \$$   \$$ \$$  \$$$$$$$ \$$       \$$$$$$$ \$$   \$$  \$$$$$$  \$$$$$$$  \$$   \$$
                                                                                             
                                                                                             
                                                                                                               
EOF
}
show_menu() {
    local ws="$1"
    echo -e "\n${CYAN}============================================================${RESET}"
    echo -e "${BOLD} PIPELINE CONTROL MENU | Workspace: $(basename "$ws")${RESET}"
    echo -e "${CYAN}============================================================${RESET}"
    
    declare -A desc
    desc[1]="Extract functions from binary (Ghidra)"
    desc[2]="Extract global variables & data (Ghidra)"
    desc[3]="Beautify & refactor extracted C code (LLM)"
    desc[4]="Resolve & add missing global declarations"
    desc[5]="Generate main wrapper script"
    desc[6]="Apply defensive evasion techniques"
    desc[7]="Compile LLM_globals.c & main.c"
    desc[8]="Agentic compilation loop & patching (LLM)"
    desc[9]="Link output objects into final executable"
    desc[10]="Verify behavioral equivalence against original binary"

    # Updated to loop up to 10
    for stage in {1..10}; do
        if check_stage "$stage"; then
            status="${GREEN}[✓]${RESET}"
        else
            status="${DIM}[ ]${RESET}"
        fi
        printf "  ${CYAN}%d.${RESET} %b %s\n" "$stage" "$status" "${desc[$stage]}"
    done
    echo -e "  ${CYAN}0.${RESET} ${RED}Exit${RESET}"
    echo -e "${CYAN}------------------------------------------------------------${RESET}"
}

show_banner

read -p "$(echo -e "${YELLOW}Please enter the path to the exe: ${RESET}")" raw_input_exe
if [[ -z "$raw_input_exe" ]]; then
    echo -e "${RED}${BOLD}Error:${RESET} ${RED}No executable path provided.${RESET}"
    exit 1
fi

raw_input_exe=$(realpath "$raw_input_exe" 2>/dev/null || echo "$raw_input_exe")

if [[ ! -f "$raw_input_exe" ]]; then
    echo -e "${RED}${BOLD}Error:${RESET} ${RED}Specified executable '$raw_input_exe' does not exist.${RESET}"
    exit 1
fi

workspace_dir=$(get_or_create_workspace)
echo -e "${GREEN}Allocated workspace: ${BOLD}${workspace_dir}${RESET}"

# Copy target binary into workspace
target_exe_name=$(basename "$raw_input_exe")
copied_exe_path="${workspace_dir}/${target_exe_name}"
cp "$raw_input_exe" "$copied_exe_path"
echo -e "${GREEN}Copied executable into workspace: ${BOLD}${copied_exe_path}${RESET}"

update_env_var "INPUT_EXE_PATH" "$copied_exe_path"
update_env_var "LAST_COMPLETED_STAGE" "0"

while true; do
    show_menu "$workspace_dir"
    
    read -p "$(echo -e "${YELLOW}${BOLD}Select stage to start/resume from (0-10): ${RESET}")" choice
    
    if [[ "$choice" == "0" ]]; then
        echo -e "${RED}Exiting pipeline.${RESET}"
        exit 0
    fi
    
    if [[ "$choice" =~ ^([1-9]|10)$ ]]; then
        echo -e "${GREEN}Starting pipeline from stage $choice inside Docker...${RESET}"
        
        # --- Handle Dynamic Evasion Selection for Stage 6 ---
        EVASION_ENV=""
        if [[ "$choice" == "6" ]]; then
            echo -e "\n${YELLOW}${BOLD}Available Evasion Techniques:${RESET}"
            echo -e "  1. Junk Code Insertion"
            echo -e "  2. String Encryption"
            echo -e "  3. API Call Substitution"
            echo -e "  4. Anti-Debugging"
            echo -e "  5. Control Flow Obfuscation"
            echo -e "  6. Anti-Disassembly"
            echo -e "${CYAN}Enter the numbers of the techniques to apply, separated by commas (e.g., 1,2,4): ${RESET}\c"
            read -r tech_choices
            
            TECH_NAMES=()
            for opt in $(echo "$tech_choices" | tr "," "\n" | tr -d ' '); do
                case $opt in
                    1) TECH_NAMES+=("junk_code_insertion") ;;
                    2) TECH_NAMES+=("string_encryption") ;;
                    3) TECH_NAMES+=("api_call_substitution") ;;
                    4) TECH_NAMES+=("anti_debugging") ;;
                    5) TECH_NAMES+=("control_flow_obfuscation") ;;
                    6) TECH_NAMES+=("anti_disassembly") ;;
                    *) echo -e "${RED}Warning: Ignored invalid option '$opt'${RESET}" ;;
                esac
            done
            
            # Join the array into a comma-separated string for the env var
            EVASION_ENV=$(IFS=, ; echo "${TECH_NAMES[*]}")
            
            if [[ -z "$EVASION_ENV" ]]; then
                echo -e "${RED}No valid techniques selected. Aborting Stage 6.${RESET}"
                continue
            fi
        fi
        # Pass the EVASION_TECHNIQUES via environment variable to Docker
        docker compose -f "$COMPOSE_FILE" run --rm -e EVASION_TECHNIQUES="$EVASION_ENV" app python3 ./src/entry.py \
            --stage "$choice" \
            --workspace "$workspace_dir" \
            --exe "$copied_exe_path"
        
        if [ $? -ne 0 ]; then
            echo -e "\n${RED}${BOLD}Pipeline halted due to an error. Check the logs above.${RESET}"
        fi
    else
        echo -e "${RED}Invalid option. Please enter a number between 0 and 10.${RESET}"
    fi
done