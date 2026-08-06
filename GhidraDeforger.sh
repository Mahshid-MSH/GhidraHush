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
    desc[6]="Compile LLM_globals.c & main.c"
    desc[7]="Agentic compilation loop & patching (LLM)"
    desc[8]="Link output objects into final executable"

    for stage in {1..8}; do
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

# Ask for Executable Path
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

# Auto-Create Workspace
workspace_dir=$(get_or_create_workspace)
echo -e "${GREEN}Allocated workspace: ${BOLD}${workspace_dir}${RESET}"

# Copy target binary into workspace
target_exe_name=$(basename "$raw_input_exe")
copied_exe_path="${workspace_dir}/${target_exe_name}"
cp "$raw_input_exe" "$copied_exe_path"
echo -e "${GREEN}Copied executable into workspace: ${BOLD}${copied_exe_path}${RESET}"

# Update .env
update_env_var "INPUT_EXE_PATH" "$copied_exe_path"
update_env_var "LAST_COMPLETED_STAGE" "0"


while true; do
    show_menu "$workspace_dir"
    
    read -p "$(echo -e "${YELLOW}${BOLD}Select stage to start/resume from (0-8): ${RESET}")" choice
    
    if [[ "$choice" == "0" ]]; then
        echo -e "${RED}Exiting pipeline.${RESET}"
        exit 0
    fi
    
    if [[ "$choice" =~ ^[1-8]$ ]]; then
        echo -e "${GREEN}Starting pipeline from stage $choice inside Docker...${RESET}"
        
        docker compose -f "$COMPOSE_FILE" run --rm app python3 ./src/entry.py \
            --stage "$choice" \
            --workspace "$workspace_dir" \
            --exe "$copied_exe_path"
        
        if [ $? -ne 0 ]; then
            echo -e "\n${RED}${BOLD}Pipeline halted due to an error. Check the logs above.${RESET}"
        fi
    else
        echo -e "${RED}Invalid option. Please enter a number between 0 and 8.${RESET}"
    fi
done