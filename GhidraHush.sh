#!/bin/bash

# --- Pin Working Directory ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

# --- Configuration ---
COMPOSE_FILE="docker-compose.yaml"
ENV_FILE=".env"
WORKSPACE_BASE_DIR="workspace"

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

prompt_menu_choice() {
    local prompt="$1"
    local valid_choices="$2"
    local answer

    while true; do
        echo -e "$prompt"
        read -r -p "Choice: " answer
        answer="${answer//[[:space:]]/}"
        if [[ "$answer" =~ ^($valid_choices)$ ]]; then
            REPLY="$answer"
            return
        fi
        echo -e "${RED}Invalid choice. Try again.${RESET}"
    done
}

prompt_menu_choices() {
    local prompt="$1"
    local valid_choices="$2"
    local answer
    local choice
    local -A seen
    local -a choices
    local valid

    while true; do
        echo -e "$prompt"
        read -r -p "Choices (comma-separated): " answer
        answer="${answer//[[:space:]]/}"
        if [[ "$answer" =~ ^[0-9]+(,[0-9]+)*$ ]]; then
            REPLY_CHOICES=()
            seen=()
            valid=1
            IFS=',' read -r -a choices <<< "$answer"
            for choice in "${choices[@]}"; do
                if [[ ! "$choice" =~ ^($valid_choices)$ ]]; then
                    valid=0
                    break
                fi
                if [[ -z "${seen[$choice]+x}" ]]; then
                    REPLY_CHOICES+=("$choice")
                    seen[$choice]=1
                fi
            done
            if [[ "$valid" -eq 1 ]]; then
                return
            fi
        fi
        echo -e "${RED}Invalid choice list. Enter valid option numbers separated by commas.${RESET}"
    done
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
    desc[5]="Apply defensive evasion techniques"
    desc[6]="Evaluate fixed/generated binaries (CAPE / VT)"

    for stage in {1..6}; do
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
raw_input_exe="${raw_input_exe/#\~/$HOME}"
raw_input_exe=$(realpath "$raw_input_exe" 2>/dev/null || echo "$raw_input_exe")

if [[ ! -f "$raw_input_exe" ]]; then
    echo -e "${RED}${BOLD}Error:${RESET} ${RED}Specified executable '$raw_input_exe' does not exist.${RESET}"
    exit 1
fi
target_exe_name=$(basename "$raw_input_exe")
binary_base_name="${target_exe_name%.*}"
WORKSPACE_PREFIX="$binary_base_name"
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
    
    read -p "$(echo -e "${YELLOW}${BOLD}Select stage to start/resume from (0-6): ${RESET}")" choice
    
    if [[ "$choice" == "0" ]]; then
        echo -e "${RED}Exiting pipeline.${RESET}"
        exit 0
    fi
    
    if [[ "$choice" =~ ^[1-6]$ ]]; then
        echo -e "${GREEN}Starting pipeline from stage $choice inside Docker...${RESET}"
        
        # --- Handle Dynamic Evasion Selection for Stage 5 ---
        EVASION_ENV=""
        EVASION_PARAMS="{}"
        if [[ "$choice" == "5" ]]; then
            echo -e "\n${YELLOW}${BOLD}Available Evasion Techniques:${RESET}"
            echo -e "  1. Junk Code Insertion (Opaque Predicates)"
            echo -e "  2. Stack-String XOR Obfuscation (Volatile Arrays)"
            echo -e "  3. Variable Aliasing (Pointer-Indirection)"
            echo -e "  4. Control Flow Flattening (State Machines)"
            echo -e "  5. Local Context Struct Packaging"
            echo -e "${CYAN}Enter the numbers of the techniques to apply, separated by commas (e.g., 1,2,4): ${RESET}\c"
            read -r tech_choices
            
            TECH_NAMES=()
            for opt in $(echo "$tech_choices" | tr "," "\n" | tr -d ' '); do
                case $opt in
         1) TECH_NAMES+=("junk_code_insertion") ;;
         2) TECH_NAMES+=("stack_string_xor_obfuscation") ;;
         3) TECH_NAMES+=("aggressive_variable_aliasing") ;;
         4) TECH_NAMES+=("control_flow_obfuscation") ;;
         5) TECH_NAMES+=("local_context_struct_packaging") ;;
         *) echo -e "${RED}Warning: Ignored invalid option '$opt'${RESET}" ;;
	     esac
            done
            
            # Join selected techniques for the app and collect one configuration
            # for each technique selected.
            EVASION_ENV=$(IFS=, ; echo "${TECH_NAMES[*]}")
            
            if [[ -z "$EVASION_ENV" ]]; then
                echo -e "${RED}No valid techniques selected. Aborting Stage 5.${RESET}"
                continue
            fi

            EVASION_PARAMS_JSON=""
            for tech in "${TECH_NAMES[@]}"; do
                case "$tech" in
                    junk_code_insertion)
                        prompt_menu_choices "${CYAN}Junk-code density (choose one or more):\n  1. Sparse\n  2. Medium\n  3. Dense${RESET}" "1|2|3"
                        config='['
                        for density_choice in "${REPLY_CHOICES[@]}"; do
                            case "$density_choice" in
                                1) density="sparse" ;;
                                2) density="medium" ;;
                                3) density="dense" ;;
                            esac
                            [[ "$config" == '[' ]] || config+=','
                            config+="{\"density\":\"$density\"}"
                        done
                        config+=']'
                        ;;
                    stack_string_xor_obfuscation)
                        prompt_menu_choices "${CYAN}String coverage (choose one or more):\n  1. API/DLL names only\n  2. Sensitive strings\n  3. All strings${RESET}" "1|2|3"
                        coverage_choices=("${REPLY_CHOICES[@]}")
                        prompt_menu_choices "${CYAN}XOR key scheme (choose one or more):\n  1. Single-byte key\n  2. Rotating multi-byte key${RESET}" "1|2"
                        key_choices=("${REPLY_CHOICES[@]}")
                        config='['
                        for coverage_choice in "${coverage_choices[@]}"; do
                            case "$coverage_choice" in
                                1) coverage="api_names_only" ;;
                                2) coverage="sensitive_only" ;;
                                3) coverage="all" ;;
                            esac
                            for key_choice in "${key_choices[@]}"; do
                                case "$key_choice" in
                                    1) key_scheme="single_byte" ;;
                                    2) key_scheme="rotating" ;;
                                esac
                                [[ "$config" == '[' ]] || config+=','
                                config+="{\"coverage\":\"$coverage\",\"key_scheme\":\"$key_scheme\"}"
                            done
                        done
                        config+=']'
                        ;;
                    aggressive_variable_aliasing)
                        prompt_menu_choices "${CYAN}Variable-aliasing scope (choose one or more):\n  1. All eligible scalars\n  2. Loop counters only\n  3. Pointers only${RESET}" "1|2|3"
                        config='['
                        for scope_choice in "${REPLY_CHOICES[@]}"; do
                            case "$scope_choice" in
                                1) scope="all_scalars" ;;
                                2) scope="loop_counters_only" ;;
                                3) scope="pointers_only" ;;
                            esac
                            [[ "$config" == '[' ]] || config+=','
                            config+="{\"scope\":\"$scope\"}"
                        done
                        config+=']'
                        ;;
                    control_flow_obfuscation)
                        prompt_menu_choices "${CYAN}Control-flow strategy (choose one or more):\n  1. Goto-based flattening\n  2. Opaque jump${RESET}" "1|2"
                        config='['
                        for dispatch_choice in "${REPLY_CHOICES[@]}"; do
                            case "$dispatch_choice" in
                                1) dispatch="goto_flattening" ;;
                                2) dispatch="opaque_jump" ;;
                            esac
                            [[ "$config" == '[' ]] || config+=','
                            config+="{\"dispatch\":\"$dispatch\"}"
                        done
                        config+=']'
                        ;;
                    local_context_struct_packaging)
                        prompt_menu_choices "${CYAN}Struct field ordering (choose one or more):\n  1. Declaration order\n  2. Group by type\n  3. Access frequency${RESET}" "1|2|3"
                        config='['
                        for grouping_choice in "${REPLY_CHOICES[@]}"; do
                            case "$grouping_choice" in
                                1) grouping="by_declaration_order" ;;
                                2) grouping="by_type" ;;
                                3) grouping="by_access_frequency" ;;
                            esac
                            [[ "$config" == '[' ]] || config+=','
                            config+="{\"grouping\":\"$grouping\"}"
                        done
                        config+=']'
                        ;;
                esac
                if [[ -n "$EVASION_PARAMS_JSON" ]]; then
                    EVASION_PARAMS_JSON+=","
                fi
                EVASION_PARAMS_JSON+="\"$tech\":$config"
            done
            EVASION_PARAMS="{$EVASION_PARAMS_JSON}"
        fi
        
        # Pass selected techniques and their configuration to the app container.
        docker compose -f "$COMPOSE_FILE" run --rm \
            -e EVASION_TECHNIQUES="$EVASION_ENV" \
            -e EVASION_PARAMS="$EVASION_PARAMS" \
            app python3 ./src/entry.py \
            --stage "$choice" \
            --workspace "$workspace_dir" \
            --exe "$copied_exe_path"
        
        if [ $? -ne 0 ]; then
            echo -e "\n${RED}${BOLD}Pipeline halted due to an error. Check the logs above.${RESET}"
        fi
    else
        echo -e "${RED}Invalid option. Please enter a number between 0 and 5.${RESET}"
    fi
done
