#!/bin/bash

# ================================================
#  ███████╗ ██████╗ █████╗ ██████╗ ██╗     ███████╗████████╗
#  ██╔════╝██╔════╝██╔══██╗██╔══██╗██║     ██╔════╝╚══██╔══╝
#  ███████╗██║     ███████║██████╔╝██║     █████╗     ██║   
#  ╚════██║██║     ██╔══██║██╔══██╗██║     ██╔══╝     ██║   
#  ███████║╚██████╗██║  ██║██║  ██║███████╗███████╗   ██║   
#  ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝   ╚═╝   
#           ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗      
#          ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝      
#          ██║  ███╗███████║██║   ██║█████╗     ██║         
#          ██║   ██║██╔══██║██║   ██║██╔══╝     ██║         
#          ╚██████╔╝██║  ██║╚██████╔╝███████╗   ██║         
#           ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝         
# ================================================
#                    SCARLET GHOST
#           Advanced Security Testing Framework
# ================================================
#                    Author: CyberGhost
#                    Version: 5.0 (Ultimate)
# ================================================

# ============= CONFIGURAÇÕES GLOBAIS =============
set -euo pipefail
IFS=$'\n\t'

# Configurações
readonly SCRIPT_VERSION="5.0"
readonly SCRIPT_NAME="Scarlet Ghost"
readonly CONFIG_DIR="$HOME/.scarlet-ghost"
readonly LOG_DIR="$CONFIG_DIR/logs"
readonly TEMPLATE_DIR="$CONFIG_DIR/templates"
readonly WORDLIST_DIR="$CONFIG_DIR/wordlists"
readonly OUTPUT_DIR="$CONFIG_DIR/output"
readonly BACKUP_DIR="$CONFIG_DIR/backups"
readonly TOOL_LIST_FILE="$CONFIG_DIR/tools-installed.json"
readonly LOG_FILE="$LOG_DIR/install-$(date +%Y%m%d-%H%M%S).log"
readonly MAX_LOG_SIZE="10485760" # 10MB
readonly MAX_BACKUPS="5"

# Cores ANSI
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly NC='\033[0m'
readonly BOLD='\033[1m'
readonly DIM='\033[2m'
readonly ITALIC='\033[3m'
readonly UNDERLINE='\033[4m'
readonly BLINK='\033[5m'

# Ícones
readonly ICON_CHECK="✓"
readonly ICON_CROSS="✗"
readonly ICON_WARNING="⚠"
readonly ICON_INFO="ℹ"
readonly ICON_ARROW="→"
readonly ICON_DOWNLOAD="↓"
readonly ICON_INSTALL="📦"
readonly ICON_UPDATE="🔄"
readonly ICON_SCAN="🔍"
readonly ICON_SUCCESS="✅"
readonly ICON_ERROR="❌"
readonly ICON_WAIT="⏳"

# ============= FUNÇÕES DE LOGGING =============
setup_environment() {
    # Criar diretórios necessários
    mkdir -p "$CONFIG_DIR" "$LOG_DIR" "$TEMPLATE_DIR" "$WORDLIST_DIR" "$OUTPUT_DIR" "$BACKUP_DIR"
    
    # Iniciar log
    exec 3>&1 4>&2
    exec 1> >(tee -a "$LOG_FILE") 2>&1
    
    # Log inicial
    log "INFO" "Iniciando $SCRIPT_NAME v$SCRIPT_VERSION"
    log "INFO" "Diretório de configuração: $CONFIG_DIR"
    log "INFO" "Arquivo de log: $LOG_FILE"
}

log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local color
    
    case "$level" in
        "INFO") color="$GREEN" ;;
        "WARN") color="$YELLOW" ;;
        "ERROR") color="$RED" ;;
        "DEBUG") color="$BLUE" ;;
        "SUCCESS") color="$PURPLE" ;;
        *) color="$NC" ;;
    esac
    
    echo -e "${color}[$timestamp] [$level] $message${NC}"
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
    
    # Rotacionar log se necessário
    if [ -f "$LOG_FILE" ] && [ $(stat -f%z "$LOG_FILE" 2>/dev/null || stat -c%s "$LOG_FILE" 2>/dev/null) -gt "$MAX_LOG_SIZE" ]; then
        rotate_logs
    fi
}

rotate_logs() {
    local log_base="${LOG_FILE%.*}"
    local log_ext="${LOG_FILE##*.}"
    
    # Remover backups antigos
    ls -t "$log_base"*."$log_ext" 2>/dev/null | tail -n +$((MAX_BACKUPS+1)) | xargs -r rm
    
    # Rotacionar logs
    for i in $(seq $((MAX_BACKUPS-1)) -1 1); do
        [ -f "$log_base-$i.$log_ext" ] && mv "$log_base-$i.$log_ext" "$log_base-$((i+1)).$log_ext"
    done
    
    [ -f "$LOG_FILE" ] && mv "$LOG_FILE" "$log_base-1.$log_ext"
}

# ============= FUNÇÕES DE INTERFACE =============
show_banner() {
    clear
    echo -e "${RED}"
    echo "  ███████╗ ██████╗ █████╗ ██████╗ ██╗     ███████╗████████╗"
    echo "  ██╔════╝██╔════╝██╔══██╗██╔══██╗██║     ██╔════╝╚══██╔══╝"
    echo "  ███████╗██║     ███████║██████╔╝██║     █████╗     ██║   "
    echo "  ╚════██║██║     ██╔══██║██╔══██╗██║     ██╔══╝     ██║   "
    echo "  ███████║╚██████╗██║  ██║██║  ██║███████╗███████╗   ██║   "
    echo "  ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝   ╚═╝   "
    echo -e "${WHITE}"
    echo "           ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗      "
    echo "          ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝      "
    echo "          ██║  ███╗███████║██║   ██║█████╗     ██║         "
    echo "          ██║   ██║██╔══██║██║   ██║██╔══╝     ██║         "
    echo "          ╚██████╔╝██║  ██║╚██████╔╝███████╗   ██║         "
    echo "           ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝         "
    echo -e "${NC}"
    
    # Status bar
    local width=50
    local fill_char="═"
    local empty_char="─"
    local fill=$((width * 100 / 100))
    
    echo -ne "${CYAN}╔"
    printf "%${width}s" | tr " " "$fill_char"
    echo -e "╗${NC}"
    
    # Informações do sistema
    local os_info=$(get_os_info)
    local kernel=$(uname -r)
    local arch=$(uname -m)
    local pkg_manager=$(detect_package_manager || echo "Não detectado")
    local uptime=$(uptime | awk -F'up ' '{print $2}' | awk -F',' '{print $1}')
    
    printf "${CYAN}║${NC}${BOLD}%-20s${NC} : ${GREEN}%-27s${NC}${CYAN}║${NC}\n" "OS" "$os_info"
    printf "${CYAN}║${NC}${BOLD}%-20s${NC} : ${GREEN}%-27s${NC}${CYAN}║${NC}\n" "Kernel" "$kernel"
    printf "${CYAN}║${NC}${BOLD}%-20s${NC} : ${GREEN}%-27s${NC}${CYAN}║${NC}\n" "Architecture" "$arch"
    printf "${CYAN}║${NC}${BOLD}%-20s${NC} : ${GREEN}%-27s${NC}${CYAN}║${NC}\n" "Package Manager" "$pkg_manager"
    printf "${CYAN}║${NC}${BOLD}%-20s${NC} : ${GREEN}%-27s${NC}${CYAN}║${NC}\n" "Uptime" "$uptime"
    
    echo -ne "${CYAN}╚"
    printf "%${width}s" | tr " " "$fill_char"
    echo -e "╝${NC}\n"
}

progress_bar() {
    local current="$1"
    local total="$2"
    local width=50
    local percentage=$((current * 100 / total))
    local fill=$((width * percentage / 100))
    local empty=$((width - fill))
    
    printf "\r${CYAN}[${NC}"
    printf "%${fill}s" | tr " " "█"
    printf "%${empty}s" | tr " " "░"
    printf "${CYAN}]${NC} ${GREEN}%3d%%${NC}" "$percentage"
}

spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    
    while ps -p "$pid" > /dev/null 2>&1; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

# ============= FUNÇÕES DE SISTEMA =============
get_os_info() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            echo "$NAME $VERSION"
        else
            echo "Linux"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macOS $(sw_vers -productVersion)"
    elif [[ "$OSTYPE" == "cygwin" ]] || [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
        echo "Windows"
    else
        echo "Desconhecido"
    fi
}

detect_package_manager() {
    local managers=(
        "apt:apt-get"
        "dnf:dnf"
        "yum:yum"
        "pacman:pacman"
        "zypper:zypper"
        "apk:apk"
        "brew:brew"
        "port:port"
        "emerge:emerge"
        "xbps:xbps-install"
        "nix:nix-env"
        "snap:snap"
        "flatpak:flatpak"
    )
    
    for pm_entry in "${managers[@]}"; do
        local pm_cmd="${pm_entry#*:}"
        if command -v "$pm_cmd" &> /dev/null; then
            echo "${pm_entry%%:*}"
            return 0
        fi
    done
    
    return 1
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log "WARN" "Algumas operações precisam de privilégios root"
        
        # Verificar sudo
        if command -v sudo &> /dev/null; then
            log "INFO" "sudo disponível, tentando obter privilégios..."
            if sudo -n true 2>/dev/null; then
                log "SUCCESS" "sudo sem senha disponível"
                return 0
            else
                log "WARN" "sudo pode pedir senha durante a execução"
            fi
        fi
        
        # Tempo de espera configurável
        read -t 10 -p "$(echo -e ${YELLOW}"$ICON_WARNING Continuar sem root? (s/N): "${NC})" continue_without_root
        if [[ ! "$continue_without_root" =~ ^[Ss]$ ]]; then
            log "INFO" "Operação cancelada pelo usuário"
            exit 1
        fi
    fi
}

check_internet() {
    log "INFO" "Verificando conexão com a internet..."
    
    local test_hosts=("8.8.8.8" "1.1.1.1" "github.com" "google.com")
    local connected=false
    
    for host in "${test_hosts[@]}"; do
        if ping -c 1 -W 2 "$host" &> /dev/null; then
            connected=true
            log "SUCCESS" "Conexão com $host estabelecida"
            break
        fi
    done
    
    if [ "$connected" = false ]; then
        log "ERROR" "Sem conexão com a internet"
        return 1
    fi
    
    return 0
}

check_disk_space() {
    local required_space="${1:-1024}" # MB
    local available_space=$(df -m "$PWD" | awk 'NR==2 {print $4}')
    
    if [ "$available_space" -lt "$required_space" ]; then
        log "ERROR" "Espaço em disco insuficiente. Necessário: ${required_space}MB, Disponível: ${available_space}MB"
        return 1
    fi
    
    log "INFO" "Espaço em disco: ${available_space}MB disponíveis"
    return 0
}

check_memory() {
    local required_mem="${1:-512}" # MB
    local available_mem
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        available_mem=$(free -m | awk '/^Mem:/ {print $7}')
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        available_mem=$(vm_stat | awk '/free/ {gsub(/\./, "", $3); print $3/256}')
    else
        log "WARN" "Não foi possível verificar memória disponível"
        return 0
    fi
    
    if [ "$available_mem" -lt "$required_mem" ]; then
        log "WARN" "Memória disponível baixa: ${available_mem}MB (recomendado: ${required_mem}MB)"
        read -p "$(echo -e ${YELLOW}"$ICON_WARNING Continuar mesmo assim? (s/N): "${NC})" continue_low_memory
        if [[ ! "$continue_low_memory" =~ ^[Ss]$ ]]; then
            return 1
        fi
    fi
    
    return 0
}

# ============= FUNÇÕES DE INSTALAÇÃO AVANÇADA =============
run_command() {
    local cmd="$1"
    local timeout="${2:-300}"
    local retries="${3:-0}"
    local retry_count=0
    local exit_code=0
    local output=""
    
    log "DEBUG" "Executando: $cmd"
    
    while [ $retry_count -le $retries ]; do
        if [ $retry_count -gt 0 ]; then
            log "WARN" "Tentativa $retry_count de $((retries+1))"
            sleep $((2 ** retry_count))
        fi
        
        if command -v timeout &> /dev/null; then
            output=$(timeout "$timeout" bash -c "$cmd" 2>&1)
            exit_code=$?
        else
            output=$(bash -c "$cmd" 2>&1)
            exit_code=$?
        fi
        
        if [ $exit_code -eq 0 ] || [ $exit_code -eq 124 ]; then
            if [ $exit_code -eq 124 ]; then
                log "WARN" "Comando atingiu timeout de ${timeout}s"
            else
                log "SUCCESS" "Comando executado com sucesso"
            fi
            echo "$output"
            return 0
        fi
        
        retry_count=$((retry_count + 1))
    done
    
    log "ERROR" "Falha após $retries tentativas (código: $exit_code)"
    echo "$output" >&2
    return $exit_code
}

install_package() {
    local package="$1"
    local manager="$2"
    local install_cmd=""
    
    log "INFO" "$ICON_INSTALL Instalando $package via $manager"
    
    case "$manager" in
        apt)
            install_cmd="sudo DEBIAN_FRONTEND=noninteractive apt-get install -y $package"
            ;;
        dnf|yum)
            install_cmd="sudo $manager install -y $package"
            ;;
        pacman)
            install_cmd="sudo pacman -S --noconfirm --needed $package"
            ;;
        zypper)
            install_cmd="sudo zypper install -y $package"
            ;;
        apk)
            install_cmd="sudo apk add $package"
            ;;
        brew)
            install_cmd="brew install $package"
            ;;
        pip)
            install_cmd="pip3 install --user $package"
            ;;
        pip3)
            install_cmd="pip3 install --user $package"
            ;;
        npm)
            install_cmd="sudo npm install -g $package"
            ;;
        go)
            install_cmd="go install $package@latest"
            ;;
        cargo)
            install_cmd="cargo install $package"
            ;;
        gem)
            install_cmd="sudo gem install $package"
            ;;
        snap)
            install_cmd="sudo snap install $package"
            ;;
        flatpak)
            install_cmd="flatpak install -y $package"
            ;;
        *)
            log "ERROR" "Gerenciador de pacotes não suportado: $manager"
            return 1
            ;;
    esac
    
    run_command "$install_cmd" 600 2
}

check_tool_version() {
    local tool="$1"
    local min_version="${2:-}"
    
    if ! command -v "$tool" &> /dev/null; then
        return 1
    fi
    
    if [ -n "$min_version" ]; then
        local version
        case "$tool" in
            go|python|python3|node|npm)
                version=$($tool --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
                ;;
            nuclei|subfinder|httpx)
                version=$($tool -version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
                ;;
            *)
                version=$($tool --version 2>/dev/null | head -1)
                ;;
        esac
        
        if [ -n "$version" ]; then
            log "INFO" "$tool versão $version encontrada"
            # Aqui poderia implementar comparação de versões
        fi
    fi
    
    return 0
}

install_go_tool() {
    local tool_name="$1"
    local tool_pkg="$2"
    
    log "INFO" "$ICON_INSTALL Instalando $tool_name via Go"
    
    if ! command -v go &> /dev/null; then
        log "ERROR" "Go não está instalado"
        return 1
    fi
    
    # Configurar GOPATH se necessário
    export GOPATH="${GOPATH:-$HOME/go}"
    export PATH="$PATH:$GOPATH/bin"
    
    # Instalar ferramenta
    if run_command "go install $tool_pkg@latest" 300 2; then
        local bin_path="$GOPATH/bin/$tool_name"
        
        if [ -f "$bin_path" ]; then
            if [ -w "/usr/local/bin" ]; then
                run_command "mv $bin_path /usr/local/bin/"
                log "SUCCESS" "$tool_name instalado em /usr/local/bin/"
            else
                log "WARN" "Não foi possível mover $tool_name para /usr/local/bin"
                log "INFO" "Adicionando $GOPATH/bin ao PATH..."
                
                # Adicionar ao PATH permanentemente
                if ! grep -q "export PATH=\$PATH:$GOPATH/bin" ~/.bashrc; then
                    echo "export PATH=\$PATH:$GOPATH/bin" >> ~/.bashrc
                fi
                if ! grep -q "export PATH=\$PATH:$GOPATH/bin" ~/.zshrc 2>/dev/null; then
                    echo "export PATH=\$PATH:$GOPATH/bin" >> ~/.zshrc 2>/dev/null
                fi
                
                log "SUCCESS" "$tool_name instalado em $bin_path"
            fi
            update_tool_status "$tool_name" "installed" "$(date +%Y-%m-%d)"
        else
            log "ERROR" "Binário do $tool_name não encontrado em $bin_path"
            return 1
        fi
    else
        log "ERROR" "Falha ao instalar $tool_name"
        return 1
    fi
}

install_from_git() {
    local repo_url="$1"
    local target_dir="$2"
    local install_cmd="${3:-}"
    
    log "INFO" "$ICON_DOWNLOAD Clonando $repo_url"
    
    if [ -d "$target_dir" ]; then
        log "WARN" "Diretório $target_dir já existe"
        read -p "$(echo -e ${YELLOW}"$ICON_WARNING Sobrescrever? (s/N): "${NC})" overwrite
        if [[ "$overwrite" =~ ^[Ss]$ ]]; then
            rm -rf "$target_dir"
        else
            log "INFO" "Usando instalação existente"
            return 0
        fi
    fi
    
    if run_command "git clone --depth 1 $repo_url $target_dir" 300 2; then
        log "SUCCESS" "Repositório clonado com sucesso"
        
        if [ -n "$install_cmd" ]; then
            log "INFO" "Executando comando de instalação..."
            (cd "$target_dir" && eval "$install_cmd")
        fi
        
        return 0
    else
        log "ERROR" "Falha ao clonar repositório"
        return 1
    fi
}

# ============= GERENCIAMENTO DE FERRAMENTAS =============
declare -A TOOL_CATEGORIES=(
    ["nuclei-suite"]="nuclei,dnsx,subfinder,httpx,naabu,asnmap,interactsh-client,notify,uncover,mapcidr"
    ["tomnomnom"]="waybackurls,httprobe,anew,assetfinder,unfurl,gf,fff,qsreplace,concurl,filter-resolved"
    ["recon"]="gau,gauplus,hakrawler,katana,amass,shuffledns,findomain,chaos,altdns,massdns"
    ["scanning"]="nmap,masscan,rustscan,fscan,naabu"
    ["exploitation"]="metasploit,burpsuite,sqlmap,beef,commix"
    ["web"]="ffuf,dirstalk,dalfox,nikto,wpscan,joomscan,droopescan"
    ["mobile"]="apktool,dex2jar,jadx,mobsf"
    ["cloud"]="s3scanner,cloudlist,cloudfox,pacu"
    ["wordlists"]="seclists,fuzzdb,payloads,rockyou"
    ["misc"]="jq,node,npm,yarn,python3-pip,ruby,go,rust,curl,wget,git,unzip"
)

update_tool_status() {
    local tool="$1"
    local status="$2"
    local date="$3"
    local temp_file=$(mktemp)
    
    if [ -f "$TOOL_LIST_FILE" ]; then
        jq --arg tool "$tool" --arg status "$status" --arg date "$date" \
           '.[$tool] = {"status": $status, "installed_date": $date}' \
           "$TOOL_LIST_FILE" > "$temp_file" && mv "$temp_file" "$TOOL_LIST_FILE"
    else
        echo "{\"$tool\": {\"status\": \"$status\", \"installed_date\": \"$date\"}}" > "$TOOL_LIST_FILE"
    fi
}

verify_tools() {
    local category="${1:-all}"
    local tools_to_check=()
    
    log "INFO" "Verificando ferramentas instaladas..."
    
    if [ "$category" = "all" ]; then
        for cat_tools in "${TOOL_CATEGORIES[@]}"; do
            IFS=',' read -ra tools <<< "$cat_tools"
            tools_to_check+=("${tools[@]}")
        done
    else
        IFS=',' read -ra tools <<< "${TOOL_CATEGORIES[$category]}"
        tools_to_check=("${tools[@]}")
    fi
    
    local installed=0
    local total=${#tools_to_check[@]}
    local current=0
    
    for tool in "${tools_to_check[@]}"; do
        if command -v "$tool" &> /dev/null; then
            echo -e "${GREEN}[$ICON_CHECK] $tool${NC} ${DIM}$(which $tool)${NC}"
            installed=$((installed + 1))
        else
            echo -e "${RED}[$ICON_CROSS] $tool${NC}"
        fi
        current=$((current + 1))
        progress_bar $current $total
    done
    
    echo -e "\n\n${BOLD}Resumo:${NC} $installed/$total ferramentas instaladas"
    
    if [ $installed -eq $total ]; then
        echo -e "${GREEN}${ICON_SUCCESS} Todas as ferramentas estão instaladas!${NC}"
    else
        echo -e "${YELLOW}${ICON_WARNING} $((total - installed)) ferramentas não encontradas${NC}"
    fi
}

export_tool_list() {
    local output_file="$OUTPUT_DIR/tool-list-$(date +%Y%m%d).txt"
    
    {
        echo "=== SCARLET GHOST - Tool List ==="
        echo "Gerado em: $(date)"
        echo "Sistema: $(get_os_info)"
        echo ""
        
        for category in "${!TOOL_CATEGORIES[@]}"; do
            echo "[$category]"
            IFS=',' read -ra tools <<< "${TOOL_CATEGORIES[$category]}"
            for tool in "${tools[@]}"; do
                if command -v "$tool" &> /dev/null; then
                    echo "  ✓ $tool ($(which $tool))"
                else
                    echo "  ✗ $tool"
                fi
            done
            echo ""
        done
    } > "$output_file"
    
    log "SUCCESS" "Lista de ferramentas exportada para $output_file"
}

# ============= INSTALAÇÕES ESPECÍFICAS =============
install_golang() {
    local manager=$(detect_package_manager)
    
    if ! command -v go &> /dev/null; then
        log "INFO" "Instalando Go..."
        
        case "$manager" in
            apt)
                install_package "golang" "$manager"
                ;;
            dnf|yum)
                install_package "golang" "$manager"
                ;;
            pacman)
                install_package "go" "$manager"
                ;;
            brew)
                install_package "go" "$manager"
                ;;
            *)
                # Instalação manual da versão mais recente
                local go_version="1.21.0"
                local go_os="linux"
                [[ "$OSTYPE" == "darwin"* ]] && go_os="darwin"
                local go_arch="amd64"
                [[ "$(uname -m)" == "arm64" ]] && go_arch="arm64"
                
                wget -q "https://golang.org/dl/go$go_version.$go_os-$go_arch.tar.gz" -O /tmp/go.tar.gz
                sudo tar -C /usr/local -xzf /tmp/go.tar.gz
                echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
                echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.zshrc 2>/dev/null
                export PATH=$PATH:/usr/local/go/bin
                ;;
        esac
        
        log "SUCCESS" "Go instalado com sucesso"
    else
        log "SUCCESS" "Go já está instalado"
    fi
    
    # Configurar Go
    export GOPATH="$HOME/go"
    export PATH="$PATH:$GOPATH/bin"
    mkdir -p "$GOPATH"/{bin,src,pkg}
}

install_python_tools_enhanced() {
    local manager=$(detect_package_manager)
    
    log "INFO" "Instalando ferramentas Python..."
    
    # Pip tools
    local python_tools=(
        "shodan"
        "colorama"
        "requests"
        "beautifulsoup4"
        "scrapy"
        "selenium"
        "paramiko"
        "scapy"
        "impacket"
        "cryptography"
        "pwntools"
        "pwntools"
        "capstone"
        "keystone-engine"
        "unicorn"
        "angr"
        "frida-tools"
        "objection"
        "drozer"
        "mobsfscan"
    )
    
    for tool in "${python_tools[@]}"; do
        install_package "$tool" "pip3"
    done
    
    # Ferramentas específicas via git
    local git_tools=(
        "https://github.com/devanshbatham/paramspider:paramspider:cd paramspider && python3 setup.py install"
        "https://github.com/s0md3v/Arjun:arjun:cd arjun && python3 setup.py install"
        "https://github.com/sqlmapproject/sqlmap:sqlmap:cd sqlmap && python3 setup.py install"
        "https://github.com/epsylon/xsser:xsser:cd xsser && python3 setup.py install"
        "https://github.com/s0md3v/XSStrike:XSStrike:cd XSStrike && pip3 install -r requirements.txt"
        "https://github.com/aboul3la/Sublist3r:Sublist3r:cd Sublist3r && pip3 install -r requirements.txt && python3 setup.py install"
        "https://github.com/darkoperator/dnsrecon:dnsrecon:cd dnsrecon && python3 setup.py install"
    )
    
    for tool_entry in "${git_tools[@]}"; do
        IFS=':' read -r repo_url target_dir install_cmd <<< "$tool_entry"
        install_from_git "$repo_url" "$target_dir" "$install_cmd"
    done
}

install_nuclei_suite_enhanced() {
    log "INFO" "Instalando Nuclei Suite..."
    
    install_golang
    
    # ProjectDiscovery tools
    local pd_tools=(
        "nuclei:github.com/projectdiscovery/nuclei/v2/cmd/nuclei"
        "dnsx:github.com/projectdiscovery/dnsx/cmd/dnsx"
        "subfinder:github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
        "httpx:github.com/projectdiscovery/httpx/cmd/httpx"
        "naabu:github.com/projectdiscovery/naabu/v2/cmd/naabu"
        "asnmap:github.com/projectdiscovery/asnmap/cmd/asnmap"
        "interactsh-client:github.com/projectdiscovery/interactsh/cmd/interactsh-client"
        "notify:github.com/projectdiscovery/notify/cmd/notify"
        "uncover:github.com/projectdiscovery/uncover/cmd/uncover"
        "mapcidr:github.com/projectdiscovery/mapcidr/cmd/mapcidr"
        "pdtm:github.com/projectdiscovery/pdtm/cmd/pdtm"
    )
    
    for tool_entry in "${pd_tools[@]}"; do
        IFS=':' read -r tool_name tool_pkg <<< "$tool_entry"
        if ! command -v "$tool_name" &> /dev/null; then
            install_go_tool "$tool_name" "$tool_pkg"
        fi
    done
    
    # Templates do Nuclei
    if [ ! -d "$TEMPLATE_DIR/nuclei-templates" ]; then
        log "INFO" "Baixando Nuclei templates..."
        install_from_git "https://github.com/projectdiscovery/nuclei-templates.git" \
                        "$TEMPLATE_DIR/nuclei-templates"
        
        # Configurar Nuclei
        nuclei -update-templates -silent
        nuclei -update -silent
    fi
    
    # Template personalizados
    log "INFO" "Configurando templates customizados..."
    mkdir -p "$TEMPLATE_DIR/custom-templates"
    
    # Template de exemplo
    cat > "$TEMPLATE_DIR/custom-templates/default-login.yaml" << 'EOF'
id: default-login

info:
  name: Default Login Page
  author: ScarletGhost
  severity: info
  description: Detects common default login pages

requests:
  - method: GET
    path:
      - "{{BaseURL}}/admin"
      - "{{BaseURL}}/login"
      - "{{BaseURL}}/admin/login"
      - "{{BaseURL}}/administrator"
      - "{{BaseURL}}/wp-admin"
      - "{{BaseURL}}/phpmyadmin"
      - "{{BaseURL}}/cpanel"
    
    matchers:
      - type: word
        words:
          - "login"
          - "sign in"
          - "username"
          - "password"
        condition: or
        case-insensitive: true
EOF
    
    log "SUCCESS" "Nuclei Suite configurado com sucesso"
}

install_tomnomnom_tools_enhanced() {
    log "INFO" "Instalando Tomnomnom tools..."
    
    install_golang
    
    local tools=(
        "waybackurls:github.com/tomnomnom/waybackurls"
        "httprobe:github.com/tomnomnom/httprobe"
        "anew:github.com/tomnomnom/anew"
        "assetfinder:github.com/tomnomnom/assetfinder"
        "unfurl:github.com/tomnomnom/unfurl"
        "gf:github.com/tomnomnom/gf"
        "fff:github.com/tomnomnom/fff"
        "qsreplace:github.com/tomnomnom/qsreplace"
        "concurl:github.com/tomnomnom/concurl"
        "filter-resolved:github.com/tomnomnom/hacks/filter-resolved"
        "comb:github.com/tomnomnom/hacks/comb"
        "anti-burl:github.com/tomnomnom/hacks/anti-burl"
    )
    
    for tool_entry in "${tools[@]}"; do
        IFS=':' read -r tool_name tool_pkg <<< "$tool_entry"
        if ! command -v "$tool_name" &> /dev/null; then
            install_go_tool "$tool_name" "$tool_pkg"
        fi
    done
    
    # Configurar gf patterns
    if command -v gf &> /dev/null; then
        log "INFO" "Configurando gf patterns..."
        if [ ! -d "$HOME/.gf" ]; then
            install_from_git "https://github.com/1ndianl33t/Gf-Patterns" "$HOME/Gf-Patterns"
            cp -r "$HOME/Gf-Patterns/"* "$HOME/.gf/" 2>/dev/null || true
            rm -rf "$HOME/Gf-Patterns"
        fi
    fi
}

install_recon_tools() {
    log "INFO" "Instalando ferramentas de recon..."
    
    install_golang
    
    local go_tools=(
        "gau:github.com/lc/gau/v2/cmd/gau"
        "gauplus:github.com/bp0lr/gauplus"
        "hakrawler:github.com/hakluke/hakrawler"
        "katana:github.com/projectdiscovery/katana/cmd/katana"
        "amass:github.com/OWASP/Amass/v3/...@master"
        "shuffledns:github.com/projectdiscovery/shuffledns/cmd/shuffledns"
        "findomain:github.com/findomain/findomain"
        "chaos:github.com/projectdiscovery/chaos-client/cmd/chaos"
        "altdns:github.com/infosec-au/altdns"
    )
    
    for tool_entry in "${go_tools[@]}"; do
        IFS=':' read -r tool_name tool_pkg <<< "$tool_entry"
        if ! command -v "$tool_name" &> /dev/null; then
            install_go_tool "$tool_name" "$tool_pkg"
        fi
    done
    
    # MassDNS (não é Go)
    if ! command -v massdns &> /dev/null; then
        log "INFO" "Instalando massdns..."
        install_from_git "https://github.com/blechschmidt/massdns.git" "/tmp/massdns" "make && sudo make install"
    fi
}

install_scanning_tools() {
    local manager=$(detect_package_manager)
    
    log "INFO" "Instalando ferramentas de scanning..."
    
    # Nmap
    if ! command -v nmap &> /dev/null; then
        install_package "nmap" "$manager"
    fi
    
    # Masscan
    if ! command -v masscan &> /dev/null; then
        if command -v "$manager" &> /dev/null; then
            install_package "masscan" "$manager"
        else
            install_from_git "https://github.com/robertdavidgraham/masscan" "/tmp/masscan" "make && sudo make install"
        fi
    fi
    
    # RustScan
    if ! command -v rustscan &> /dev/null; then
        log "INFO" "Instalando rustscan..."
        if command -v cargo &> /dev/null; then
            cargo install rustscan
        else
            install_package "rustscan" "$manager" 2>/dev/null || {
                wget -qO- https://api.github.com/repos/RustScan/RustScan/releases/latest | \
                grep "browser_download_url.*amd64.deb" | \
                cut -d '"' -f 4 | \
                wget -qi - && sudo dpkg -i rustscan*.deb
            }
        fi
    fi
}

install_web_tools() {
    local manager=$(detect_package_manager)
    
    log "INFO" "Instalando ferramentas web..."
    
    # FFUF
    if ! command -v ffuf &> /dev/null; then
        install_go_tool "ffuf" "github.com/ffuf/ffuf"
    fi
    
    # Dirsearch/Dirstalk
    if ! command -v dirstalk &> /dev/null; then
        install_go_tool "dirstalk" "github.com/stefanoj3/dirstalk"
    fi
    
    # Dalfox
    if ! command -v dalfox &> /dev/null; then
        install_go_tool "dalfox" "github.com/hahwul/dalfox/v2"
    fi
    
    # Nikto
    if ! command -v nikto &> /dev/null; then
        install_from_git "https://github.com/sullo/nikto" "/opt/nikto" "cd program && ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto"
    fi
    
    # WPScan
    if ! command -v wpscan &> /dev/null; then
        install_package "ruby" "$manager"
        sudo gem install wpscan
    fi
}

install_wordlists() {
    log "INFO" "Baixando wordlists..."
    
    mkdir -p "$WORDLIST_DIR"
    
    # SecLists
    if [ ! -d "$WORDLIST_DIR/SecLists" ]; then
        log "INFO" "Baixando SecLists..."
        install_from_git "https://github.com/danielmiessler/SecLists.git" "$WORDLIST_DIR/SecLists"
    fi
    
    # FuzzDB
    if [ ! -d "$WORDLIST_DIR/FuzzDB" ]; then
        log "INFO" "Baixando FuzzDB..."
        install_from_git "https://github.com/fuzzdb-project/fuzzdb.git" "$WORDLIST_DIR/FuzzDB"
    fi
    
    # Payloads All The Things
    if [ ! -d "$WORDLIST_DIR/PayloadsAllTheThings" ]; then
        log "INFO" "Baixando PayloadsAllTheThings..."
        install_from_git "https://github.com/swisskyrepo/PayloadsAllTheThings.git" "$WORDLIST_DIR/PayloadsAllTheThings"
    fi
    
    # Wordlists comuns
    local common_wordlists=(
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt"
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-directories.txt"
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt"
    )
    
    for url in "${common_wordlists[@]}"; do
        local filename=$(basename "$url")
        if [ ! -f "$WORDLIST_DIR/$filename" ]; then
            log "INFO" "Baixando $filename..."
            wget -q "$url" -O "$WORDLIST_DIR/$filename"
        fi
    done
    
    log "SUCCESS" "Wordlists baixadas em $WORDLIST_DIR"
}

# ============= FUNÇÕES DE SCAN E PROCESSAMENTO =============
process_dns_scan_enhanced() {
    local json_file="$1"
    
    if [ ! -f "$json_file" ]; then
        log "ERROR" "Arquivo $json_file não encontrado"
        return 1
    fi
    
    if ! command -v jq &> /dev/null; then
        log "ERROR" "jq não está instalado. Instale com: sudo apt install jq"
        return 1
    fi
    
    log "INFO" "Processando DNS scan: $json_file"
    
    # Criar diretório para resultados
    local output_dir="$OUTPUT_DIR/dns-scan-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$output_dir"
    
    # Extrair informações básicas
    {
        echo "=== DNS SCAN REPORT ==="
        echo "Generated: $(date)"
        echo "Source file: $json_file"
        echo ""
        
        # Host info
        jq -r '
        "HOST INFORMATION",
        "-----------------",
        "Host: " + (.host // "N/A"),
        "TTL: " + (.ttl // "N/A" | tostring),
        "Status: " + (.status_code // "N/A" | tostring),
        "Timestamp: " + (.timestamp // "N/A"),
        "",
        "RESOLVERS",
        "---------",
        (.resolver[] // [] | .),
        "",
        "ALL RECORDS",
        "-----------",
        (.all[] // [] | .),
        "",
        "A RECORDS",
        "---------",
        (.a[] // [] | .),
        "",
        "AAAA RECORDS",
        "-----------",
        (.aaaa[] // [] | .),
        "",
        "MX RECORDS",
        "----------",
        (.mx[] // [] | .),
        "",
        "TXT RECORDS",
        "-----------",
        (.txt[] // [] | .),
        "",
        "NS RECORDS",
        "----------",
        (.ns[] // [] | .),
        "",
        "CNAME RECORDS",
        "-------------",
        (.cname[] // [] | .),
        "",
        "SOA RECORDS",
        "-----------",
        (.soa[]? // [] | "Name: " + (.name // "N/A") + "\nNS: " + (.ns // "N/A") + "\nMailbox: " + (.mailbox // "N/A") + "\n"),
        "",
        "AXFR INFO",
        "---------",
        (.axfr // "N/A" | tostring)
        ' "$json_file" > "$output_dir/report.txt"
    }
    
    # Extrair registros para arquivos separados
    jq -r '.all[]? // empty' "$json_file" > "$output_dir/all_records.txt"
    jq -r '.a[]? // empty' "$json_file" > "$output_dir/a_records.txt"
    jq -r '.aaaa[]? // empty' "$json_file" > "$output_dir/aaaa_records.txt"
    jq -r '.mx[]? // empty' "$json_file" > "$output_dir/mx_records.txt"
    jq -r '.txt[]? // empty' "$json_file" > "$output_dir/txt_records.txt"
    jq -r '.ns[]? // empty' "$json_file" > "$output_dir/ns_records.txt"
    jq -r '.cname[]? // empty' "$json_file" > "$output_dir/cname_records.txt"
    
    # Estatísticas
    {
        echo "=== STATISTICS ==="
        echo "Total A records: $(wc -l < "$output_dir/a_records.txt" 2>/dev/null || echo 0)"
        echo "Total AAAA records: $(wc -l < "$output_dir/aaaa_records.txt" 2>/dev/null || echo 0)"
        echo "Total MX records: $(wc -l < "$output_dir/mx_records.txt" 2>/dev/null || echo 0)"
        echo "Total TXT records: $(wc -l < "$output_dir/txt_records.txt" 2>/dev/null || echo 0)"
        echo "Total NS records: $(wc -l < "$output_dir/ns_records.txt" 2>/dev/null || echo 0)"
        echo "Total CNAME records: $(wc -l < "$output_dir/cname_records.txt" 2>/dev/null || echo 0)"
    } >> "$output_dir/report.txt"
    
    # Gerar HTML report se possível
    if command -v pandoc &> /dev/null; then
        pandoc "$output_dir/report.txt" -o "$output_dir/report.html"
        log "SUCCESS" "Relatório HTML gerado: $output_dir/report.html"
    fi
    
    # Criar arquivo compactado
    tar -czf "$output_dir.tar.gz" -C "$OUTPUT_DIR" "$(basename $output_dir)"
    
    log "SUCCESS" "Scan processado. Resultados em:"
    log "SUCCESS" "  - Diretório: $output_dir"
    log "SUCCESS" "  - Arquivo compactado: $output_dir.tar.gz"
    
    # Mostrar resumo
    echo ""
    echo -e "${CYAN}═══ RESUMO DO SCAN ═══${NC}"
    echo -e "${GREEN}Total de registros:${NC} $(wc -l < "$output_dir/all_records.txt" 2>/dev/null || echo 0)"
    echo -e "${GREEN}Resolvers:${NC} $(wc -l < "$output_dir/../resolvers.txt" 2>/dev/null || echo 0)"
    echo -e "${GREEN}Arquivos gerados:${NC} $(ls -1 "$output_dir" | wc -l)"
    echo -e "${CYAN}══════════════════════${NC}"
}

# ============= FUNÇÕES DE BACKUP E RESTORE =============
backup_config() {
    local backup_file="$BACKUP_DIR/backup-$(date +%Y%m%d-%H%M%S).tar.gz"
    
    log "INFO" "Criando backup da configuração..."
    
    tar -czf "$backup_file" \
        -C "$(dirname "$CONFIG_DIR")" \
        "$(basename "$CONFIG_DIR")" 2>/dev/null || {
        log "ERROR" "Falha ao criar backup"
        return 1
    }
    
    log "SUCCESS" "Backup criado: $backup_file"
    
    # Manter apenas os últimos MAX_BACKUPS backups
    ls -t "$BACKUP_DIR"/backup-*.tar.gz 2>/dev/null | tail -n +$((MAX_BACKUPS+1)) | xargs -r rm
}

restore_backup() {
    local backup_file="$1"
    
    if [ ! -f "$backup_file" ]; then
        log "ERROR" "Arquivo de backup não encontrado: $backup_file"
        return 1
    fi
    
    log "INFO" "Restaurando backup: $backup_file"
    
    # Fazer backup atual antes de restaurar
    backup_config
    
    # Restaurar backup
    tar -xzf "$backup_file" -C "$HOME"
    
    log "SUCCESS" "Backup restaurado com sucesso"
}

# ============= MENU PRINCIPAL MELHORADO =============
show_menu() {
    clear
    show_banner
    
    # Menu com submenus
    echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║                      MENU PRINCIPAL                           ║${NC}"
    echo -e "${YELLOW}╠══════════════════════════════════════════════════════════════╣${NC}"
    
    # Linha 1
    printf "${YELLOW}║${NC} ${WHITE}1)${NC} ${GREEN}📦${NC} Instalação Completa    "
    printf "${YELLOW}║${NC} ${WHITE}2)${NC} ${CYAN}🎯${NC} Nuclei Suite         "
    printf "${YELLOW}║${NC} ${WHITE}3)${NC} ${PURPLE}🔧${NC} Tomnomnom Tools    "
    printf "${YELLOW}║${NC}\n"
    
    # Linha 2
    printf "${YELLOW}║${NC} ${WHITE}4)${NC} ${BLUE}🐍${NC} Python Tools         "
    printf "${YELLOW}║${NC} ${WHITE}5)${NC} ${CYAN}🔍${NC} Recon Tools         "
    printf "${YELLOW}║${NC} ${WHITE}6)${NC} ${RED}🌐${NC} Web Tools           "
    printf "${YELLOW}║${NC}\n"
    
    # Linha 3
    printf "${YELLOW}║${NC} ${WHITE}7)${NC} ${GREEN}📚${NC} Wordlists           "
    printf "${YELLOW}║${NC} ${WHITE}8)${NC} ${YELLOW}✓${NC} Verificar Tools    "
    printf "${YELLOW}║${NC} ${WHITE}9)${NC} ${BLUE}📋${NC} Exportar Lista     "
    printf "${YELLOW}║${NC}\n"
    
    # Linha 4
    printf "${YELLOW}║${NC} ${WHITE}10)${NC} ${PURPLE}🔄${NC} Update Sistema     "
    printf "${YELLOW}║${NC} ${WHITE}11)${NC} ${CYAN}📊${NC} Processar DNS      "
    printf "${YELLOW}║${NC} ${WHITE}12)${NC} ${GREEN}💾${NC} Backup Config     "
    printf "${YELLOW}║${NC}\n"
    
    # Linha 5
    printf "${YELLOW}║${NC} ${WHITE}13)${NC} ${BLUE}↩️${NC} Restore Backup     "
    printf "${YELLOW}║${NC} ${WHITE}14)${NC} ${RED}⚠️${NC}  WSL Check         "
    printf "${YELLOW}║${NC} ${WHITE}15)${NC} ${WHITE}ℹ️${NC}  System Info      "
    printf "${YELLOW}║${NC}\n"
    
    # Linha 6
    printf "${YELLOW}║${NC} ${WHITE}16)${NC} ${RED}🧹${NC} Clean Cache        "
    printf "${YELLOW}║${NC} ${WHITE}17)${NC} ${PURPLE}📝${NC} View Logs         "
    printf "${YELLOW}║${NC} ${WHITE}0)${NC}  ${RED}🚪${NC} Sair              "
    printf "${YELLOW}║${NC}\n"
    
    echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════╝${NC}\n"
}

main_menu() {
    local option
    
    while true; do
        show_menu
        
        read -p "$(echo -e ${CYAN}"[*] Escolha uma opção [0-17]: "${NC})" option
        
        case $option in
            1)  # Instalação Completa
                log "INFO" "Iniciando instalação completa..."
                if check_internet && check_disk_space 5120 && check_memory 1024; then
                    local manager=$(detect_package_manager)
                    [ -n "$manager" ] && update_system "$manager"
                    ensure_pip "$manager"
                    install_golang
                    install_nuclei_suite_enhanced
                    install_tomnomnom_tools_enhanced
                    install_recon_tools
                    install_scanning_tools
                    install_web_tools
                    install_python_tools_enhanced
                    install_wordlists
                    backup_config
                    log "SUCCESS" "Instalação completa finalizada!"
                fi
                ;;
            2)  # Nuclei Suite
                log "INFO" "Instalando Nuclei Suite..."
                install_golang
                install_nuclei_suite_enhanced
                ;;
            3)  # Tomnomnom Tools
                log "INFO" "Instalando Tomnomnom tools..."
                install_golang
                install_tomnomnom_tools_enhanced
                ;;
            4)  # Python Tools
                log "INFO" "Instalando Python tools..."
                local manager=$(detect_package_manager)
                ensure_pip "$manager"
                install_python_tools_enhanced
                ;;
            5)  # Recon Tools
                log "INFO" "Instalando Recon tools..."
                install_recon_tools
                ;;
            6)  # Web Tools
                log "INFO" "Instalando Web tools..."
                install_web_tools
                ;;
            7)  # Wordlists
                log "INFO" "Baixando wordlists..."
                install_wordlists
                ;;
            8)  # Verificar Tools
                verify_tools
                ;;
            9)  # Exportar Lista
                export_tool_list
                ;;
            10) # Update Sistema
                local manager=$(detect_package_manager)
                if [ -n "$manager" ]; then
                    update_system "$manager"
                else
                    log "ERROR" "Gerenciador de pacotes não detectado"
                fi
                ;;
            11) # Processar DNS
                read -p "$(echo -e ${CYAN}"[*] Caminho do arquivo JSON: "${NC})" json_file
                process_dns_scan_enhanced "$json_file"
                ;;
            12) # Backup
                backup_config
                ;;
            13) # Restore
                echo -e "${YELLOW}Backups disponíveis:${NC}"
                ls -1 "$BACKUP_DIR"/backup-*.tar.gz 2>/dev/null || echo "Nenhum backup encontrado"
                read -p "$(echo -e ${CYAN}"[*] Caminho do arquivo de backup: "${NC})" backup_file
                restore_backup "$backup_file"
                ;;
            14) # WSL Check
                if check_wsl; then
                    log "INFO" "Sistema rodando no WSL"
                else
                    log "INFO" "Sistema não está no WSL"
                fi
                ;;
            15) # System Info
                show_system_info
                ;;
            16) # Clean Cache
                clean_cache
                ;;
            17) # View Logs
                view_logs
                ;;
            0)  # Sair
                log "INFO" "Finalizando $SCRIPT_NAME v$SCRIPT_VERSION"
                backup_config
                echo -e "\n${GREEN}${ICON_SUCCESS} Até logo, Ghost! 👻${NC}\n"
                exit 0
                ;;
            *)
                log "ERROR" "Opção inválida: $option"
                sleep 2
                ;;
        esac
        
        echo -e "\n${YELLOW}${ICON_WAIT} Pressione ENTER para continuar...${NC}"
        read
    done
}

# ============= FUNÇÕES ADICIONAIS =============
check_wsl() {
    if [ -f "/proc/version" ] && grep -qi microsoft /proc/version; then
        return 0
    fi
    return 1
}

update_system() {
    local manager="$1"
    
    log "INFO" "$ICON_UPDATE Atualizando sistema..."
    
    case "$manager" in
        apt)
            run_command "sudo apt-get update" 120 2
            run_command "sudo apt-get upgrade -y" 600 2
            run_command "sudo apt-get autoremove -y" 120
            run_command "sudo apt-get autoclean" 60
            ;;
        dnf|yum)
            run_command "sudo $manager update -y" 600 2
            run_command "sudo $manager upgrade -y" 600 2
            run_command "sudo $manager autoremove -y" 120
            run_command "sudo $manager clean all" 60
            ;;
        pacman)
            run_command "sudo pacman -Syu --noconfirm" 600 2
            run_command "sudo pacman -Sc --noconfirm" 120
            ;;
        zypper)
            run_command "sudo zypper refresh" 120
            run_command "sudo zypper update -y" 600 2
            run_command "sudo zypper clean" 60
            ;;
        apk)
            run_command "sudo apk update" 120
            run_command "sudo apk upgrade" 600 2
            run_command "sudo apk cache clean" 60
            ;;
        brew)
            run_command "brew update" 120
            run_command "brew upgrade" 600 2
            run_command "brew cleanup" 120
            ;;
    esac
    
    log "SUCCESS" "Sistema atualizado com sucesso"
}

ensure_pip() {
    local manager="$1"
    
    if ! command -v pip3 &> /dev/null && ! command -v pip &> /dev/null; then
        log "INFO" "Instalando pip..."
        
        case "$manager" in
            apt)
                install_package "python3-pip" "$manager"
                ;;
            dnf|yum)
                install_package "python3-pip" "$manager"
                ;;
            pacman)
                install_package "python-pip" "$manager"
                ;;
            zypper)
                install_package "python3-pip" "$manager"
                ;;
            apk)
                install_package "py3-pip" "$manager"
                ;;
            brew)
                install_package "python" "$manager"
                ;;
            *)
                # Instalação manual
                curl -sS https://bootstrap.pypa.io/get-pip.py | python3
                ;;
        esac
        
        log "SUCCESS" "pip instalado com sucesso"
    else
        log "SUCCESS" "pip já está instalado"
    fi
    
    # Atualizar pip
    log "INFO" "Atualizando pip..."
    pip3 install --upgrade pip --user 2>/dev/null || true
}

show_system_info() {
    echo -e "\n${CYAN}═══ INFORMAÇÕES DO SISTEMA ═══${NC}\n"
    
    echo -e "${BOLD}OS:${NC} $(get_os_info)"
    echo -e "${BOLD}Kernel:${NC} $(uname -r)"
    echo -e "${BOLD}Architecture:${NC} $(uname -m)"
    echo -e "${BOLD}Hostname:${NC} $(hostname)"
    echo -e "${BOLD}Uptime:${NC} $(uptime | awk -F'up ' '{print $2}' | awk -F',' '{print $1}')"
    echo -e "${BOLD}Shell:${NC} $SHELL"
    echo -e "${BOLD}User:${NC} $USER ($(id -un))"
    echo -e "${BOLD}Home:${NC} $HOME"
    echo -e "${BOLD}Current Dir:${NC} $PWD"
    
    echo -e "\n${CYAN}═══ RECURSOS ═══${NC}\n"
    
    # CPU
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo -e "${BOLD}CPU:${NC} $(grep "model name" /proc/cpuinfo | head -1 | cut -d':' -f2 | xargs)"
        echo -e "${BOLD}Cores:${NC} $(nproc)"
        
        # Memory
        local mem_total=$(free -h | awk '/^Mem:/ {print $2}')
        local mem_used=$(free -h | awk '/^Mem:/ {print $3}')
        local mem_free=$(free -h | awk '/^Mem:/ {print $4}')
        echo -e "${BOLD}Memory Total:${NC} $mem_total"
        echo -e "${BOLD}Memory Used:${NC} $mem_used"
        echo -e "${BOLD}Memory Free:${NC} $mem_free"
        
        # Disk
        df -h / | awk 'NR==2 {printf "${BOLD}Disk Total:${NC} %s\n${BOLD}Disk Used:${NC} %s\n${BOLD}Disk Free:${NC} %s\n", $2, $3, $4}'
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo -e "${BOLD}CPU:${NC} $(sysctl -n machdep.cpu.brand_string)"
        echo -e "${BOLD}Cores:${NC} $(sysctl -n hw.ncpu)"
        
        # Memory
        local mem_total=$(sysctl -n hw.memsize | awk '{print $0/1073741824 " GB"}')
        echo -e "${BOLD}Memory Total:${NC} $mem_total"
    fi
    
    echo -e "\n${CYAN}═══ REDE ═══${NC}\n"
    
    # IP addresses
    echo -e "${BOLD}IP Local:${NC} $(hostname -I 2>/dev/null | awk '{print $1}')"
    echo -e "${BOLD}IP Público:${NC} $(curl -s ifconfig.me 2>/dev/null || echo "Não disponível")"
    
    # DNS
    if [ -f /etc/resolv.conf ]; then
        echo -e "${BOLD}DNS:${NC} $(grep nameserver /etc/resolv.conf | head -1 | awk '{print $2}')"
    fi
    
    echo -e "\n${CYAN}════════════════════════════════════════${NC}\n"
}

clean_cache() {
    log "INFO" "Limpando cache..."
    
    # Cache Go
    if command -v go &> /dev/null; then
        go clean -cache -testcache -modcache 2>/dev/null || true
        log "INFO" "Cache Go limpo"
    fi
    
    # Cache pip
    if command -v pip3 &> /dev/null; then
        pip3 cache purge 2>/dev/null || true
        log "INFO" "Cache pip limpo"
    fi
    
    # Cache npm
    if command -v npm &> /dev/null; then
        npm cache clean --force 2>/dev/null || true
        log "INFO" "Cache npm limpo"
    fi
    
    # Cache do sistema
    sudo rm -rf /var/cache/apt/archives/*.deb 2>/dev/null || true
    sudo rm -rf /var/cache/pacman/pkg/* 2>/dev/null || true
    
    # Logs antigos
    find "$LOG_DIR" -name "*.log" -type f -mtime +30 -delete 2>/dev/null || true
    
    log "SUCCESS" "Cache limpo com sucesso"
}

view_logs() {
    echo -e "\n${CYAN}═══ LOGS DISPONÍVEIS ═══${NC}\n"
    
    local logs=($(ls -t "$LOG_DIR"/*.log 2>/dev/null))
    
    if [ ${#logs[@]} -eq 0 ]; then
        log "INFO" "Nenhum log encontrado"
        return
    fi
    
    local i=1
    for log in "${logs[@]}"; do
        local log_size=$(du -h "$log" | cut -f1)
        local log_date=$(stat -c %y "$log" 2>/dev/null | cut -d'.' -f1 || stat -f "%Sm" "$log" 2>/dev/null)
        echo -e "${WHITE}$i)${NC} $(basename "$log") ${DIM}($log_size, $log_date)${NC}"
        i=$((i + 1))
    done
    
    echo ""
    read -p "$(echo -e ${CYAN}"[*] Escolha um log para visualizar (0 para voltar): "${NC})" log_choice
    
    if [[ "$log_choice" -gt 0 ]] && [[ "$log_choice" -le ${#logs[@]} ]]; then
        less "${logs[$((log_choice-1))]}"
    fi
}

# ============= TRATAMENTO DE SINAIS =============
cleanup() {
    local exit_code=$?
    log "INFO" "Limpando recursos..."
    
    # Restaurar descritores de arquivo
    exec 1>&3 2>&4
    exec 3>&- 4>&-
    
    log "INFO" "Script finalizado com código: $exit_code"
    exit $exit_code
}

trap cleanup EXIT INT TERM

# ============= INICIALIZAÇÃO =============
main() {
    # Configurar ambiente
    setup_environment
    
    # Verificar pré-requisitos
    log "INFO" "Verificando pré-requisitos..."
    check_root
    check_internet || {
        log "ERROR" "Conexão com internet necessária"
        exit 1
    }
    
    # Iniciar menu principal
    main_menu
}

# Executar programa principal
main "$@"
