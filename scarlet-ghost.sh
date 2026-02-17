#!/bin/bash

# ================================================
#  ███████╗ ██████╗ █████╗ ██████╗ ██╗     ███████╗████████╗
#  ██╔════╝██╔════╝██╔══██╗██╔══██╗██║     ██╔════╝╚══██╔══╝
#  ███████╗██║     ███████║██████╔╝██║     █████╗     ██║   
#  ╚════██║██║     ██╔══██║██╔══██╗██║     ██╔══╝     ██║   
#  ███████║╚██████╗██║  ██║██║  ██║███████╗███████╗   ██║   
#  ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝   ╚═╝   
# ================================================
#                    SCARLET GHOST
#           Advanced Security Testing Framework
# ================================================
#                    Author: CyberGhost
#                    Version: 6.0 (GOD MODE)
# ================================================

# ============= CONFIGURAÇÕES GLOBAIS =============
set -uo pipefail
IFS=$'\n\t'

# Diretórios e Arquivos
readonly SCRIPT_VERSION="6.0 (God Mode)"
readonly SCRIPT_NAME="Scarlet Ghost"
readonly CONFIG_DIR="$HOME/.scarlet-ghost"
readonly LOG_DIR="$CONFIG_DIR/logs"
readonly TEMPLATE_DIR="$CONFIG_DIR/templates"
readonly WORDLIST_DIR="$CONFIG_DIR/wordlists"
readonly OUTPUT_DIR="$CONFIG_DIR/output"
readonly BACKUP_DIR="$CONFIG_DIR/backups"
readonly API_CONFIG_FILE="$CONFIG_DIR/api-keys.env"
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
readonly NC='\033[0m' # No Color
readonly BOLD='\033[1m'
readonly DIM='\033[2m'

# Ícones
readonly ICON_CHECK="✓"
readonly ICON_CROSS="✗"
readonly ICON_WARNING="⚠"
readonly ICON_INFO="ℹ"
readonly ICON_INSTALL="📦"
readonly ICON_GHOST="👻"
readonly ICON_DOCKER="🐳"
readonly ICON_SHIELD="🛡️"
readonly ICON_KEY="🔑"
readonly ICON_CLOUD="☁️"

# ============= FUNÇÕES CORE E LOGGING =============

setup_environment() {
    # Criar estrutura de pastas
    mkdir -p "$CONFIG_DIR" "$LOG_DIR" "$TEMPLATE_DIR" "$WORDLIST_DIR" "$OUTPUT_DIR" "$BACKUP_DIR"
    
    # Criar arquivo de API se não existir e proteger
    touch "$API_CONFIG_FILE"
    chmod 600 "$API_CONFIG_FILE"
    
    # Iniciar Logging
    exec 3>&1 4>&2
    exec 1> >(tee -a "$LOG_FILE") 2>&1
    
    log "INFO" "Iniciando $SCRIPT_NAME v$SCRIPT_VERSION"
    log "INFO" "Log file: $LOG_FILE"
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
        "OPSEC") color="$PURPLE" ;;
        "SUCCESS") color="$CYAN" ;;
        *) color="$NC" ;;
    esac
    
    echo -e "${color}[$timestamp] [$level] $message${NC}"
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        if command -v sudo &> /dev/null; then
            if sudo -n true 2>/dev/null; then 
                return 0
            else 
                log "WARN" "Solicitando permissão sudo..."
                sudo -v
            fi
        else
            log "ERROR" "Este script requer privilégios de root (ou sudo)."
            exit 1
        fi
    fi
}

check_internet() {
    log "INFO" "Checando conexão..."
    if ping -c 1 8.8.8.8 &> /dev/null; then
        return 0
    else
        log "ERROR" "Sem conexão com a internet."
        return 1
    fi
}

detect_package_manager() {
    if command -v apt &> /dev/null; then echo "apt"; return 0; fi
    if command -v dnf &> /dev/null; then echo "dnf"; return 0; fi
    if command -v pacman &> /dev/null; then echo "pacman"; return 0; fi
    if command -v brew &> /dev/null; then echo "brew"; return 0; fi
    return 1
}

# ============= MÓDULOS NOVOS (GOD MODE) =============

# 1. Docker Stack (Inspirado no instala.txt e necessidade moderna)
install_docker_stack() {
    log "INFO" "$ICON_DOCKER Instalando Stack de Infra (Docker + Portainer)..."
    local manager=$(detect_package_manager)
    
    if ! command -v docker &> /dev/null; then
        log "INFO" "Docker não detectado. Instalando..."
        if [ "$manager" == "apt" ]; then
            curl -fsSL https://get.docker.com | sh
            sudo usermod -aG docker $USER
            sudo systemctl enable docker
            sudo systemctl start docker
        elif [ "$manager" == "pacman" ]; then
            sudo pacman -S --noconfirm docker docker-compose
            sudo systemctl start docker
        fi
    else
        log "SUCCESS" "Docker já instalado."
    fi

    # Portainer Check & Install
    if command -v docker &> /dev/null; then
        if ! docker ps -a | grep -q portainer; then
            log "INFO" "Subindo Portainer (Gerenciador Visual)..."
            docker volume create portainer_data
            docker run -d -p 8000:8000 -p 9443:9443 --name portainer \
                --restart=always \
                -v /var/run/docker.sock:/var/run/docker.sock \
                -v portainer_data:/data \
                portainer/portainer-ce:latest
            log "SUCCESS" "Portainer acessível em: https://localhost:9443"
        else
            log "INFO" "Container Portainer já existe."
        fi
    fi
}

# 2. C2 Framework (Adicionado para completar o Red Team)
install_c2_framework() {
    log "INFO" "$ICON_GHOST Instalando Frameworks C2..."
    
    # Sliver (Moderno, Go-based)
    if ! command -v sliver-server &> /dev/null; then
        log "INFO" "Baixando Sliver C2..."
        curl https://sliver.sh/install | sudo bash
        log "SUCCESS" "Sliver instalado. Execute 'sliver' no terminal."
    else
        log "INFO" "Sliver já instalado."
    fi

    # Metasploit (Clássico)
    if ! command -v msfconsole &> /dev/null; then
        log "INFO" "Instalando Metasploit..."
        curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && \
        chmod 755 msfinstall && \
        ./msfinstall
    fi
}

# 3. Anonymity (OpSec - Inspirado no cyber.txt proxy logic)
setup_anonymity() {
    log "OPSEC" "$ICON_SHIELD Configurando Anonimato (Tor/Proxychains)..."
    local manager=$(detect_package_manager)
    
    # Instalação
    case "$manager" in
        apt) sudo apt-get install -y tor proxychains4 ;;
        pacman) sudo pacman -S --noconfirm tor proxychains ;;
        dnf) sudo dnf install -y tor proxychains ;;
    esac
    
    # Configuração do Proxychains (Dynamic Chain é mais estável)
    local conf_file="/etc/proxychains4.conf"
    if [ -f "$conf_file" ]; then
        sudo sed -i 's/^strict_chain/#strict_chain/' "$conf_file"
        sudo sed -i 's/^#dynamic_chain/dynamic_chain/' "$conf_file"
        sudo sed -i 's/^quiet_mode/#quiet_mode/' "$conf_file" 
        log "INFO" "Proxychains configurado para Dynamic Chain."
    fi
    
    # Iniciar Tor
    sudo systemctl enable tor
    sudo systemctl start tor
    
    log "SUCCESS" "OpSec configurada. Use: 'proxychains4 <ferramenta>'"
}

# 4. Cloud Tools (Inspirado no cyber.txt AWS/Azure Scan)
install_cloud_tools() {
    log "INFO" "$ICON_CLOUD Instalando Ferramentas de Cloud..."
    local mgr=$(detect_package_manager)
    
    if ! command -v aws &> /dev/null; then
        log "INFO" "Instalando AWS CLI..."
        if [ "$mgr" == "apt" ]; then sudo apt install -y awscli; fi
    fi
    
    # ScoutSuite (Multi-Cloud Audit)
    pip3 install scoutsuite --break-system-packages 2>/dev/null || pip3 install scoutsuite
    
    log "SUCCESS" "Ferramentas de Cloud Instaladas."
}

# 5. API Key Manager (Para gerenciar chaves do cyber.txt)
manage_api_keys() {
    clear
    echo -e "${YELLOW}╔══════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║           GERENCIADOR DE APIs            ║${NC}"
    echo -e "${YELLOW}╚══════════════════════════════════════════╝${NC}"
    echo "As chaves são salvas em: $API_CONFIG_FILE"
    echo ""
    
    # Carregar chaves
    if [ -f "$API_CONFIG_FILE" ]; then source "$API_CONFIG_FILE"; fi
    
    read -p ">> Shodan API Key [Atual: ${SHODAN_API_KEY:-N/A}]: " shodan_in
    if [ -n "$shodan_in" ]; then 
        echo "export SHODAN_API_KEY=\"$shodan_in\"" >> "$API_CONFIG_FILE"
        if command -v shodan &> /dev/null; then shodan init "$shodan_in"; fi
    fi
    
    read -p ">> Github Token (Recon) [Atual: ${GITHUB_TOKEN:-N/A}]: " git_in
    if [ -n "$git_in" ]; then echo "export GITHUB_TOKEN=\"$git_in\"" >> "$API_CONFIG_FILE"; fi
    
    read -p ">> IPInfo Token [Atual: ${IPINFO_TOKEN:-N/A}]: " ip_in
    if [ -n "$ip_in" ]; then echo "export IPINFO_TOKEN=\"$ip_in\"" >> "$API_CONFIG_FILE"; fi

    log "SUCCESS" "Chaves salvas com sucesso!"
}

# ============= MÓDULOS CLÁSSICOS (OTIMIZADOS) =============

install_go_tool() {
    local tool_name="$1"
    local tool_pkg="$2"
    log "INFO" "Instalando via Go: $tool_name"
    
    export GOPATH="$HOME/go"
    export PATH="$PATH:$GOPATH/bin"
    
    if ! command -v go &> /dev/null; then
        local mgr=$(detect_package_manager)
        if [ "$mgr" == "apt" ]; then sudo apt install -y golang; fi
        if [ "$mgr" == "pacman" ]; then sudo pacman -S --noconfirm go; fi
    fi
    
    go install "$tool_pkg@latest"
    
    if [ -f "$GOPATH/bin/$tool_name" ]; then
        sudo ln -sf "$GOPATH/bin/$tool_name" "/usr/local/bin/$tool_name"
        log "SUCCESS" "$tool_name instalado."
    else
        log "ERROR" "Falha ao instalar $tool_name"
    fi
}

install_nuclei_suite() {
    log "INFO" "Instalando Nuclei Suite..."
    install_go_tool "nuclei" "github.com/projectdiscovery/nuclei/v2/cmd/nuclei"
    install_go_tool "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
    install_go_tool "httpx" "github.com/projectdiscovery/httpx/cmd/httpx"
    install_go_tool "naabu" "github.com/projectdiscovery/naabu/v2/cmd/naabu"
    install_go_tool "dnsx" "github.com/projectdiscovery/dnsx/cmd/dnsx"
    install_go_tool "katana" "github.com/projectdiscovery/katana/cmd/katana"
    
    if command -v nuclei &> /dev/null; then
        nuclei -update-templates -silent
    fi
}

install_tomnomnom() {
    log "INFO" "Instalando Tomnomnom Tools..."
    local tools=(
        "waybackurls:github.com/tomnomnom/waybackurls"
        "anew:github.com/tomnomnom/anew"
        "gf:github.com/tomnomnom/gf"
        "assetfinder:github.com/tomnomnom/assetfinder"
        "qsreplace:github.com/tomnomnom/qsreplace"
        "httprobe:github.com/tomnomnom/httprobe"
    )
    for t in "${tools[@]}"; do
        IFS=':' read -r name pkg <<< "$t"
        install_go_tool "$name" "$pkg"
    done
    
    # Configurar GF Patterns (Crucial para GF funcionar)
    if [ ! -d "$HOME/.gf" ]; then
        log "INFO" "Baixando GF Patterns..."
        mkdir -p ~/.gf
        git clone https://github.com/1ndianl33t/Gf-Patterns /tmp/gf_patterns 2>/dev/null
        cp /tmp/gf_patterns/*.json ~/.gf/ 2>/dev/null
        rm -rf /tmp/gf_patterns
    fi
}

install_python_stack() {
    log "INFO" "Instalando Python Tools (Inspirado no cyber.txt)..."
    local mgr=$(detect_package_manager)
    
    if [ "$mgr" == "apt" ]; then sudo apt install -y python3-pip python3-venv; fi
    
    pip3 install --upgrade pip --break-system-packages 2>/dev/null || pip3 install --upgrade pip
    
    # Ferramentas extraídas do cyber.txt e instala.txt
    local p_tools=(
        "requests" "impacket" "scapy" "pwntools" "shodan" 
        "paramspider" "arjun" "colorama" "dnspython" 
        "ipinfo" "boto3" "scoutsuite"
    )
    for pt in "${p_tools[@]}"; do
        pip3 install "$pt" --break-system-packages 2>/dev/null || pip3 install "$pt"
    done
}

install_wordlists() {
    log "INFO" "Baixando SecLists (Mode: Light)..."
    if [ ! -d "$WORDLIST_DIR/SecLists" ]; then
        git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$WORDLIST_DIR/SecLists"
    else
        log "INFO" "SecLists já existe."
    fi
}

# ============= UTILITÁRIO DE DNS PARSING (Inspirado no dns.txt) =============
process_dns_scan() {
    local json_file="$1"
    if [ ! -f "$json_file" ]; then
        log "ERROR" "Arquivo não encontrado: $json_file"
        return 1
    fi
    
    if ! command -v jq &> /dev/null; then
        log "ERROR" "Instale 'jq' primeiro (sudo apt install jq)."
        return 1
    fi
    
    local out_folder="$OUTPUT_DIR/dns_report_$(date +%s)"
    mkdir -p "$out_folder"
    log "INFO" "Gerando relatório em: $out_folder"
    
    # Extração baseada na lógica do dns.txt mas usando jq (mais rápido em bash)
    jq -r '.a[]? // empty' "$json_file" > "$out_folder/a_records.txt"
    jq -r '.cname[]? // empty' "$json_file" > "$out_folder/cname_records.txt"
    jq -r '.mx[]? // empty' "$json_file" > "$out_folder/mx_records.txt"
    jq -r '.txt[]? // empty' "$json_file" > "$out_folder/txt_records.txt"
    jq -r '.ns[]? // empty' "$json_file" > "$out_folder/ns_records.txt"
    
    # Relatório Simples
    echo "=== RELATÓRIO DNS SCARLET GHOST ===" > "$out_folder/SUMMARY.txt"
    echo "Gerado em: $(date)" >> "$out_folder/SUMMARY.txt"
    echo "-----------------------------------" >> "$out_folder/SUMMARY.txt"
    echo "Total A Records: $(wc -l < $out_folder/a_records.txt)" >> "$out_folder/SUMMARY.txt"
    echo "Total CNAMEs:    $(wc -l < $out_folder/cname_records.txt)" >> "$out_folder/SUMMARY.txt"
    echo "Total MX:        $(wc -l < $out_folder/mx_records.txt)" >> "$out_folder/SUMMARY.txt"
    
    log "SUCCESS" "Processamento concluído. Verifique $out_folder"
}

# ============= MENU PRINCIPAL =============
show_menu() {
    clear
    echo -e "${RED}"
    echo "   ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗"
    echo "  ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝"
    echo "  ██║  ███╗███████║██║   ██║███████╗   ██║   "
    echo "  ██║   ██║██╔══██║██║   ██║╚════██║   ██║   "
    echo "  ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   "
    echo "   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   "
    echo -e "${WHITE}      SCARLET GHOST v$SCRIPT_VERSION${NC}"
    echo ""
    
    # Dashboard Dinâmico
    local ip_pub=$(curl -s --max-time 2 ifconfig.me || echo "Offline")
    local docker_stat=$(command -v docker >/dev/null && echo "${GREEN}ON${NC}" || echo "${RED}OFF${NC}")
    local tor_stat=$(pgrep -x tor >/dev/null && echo "${GREEN}ON${NC}" || echo "${RED}OFF${NC}")
    
    echo -e "${CYAN}┌──[ SYSTEM DASHBOARD ]──────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} IP Pub: $ip_pub                      ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} Docker: $docker_stat       Tor Service: $tor_stat   ${CYAN}│${NC}"
    echo -e "${CYAN}└────────────────────────────────────────────┘${NC}"
    echo ""

    echo -e "${YELLOW}[ 🚀 INSTALAÇÃO & FERRAMENTAS ]${NC}"
    echo -e "1) ${GREEN}📦${NC} Instalação Completa (All-in-One)"
    echo -e "2) ${BLUE}🐳${NC} Docker & Portainer Stack"
    echo -e "3) ${PURPLE}👽${NC} C2 Framework (Sliver & Metasploit)"
    echo -e "4) ${RED}🎯${NC} Nuclei & Recon Suite"
    echo -e "5) ${CYAN}🔧${NC} Tomnomnom & Web Tools"
    echo -e "6) ${WHITE}🐍${NC} Python Stack (SpyHunt Dependencies)"
    echo -e "7) ${WHITE}☁️${NC}  Cloud Tools (AWS/Azure)"
    echo -e "8) ${WHITE}📚${NC} Wordlists (SecLists)"
    
    echo -e "\n${YELLOW}[ 🛡️ INFRA & OPSEC ]${NC}"
    echo -e "9) ${PURPLE}🕵️${NC}  Configurar Anonimato (Tor/Proxychains)"
    echo -e "10) ${YELLOW}🔑${NC} Gerenciador de API Keys"
    echo -e "11) ${BLUE}📊${NC} Processar Logs DNS (.json)"
    echo -e "12) ${RED}🔄${NC} Update System & Tools"
    echo -e "0) ${RED}🚪${NC} Sair"
    echo ""
}

main_menu() {
    while true; do
        show_menu
        read -p "$(echo -e ${CYAN}"┌──(ghost㉿ui)-[menu]\n└─$ "${NC})" option
        
        case $option in
            1)
                log "INFO" "Iniciando Full Setup..."
                check_internet
                setup_environment
                install_docker_stack
                install_c2_framework
                install_nuclei_suite
                install_tomnomnom
                install_python_stack
                install_cloud_tools
                install_wordlists
                setup_anonymity
                log "SUCCESS" "Instalação Completa Finalizada!"
                ;;
            2) install_docker_stack ;;
            3) install_c2_framework ;;
            4) install_nuclei_suite ;;
            5) install_tomnomnom ;;
            6) install_python_stack ;;
            7) install_cloud_tools ;;
            8) install_wordlists ;;
            9) setup_anonymity ;;
            10) manage_api_keys ;;
            11) 
                read -p "Caminho do arquivo JSON: " f
                process_dns_scan "$f" 
                ;;
            12) 
                local mgr=$(detect_package_manager)
                log "INFO" "Atualizando sistema via $mgr..."
                if [ "$mgr" == "apt" ]; then sudo apt update && sudo apt upgrade -y; fi
                if [ "$mgr" == "pacman" ]; then sudo pacman -Syu --noconfirm; fi
                if command -v nuclei &> /dev/null; then nuclei -update; fi
                log "SUCCESS" "Sistema atualizado."
                ;;
            0) 
                log "INFO" "Encerrando..."
                exit 0 
                ;;
            *) echo "Opção inválida" ;;
        esac
        
        echo ""
        read -p "Pressione ENTER para continuar..."
    done
}

# ============= EXECUÇÃO =============
trap "echo -e '\n${RED}Interrompido pelo usuário.${NC}'; exit 1" INT TERM
setup_environment
check_root
main_menu
