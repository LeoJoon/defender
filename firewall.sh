#!/bin/bash

# Exit on error
set +e  # Don't exit on error in menu mode

# Colors for output
COLOR_RESET='\033[0m'
COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_BLUE='\033[0;34m'
COLOR_CYAN='\033[0;36m'

# Configuration files
CONFIG_DIR="/etc/nftables"
PORTS_FILE="$CONFIG_DIR/ports.conf"
RATELIMIT_FILE="$CONFIG_DIR/ratelimit.conf"
ICMP_FILE="$CONFIG_DIR/icmp.conf"

# Function to log messages with color and timestamp
log() {
    local LOG_LEVEL=$1
    local MESSAGE=$2
    local TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")

    case $LOG_LEVEL in
        ERROR)
            echo -e "${COLOR_RED}[${TIMESTAMP}] [ERROR] ${MESSAGE}${COLOR_RESET}"
            ;;
        SUCCESS)
            echo -e "${COLOR_GREEN}[${TIMESTAMP}] [SUCCESS] ${MESSAGE}${COLOR_RESET}"
            ;;
        INFO)
            echo -e "${COLOR_BLUE}[${TIMESTAMP}] [INFO] ${MESSAGE}${COLOR_RESET}"
            ;;
        WARNING)
            echo -e "${COLOR_YELLOW}[${TIMESTAMP}] [WARNING] ${MESSAGE}${COLOR_RESET}"
            ;;
        *)
            echo -e "[${TIMESTAMP}] [UNKNOWN] ${MESSAGE}${COLOR_RESET}"
            ;;
    esac
}

# Function to check root privileges
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log "ERROR" "This script must be run as root or with sudo privileges."
        exit 1
    fi
}

# Function to check and install nftables
install_nftables() {
    if ! command -v nft >/dev/null 2>&1; then
        log "INFO" "Installing nftables..."
        apt-get update > /dev/null 2>&1
        apt-get install -y nftables > /dev/null 2>&1
        log "SUCCESS" "nftables installed"
    fi
    
    systemctl enable nftables > /dev/null 2>&1
    systemctl start nftables > /dev/null 2>&1
}

# Function to check if nftables is active
is_nftables_active() {
    nft list ruleset > /dev/null 2>&1
    return $?
}

# Function to get script directory
get_script_dir() {
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
}

# Function to read IPs from Ips.txt
read_blocked_ips() {
    local IPS_FILE="$SCRIPT_DIR/Ips.txt"
    
    if [ ! -f "$IPS_FILE" ]; then
        log "ERROR" "Ips.txt not found in: $SCRIPT_DIR"
        return 1
    fi
    
    BLOCKED_IPS=()
    while IFS= read -r line; do
        if [[ -n "$line" && ! "$line" =~ ^[[:space:]]*# ]]; then
            if [[ "$line" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]]; then
                BLOCKED_IPS+=("$line")
            fi
        fi
    done < "$IPS_FILE"
    
    return 0
}

# Function to save blocked IPs to file
save_blocked_ips() {
    mkdir -p "$CONFIG_DIR"
    
    cat > "$CONFIG_DIR/blocked-ips.nft" << 'EOF'
# Blocked IP ranges from Ips.txt
EOF
    
    if [ ${#BLOCKED_IPS[@]} -gt 0 ]; then
        for ip_range in "${BLOCKED_IPS[@]}"; do
            echo "add rule inet firewall output ip daddr $ip_range drop" >> "$CONFIG_DIR/blocked-ips.nft"
            echo "add rule inet firewall input ip saddr $ip_range drop" >> "$CONFIG_DIR/blocked-ips.nft"
        done
    else
        echo "# No IPs to block" >> "$CONFIG_DIR/blocked-ips.nft"
    fi
}

# Function to load current ports from config
load_ports() {
    USER_PORTS=()
    if [ -f "$PORTS_FILE" ]; then
        while IFS= read -r line; do
            if [[ -n "$line" && ! "$line" =~ ^[[:space:]]*# ]]; then
                USER_PORTS+=("$line")
            fi
        done < "$PORTS_FILE"
    fi
}

# Function to save ports to config
save_ports() {
    mkdir -p "$CONFIG_DIR"
    > "$PORTS_FILE"
    for port_entry in "${USER_PORTS[@]}"; do
        echo "$port_entry" >> "$PORTS_FILE"
    done
}

# Function to load rate limit config
load_ratelimit() {
    RATELIMIT_PORTS=()
    RATELIMIT_RATE=""
    if [ -f "$RATELIMIT_FILE" ]; then
        while IFS= read -r line; do
            if [[ "$line" =~ ^RATE= ]]; then
                RATELIMIT_RATE="${line#RATE=}"
            elif [[ -n "$line" && ! "$line" =~ ^[[:space:]]*# ]]; then
                RATELIMIT_PORTS+=("$line")
            fi
        done < "$RATELIMIT_FILE"
    fi
}

# Function to save rate limit config
save_ratelimit() {
    mkdir -p "$CONFIG_DIR"
    > "$RATELIMIT_FILE"
    if [ -n "$RATELIMIT_RATE" ]; then
        echo "RATE=$RATELIMIT_RATE" >> "$RATELIMIT_FILE"
    fi
    for port_entry in "${RATELIMIT_PORTS[@]}"; do
        echo "$port_entry" >> "$RATELIMIT_FILE"
    done
}

# Function to load ICMP config
load_icmp() {
    ICMP_ENABLED=true
    if [ -f "$ICMP_FILE" ]; then
        ICMP_ENABLED=$(cat "$ICMP_FILE")
    fi
}

# Function to save ICMP config
save_icmp() {
    mkdir -p "$CONFIG_DIR"
    echo "$ICMP_ENABLED" > "$ICMP_FILE"
}

# Function to create nftables rules
create_nftables_rules() {
    log "INFO" "Creating nftables rules..."
    
    nft flush ruleset 2>/dev/null
    
    # Create table
    nft create table inet firewall 2>/dev/null || nft add table inet firewall
    
    # Create rate limit set if needed
    if [ ${#RATELIMIT_PORTS[@]} -gt 0 ] && [ -n "$RATELIMIT_RATE" ]; then
        nft create set inet firewall ratelimit_set { type ipv4_addr \; flags timeout \; timeout 60s \; } 2>/dev/null || \
            nft flush set inet firewall ratelimit_set 2>/dev/null
    fi
    
    # Create chains
    nft create chain inet firewall input { type filter hook input priority 0 \; policy drop \; } 2>/dev/null || \
        (nft flush chain inet firewall input 2>/dev/null; nft delete chain inet firewall input 2>/dev/null; \
         nft create chain inet firewall input { type filter hook input priority 0 \; policy drop \; })
    
    nft create chain inet firewall forward { type filter hook forward priority 0 \; policy drop \; } 2>/dev/null || \
        (nft flush chain inet firewall forward 2>/dev/null; nft delete chain inet firewall forward 2>/dev/null; \
         nft create chain inet firewall forward { type filter hook forward priority 0 \; policy drop \; })
    
    nft create chain inet firewall output { type filter hook output priority 0 \; policy accept \; } 2>/dev/null || \
        (nft flush chain inet firewall output 2>/dev/null; nft delete chain inet firewall output 2>/dev/null; \
         nft create chain inet firewall output { type filter hook output priority 0 \; policy accept \; })
    
    # Allow loopback
    nft add rule inet firewall input iif lo accept
    nft add rule inet firewall output oif lo accept
    
    # Allow established and related
    nft add rule inet firewall input ct state established,related accept
    
    # ICMP
    if [ "$ICMP_ENABLED" = "true" ]; then
        nft add rule inet firewall input ip protocol icmp accept
    fi
    
    # SSH on port 2244 with rate limiting
    if [ ${#RATELIMIT_PORTS[@]} -gt 0 ] && [ -n "$RATELIMIT_RATE" ]; then
        # Check if 2244 is in rate limit ports
        SSH_RATELIMIT=false
        for port_entry in "${RATELIMIT_PORTS[@]}"; do
            IFS='/' read -r port protocol <<< "$port_entry"
            if [ "$port" = "2244" ] && [ "$protocol" = "tcp" ]; then
                SSH_RATELIMIT=true
                break
            fi
        done
        
        if [ "$SSH_RATELIMIT" = "true" ]; then
            nft add rule inet firewall input tcp dport 2244 ct state new limit rate over "$RATELIMIT_RATE"/minute add @ratelimit_set { ip saddr } drop
        fi
    fi
    nft add rule inet firewall input tcp dport 2244 ct state new accept
    
    # User ports with rate limiting
    for port_entry in "${USER_PORTS[@]}"; do
        IFS='/' read -r port protocol <<< "$port_entry"
        
        # Check if this port has rate limiting
        HAS_RATELIMIT=false
        if [ ${#RATELIMIT_PORTS[@]} -gt 0 ] && [ -n "$RATELIMIT_RATE" ]; then
            for rl_port in "${RATELIMIT_PORTS[@]}"; do
                if [ "$rl_port" = "$port_entry" ]; then
                    HAS_RATELIMIT=true
                    break
                fi
            done
        fi
        
        if [ "$HAS_RATELIMIT" = "true" ]; then
            nft add rule inet firewall input "$protocol" dport "$port" ct state new limit rate over "$RATELIMIT_RATE"/minute add @ratelimit_set { ip saddr } drop
        fi
        nft add rule inet firewall input "$protocol" dport "$port" ct state new accept
    done
    
    log "SUCCESS" "nftables rules created"
}

# Function to save rules to file
save_rules() {
    save_blocked_ips
    save_ports
    save_ratelimit
    save_icmp
    
    cat > /etc/nftables.conf << 'EOF'
#!/usr/sbin/nft -f
flush ruleset

table inet firewall {
EOF
    
    # Add rate limit set if needed
    if [ ${#RATELIMIT_PORTS[@]} -gt 0 ] && [ -n "$RATELIMIT_RATE" ]; then
        cat >> /etc/nftables.conf << EOF
    set ratelimit_set {
        type ipv4_addr
        flags timeout
        timeout 60s
    }
EOF
    fi
    
    cat >> /etc/nftables.conf << 'EOF'
    chain input {
        type filter hook input priority 0; policy drop;
        iif lo accept
        ct state established,related accept
EOF
    
    # ICMP
    if [ "$ICMP_ENABLED" = "true" ]; then
        echo "        ip protocol icmp accept" >> /etc/nftables.conf
    fi
    
    # SSH with rate limiting
    SSH_RATELIMIT=false
    if [ ${#RATELIMIT_PORTS[@]} -gt 0 ] && [ -n "$RATELIMIT_RATE" ]; then
        for port_entry in "${RATELIMIT_PORTS[@]}"; do
            IFS='/' read -r port protocol <<< "$port_entry"
            if [ "$port" = "2244" ] && [ "$protocol" = "tcp" ]; then
                SSH_RATELIMIT=true
                break
            fi
        done
    fi
    
    if [ "$SSH_RATELIMIT" = "true" ]; then
        echo "        tcp dport 2244 ct state new limit rate over $RATELIMIT_RATE/minute add @ratelimit_set { ip saddr } drop" >> /etc/nftables.conf
    fi
    echo "        tcp dport 2244 ct state new accept" >> /etc/nftables.conf
    
    # User ports
    for port_entry in "${USER_PORTS[@]}"; do
        IFS='/' read -r port protocol <<< "$port_entry"
        
        HAS_RATELIMIT=false
        if [ ${#RATELIMIT_PORTS[@]} -gt 0 ] && [ -n "$RATELIMIT_RATE" ]; then
            for rl_port in "${RATELIMIT_PORTS[@]}"; do
                if [ "$rl_port" = "$port_entry" ]; then
                    HAS_RATELIMIT=true
                    break
                fi
            done
        fi
        
        if [ "$HAS_RATELIMIT" = "true" ]; then
            echo "        $protocol dport $port ct state new limit rate over $RATELIMIT_RATE/minute add @ratelimit_set { ip saddr } drop" >> /etc/nftables.conf
        fi
        echo "        $protocol dport $port ct state new accept" >> /etc/nftables.conf
    done
    
    cat >> /etc/nftables.conf << 'EOF'
    }
    
    chain forward {
        type filter hook forward priority 0; policy drop;
    }
    
    chain output {
        type filter hook output priority 0; policy accept;
    }
}

include "/etc/nftables/blocked-ips.nft"
EOF
    
    chmod +x /etc/nftables.conf
    log "SUCCESS" "Rules saved to /etc/nftables.conf"
}

# Function to configure SSH
configure_ssh() {
    SSHD_CONFIG="/etc/ssh/sshd_config"
    
    if [ ! -f "$SSHD_CONFIG" ]; then
        log "WARNING" "SSH config not found"
        return
    fi
    
    cp "$SSHD_CONFIG" "${SSHD_CONFIG}.backup.$(date +%Y%m%d_%H%M%S)"
    
    # Comment out all Port lines
    sed -i 's/^Port /#Port /g' "$SSHD_CONFIG"
    
    # Remove any Port 2244
    sed -i '/^#*Port 2244/d' "$SSHD_CONFIG"
    
    # Add Port 2244 without comment
    TEMP_FILE=$(mktemp)
    INSERTED=false
    while IFS= read -r line; do
        if [[ "$line" =~ ^#Port\ 22 ]] && [ "$INSERTED" = false ]; then
            echo "$line" >> "$TEMP_FILE"
            echo "Port 2244" >> "$TEMP_FILE"
            INSERTED=true
        else
            echo "$line" >> "$TEMP_FILE"
        fi
    done < "$SSHD_CONFIG"
    
    if [ "$INSERTED" = false ]; then
        echo "Port 2244" > "$TEMP_FILE"
        cat "$SSHD_CONFIG" >> "$TEMP_FILE"
    fi
    
    mv "$TEMP_FILE" "$SSHD_CONFIG"
    sed -i 's/^#Port 2244/Port 2244/' "$SSHD_CONFIG"
    
    # Configure SSH service
    systemctl stop ssh.socket 2>/dev/null
    systemctl disable ssh.socket 2>/dev/null
    systemctl daemon-reload
    systemctl enable ssh.service 2>/dev/null || systemctl enable ssh 2>/dev/null
    systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
    
    log "SUCCESS" "SSH configured on port 2244"
}

# Function: Install and apply rules
menu_install() {
    clear
    echo -e "${COLOR_CYAN}=== Install and Apply nftables Rules ===${COLOR_RESET}"
    echo ""
    
    check_root
    install_nftables
    get_script_dir
    
    if ! read_blocked_ips; then
        log "ERROR" "Failed to read IPs"
        read -p "Press Enter to continue..."
        return
    fi
    
    load_ports
    load_ratelimit
    load_icmp
    
    create_nftables_rules
    save_rules
    configure_ssh
    
    log "SUCCESS" "Installation completed"
    read -p "Press Enter to continue..."
}

# Function: Add/Update ports
menu_add_ports() {
    clear
    echo -e "${COLOR_CYAN}=== Add/Update Ports ===${COLOR_RESET}"
    echo ""
    
    if ! is_nftables_active; then
        log "WARNING" "nftables is not active. Please install rules first (option 1)."
        read -p "Press Enter to continue..."
        return
    fi
    
    load_ports
    
    echo -e "${COLOR_BLUE}Current open ports (excluding SSH 2244):${COLOR_RESET}"
    if [ ${#USER_PORTS[@]} -eq 0 ]; then
        echo "  (none)"
    else
        for port_entry in "${USER_PORTS[@]}"; do
            echo "  - $port_entry"
        done
    fi
    echo ""
    
    echo "Enter new ports (format: 8443/tcp, 8443/udp, 53/udp, etc.)"
    echo "Separate multiple ports with commas or spaces"
    echo "Press Enter without input to keep current ports"
    echo -n "New ports: "
    read USER_INPUT
    
    if [ -z "$USER_INPUT" ]; then
        log "INFO" "No changes made"
        read -p "Press Enter to continue..."
        return
    fi
    
    # Parse input
    NEW_PORTS=()
    USER_INPUT=$(echo "$USER_INPUT" | tr ',' ' ')
    
    for port_entry in $USER_INPUT; do
        port_entry=$(echo "$port_entry" | xargs)
        if [[ "$port_entry" =~ ^[0-9]+/(tcp|udp)$ ]]; then
            NEW_PORTS+=("$port_entry")
        else
            log "WARNING" "Invalid format: $port_entry (skipping)"
        fi
    done
    
    if [ ${#NEW_PORTS[@]} -eq 0 ]; then
        log "WARNING" "No valid ports entered"
        read -p "Press Enter to continue..."
        return
    fi
    
    # Replace old ports with new ones
    USER_PORTS=("${NEW_PORTS[@]}")
    save_ports
    
    # Recreate rules
    load_ratelimit
    load_icmp
    get_script_dir
    read_blocked_ips
    create_nftables_rules
    save_rules
    
    log "SUCCESS" "Ports updated"
    read -p "Press Enter to continue..."
}

# Function: Update IP list
menu_update_ips() {
    clear
    echo -e "${COLOR_CYAN}=== Update Blocked IP List ===${COLOR_RESET}"
    echo ""
    
    if ! is_nftables_active; then
        log "WARNING" "nftables is not active. Please install rules first (option 1)."
        read -p "Press Enter to continue..."
        return
    fi
    
    get_script_dir
    
    if ! read_blocked_ips; then
        log "ERROR" "Failed to read IPs"
        read -p "Press Enter to continue..."
        return
    fi
    
    log "INFO" "Loaded ${#BLOCKED_IPS[@]} IP ranges"
    
    save_blocked_ips
    
    # Recreate rules
    load_ports
    load_ratelimit
    load_icmp
    create_nftables_rules
    save_rules
    
    log "SUCCESS" "IP list updated"
    read -p "Press Enter to continue..."
}

# Function: Toggle ICMP
menu_toggle_icmp() {
    clear
    echo -e "${COLOR_CYAN}=== Toggle ICMP ===${COLOR_RESET}"
    echo ""
    
    if ! is_nftables_active; then
        log "WARNING" "nftables is not active. Please install rules first (option 1)."
        read -p "Press Enter to continue..."
        return
    fi
    
    load_icmp
    
    if [ "$ICMP_ENABLED" = "true" ]; then
        echo "ICMP is currently: ${COLOR_GREEN}ENABLED${COLOR_RESET}"
        echo -n "Disable ICMP? (y/n): "
    else
        echo "ICMP is currently: ${COLOR_RED}DISABLED${COLOR_RESET}"
        echo -n "Enable ICMP? (y/n): "
    fi
    
    read answer
    if [[ "$answer" =~ ^[Yy]$ ]]; then
        if [ "$ICMP_ENABLED" = "true" ]; then
            ICMP_ENABLED="false"
        else
            ICMP_ENABLED="true"
        fi
        
        save_icmp
        
        # Recreate rules
        load_ports
        load_ratelimit
        get_script_dir
        read_blocked_ips
        create_nftables_rules
        save_rules
        
        log "SUCCESS" "ICMP toggled"
    else
        log "INFO" "No changes made"
    fi
    
    read -p "Press Enter to continue..."
}

# Function: Rate limit submenu
menu_ratelimit() {
    while true; do
        clear
        echo -e "${COLOR_CYAN}=== Rate Limit Management ===${COLOR_RESET}"
        echo ""
        echo "1. Enable/Apply rate limit"
        echo "2. Add port to rate limit"
        echo "3. Change rate limit value"
        echo "4. Remove rate limit"
        echo "5. Back to main menu"
        echo ""
        echo -n "Select option: "
        read choice
        
        case $choice in
            1)
                menu_ratelimit_enable
                ;;
            2)
                menu_ratelimit_add_port
                ;;
            3)
                menu_ratelimit_change_rate
                ;;
            4)
                menu_ratelimit_remove
                ;;
            5)
                return
                ;;
            *)
                log "WARNING" "Invalid option"
                sleep 1
                ;;
        esac
    done
}

# Function: Enable rate limit
menu_ratelimit_enable() {
    clear
    echo -e "${COLOR_CYAN}=== Enable Rate Limit ===${COLOR_RESET}"
    echo ""
    
    if ! is_nftables_active; then
        log "WARNING" "nftables is not active. Please install rules first (option 1)."
        read -p "Press Enter to continue..."
        return
    fi
    
    echo "Enter ports for rate limiting (format: 8443/tcp, 53/udp, etc.)"
    echo "Separate multiple ports with commas or spaces"
    echo -n "Ports: "
    read USER_INPUT
    
    if [ -z "$USER_INPUT" ]; then
        log "WARNING" "No ports entered"
        read -p "Press Enter to continue..."
        return
    fi
    
    NEW_RATELIMIT_PORTS=()
    USER_INPUT=$(echo "$USER_INPUT" | tr ',' ' ')
    
    for port_entry in $USER_INPUT; do
        port_entry=$(echo "$port_entry" | xargs)
        if [[ "$port_entry" =~ ^[0-9]+/(tcp|udp)$ ]]; then
            NEW_RATELIMIT_PORTS+=("$port_entry")
        else
            log "WARNING" "Invalid format: $port_entry (skipping)"
        fi
    done
    
    if [ ${#NEW_RATELIMIT_PORTS[@]} -eq 0 ]; then
        log "WARNING" "No valid ports entered"
        read -p "Press Enter to continue..."
        return
    fi
    
    echo -n "Enter rate limit (e.g., 5 for 5 connections per minute): "
    read RATE_INPUT
    
    if ! [[ "$RATE_INPUT" =~ ^[0-9]+$ ]]; then
        log "ERROR" "Invalid rate value"
        read -p "Press Enter to continue..."
        return
    fi
    
    RATELIMIT_PORTS=("${NEW_RATELIMIT_PORTS[@]}")
    RATELIMIT_RATE="$RATE_INPUT"
    save_ratelimit
    
    # Recreate rules
    load_ports
    load_icmp
    get_script_dir
    read_blocked_ips
    create_nftables_rules
    save_rules
    
    log "SUCCESS" "Rate limit enabled"
    read -p "Press Enter to continue..."
}

# Function: Add port to rate limit
menu_ratelimit_add_port() {
    clear
    echo -e "${COLOR_CYAN}=== Add Port to Rate Limit ===${COLOR_RESET}"
    echo ""
    
    if ! is_nftables_active; then
        log "WARNING" "nftables is not active. Please install rules first (option 1)."
        read -p "Press Enter to continue..."
        return
    fi
    
    load_ratelimit
    
    if [ -z "$RATELIMIT_RATE" ]; then
        log "WARNING" "Rate limit not configured. Please enable it first (option 1)."
        read -p "Press Enter to continue..."
        return
    fi
    
    echo "Current rate limit: $RATELIMIT_RATE/minute"
    echo "Current rate limited ports:"
    if [ ${#RATELIMIT_PORTS[@]} -eq 0 ]; then
        echo "  (none)"
    else
        for port_entry in "${RATELIMIT_PORTS[@]}"; do
            echo "  - $port_entry"
        done
    fi
    echo ""
    
    echo -n "Enter new port (format: 8443/tcp): "
    read PORT_INPUT
    
    if [ -z "$PORT_INPUT" ]; then
        log "WARNING" "No port entered"
        read -p "Press Enter to continue..."
        return
    fi
    
    PORT_INPUT=$(echo "$PORT_INPUT" | xargs)
    if ! [[ "$PORT_INPUT" =~ ^[0-9]+/(tcp|udp)$ ]]; then
        log "ERROR" "Invalid format"
        read -p "Press Enter to continue..."
        return
    fi
    
    # Check if already exists
    for port_entry in "${RATELIMIT_PORTS[@]}"; do
        if [ "$port_entry" = "$PORT_INPUT" ]; then
            log "WARNING" "Port already in rate limit list"
            read -p "Press Enter to continue..."
            return
        fi
    done
    
    RATELIMIT_PORTS+=("$PORT_INPUT")
    save_ratelimit
    
    # Recreate rules
    load_ports
    load_icmp
    get_script_dir
    read_blocked_ips
    create_nftables_rules
    save_rules
    
    log "SUCCESS" "Port added to rate limit"
    read -p "Press Enter to continue..."
}

# Function: Change rate limit value
menu_ratelimit_change_rate() {
    clear
    echo -e "${COLOR_CYAN}=== Change Rate Limit Value ===${COLOR_RESET}"
    echo ""
    
    if ! is_nftables_active; then
        log "WARNING" "nftables is not active. Please install rules first (option 1)."
        read -p "Press Enter to continue..."
        return
    fi
    
    load_ratelimit
    
    if [ -z "$RATELIMIT_RATE" ]; then
        log "WARNING" "Rate limit not configured. Please enable it first (option 1)."
        read -p "Press Enter to continue..."
        return
    fi
    
    echo "Current rate limit: $RATELIMIT_RATE/minute"
    echo -n "Enter new rate limit value: "
    read RATE_INPUT
    
    if ! [[ "$RATE_INPUT" =~ ^[0-9]+$ ]]; then
        log "ERROR" "Invalid rate value"
        read -p "Press Enter to continue..."
        return
    fi
    
    RATELIMIT_RATE="$RATE_INPUT"
    save_ratelimit
    
    # Recreate rules
    load_ports
    load_icmp
    get_script_dir
    read_blocked_ips
    create_nftables_rules
    save_rules
    
    log "SUCCESS" "Rate limit value changed"
    read -p "Press Enter to continue..."
}

# Function: Remove rate limit
menu_ratelimit_remove() {
    clear
    echo -e "${COLOR_CYAN}=== Remove Rate Limit ===${COLOR_RESET}"
    echo ""
    
    if ! is_nftables_active; then
        log "WARNING" "nftables is not active. Please install rules first (option 1)."
        read -p "Press Enter to continue..."
        return
    fi
    
    load_ratelimit
    
    if [ -z "$RATELIMIT_RATE" ]; then
        log "WARNING" "Rate limit not configured"
        read -p "Press Enter to continue..."
        return
    fi
    
    echo "Current rate limit: $RATELIMIT_RATE/minute"
    echo "Rate limited ports:"
    for port_entry in "${RATELIMIT_PORTS[@]}"; do
        echo "  - $port_entry"
    done
    echo ""
    echo -n "Remove all rate limit rules? (y/n): "
    read answer
    
    if [[ "$answer" =~ ^[Yy]$ ]]; then
        RATELIMIT_PORTS=()
        RATELIMIT_RATE=""
        save_ratelimit
        
        # Recreate rules
        load_ports
        load_icmp
        get_script_dir
        read_blocked_ips
        create_nftables_rules
        save_rules
        
        log "SUCCESS" "Rate limit removed"
    else
        log "INFO" "No changes made"
    fi
    
    read -p "Press Enter to continue..."
}

# Function: Flush all rules
menu_flush() {
    clear
    echo -e "${COLOR_CYAN}=== Flush All Rules ===${COLOR_RESET}"
    echo ""
    
    echo -e "${COLOR_RED}WARNING: This will remove all nftables rules!${COLOR_RESET}"
    echo -n "Are you sure? (y/n): "
    read answer
    
    if [[ "$answer" =~ ^[Yy]$ ]]; then
        nft flush ruleset 2>/dev/null
        systemctl stop nftables 2>/dev/null
        systemctl disable nftables 2>/dev/null
        
        # Clear config files
        rm -f "$PORTS_FILE"
        rm -f "$RATELIMIT_FILE"
        rm -f "$ICMP_FILE"
        rm -f "$CONFIG_DIR/blocked-ips.nft"
        
        log "SUCCESS" "All rules flushed and nftables disabled"
    else
        log "INFO" "Operation cancelled"
    fi
    
    read -p "Press Enter to continue..."
}

# Main menu
main_menu() {
    while true; do
        clear
        echo -e "${COLOR_CYAN}=== nftables Firewall Manager ===${COLOR_RESET}"
        echo ""
        echo "1. Install & Apply Rules"
        echo "2. Add/Update Ports"
        echo "3. Update IP List"
        echo "4. On/Off ICMP"
        echo "5. Rate Limit"
        echo "6. Flush All Rules"
        echo "0. Exit"
        echo ""
        echo -n "Select option: "
        read choice
        
        case $choice in
            1)
                menu_install
                ;;
            2)
                menu_add_ports
                ;;
            3)
                menu_update_ips
                ;;
            4)
                menu_toggle_icmp
                ;;
            5)
                menu_ratelimit
                ;;
            6)
                menu_flush
                ;;
            0)
                echo "Goodbye!"
                exit 0
                ;;
            *)
                log "WARNING" "Invalid option"
                sleep 1
                ;;
        esac
    done
}

# Initialize
check_root
mkdir -p "$CONFIG_DIR"

# Start main menu
main_menu
