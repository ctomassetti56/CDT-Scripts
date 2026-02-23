#!/usr/bin/env bash
# ==============================================================================
# SecureNix.sh - Linux Hardening Script
# Blue Team Hardening Script for CDT Competition - Team Alpha Spring 2026
# ==============================================================================
#
# SYNOPSIS:
#   Comprehensive hardening script for Blue vs Red team competitions.
#   Removes/locks unauthorized users, hardens SSH, configures UFW firewall,
#   and locks down the system while preserving competition infrastructure
#   through whitelisting.
#
# BEFORE_RUNNING:
#   **REQUIRED CONFIGURATION - EDIT THESE VARIABLES:**
#
#   1. AUTHORIZED_ADMINS   - Add your blue team usernames (done for you already!)
#   2. SET_ALL_USER_PASSWORDS - Change to YOUR secure password (around line ~130)
#   3. SAFE_IP_ADDRESSES   - Verify scoring engine/jumpbox IPs (done already!)
#
#   **OPTIONAL:** Review SAFE_USERS to ensure all competition users are protected
#
# CRITICAL_RULES:
#   Rule 9:  DO NOT disable any valid user accounts listed in the packet
#   Rule 10: DO NOT disable SSH on Linux machines - only HARDEN it!
#   Rule 15: Blue Team may request up to 3 host reverts per competition day
#   Rule 7:  DO NOT block entire subnets (no subnet blocking)
#   Rule 14: Password changes limited to 3 per host per comp session
#   Rule 5:  DO NOT modify artifacts with "greyteam" in their name
#
# SCORED LINUX SERVICES:
#   ponyville       (10.0.10.3)  Debian 13    Apache2
#   seaddle         (10.0.10.4)  Debian 13    MariaDB
#   trotsylvania    (10.0.10.5)  Debian 13    CUPS
#   crystal-empire  (10.0.10.6)  Debian 13    vsftpd
#   everfree-forest (10.0.20.3)  Debian 13    IRC
#   griffonstone    (10.0.20.4)  Debian 13    Nginx
#   cloudsdale      (10.0.30.4)  Ubuntu 24.04 Workstation
#   vanhoover       (10.0.30.5)  Ubuntu 24.04 Workstation
#   whinnyapolis    (10.0.30.6)  Ubuntu 24.04 Workstation
#
# NOTES:
#   Author:       CDT Team Alpha + Claude AI
#   Requires:     Bash 4+ and root (sudo) privileges
#   Compatible:   Debian 13, Ubuntu 24.04
#   Last Updated: 02/23/2026
#
# USAGE:
#   sudo ./SecureNix.sh [OPTIONS]
#
# OPTIONS:
#   --help           Display this help menu
#   --all            Run ALL phases (same as no args)
#   --phase1         User Account Management
#   --phase2         Password Policy Hardening
#   --phase3         Firewall Hardening (UFW)
#   --phase4         SSH Hardening (NEVER disable - Rule 10!)
#   --phase5         Network Security (disable vulnerable protocols)
#   --phase6         Backdoor Detection
#   --phase7         System Hardening
#   --phase8         Audit Logging (auditd)
#   --phases N,M,... Run selected phases by number (e.g., --phases 1,3,8)
#
# EXAMPLES:
#   sudo ./SecureNix.sh
#   sudo ./SecureNix.sh --all
#   sudo ./SecureNix.sh --phase1
#   sudo ./SecureNix.sh --phase1 --phase3 --phase8
#   sudo ./SecureNix.sh --phases 1,3,8
#   sudo ./SecureNix.sh --help
# ==============================================================================

set -euo pipefail

# ==============================================================================
# ROOT CHECK
# ==============================================================================
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root."
    echo "Usage: sudo ./SecureNix.sh"
    exit 1
fi

# ==============================================================================
# ARGUMENT PARSING
# ==============================================================================
RUN_PHASE1=false
RUN_PHASE2=false
RUN_PHASE3=false
RUN_PHASE4=false
RUN_PHASE5=false
RUN_PHASE6=false
RUN_PHASE7=false
RUN_PHASE8=false
RUNNING_INDIVIDUAL_PHASE=false
SELECTED_PHASES=()

show_help() {
    echo ""
    echo "================================================================================"
    echo "                SecureNix.sh - Linux Hardening Script"
    echo "                CDT Team Alpha - Spring 2026"
    echo "                Time to lock out the Red... For good :)"
    echo "================================================================================"
    echo ""
    echo "USAGE:"
    echo "    sudo ./SecureNix.sh [OPTIONS]"
    echo ""
    echo "OPTIONS:"
    echo "    --help          Display this help menu"
    echo "    --all           Run ALL phases (same as no args)"
    echo "    --phase1        User Account Management   - Lock bad users, change passwords!"
    echo "    --phase2        Password Policy           - Enforce strong passwords via PAM!"
    echo "    --phase3        Firewall Hardening (UFW)  - Block bad traffic, allow scoring!"
    echo "    --phase4        SSH Hardening             - Harden SSH (DO NOT DISABLE - Rule 10)!"
    echo "    --phase5        Network Security          - Disable vulnerable protocols/services!"
    echo "    --phase6        Backdoor Detection        - Scan for sneaky persistence!"
    echo "    --phase7        System Hardening          - Kernel, permissions, AppArmor!"
    echo "    --phase8        Audit Logging (auditd)    - Enable advanced auditing!"
    echo "    --phases N,...  Run selected phases       - e.g., --phases 1,3,8"
    echo ""
    echo "DEFAULT:"
    echo "    (no args)       Run ALL phases"
    echo ""
    echo "EXAMPLES:"
    echo "    sudo ./SecureNix.sh"
    echo "    sudo ./SecureNix.sh --all"
    echo "    sudo ./SecureNix.sh --phase1"
    echo "    sudo ./SecureNix.sh --phase1 --phase3 --phase8"
    echo "    sudo ./SecureNix.sh --phases 1,3,8"
    echo ""
    echo "================================================================================"
    exit 0
}

# Parse arguments
if [[ $# -eq 0 ]]; then
    RUN_PHASE1=true; RUN_PHASE2=true; RUN_PHASE3=true; RUN_PHASE4=true
    RUN_PHASE5=true; RUN_PHASE6=true; RUN_PHASE7=true; RUN_PHASE8=true
    SELECTED_PHASES=(1 2 3 4 5 6 7 8)
else
    PARSED_PHASES=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --help|-h)   show_help ;;
            --all)
                RUN_PHASE1=true; RUN_PHASE2=true; RUN_PHASE3=true; RUN_PHASE4=true
                RUN_PHASE5=true; RUN_PHASE6=true; RUN_PHASE7=true; RUN_PHASE8=true
                SELECTED_PHASES=(1 2 3 4 5 6 7 8)
                ;;
            --phase1)    PARSED_PHASES+=(1) ;;
            --phase2)    PARSED_PHASES+=(2) ;;
            --phase3)    PARSED_PHASES+=(3) ;;
            --phase4)    PARSED_PHASES+=(4) ;;
            --phase5)    PARSED_PHASES+=(5) ;;
            --phase6)    PARSED_PHASES+=(6) ;;
            --phase7)    PARSED_PHASES+=(7) ;;
            --phase8)    PARSED_PHASES+=(8) ;;
            --phases)
                shift
                IFS=',' read -ra nums <<< "$1"
                for n in "${nums[@]}"; do PARSED_PHASES+=("$n"); done
                ;;
            *)
                echo "ERROR: Unknown option: $1"
                echo "Run with --help for usage."
                exit 1
                ;;
        esac
        shift
    done

    if [[ ${#PARSED_PHASES[@]} -gt 0 ]]; then
        mapfile -t SELECTED_PHASES < <(printf '%s\n' "${PARSED_PHASES[@]}" | sort -un)
        RUNNING_INDIVIDUAL_PHASE=true
        for p in "${SELECTED_PHASES[@]}"; do
            if [[ $p -lt 1 || $p -gt 8 ]]; then
                echo "ERROR: Invalid phase number: $p. Valid phases are 1-8."
                exit 1
            fi
        done
        for p in "${SELECTED_PHASES[@]}"; do
            case "$p" in
                1) RUN_PHASE1=true ;;  2) RUN_PHASE2=true ;;
                3) RUN_PHASE3=true ;;  4) RUN_PHASE4=true ;;
                5) RUN_PHASE5=true ;;  6) RUN_PHASE6=true ;;
                7) RUN_PHASE7=true ;;  8) RUN_PHASE8=true ;;
            esac
        done
        echo "========================================"
        echo "RUNNING SELECTED PHASE(S): $(IFS=', '; echo "${SELECTED_PHASES[*]}")"
        echo "========================================"
        echo ""
    fi
fi

# ==============================================================================
# CRITICAL COMPETITION VARIABLES - CDT TEAM ALPHA SPRING 2026
# *** EDIT THE SECTIONS MARKED BELOW BEFORE RUNNING ***
# ==============================================================================

# ---------------------------------------------------------------------------
# SAFE USERS - Competition packet users (Rule 9: DO NOT disable these!)
# ---------------------------------------------------------------------------
SAFE_USERS=(
    # === SYSTEM / SERVICE ACCOUNTS (never touch these) ===
    "root" "daemon" "bin" "sys" "sync" "games" "man" "lp" "mail"
    "news" "uucp" "proxy" "www-data" "backup" "list" "irc" "gnats"
    "nobody" "systemd-network" "systemd-resolve" "systemd-timesync"
    "messagebus" "avahi-autoipd" "sshd" "ntp" "ftp" "cups" "postfix"
    "mysql" "mariadb" "ftpuser" "vsftpd" "nginx" "apache2" "www"
    "_apt" "systemd-coredump" "landscape" "pollinate" "ubuntu" "lxd"
    "tcpdump" "usbmux" "rtkit" "pulse" "saned" "colord" "geoclue"
    "gdm" "lightdm" "sddm" "ircd" "ngircd" "inspircd"

    # === COMPETITION PACKET USERS (Rule 9 - DO NOT DISABLE!) ===
    # Local Users
    "twilight" "pinkiepie" "applejack" "rarity" "rainbowdash" "fluttershy"
    # Local Admins
    "bigmac" "mayormare" "shiningarmor" "cadance"
    # Domain Users (may also exist as local accounts)
    "spike" "starlight" "trixie" "derpy" "snips" "snails"
    # Domain Admins
    "celestia" "discord" "luna" "starswirl"

    # === BLUE TEAM ADMIN ACCOUNTS ===
    # *** ADD YOUR BLUE TEAM USERNAMES HERE ***
    "blueteam"
)

# All competition-packet users (used for password changes)
COMP_USERS=(
    "twilight" "pinkiepie" "applejack" "rarity" "rainbowdash" "fluttershy"
    "bigmac" "mayormare" "shiningarmor" "cadance"
    "spike" "starlight" "trixie" "derpy" "snips" "snails"
    "celestia" "discord" "luna" "starswirl"
)

# Blue team members (accounts YOU control - keep their authorized_keys!)
# *** EDIT THIS LIST WITH YOUR ACTUAL BLUE TEAM USERNAMES ***
AUTHORIZED_ADMINS=(
    "blueteam"
    "celestia"
)

# ---------------------------------------------------------------------------
# PASSWORD CONFIGURATION
# *** CHANGE THIS TO YOUR SECURE PASSWORD BEFORE RUNNING! ***
# CRITICAL: Update on the scoring portal FIRST (Rule 14 - max 3 changes/host)
# ---------------------------------------------------------------------------
SET_ALL_USER_PASSWORDS="<CHANGE-THIS-BEFORE-RUNNING>"   # <--- CHANGE ME

# ---------------------------------------------------------------------------
# SAFE IP ADDRESSES - Scoring engine, jumpboxes, competition infrastructure
# Per Rule 7: These are individual IPs only, NOT subnet blocks!
# ---------------------------------------------------------------------------
SAFE_IP_ADDRESSES=(
    # Scoring engine
    "172.20.0.100"
    # Blue Team jumpboxes
    "172.20.0.40" "172.20.0.41" "172.20.0.42" "172.20.0.43" "172.20.0.44"
    "172.20.0.45" "172.20.0.46" "172.20.0.47" "172.20.0.48" "172.20.0.49"
    # Core subnet (10.0.10.x)
    "10.0.10.1"   # canterlot  - Active Directory
    "10.0.10.2"   # manehatten - MSSQL
    "10.0.10.3"   # ponyville  - Apache2
    "10.0.10.4"   # seaddle    - MariaDB
    "10.0.10.5"   # trotsylvania - CUPS
    "10.0.10.6"   # crystal-empire - vsftpd
    # DMZ subnet (10.0.20.x)
    "10.0.20.1"   # las-pegasus - IIS
    "10.0.20.2"   # appleloosa  - SMB
    "10.0.20.3"   # everfree-forest - IRC
    "10.0.20.4"   # griffonstone - Nginx
    # Internal subnet workstations (10.0.30.x)
    "10.0.30.1"   # baltamare
    "10.0.30.2"   # neighara-falls
    "10.0.30.3"   # fillydelphia
    "10.0.30.4"   # cloudsdale
    "10.0.30.5"   # vanhoover
    "10.0.30.6"   # whinnyapolis
    # Loopback
    "127.0.0.1" "::1"
)

# Scored/allowed service ports (never block these)
SAFE_PORTS=(
    22    # SSH  - Rule 10: NEVER disable SSH on Linux!
    80    # HTTP (Apache2, Nginx, IIS)
    443   # HTTPS / Scoring portal
    444   # Scoring engine netcat port
    3306  # MariaDB / MySQL
    21    # FTP data command (vsftpd)
    20    # FTP data transfer (vsftpd)
    631   # CUPS printing
    6667  # IRC
    6697  # IRC over TLS
    139   # SMB
    445   # SMB
    389   # LDAP
    636   # LDAPS
    88    # Kerberos
    53    # DNS
    3389  # RDP (Windows)
    1433  # MSSQL
)

# ==============================================================================
# LOGGING & STATE INFRASTRUCTURE
# ==============================================================================
LOG_DIR="/var/log/blueteam"
LOG_FILE="$LOG_DIR/SecureNix_$(date +%Y%m%d_%H%M%S).log"
STATE_DIR="/var/lib/blueteam"
STATE_FILE="$STATE_DIR/last-completion-state.json"
SCRIPT_START_TIME=$(date +%s)
HOSTNAME_VAL=$(hostname)
CHANGES=()
REMOVED_USERS=()
SECURITY_ISSUES=()
CHANGES_COUNT=0

mkdir -p "$LOG_DIR" "$STATE_DIR"

# Script run counter
SCRIPT_RUN_COUNT=1
if [[ -f "$STATE_FILE" ]]; then
    prev=$(grep -o '"RunCount":[0-9]*' "$STATE_FILE" 2>/dev/null | grep -o '[0-9]*' || echo 0)
    SCRIPT_RUN_COUNT=$(( prev + 1 ))
fi

# Color codes
C_RESET='\033[0m';   C_RED='\033[0;31m';     C_GREEN='\033[0;32m'
C_YELLOW='\033[1;33m'; C_CYAN='\033[0;36m';  C_MAGENTA='\033[0;35m'
C_WHITE='\033[1;37m';  C_BOLD='\033[1m'

# Log function - writes to file (no color) and console (with color)
log() {
    local msg="$1"
    local level="${2:-INFO}"
    local timestamp; timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    local line="[$timestamp] [$level] $msg"
    echo "$line" >> "$LOG_FILE"
    case "$level" in
        SUCCESS)  echo -e "${C_GREEN}${line}${C_RESET}" ;;
        WARNING)  echo -e "${C_YELLOW}${line}${C_RESET}" ;;
        ERROR)    echo -e "${C_RED}${line}${C_RESET}" ;;
        CRITICAL) echo -e "${C_MAGENTA}${C_BOLD}${line}${C_RESET}" ;;
        REMOVED)  echo -e "${C_CYAN}${line}${C_RESET}" ;;
        *)        echo -e "${C_WHITE}${line}${C_RESET}" ;;
    esac
}

add_change() {
    CHANGES+=("[${1}] ${2} - ${3}${4:+ | $4}")
    (( CHANGES_COUNT++ )) || true
}

add_security_issue() {
    SECURITY_ISSUES+=("$1")
    log "SECURITY ISSUE: $1" "CRITICAL"
}

is_safe_user() {
    local user="$1"
    for su in "${SAFE_USERS[@]}"; do [[ "$su" == "$user" ]] && return 0; done
    return 1
}

# ==============================================================================
# BANNER
# ==============================================================================
echo ""
echo -e "${C_CYAN}================================================================================${C_RESET}"
echo -e "${C_GREEN}           SecureNix.sh - Linux Hardening Script${C_RESET}"
echo -e "${C_GREEN}           CDT Team Alpha - Spring 2026 | FQDN: mlp.local${C_RESET}"
echo -e "${C_GREEN}           Time to lock out the Red... For good :)${C_RESET}"
echo -e "${C_CYAN}================================================================================${C_RESET}"
echo -e "${C_YELLOW}  Host:        $HOSTNAME_VAL${C_RESET}"
echo -e "${C_YELLOW}  Script Run:  #$SCRIPT_RUN_COUNT${C_RESET}"
echo -e "${C_YELLOW}  Log File:    $LOG_FILE${C_RESET}"
echo -e "${C_YELLOW}  Phases:      $(IFS=', '; echo "${SELECTED_PHASES[*]}")${C_RESET}"
echo -e "${C_CYAN}================================================================================${C_RESET}"
echo ""
log "SecureNix.sh started - Run #$SCRIPT_RUN_COUNT | Host: $HOSTNAME_VAL" "INFO"
log "Executing phase(s): $(IFS=', '; echo "${SELECTED_PHASES[*]}")" "INFO"

# ==============================================================================
# PHASE 1 - USER ACCOUNT MANAGEMENT
# ==============================================================================
if $RUN_PHASE1; then
log "" "INFO"
log "============================================================" "INFO"
log "PHASE 1: USER ACCOUNT MANAGEMENT" "CRITICAL"
log "============================================================" "INFO"
log "Rule 9:  DO NOT disable valid competition users!" "WARNING"
log "Rule 14: Password changes limited to 3 per host per session!" "WARNING"
log "IMPORTANT: Update scoring portal BEFORE changing passwords!" "WARNING"

# --- 1a: Lock unauthorized user accounts ------------------------------------
log "Scanning all user accounts for unauthorized entries..." "INFO"
while IFS=: read -r username _ uid _ _ home shell; do
    # Skip system accounts (UID < 1000) and nobody (65534)
    [[ $uid -lt 1000 || $uid -eq 65534 ]] && continue
    # Skip already-nologin accounts
    [[ "$shell" == "/usr/sbin/nologin" || "$shell" == "/bin/false" ]] && continue

    if ! is_safe_user "$username"; then
        log "UNAUTHORIZED USER: $username (UID=$uid, shell=$shell)" "CRITICAL"
        add_security_issue "Unauthorized user account: $username (UID=$uid)"

        # Lock the account (safer than deleting for competition)
        usermod -L "$username" 2>/dev/null && \
            log "Locked account: $username" "REMOVED" || \
            log "Failed to lock: $username" "ERROR"

        # Expire immediately so no login possible
        usermod -e 1 "$username" 2>/dev/null || true

        # Kill any live sessions
        pkill -u "$username" 2>/dev/null || true

        REMOVED_USERS+=("$username (locked)")
        add_change "Users" "Lock unauthorized account" "SUCCESS" "$username"
    fi
done < /etc/passwd

# --- 1b: Check for UID=0 accounts other than root ---------------------------
log "Checking for non-root UID=0 accounts..." "INFO"
while IFS=: read -r username _ uid _; do
    if [[ $uid -eq 0 && "$username" != "root" ]]; then
        add_security_issue "Non-root UID=0 account: $username - INVESTIGATE IMMEDIATELY"
        log "CRITICAL: Non-root UID=0: $username" "CRITICAL"
    fi
done < /etc/passwd

# --- 1c: Audit sudo privileges ----------------------------------------------
log "Auditing sudo configuration..." "INFO"
# sudoers main file
if [[ -f /etc/sudoers ]]; then
    while IFS= read -r line; do
        [[ "$line" =~ ^# || -z "$line" ]] && continue
        if echo "$line" | grep -qE 'NOPASSWD'; then
            add_security_issue "NOPASSWD sudo entry in /etc/sudoers: $line"
            log "WARNING: NOPASSWD sudo: $line" "WARNING"
        fi
    done < /etc/sudoers
fi
# sudoers.d directory
if [[ -d /etc/sudoers.d ]]; then
    for sf in /etc/sudoers.d/*; do
        [[ -f "$sf" ]] || continue
        [[ "$sf" == *greyteam* ]] && continue  # Rule 5
        while IFS= read -r line; do
            [[ "$line" =~ ^# || -z "$line" ]] && continue
            if echo "$line" | grep -qE 'NOPASSWD'; then
                add_security_issue "NOPASSWD sudo in $sf: $line"
                log "WARNING: NOPASSWD sudo in $sf: $line" "WARNING"
            fi
        done < "$sf"
    done
fi

# --- 1d: Audit and clean SSH authorized_keys --------------------------------
log "Auditing SSH authorized_keys files..." "INFO"
for homedir in /home/*/; do
    [[ -d "$homedir" ]] || continue
    auth_keys="$homedir/.ssh/authorized_keys"
    username=$(basename "$homedir")
    if [[ -f "$auth_keys" ]]; then
        key_count=$(grep -vc '^#\|^$' "$auth_keys" 2>/dev/null || echo 0)
        log "Found $key_count SSH key(s) for user: $username" "WARNING"
        # Only clear keys for non-admin users
        if printf '%s\n' "${AUTHORIZED_ADMINS[@]}" | grep -qx "$username"; then
            log "Kept authorized_keys for admin: $username" "INFO"
        else
            cp "$auth_keys" "${auth_keys}.bak.$(date +%s)" 2>/dev/null || true
            > "$auth_keys"
            log "Cleared authorized_keys for: $username" "REMOVED"
            add_change "SSH" "Clear unauthorized authorized_keys" "SUCCESS" "$username"
            add_security_issue "Cleared SSH authorized_keys for: $username ($key_count keys)"
        fi
    fi
done
# Check root
if [[ -f /root/.ssh/authorized_keys ]]; then
    key_count=$(grep -vc '^#\|^$' /root/.ssh/authorized_keys 2>/dev/null || echo 0)
    add_security_issue "SSH authorized_keys found for root ($key_count keys) - review manually!"
    log "WARNING: root authorized_keys has $key_count key(s) - review manually!" "WARNING"
fi

# --- 1e: Change passwords for all competition users -------------------------
log "Changing competition user passwords..." "WARNING"
log "*** Ensure scoring portal is already updated before this step! ***" "CRITICAL"
for cuser in "${COMP_USERS[@]}"; do
    if id "$cuser" &>/dev/null; then
        if echo "$cuser:$SET_ALL_USER_PASSWORDS" | chpasswd 2>/dev/null; then
            log "Password changed: $cuser" "SUCCESS"
            add_change "Users" "Change password" "SUCCESS" "$cuser"
        else
            log "Failed to change password for: $cuser" "ERROR"
        fi
    fi
done

log "Phase 1 complete." "SUCCESS"
fi

# ==============================================================================
# PHASE 2 - PASSWORD POLICY HARDENING
# ==============================================================================
if $RUN_PHASE2; then
log "" "INFO"
log "============================================================" "INFO"
log "PHASE 2: PASSWORD POLICY HARDENING" "CRITICAL"
log "============================================================" "INFO"

# Install PAM password quality lib
if command -v apt-get &>/dev/null; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y libpam-pwquality 2>/dev/null | \
        grep -E "install|upgraded" | while IFS= read -r l; do log "$l" "INFO"; done || true
fi

# --- 2a: /etc/login.defs ----------------------------------------------------
log "Hardening /etc/login.defs..." "INFO"
LOGIN_DEFS="/etc/login.defs"
cp "$LOGIN_DEFS" "${LOGIN_DEFS}.bak.$(date +%s)" 2>/dev/null || true

set_login_def() {
    local key="$1" val="$2"
    if grep -qE "^${key}[[:space:]]" "$LOGIN_DEFS" 2>/dev/null; then
        sed -i "s|^${key}[[:space:]].*|${key}\t${val}|" "$LOGIN_DEFS"
    else
        echo -e "${key}\t${val}" >> "$LOGIN_DEFS"
    fi
}
set_login_def "PASS_MAX_DAYS"  "90"
set_login_def "PASS_MIN_DAYS"  "1"
set_login_def "PASS_MIN_LEN"   "12"
set_login_def "PASS_WARN_AGE"  "7"
set_login_def "LOGIN_RETRIES"  "3"
set_login_def "LOGIN_TIMEOUT"  "60"
set_login_def "DEFAULT_HOME"   "yes"
set_login_def "UMASK"          "027"
add_change "PasswordPolicy" "login.defs hardened" "SUCCESS" "90d max, 12 char min"
log "login.defs updated." "SUCCESS"

# --- 2b: PAM pwquality.conf -------------------------------------------------
log "Configuring /etc/security/pwquality.conf..." "INFO"
PWQUAL="/etc/security/pwquality.conf"
if [[ -f "$PWQUAL" ]]; then
    cp "$PWQUAL" "${PWQUAL}.bak.$(date +%s)" 2>/dev/null || true
    cat > "$PWQUAL" << 'PWEOF'
# SecureNix - CDT Team Alpha - Hardened password quality
minlen = 12
minclass = 3
maxrepeat = 3
maxsequence = 4
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
dictcheck = 1
usercheck = 1
enforcing = 1
PWEOF
    add_change "PasswordPolicy" "pwquality.conf" "SUCCESS" "minlen=12 minclass=3"
    log "pwquality.conf hardened." "SUCCESS"
fi

# --- 2c: PAM common-password (Debian/Ubuntu) --------------------------------
log "Configuring PAM common-password..." "INFO"
PAMPASS="/etc/pam.d/common-password"
if [[ -f "$PAMPASS" ]]; then
    cp "$PAMPASS" "${PAMPASS}.bak.$(date +%s)" 2>/dev/null || true
    if ! grep -q "pam_pwquality" "$PAMPASS"; then
        sed -i '/pam_unix.so/i password\trequisite\t\t\t\tpam_pwquality.so retry=3 enforce_for_root' "$PAMPASS"
    fi
    # Add password history (remember last 5)
    if grep -q "pam_unix.so" "$PAMPASS" && ! grep -q "remember=" "$PAMPASS"; then
        sed -i '/pam_unix.so/ s/$/ remember=5/' "$PAMPASS"
    fi
    add_change "PasswordPolicy" "PAM common-password" "SUCCESS" "pwquality enforced, remember=5"
    log "PAM common-password configured." "SUCCESS"
fi

# --- 2d: PAM account lockout (pam_faillock) ---------------------------------
log "Configuring PAM account lockout (pam_faillock)..." "INFO"
PAMAUTH="/etc/pam.d/common-auth"
PAMACCT="/etc/pam.d/common-account"
if [[ -f "$PAMAUTH" ]]; then
    cp "$PAMAUTH" "${PAMAUTH}.bak.$(date +%s)" 2>/dev/null || true
    if ! grep -q "pam_faillock" "$PAMAUTH"; then
        # Prepend preauth line, append authfail line
        sed -i "1s|^|auth\trequired\t\t\t\tpam_faillock.so preauth silent deny=5 unlock_time=900 fail_interval=900\n|" "$PAMAUTH"
        echo "auth\t[default=die]\t\t\t\tpam_faillock.so authfail deny=5 unlock_time=900 fail_interval=900" >> "$PAMAUTH"
    fi
    add_change "PasswordPolicy" "PAM pam_faillock" "SUCCESS" "deny=5 unlock=15min"
    log "Account lockout configured (5 failures = 15 min lockout)." "SUCCESS"
fi
if [[ -f "$PAMACCT" ]] && ! grep -q "pam_faillock" "$PAMACCT"; then
    echo "account\trequired\t\t\t\tpam_faillock.so" >> "$PAMACCT"
fi

# --- 2e: Password aging on existing competition accounts --------------------
log "Applying password aging to competition users..." "INFO"
for cuser in "${COMP_USERS[@]}"; do
    id "$cuser" &>/dev/null && chage -M 90 -m 1 -W 7 "$cuser" 2>/dev/null || true
done
add_change "PasswordPolicy" "chage aging on all comp users" "SUCCESS" "90d max, 1d min, 7d warn"
log "Password aging applied." "SUCCESS"

log "Phase 2 complete." "SUCCESS"
fi

# ==============================================================================
# PHASE 3 - FIREWALL HARDENING (UFW)
# ==============================================================================
if $RUN_PHASE3; then
log "" "INFO"
log "============================================================" "INFO"
log "PHASE 3: FIREWALL HARDENING (UFW)" "CRITICAL"
log "============================================================" "INFO"
log "Rule 7:  DO NOT block entire subnets!" "WARNING"
log "Rule 10: NEVER block SSH (port 22)!" "WARNING"

# Install UFW if missing
if ! command -v ufw &>/dev/null; then
    log "Installing UFW..." "INFO"
    DEBIAN_FRONTEND=noninteractive apt-get install -y ufw 2>/dev/null || true
fi

# Backup current iptables state
iptables-save  > "$LOG_DIR/iptables_backup_$(date +%s).rules"  2>/dev/null || true
ip6tables-save > "$LOG_DIR/ip6tables_backup_$(date +%s).rules" 2>/dev/null || true
log "iptables rules backed up to $LOG_DIR" "INFO"

# Reset UFW cleanly
log "Resetting UFW..." "INFO"
ufw --force reset 2>/dev/null || true

# Default policies
ufw default deny incoming
ufw default allow outgoing
ufw default deny forward
log "Default policies set: deny incoming, allow outgoing" "INFO"

# --- SSH FIRST (CRITICAL - Rule 10) -----------------------------------------
log "Allowing SSH (port 22) - REQUIRED by Rule 10..." "INFO"
ufw allow 22/tcp
ufw limit ssh    # Rate limiting to slow brute force
add_change "Firewall" "Allow + rate-limit SSH (Rule 10)" "SUCCESS" "port 22/tcp"

# --- Scoring engine and jumpboxes -------------------------------------------
log "Whitelisting scoring engine and jumpbox IPs..." "INFO"
for ip in "${SAFE_IP_ADDRESSES[@]}"; do
    ufw allow from "$ip" to any 2>/dev/null || \
        log "Could not add UFW rule for $ip" "WARNING"
done
add_change "Firewall" "Whitelist safe IPs" "SUCCESS" "${#SAFE_IP_ADDRESSES[@]} IPs added"

# --- Scored service ports ---------------------------------------------------
log "Opening scored service ports..." "INFO"
ufw allow 80/tcp          # HTTP
ufw allow 443/tcp         # HTTPS / scoring portal
ufw allow 444/tcp         # Scoring engine netcat
ufw allow 3306/tcp        # MariaDB (seaddle)
ufw allow 20/tcp          # FTP data (crystal-empire)
ufw allow 21/tcp          # FTP command (crystal-empire)
ufw allow 631/tcp         # CUPS (trotsylvania)
ufw allow 631/udp         # CUPS
ufw allow 6667/tcp        # IRC (everfree-forest)
ufw allow 6697/tcp        # IRC over TLS
ufw allow 53/tcp          # DNS
ufw allow 53/udp          # DNS
ufw allow 88/tcp          # Kerberos (AD interop)
ufw allow 88/udp
ufw allow 389/tcp         # LDAP
ufw allow 636/tcp         # LDAPS
ufw allow 139/tcp         # SMB (NetBIOS)
ufw allow 445/tcp         # SMB
add_change "Firewall" "Scored service ports opened" "SUCCESS" "HTTP,FTP,CUPS,IRC,MariaDB,DNS,LDAP,SMB"

# --- Block known attack / unnecessary ports ---------------------------------
log "Blocking high-risk unnecessary ports..." "INFO"
ufw deny  23/tcp    # Telnet
ufw deny  512/tcp   # rexec
ufw deny  513/tcp   # rlogin
ufw deny  514/tcp   # rsh
ufw deny  69/udp    # TFTP
ufw deny  111/tcp   # RPC portmapper
ufw deny  111/udp
ufw deny  2049/tcp  # NFS (unless needed)
ufw deny  2049/udp
add_change "Firewall" "Blocked risky ports" "SUCCESS" "Telnet, rsh, TFTP, RPC, NFS"

# Enable UFW
log "Enabling UFW firewall..." "INFO"
ufw --force enable
add_change "Firewall" "UFW enabled" "SUCCESS" ""

log "UFW status:" "INFO"
ufw status verbose 2>/dev/null | while IFS= read -r line; do log "  $line" "INFO"; done

log "Phase 3 complete." "SUCCESS"
fi

# ==============================================================================
# PHASE 4 - SSH HARDENING
# ==============================================================================
if $RUN_PHASE4; then
log "" "INFO"
log "============================================================" "INFO"
log "PHASE 4: SSH HARDENING" "CRITICAL"
log "============================================================" "INFO"
log "Rule 10: NEVER disable SSH on Linux - harden it only!" "WARNING"

SSHD_CONFIG="/etc/ssh/sshd_config"
if [[ ! -f "$SSHD_CONFIG" ]]; then
    log "sshd_config not found - is SSH installed?" "ERROR"
else
    cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak.$(date +%s)"
    log "Backed up sshd_config." "INFO"

    # Helper: replace or append an SSH option (removes commented versions too)
    set_ssh_opt() {
        local key="$1" val="$2"
        sed -i "/^#*[[:space:]]*${key}[[:space:]]/d" "$SSHD_CONFIG"
        echo "${key} ${val}" >> "$SSHD_CONFIG"
    }

    log "Hardening SSH configuration..." "INFO"

    # Protocol and authentication
    set_ssh_opt "Protocol"                  "2"
    set_ssh_opt "PermitRootLogin"           "no"
    set_ssh_opt "PermitEmptyPasswords"      "no"
    set_ssh_opt "MaxAuthTries"              "3"
    set_ssh_opt "MaxSessions"              "4"
    set_ssh_opt "LoginGraceTime"            "30"
    set_ssh_opt "UsePAM"                    "yes"

    # Disable dangerous / unneeded features
    set_ssh_opt "X11Forwarding"             "no"
    set_ssh_opt "AllowAgentForwarding"      "no"
    set_ssh_opt "AllowTcpForwarding"        "no"
    set_ssh_opt "PermitTunnel"              "no"
    set_ssh_opt "GatewayPorts"              "no"
    set_ssh_opt "HostbasedAuthentication"   "no"
    set_ssh_opt "IgnoreRhosts"              "yes"

    # Timeout / keepalive
    set_ssh_opt "ClientAliveInterval"       "300"
    set_ssh_opt "ClientAliveCountMax"       "2"
    set_ssh_opt "TCPKeepAlive"              "no"

    # Strict modes and verbose logging
    set_ssh_opt "StrictModes"               "yes"
    set_ssh_opt "LogLevel"                  "VERBOSE"
    set_ssh_opt "SyslogFacility"            "AUTH"
    set_ssh_opt "PrintLastLog"              "yes"

    # Warning banner
    set_ssh_opt "Banner"                    "/etc/ssh/banner"
    cat > /etc/ssh/banner << 'BANNER'
*******************************************************************************
     AUTHORIZED USERS ONLY - CDT Team Alpha Competition System
     All unauthorized access attempts are monitored and logged.
     Legion of Doom: you will not pass!
*******************************************************************************
BANNER
    chmod 644 /etc/ssh/banner 2>/dev/null || true

    # AllowUsers: restrict SSH to only known competition + admin users
    ALL_SSH_USERS=$(printf '%s\n' "${COMP_USERS[@]}" "${AUTHORIZED_ADMINS[@]}" | sort -u | tr '\n' ' ')
    set_ssh_opt "AllowUsers"                "$ALL_SSH_USERS"
    log "AllowUsers restricted to: $ALL_SSH_USERS" "INFO"

    # Secure the sshd_config file itself
    chmod 600 "$SSHD_CONFIG"

    # Validate config before restarting
    log "Validating SSH configuration..." "INFO"
    if sshd -t 2>&1 | tee -a "$LOG_FILE"; then
        systemctl restart sshd 2>/dev/null || service ssh restart 2>/dev/null || true
        add_change "SSH" "sshd hardened and restarted" "SUCCESS" \
            "PermitRootLogin=no X11=no AgentFwd=no AllowUsers set"
        log "SSH hardened and restarted successfully." "SUCCESS"
    else
        log "SSH config validation FAILED - restoring backup!" "ERROR"
        LATEST_BAK=$(ls -t "${SSHD_CONFIG}.bak."* 2>/dev/null | head -1)
        [[ -n "$LATEST_BAK" ]] && cp "$LATEST_BAK" "$SSHD_CONFIG"
        systemctl restart sshd 2>/dev/null || true
        add_security_issue "SSH config validation failed - original config restored!"
    fi
fi

log "Phase 4 complete." "SUCCESS"
fi

# ==============================================================================
# PHASE 5 - NETWORK SECURITY
# ==============================================================================
if $RUN_PHASE5; then
log "" "INFO"
log "============================================================" "INFO"
log "PHASE 5: NETWORK SECURITY" "CRITICAL"
log "============================================================" "INFO"

# --- 5a: Kernel hardening via sysctl ----------------------------------------
log "Applying kernel network hardening (sysctl)..." "INFO"
SYSCTL_FILE="/etc/sysctl.d/99-blueteam-hardening.conf"
cat > "$SYSCTL_FILE" << 'SYSCTL'
# =============================================================================
# SecureNix - CDT Team Alpha - Kernel Hardening
# =============================================================================

# --- Reverse path filtering (anti-spoofing) ---
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# --- Disable IP source routing ---
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# --- Disable ICMP redirect acceptance (prevents MITM) ---
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# --- SYN flood protection ---
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_max_syn_backlog = 4096

# --- Disable IP forwarding (we are not a router) ---
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# --- Log martian packets (suspicious source IPs) ---
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# --- Smurf attack protection ---
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# --- Disable TCP timestamps (info leakage) ---
net.ipv4.tcp_timestamps = 0

# --- TCP RFC 1337 fix ---
net.ipv4.tcp_rfc1337 = 1

# --- ASLR (Address Space Layout Randomization) ---
kernel.randomize_va_space = 2

# --- Kernel pointer restriction ---
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1

# --- Disable core dumps ---
fs.suid_dumpable = 0
kernel.core_pattern = /dev/null

# --- Performance events paranoia ---
kernel.perf_event_paranoid = 3

# --- Hardlink/symlink protection ---
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
SYSCTL

sysctl -p "$SYSCTL_FILE" 2>&1 | while IFS= read -r l; do log "  sysctl: $l" "INFO"; done || true
add_change "Network" "Kernel sysctl hardening applied" "SUCCESS" \
    "ASLR,SYN-cookies,RP-filter,ICMP-hardening,anti-spoof"
log "sysctl hardening applied." "SUCCESS"

# --- 5b: Disable vulnerable services ----------------------------------------
log "Disabling unnecessary/vulnerable services..." "INFO"
DISABLE_SERVICES=(
    "telnet" "rsh" "rlogin" "rexec" "tftp" "xinetd"
    "finger" "talk" "ntalk" "avahi-daemon"
)
for svc in "${DISABLE_SERVICES[@]}"; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        systemctl stop "$svc" 2>/dev/null && systemctl disable "$svc" 2>/dev/null && \
            log "Stopped and disabled: $svc" "SUCCESS" || \
            log "Could not stop: $svc" "WARNING"
        add_change "Network" "Disable service" "SUCCESS" "$svc"
    elif systemctl list-unit-files --quiet "${svc}.service" 2>/dev/null | grep -q "$svc"; then
        systemctl disable "$svc" 2>/dev/null || true
        log "Disabled (was already inactive): $svc" "INFO"
    fi
done

# --- 5c: Remove insecure packages -------------------------------------------
log "Removing insecure network packages..." "INFO"
REMOVE_PKGS=(
    "telnet" "telnetd" "rsh-client" "rsh-server"
    "rlogin" "tftp" "tftpd" "nis" "talk" "talkd"
    "finger" "xinetd"
)
for pkg in "${REMOVE_PKGS[@]}"; do
    if dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
        DEBIAN_FRONTEND=noninteractive apt-get remove -y "$pkg" 2>/dev/null && \
            log "Removed package: $pkg" "SUCCESS" || \
            log "Could not remove: $pkg" "WARNING"
        add_change "Network" "Remove insecure package" "SUCCESS" "$pkg"
    fi
done

# --- 5d: TCP Wrappers (hosts.deny / hosts.allow) ----------------------------
log "Configuring TCP Wrappers..." "INFO"
cp /etc/hosts.deny  /etc/hosts.deny.bak.$(date +%s)  2>/dev/null || true
cp /etc/hosts.allow /etc/hosts.allow.bak.$(date +%s)  2>/dev/null || true

cat > /etc/hosts.deny << 'DENY'
# SecureNix - Deny all by default
ALL: ALL
DENY

{
    echo "# SecureNix - CDT Team Alpha - Allowed hosts"
    echo "ALL: 127.0.0.1"
    echo "ALL: ::1"
    for ip in "${SAFE_IP_ADDRESSES[@]}"; do echo "ALL: $ip"; done
} > /etc/hosts.allow

add_change "Network" "TCP Wrappers configured" "SUCCESS" "deny all, allow safe IPs only"
log "TCP Wrappers configured." "SUCCESS"

# --- 5e: Disable USB mass storage -------------------------------------------
log "Blacklisting USB mass storage..." "INFO"
echo "install usb-storage /bin/true" >  /etc/modprobe.d/blueteam-disable-usb.conf
echo "blacklist usb-storage"         >> /etc/modprobe.d/blueteam-disable-usb.conf
add_change "Network" "USB mass storage blacklisted" "SUCCESS" ""
log "USB storage blacklisted." "INFO"

log "Phase 5 complete." "SUCCESS"
fi

# ==============================================================================
# PHASE 6 - BACKDOOR DETECTION
# ==============================================================================
if $RUN_PHASE6; then
log "" "INFO"
log "============================================================" "INFO"
log "PHASE 6: BACKDOOR DETECTION" "CRITICAL"
log "============================================================" "INFO"

BD_REPORT="$LOG_DIR/backdoor_report_$(date +%Y%m%d_%H%M%S).txt"
log "Writing backdoor report to: $BD_REPORT" "INFO"

{
echo "======================================================================"
echo "  SecureNix - Backdoor Detection Report"
echo "  Host: $HOSTNAME_VAL  |  Date: $(date)"
echo "======================================================================"
} > "$BD_REPORT"

# --- 6a: Listening ports (unexpected = potential backdoor) ------------------
log "Scanning for unexpected listening ports..." "INFO"
{
echo ""
echo "=== LISTENING PORTS ==="
ss -tlnup 2>/dev/null || netstat -tlnup 2>/dev/null || echo "ss/netstat unavailable"
echo ""
} >> "$BD_REPORT"

if command -v ss &>/dev/null; then
    ss -tlnup 2>/dev/null | awk 'NR>1 {print $5}' | grep -oP ':\K[0-9]+' | sort -un | \
    while read -r port; do
        is_safe=false
        for sp in "${SAFE_PORTS[@]}"; do [[ "$port" == "$sp" ]] && is_safe=true && break; done
        if ! $is_safe; then
            log "SUSPICIOUS LISTENING PORT: $port" "CRITICAL"
            add_security_issue "Unexpected listening port: $port"
        fi
    done
fi

# --- 6b: SUID/SGID binaries -------------------------------------------------
log "Scanning for SUID/SGID binaries..." "INFO"
{
echo "=== SUID BINARIES ==="
find / -xdev -perm -4000 -type f 2>/dev/null | sort
echo ""
echo "=== SGID BINARIES ==="
find / -xdev -perm -2000 -type f 2>/dev/null | sort
echo ""
} >> "$BD_REPORT"

KNOWN_SUID=(
    "/bin/su" "/usr/bin/su" "/bin/sudo" "/usr/bin/sudo"
    "/bin/passwd" "/usr/bin/passwd" "/bin/mount" "/usr/bin/mount"
    "/bin/umount" "/usr/bin/umount" "/usr/bin/newgrp" "/usr/bin/chfn"
    "/usr/bin/chsh" "/usr/bin/gpasswd" "/usr/bin/pkexec"
    "/usr/lib/openssh/ssh-keysign" "/bin/ping" "/usr/bin/ping"
    "/usr/bin/at" "/usr/sbin/pppd"
)
find / -xdev -perm -4000 -type f 2>/dev/null | while read -r sf; do
    is_known=false
    for ks in "${KNOWN_SUID[@]}"; do [[ "$sf" == "$ks" ]] && is_known=true && break; done
    if ! $is_known; then
        log "UNUSUAL SUID FILE: $sf" "CRITICAL"
        add_security_issue "Unusual SUID file: $sf"
    fi
done

# --- 6c: Scheduled tasks (cron + systemd timers) ----------------------------
log "Auditing scheduled tasks..." "INFO"
{
echo "=== CRONTAB (/etc/crontab) ==="
cat /etc/crontab 2>/dev/null || echo "(not found)"
echo ""
echo "=== /etc/cron.d/ ==="
for cf in /etc/cron.d/*; do [[ -f "$cf" ]] && echo "--- $cf ---" && cat "$cf"; done
echo ""
echo "=== USER CRONTABS (/var/spool/cron/crontabs/) ==="
ls /var/spool/cron/crontabs/ 2>/dev/null || echo "(empty)"
for uc in /var/spool/cron/crontabs/*; do
    [[ -f "$uc" ]] && echo "--- $(basename $uc) ---" && cat "$uc"
done
echo ""
echo "=== SYSTEMD TIMERS ==="
systemctl list-timers --all 2>/dev/null | head -30
echo ""
} >> "$BD_REPORT"

# Flag crontabs for unauthorized users
for uc in /var/spool/cron/crontabs/*; do
    [[ -f "$uc" ]] || continue
    cron_user=$(basename "$uc")
    if ! is_safe_user "$cron_user"; then
        log "SUSPICIOUS CRONTAB for unauthorized user: $cron_user" "CRITICAL"
        add_security_issue "Crontab for unauthorized user: $cron_user"
    else
        log "Crontab found for: $cron_user (competition user - review contents)" "WARNING"
    fi
done

# --- 6d: Startup scripts & init --------------------------------------------
log "Checking startup/init scripts..." "INFO"
{
echo "=== /etc/rc.local ==="
cat /etc/rc.local 2>/dev/null || echo "(not found)"
echo ""
echo "=== RUNNING SERVICES ==="
systemctl list-units --type=service --state=running 2>/dev/null | head -40
echo ""
} >> "$BD_REPORT"

# --- 6e: World-writable files in sensitive paths ----------------------------
log "Scanning for world-writable files in sensitive paths..." "INFO"
{
echo "=== WORLD-WRITABLE FILES (sensitive dirs) ==="
find /etc /usr/bin /usr/sbin /bin /sbin -xdev -perm -002 -type f 2>/dev/null | sort
echo ""
} >> "$BD_REPORT"

find /etc /usr/bin /usr/sbin /bin /sbin -xdev -perm -002 -type f 2>/dev/null | while read -r wwf; do
    [[ "$wwf" == *greyteam* ]] && continue   # Rule 5
    log "WORLD-WRITABLE IN SENSITIVE PATH: $wwf" "CRITICAL"
    add_security_issue "World-writable sensitive file: $wwf"
    chmod o-w "$wwf" 2>/dev/null && log "Fixed permissions: $wwf" "SUCCESS" || true
done

# --- 6f: /etc/passwd & /etc/shadow anomalies --------------------------------
log "Auditing /etc/passwd and /etc/shadow..." "INFO"
{
echo "=== ACCOUNTS WITH VALID SHELLS (potential login accounts) ==="
grep -v '/nologin\|/false' /etc/passwd 2>/dev/null
echo ""
echo "=== ACCOUNTS WITH EMPTY PASSWORDS ==="
awk -F: '($2 == "" || $2 == "!!")' /etc/shadow 2>/dev/null || echo "(could not read shadow)"
echo ""
} >> "$BD_REPORT"

# Lock empty-password accounts
awk -F: '($2 == "")' /etc/shadow 2>/dev/null | cut -d: -f1 | while read -r emp_user; do
    log "EMPTY PASSWORD - locking: $emp_user" "CRITICAL"
    add_security_issue "Empty password for user: $emp_user"
    passwd -l "$emp_user" 2>/dev/null || true
done

# --- 6g: Running processes ---------------------------------------------------
log "Capturing process and network snapshot..." "INFO"
{
echo "=== RUNNING PROCESSES ==="
ps auxf 2>/dev/null || ps aux 2>/dev/null
echo ""
echo "=== ALL NETWORK CONNECTIONS ==="
ss -anp 2>/dev/null || netstat -anp 2>/dev/null || echo "(unavailable)"
echo ""
} >> "$BD_REPORT"

# --- 6h: Executables in /tmp and /dev/shm -----------------------------------
log "Scanning /tmp and /dev/shm for executables..." "INFO"
{
echo "=== EXECUTABLES IN /tmp ==="
find /tmp -type f -perm /111 2>/dev/null | sort
echo ""
echo "=== HIDDEN FILES IN /tmp ==="
find /tmp -name ".*" -type f 2>/dev/null | sort
echo ""
echo "=== EXECUTABLES IN /dev/shm ==="
find /dev/shm -type f -perm /111 2>/dev/null | sort
echo ""
} >> "$BD_REPORT"

find /tmp /dev/shm -type f -perm /111 2>/dev/null | while read -r tmpexec; do
    log "EXECUTABLE IN TEMP DIR: $tmpexec" "CRITICAL"
    add_security_issue "Executable in temp dir: $tmpexec"
done

# --- 6i: /etc/hosts DNS poisoning check -------------------------------------
log "Checking /etc/hosts for DNS poisoning..." "INFO"
{
echo "=== /etc/hosts ==="
cat /etc/hosts 2>/dev/null
echo ""
} >> "$BD_REPORT"

while IFS= read -r hosts_line; do
    [[ "$hosts_line" =~ ^# || -z "$hosts_line" ]] && continue
    if echo "$hosts_line" | grep -qiE 'scoring|mlp\.local'; then
        if ! echo "$hosts_line" | grep -q "172.20.0.100"; then
            log "POSSIBLE /etc/hosts POISONING: $hosts_line" "CRITICAL"
            add_security_issue "/etc/hosts may be poisoning scoring domain: $hosts_line"
        fi
    fi
done < /etc/hosts 2>/dev/null || true

# --- 6j: Shell init file inspection -----------------------------------------
log "Auditing shell init files..." "INFO"
{
echo "=== /etc/profile ==="
cat /etc/profile 2>/dev/null
echo ""
echo "=== /etc/bash.bashrc ==="
cat /etc/bash.bashrc 2>/dev/null
echo ""
echo "=== USER .bashrc / .profile files ==="
for h in /home/*/; do
    for sf in .bashrc .bash_profile .profile .bash_logout; do
        [[ -f "$h$sf" ]] && echo "--- $h$sf ---" && cat "$h$sf"
    done
done
echo ""
} >> "$BD_REPORT"

# --- 6k: Check for unusual kernel modules -----------------------------------
log "Checking loaded kernel modules..." "INFO"
{
echo "=== LOADED KERNEL MODULES ==="
lsmod 2>/dev/null | head -60
echo ""
} >> "$BD_REPORT"

log "Backdoor scan complete. Report saved: $BD_REPORT" "SUCCESS"
log "Security issues found so far: ${#SECURITY_ISSUES[@]}" "WARNING"
add_change "Backdoor" "Detection scan complete" "SUCCESS" "Report: $BD_REPORT"

log "Phase 6 complete." "SUCCESS"
fi

# ==============================================================================
# PHASE 7 - SYSTEM HARDENING
# ==============================================================================
if $RUN_PHASE7; then
log "" "INFO"
log "============================================================" "INFO"
log "PHASE 7: SYSTEM HARDENING" "CRITICAL"
log "============================================================" "INFO"

# --- 7a: Sensitive file permissions -----------------------------------------
log "Hardening sensitive file permissions..." "INFO"
declare -A FILE_PERMS=(
    ["/etc/passwd"]="644"         ["/etc/group"]="644"
    ["/etc/shadow"]="640"         ["/etc/gshadow"]="640"
    ["/etc/sudoers"]="440"        ["/etc/ssh/sshd_config"]="600"
    ["/etc/crontab"]="600"        ["/etc/hosts"]="644"
    ["/etc/hosts.deny"]="644"     ["/etc/hosts.allow"]="644"
    ["/boot/grub/grub.cfg"]="600"
)
for fpath in "${!FILE_PERMS[@]}"; do
    [[ -f "$fpath" ]] || continue
    chmod "${FILE_PERMS[$fpath]}" "$fpath" 2>/dev/null && \
        log "Permissions set $fpath -> ${FILE_PERMS[$fpath]}" "SUCCESS" || \
        log "Could not chmod $fpath" "WARNING"
done
chown root:shadow /etc/shadow  2>/dev/null || true
chown root:shadow /etc/gshadow 2>/dev/null || true
add_change "SystemHardening" "Sensitive file permissions hardened" "SUCCESS" \
    "shadow=640 sudoers=440 sshd_config=600"

# --- 7b: Harden /tmp (noexec) -----------------------------------------------
log "Hardening /tmp mount options..." "INFO"
if ! grep -qE 'tmpfs[[:space:]]*/tmp' /etc/fstab 2>/dev/null; then
    echo "tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev,size=512M 0 0" >> /etc/fstab
fi
mount -o remount,noexec,nosuid,nodev /tmp 2>/dev/null && \
    log "Remounted /tmp: noexec,nosuid,nodev" "SUCCESS" || \
    log "/tmp remount failed (will apply after reboot)" "WARNING"
add_change "SystemHardening" "/tmp hardened" "SUCCESS" "noexec,nosuid,nodev"

# --- 7c: Secure /dev/shm ----------------------------------------------------
log "Hardening /dev/shm..." "INFO"
if ! grep -qE 'tmpfs[[:space:]]*/dev/shm' /etc/fstab 2>/dev/null; then
    echo "tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
fi
mount -o remount,noexec,nosuid,nodev /dev/shm 2>/dev/null && \
    log "Remounted /dev/shm: noexec,nosuid,nodev" "SUCCESS" || \
    log "/dev/shm remount failed (will apply after reboot)" "WARNING"
add_change "SystemHardening" "/dev/shm hardened" "SUCCESS" "noexec,nosuid,nodev"

# --- 7d: Disable core dumps -------------------------------------------------
log "Disabling core dumps..." "INFO"
{
echo "# SecureNix - Disable core dumps"
echo "* hard core 0"
echo "* soft core 0"
} >> /etc/security/limits.conf
cat > /etc/profile.d/blueteam-hardening.sh << 'PROF'
# SecureNix hardening
ulimit -c 0
PROF
chmod 644 /etc/profile.d/blueteam-hardening.sh
add_change "SystemHardening" "Core dumps disabled" "SUCCESS" ""

# --- 7e: AppArmor enforcement -----------------------------------------------
log "Checking and enforcing AppArmor..." "INFO"
if command -v aa-status &>/dev/null; then
    if aa-status 2>/dev/null | grep -q "profiles are loaded"; then
        aa-enforce /etc/apparmor.d/* 2>/dev/null && \
            log "All AppArmor profiles set to enforce mode." "SUCCESS" || \
            log "Some AppArmor profiles could not be enforced." "WARNING"
        add_change "SystemHardening" "AppArmor enforced" "SUCCESS" ""
    else
        log "AppArmor not loaded - attempting install..." "WARNING"
        DEBIAN_FRONTEND=noninteractive apt-get install -y apparmor apparmor-utils 2>/dev/null && \
            systemctl enable apparmor && systemctl start apparmor && \
            log "AppArmor installed and started." "SUCCESS" || \
            log "AppArmor install failed." "ERROR"
    fi
else
    log "AppArmor utilities not available." "WARNING"
fi

# --- 7f: Restrict compiler access -------------------------------------------
log "Restricting compiler execute permissions for others..." "INFO"
for comp in /usr/bin/gcc /usr/bin/g++ /usr/bin/cc /usr/bin/make; do
    [[ -f "$comp" ]] && chmod o-x "$comp" 2>/dev/null && \
        log "Restricted others execute: $comp" "INFO" || true
done
add_change "SystemHardening" "Compiler access restricted for others" "SUCCESS" ""

# --- 7g: Restrict cron access -----------------------------------------------
log "Restricting cron/at access to root..." "INFO"
echo "root" > /etc/cron.allow   2>/dev/null || true
echo "root" > /etc/at.allow     2>/dev/null || true
> /etc/cron.deny               2>/dev/null || true
> /etc/at.deny                 2>/dev/null || true
chmod 600 /etc/cron.allow /etc/at.allow 2>/dev/null || true
add_change "SystemHardening" "Cron/at access restricted to root" "SUCCESS" ""

# --- 7h: Disable Ctrl+Alt+Del reboot ----------------------------------------
log "Disabling Ctrl+Alt+Del reboot..." "INFO"
systemctl mask ctrl-alt-del.target 2>/dev/null && \
    log "Ctrl+Alt+Del reboot disabled." "SUCCESS" || true
add_change "SystemHardening" "Ctrl+Alt+Del disabled" "SUCCESS" ""

# --- 7i: Remove dangerous offensive packages --------------------------------
log "Removing offensive security tools (if present)..." "INFO"
REMOVE_DANGEROUS=(
    "nmap" "masscan" "hydra" "john" "hashcat"
    "aircrack-ng" "wireshark" "metasploit-framework"
)
for pkg in "${REMOVE_DANGEROUS[@]}"; do
    if dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
        DEBIAN_FRONTEND=noninteractive apt-get remove -y "$pkg" 2>/dev/null && \
            log "Removed: $pkg" "SUCCESS" || \
            log "Could not remove: $pkg" "WARNING"
        add_change "SystemHardening" "Remove offensive tool" "SUCCESS" "$pkg"
    fi
done

# --- 7j: MOTD ------------------------------------------------------------------
log "Setting competition MOTD..." "INFO"
cat > /etc/motd << 'MOTD'
*******************************************************************************
              CDT TEAM ALPHA - Blue Team Competition System
              Spring 2026  |  FQDN: mlp.local
*******************************************************************************
  Authorized users only. All activity is monitored and logged.
  Friendship is Magic, but security is BETTER.
  Legion of Doom: you will not pass!
*******************************************************************************
MOTD
add_change "SystemHardening" "MOTD configured" "SUCCESS" ""

# --- 7k: Enable automatic security updates ----------------------------------
log "Enabling unattended security updates..." "INFO"
if command -v apt-get &>/dev/null; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y unattended-upgrades 2>/dev/null || true
    add_change "SystemHardening" "Unattended security upgrades enabled" "SUCCESS" ""
fi

log "Phase 7 complete." "SUCCESS"
fi

# ==============================================================================
# PHASE 8 - AUDIT LOGGING (auditd)
# ==============================================================================
if $RUN_PHASE8; then
log "" "INFO"
log "============================================================" "INFO"
log "PHASE 8: AUDIT LOGGING (auditd)" "CRITICAL"
log "============================================================" "INFO"

# Install auditd
if ! command -v auditctl &>/dev/null; then
    log "Installing auditd and audisp plugins..." "INFO"
    DEBIAN_FRONTEND=noninteractive apt-get install -y auditd audispd-plugins 2>/dev/null && \
        log "auditd installed." "SUCCESS" || \
        log "auditd install failed - logging may be incomplete." "ERROR"
fi

AUDITD_CONF="/etc/audit/auditd.conf"
AUDIT_RULES_DIR="/etc/audit/rules.d"
AUDIT_RULES="$AUDIT_RULES_DIR/99-blueteam.rules"

mkdir -p "$AUDIT_RULES_DIR"

# --- 8a: Configure auditd.conf ----------------------------------------------
if [[ -f "$AUDITD_CONF" ]]; then
    cp "$AUDITD_CONF" "${AUDITD_CONF}.bak.$(date +%s)" 2>/dev/null || true
    sed -i 's/^max_log_file_action.*/max_log_file_action = rotate/'  "$AUDITD_CONF" || true
    sed -i 's/^num_logs.*/num_logs = 10/'                            "$AUDITD_CONF" || true
    sed -i 's/^max_log_file\s.*/max_log_file = 50/'                 "$AUDITD_CONF" || true
    sed -i 's/^space_left_action.*/space_left_action = syslog/'     "$AUDITD_CONF" || true
    sed -i 's/^admin_space_left_action.*/admin_space_left_action = syslog/' "$AUDITD_CONF" || true
    add_change "Auditing" "auditd.conf configured" "SUCCESS" "rotate 10 logs of 50MB"
    log "auditd.conf configured." "SUCCESS"
fi

# --- 8b: Write comprehensive audit rules ------------------------------------
log "Writing audit rules to $AUDIT_RULES..." "INFO"
cat > "$AUDIT_RULES" << 'AUDITRULES'
# ==============================================================================
# SecureNix - CDT Team Alpha - Comprehensive Audit Rules
# ==============================================================================

## Delete all existing rules
-D

## Buffer size (increase for high-load servers)
-b 8192

## Failure mode: 1=log, 2=kernel panic
-f 1

# ==============================================================================
# AUTHENTICATION & SESSION
# ==============================================================================
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins

# PAM configuration changes
-w /etc/pam.d/ -p wa -k pam_config

# ==============================================================================
# SUDO & PRIVILEGE ESCALATION
# ==============================================================================
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-w /bin/su -p x -k priv_escalation
-w /usr/bin/su -p x -k priv_escalation
-w /bin/sudo -p x -k priv_escalation
-w /usr/bin/sudo -p x -k priv_escalation
-w /usr/bin/newgrp -p x -k priv_escalation

# setuid/setgid syscalls
-a always,exit -F arch=b64 -S setuid -S setgid -S setreuid -S setregid -k setuid_setgid
-a always,exit -F arch=b32 -S setuid -S setgid -S setreuid -S setregid -k setuid_setgid

# ==============================================================================
# USER & GROUP MANAGEMENT
# ==============================================================================
-w /etc/passwd -p wa -k user_accounts
-w /etc/group  -p wa -k user_accounts
-w /etc/shadow -p wa -k user_accounts
-w /etc/gshadow -p wa -k user_accounts
-w /etc/security/opasswd -p wa -k user_accounts

-w /usr/sbin/useradd -p x -k user_mgmt
-w /usr/sbin/usermod -p x -k user_mgmt
-w /usr/sbin/userdel -p x -k user_mgmt
-w /usr/sbin/groupadd -p x -k user_mgmt
-w /usr/sbin/groupmod -p x -k user_mgmt
-w /usr/sbin/groupdel -p x -k user_mgmt
-w /usr/sbin/adduser -p x -k user_mgmt
-w /usr/sbin/deluser -p x -k user_mgmt
-w /usr/bin/passwd -p x -k passwd_changes
-w /usr/bin/chage  -p x -k passwd_changes

# ==============================================================================
# SSH CONFIGURATION & KEYS
# ==============================================================================
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /root/.ssh/ -p wa -k root_ssh
-w /home/ -p wa -k home_dirs

# ==============================================================================
# NETWORK CONFIGURATION
# ==============================================================================
-w /etc/hosts -p wa -k hosts_file
-w /etc/resolv.conf -p wa -k dns_config
-w /etc/network/ -p wa -k network_config
-w /etc/NetworkManager/ -p wa -k network_config
-w /etc/hosts.allow -p wa -k tcp_wrappers
-w /etc/hosts.deny  -p wa -k tcp_wrappers

# ==============================================================================
# FIREWALL CHANGES
# ==============================================================================
-w /etc/ufw/          -p wa -k firewall
-w /etc/iptables/     -p wa -k firewall
-w /usr/sbin/ufw      -p x  -k firewall_cmd
-w /sbin/iptables     -p x  -k firewall_cmd
-w /sbin/ip6tables    -p x  -k firewall_cmd
-w /sbin/nft          -p x  -k firewall_cmd

# ==============================================================================
# SCHEDULED TASKS
# ==============================================================================
-w /etc/crontab  -p wa -k cron
-w /etc/cron.d/  -p wa -k cron
-w /etc/cron.daily/   -p wa -k cron
-w /etc/cron.weekly/  -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /var/spool/cron/   -p wa -k cron
-w /usr/bin/crontab   -p x  -k cron_cmd

# ==============================================================================
# SYSTEMD
# ==============================================================================
-w /etc/systemd/ -p wa -k systemd
-w /lib/systemd/ -p wa -k systemd
-w /usr/lib/systemd/ -p wa -k systemd

# ==============================================================================
# SYSTEM CONFIGURATION
# ==============================================================================
-w /etc/fstab        -p wa -k fstab
-w /etc/rc.local     -p wa -k init_scripts
-w /etc/init.d/      -p wa -k init_scripts
-w /boot/grub/       -p wa -k bootloader
-w /etc/sysctl.conf  -p wa -k sysctl
-w /etc/sysctl.d/    -p wa -k sysctl
-w /sbin/sysctl      -p x  -k sysctl_cmd

# ==============================================================================
# FILE PERMISSION & OWNERSHIP CHANGES
# ==============================================================================
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat  -k file_perm_change
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat  -k file_perm_change
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat  -k file_owner_change
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat  -k file_owner_change

# ==============================================================================
# MOUNT / UNMOUNT
# ==============================================================================
-a always,exit -F arch=b64 -S mount -S umount2 -k mounts
-a always,exit -F arch=b32 -S mount -S umount  -k mounts

# ==============================================================================
# KERNEL MODULE LOADING
# ==============================================================================
-w /sbin/insmod  -p x -k modules
-w /sbin/rmmod   -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S finit_module -S delete_module -k modules

# ==============================================================================
# NETWORK SYSCALLS (detect suspicious outbound connections)
# ==============================================================================
-a always,exit -F arch=b64 -S connect -k network_connect
-a always,exit -F arch=b32 -S connect -k network_connect
-a always,exit -F arch=b64 -S accept  -k network_accept
-a always,exit -F arch=b32 -S accept  -k network_accept
-a always,exit -F arch=b64 -S socket -F a0=2  -k ipv4_socket
-a always,exit -F arch=b64 -S socket -F a0=10 -k ipv6_socket

# ==============================================================================
# SUSPICIOUS LOCATIONS & TOOLS
# ==============================================================================
-w /tmp     -p x -k tmp_exec
-w /var/tmp -p x -k tmp_exec
-w /dev/shm -p x -k shm_exec

# Netcat
-w /bin/nc          -p x -k netcat
-w /usr/bin/nc      -p x -k netcat
-w /bin/netcat      -p x -k netcat
-w /usr/bin/netcat  -p x -k netcat
-w /usr/bin/ncat    -p x -k netcat

# Download tools (watch for Red Team pulling payloads)
-w /usr/bin/wget  -p x -k download_cmd
-w /usr/bin/curl  -p x -k download_cmd

# Recon tools
-w /usr/bin/nmap    -p x -k recon_tools
-w /usr/bin/masscan -p x -k recon_tools

# ==============================================================================
# MAKE RULES IMMUTABLE
# Prevents tampering without a reboot - comment out during initial setup/testing
# ==============================================================================
-e 2
AUDITRULES

# --- 8c: Enable & start auditd ----------------------------------------------
log "Enabling and starting auditd service..." "INFO"
systemctl enable auditd  2>/dev/null || true
systemctl restart auditd 2>/dev/null || service auditd restart 2>/dev/null || true

# Load the new rules
if command -v augenrules &>/dev/null; then
    augenrules --load 2>/dev/null && \
        log "Audit rules loaded successfully." "SUCCESS" || \
        log "Could not load rules with augenrules (may need reboot)." "WARNING"
elif command -v auditctl &>/dev/null; then
    auditctl -R "$AUDIT_RULES" 2>/dev/null && \
        log "Audit rules loaded via auditctl." "SUCCESS" || \
        log "Could not load audit rules (may need reboot)." "WARNING"
fi
add_change "Auditing" "auditd rules deployed and loaded" "SUCCESS" \
    "Auth,users,SSH,net,syscalls,file perms"

# --- 8d: Ensure rsyslog is running ------------------------------------------
log "Ensuring rsyslog is running..." "INFO"
systemctl enable rsyslog 2>/dev/null || true
systemctl start  rsyslog 2>/dev/null || true

# --- 8e: Configure logrotate for BlueTeam logs ------------------------------
log "Setting up log rotation for BlueTeam logs..." "INFO"
cat > /etc/logrotate.d/blueteam << 'LOGROTATE'
/var/log/blueteam/*.log {
    daily
    rotate 30
    compress
    missingok
    notifempty
    create 640 root root
}
LOGROTATE
add_change "Auditing" "Logrotate configured for /var/log/blueteam/" "SUCCESS" ""
log "Log rotation configured." "SUCCESS"

log "Phase 8 complete." "SUCCESS"
fi

# ==============================================================================
# FINAL REPORT & SUMMARY (runs only when ALL phases execute together)
# ==============================================================================
if ! $RUNNING_INDIVIDUAL_PHASE; then

SCRIPT_END_TIME=$(date +%s)
DURATION=$(( SCRIPT_END_TIME - SCRIPT_START_TIME ))

log "" "INFO"
log "============================================================" "INFO"
log "GENERATING FINAL REPORT" "CRITICAL"
log "============================================================" "INFO"

log "" "INFO"
log "EXECUTION SUMMARY:" "INFO"
log "  Host:               $HOSTNAME_VAL" "INFO"
log "  Start time:         $(date -d @"$SCRIPT_START_TIME" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date -r "$SCRIPT_START_TIME" 2>/dev/null || echo 'N/A')" "INFO"
log "  End time:           $(date '+%Y-%m-%d %H:%M:%S')" "INFO"
log "  Duration:           ${DURATION} seconds" "INFO"
log "  Script run #:       $SCRIPT_RUN_COUNT" "INFO"
log "  Total changes:      $CHANGES_COUNT" "INFO"
log "  Accounts locked:    ${#REMOVED_USERS[@]}" "INFO"
log "  Security issues:    ${#SECURITY_ISSUES[@]}" "INFO"
[[ $SCRIPT_RUN_COUNT -gt 1 ]] && \
    log "  Note: Some steps were skipped (already configured in a prior run)." "INFO"

# List all changes
log "" "INFO"
log "CHANGES APPLIED:" "INFO"
for chg in "${CHANGES[@]}"; do log "  + $chg" "INFO"; done

# Locked users
if [[ ${#REMOVED_USERS[@]} -gt 0 ]]; then
    log "" "INFO"
    log "LOCKED/REMOVED ACCOUNTS:" "REMOVED"
    for ru in "${REMOVED_USERS[@]}"; do log "  - $ru" "REMOVED"; done
fi

# Security issues
if [[ ${#SECURITY_ISSUES[@]} -gt 0 ]]; then
    log "" "INFO"
    log "SECURITY ISSUES DETECTED (${#SECURITY_ISSUES[@]} total):" "CRITICAL"
    for si in "${SECURITY_ISSUES[@]}"; do log "  ! $si" "CRITICAL"; done
fi

# Whitelisted IPs
log "" "INFO"
log "WHITELISTED IP ADDRESSES (${#SAFE_IP_ADDRESSES[@]} total):" "INFO"
for ip in "${SAFE_IP_ADDRESSES[@]}"; do log "  - $ip" "INFO"; done

# Recommendations
log "" "INFO"
log "============================================================" "INFO"
log "BLUE TEAM RECOMMENDATIONS - CDT COMPETITION:" "CRITICAL"
log "============================================================" "INFO"
log "1.  REBOOT to apply all kernel / mount changes" "WARNING"
log "2.  REVIEW log file for errors: $LOG_FILE" "WARNING"
log "3.  VERIFY scoring engine: curl -k https://scoring.mlp.local:443" "WARNING"
log "4.  NETCAT scoring: nc scoring.mlp.local 444" "WARNING"
log "5.  CHECK scored services are running:" "WARNING"
log "      Apache2:  systemctl status apache2" "WARNING"
log "      MariaDB:  systemctl status mariadb" "WARNING"
log "      CUPS:     systemctl status cups" "WARNING"
log "      vsftpd:   systemctl status vsftpd" "WARNING"
log "      IRC:      systemctl status ngircd / inspircd" "WARNING"
log "      Nginx:    systemctl status nginx" "WARNING"
log "6.  VERIFY competition users can still SSH into the system" "WARNING"
log "7.  REMEMBER: Max 3 password changes per host per session (Rule 14)!" "CRITICAL"
log "8.  NEVER disable SSH on Linux - Rule 10 violation!" "CRITICAL"
log "9.  NEVER disable competition user accounts - Rule 9 violation!" "CRITICAL"
log "10. NEVER block entire subnets - Rule 7 violation!" "CRITICAL"
log "11. WATCH /var/log/auth.log for Red Team SSH attempts" "WARNING"
log "12. MONITOR audit logs: ausearch -k priv_escalation | tail -50" "WARNING"
log "13. REVIEW backdoor report: ls $LOG_DIR/backdoor_report_*" "WARNING"
log "14. WATCH for re-appearing cron jobs or new user accounts" "WARNING"
log "15. CHECK /etc/hosts wasn't tampered with (DNS poisoning)" "WARNING"
log "16. DO NOT modify any files with 'greyteam' in the name (Rule 5)!" "CRITICAL"
log "17. DOCUMENT all actions taken - needed for inject responses!" "WARNING"
log "18. RUN this script periodically to maintain security posture" "WARNING"

log "" "INFO"
log "============================================================" "INFO"
log "HARDENING COMPLETE - SYSTEM READY FOR COMPETITION" "SUCCESS"
log "============================================================" "INFO"

# Save completion state JSON
cat > "$STATE_FILE" << JSON
{
  "LastRunTime":     "$(date '+%Y-%m-%d %H:%M:%S')",
  "RunCount":        $SCRIPT_RUN_COUNT,
  "ChangesApplied":  $CHANGES_COUNT,
  "AccountsLocked":  ${#REMOVED_USERS[@]},
  "SecurityIssues":  ${#SECURITY_ISSUES[@]},
  "Hostname":        "$HOSTNAME_VAL",
  "ScriptVersion":   "1.0-CDT-Alpha",
  "LogFile":         "$LOG_FILE"
}
JSON

# Final status banner
echo ""
echo -e "${C_CYAN}================================================================================${C_RESET}"
echo -e "${C_GREEN}                    BLUE TEAM HARDENING COMPLETE${C_RESET}"
echo -e "${C_CYAN}================================================================================${C_RESET}"
echo ""
echo -e "${C_WHITE}Script Run #:    ${C_RESET}$(if [[ $SCRIPT_RUN_COUNT -gt 1 ]]; then echo -e "${C_YELLOW}#$SCRIPT_RUN_COUNT${C_RESET}"; else echo -e "${C_GREEN}#$SCRIPT_RUN_COUNT${C_RESET}"; fi)"
echo -e "${C_WHITE}Log File:        ${C_RESET}${C_YELLOW}${LOG_FILE}${C_RESET}"
echo -e "${C_WHITE}Backdoor Report: ${C_RESET}${C_YELLOW}$(ls "$LOG_DIR"/backdoor_report_*.txt 2>/dev/null | tail -1 || echo 'N/A')${C_RESET}"
echo -e "${C_WHITE}Changes Applied: ${C_RESET}${C_GREEN}${CHANGES_COUNT}${C_RESET}"
echo -e "${C_WHITE}Accounts Locked: ${C_RESET}${C_CYAN}${#REMOVED_USERS[@]}${C_RESET}"
if [[ ${#SECURITY_ISSUES[@]} -gt 0 ]]; then
    echo -e "${C_WHITE}Security Issues: ${C_RESET}${C_RED}${#SECURITY_ISSUES[@]} - REVIEW IMMEDIATELY!${C_RESET}"
else
    echo -e "${C_WHITE}Security Issues: ${C_RESET}${C_GREEN}0${C_RESET}"
fi
echo ""
echo -e "${C_CYAN}================================================================================${C_RESET}"
echo ""

# Smart reboot logic (mirrors SecureWin behavior)
SHOULD_REBOOT=false
REBOOT_REASON=""

if [[ $SCRIPT_RUN_COUNT -eq 1 ]]; then
    SHOULD_REBOOT=true
    REBOOT_REASON="First run - reboot required to apply all kernel/mount changes"
elif [[ $CHANGES_COUNT -ge 5 ]]; then
    SHOULD_REBOOT=true
    REBOOT_REASON="Significant changes applied ($CHANGES_COUNT total) - reboot recommended"
else
    echo -e "${C_YELLOW}This is run #$SCRIPT_RUN_COUNT with $CHANGES_COUNT change(s) applied.${C_RESET}"
    echo -e "${C_YELLOW}Most settings are already configured - a reboot may not be necessary.${C_RESET}"
    echo ""
    read -rp "$(echo -e "${C_CYAN}Do you want to reboot now? (y/N): ${C_RESET}")" reboot_choice
    if [[ "$reboot_choice" =~ ^[Yy]$ ]]; then
        SHOULD_REBOOT=true
        REBOOT_REASON="Manual reboot requested"
    else
        echo ""
        echo -e "${C_YELLOW}Reboot skipped. You can reboot later with: sudo reboot${C_RESET}"
        echo ""
        exit 0
    fi
fi

if $SHOULD_REBOOT; then
    log "Initiating system reboot: $REBOOT_REASON" "CRITICAL"
    echo ""
    echo -e "${C_YELLOW}${REBOOT_REASON}${C_RESET}"
    echo ""
    for i in $(seq 10 -1 1); do
        printf "\r${C_YELLOW}Rebooting in ${C_RED}%2d${C_YELLOW} seconds... (Ctrl+C to cancel)${C_RESET}" "$i"
        sleep 1
    done
    echo ""
    echo -e "${C_RED}REBOOTING NOW...${C_RESET}"
    log "Reboot initiated." "CRITICAL"
    sleep 1
    reboot
fi

else
    # Individual phase banner
    echo ""
    echo -e "${C_GREEN}========================================${C_RESET}"
    echo -e "${C_GREEN}Individual Phase(s) Complete${C_RESET}"
    echo -e "${C_GREEN}Phase(s) $(IFS=', '; echo "${SELECTED_PHASES[*]}") executed successfully.${C_RESET}"
    echo -e "${C_YELLOW}Check log: $LOG_FILE${C_RESET}"
    echo -e "${C_GREEN}========================================${C_RESET}"
    echo ""
fi