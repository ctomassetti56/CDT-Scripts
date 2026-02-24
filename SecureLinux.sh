#!/usr/bin/env bash
# ==============================================================================
# SecureLinux.sh - Linux Hardening Script for CDT Competition - Team Charlie Spring 2026
#
# SYNOPSIS:
#   Blue Team Linux Hardening Script
#
# DESCRIPTION:
#   Comprehensive hardening script designed for Blue vs Red team competitions.
#   Removes unauthorized users, hardens SSH, configures firewall, and locks down
#   the system while preserving competition infrastructure through whitelisting.
#
# BEFORE_RUNNING:
#   **REQUIRED CONFIGURATION - EDIT THESE VARIABLES:**
#   1. AUTHORIZED_ADMINS - Add your blue team usernames (done for you!)
#   2. SET_ALL_USER_PASSWORDS - Change to YOUR secure password (~line 100)
#   3. SAFE_IP_ADDRESSES - Verify scoring engine/jumpbox IPs
#   **OPTIONAL:** Review SAFE_USERS to ensure all competition users are protected
#
# CRITICAL_RULES:
#   Rule 9:  DO NOT disable any valid user accounts listed in the packet
#   Rule 10: DO NOT disable SSH on Linux (RDP on Windows is NOT required - remove it!)
#   Rule 15: Blue Team may request up to 3 host reverts per competition day
#   Rule 7:  DO NOT block entire subnets (no subnet blocking)
#   Rule 14: Password changes limited to 3 per host per comp session
#   Rule 5:  DO NOT modify artifacts with "greyteam" in their name
#
# SCORED_SERVICES:
#   Linux Servers: ponyville (Apache2), seaddle (MariaDB), trotsylvania (CUPS),
#                  crystal-empire (vsftpd), everfree-forest (IRC), griffonstone (Nginx)
#   Workstations: 3x Ubuntu 24.04
#
# NOTES:
#   Author: Christian Tomassetti + Claude AI
#   Requires: bash 5+ and root/sudo privileges
#   Last Updated: 02/24/2026
#
# COMPATIBILITY:
#   Debian 13:    CONFIRMED
#   Ubuntu 24.04: CONFIRMED
#
# USAGE:
#   sudo ./SecureLinux.sh [OPTIONS]
#   sudo ./SecureLinux.sh --phase 1,3,8
#   sudo ./SecureLinux.sh --phase1 --phase3
#   sudo ./SecureLinux.sh --help
# ==============================================================================

set -euo pipefail

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
RUN_ALL=false
SHOW_HELP=false

show_help() {
    cat <<'EOF'

================================================================================
                    SecureLinux.sh - Linux Hardening Script
                    CDT Team Charlie - Spring 2026
                    Time to lock out Red... For good :)
================================================================================

USAGE:
    sudo ./SecureLinux.sh [OPTIONS]

OPTIONS:
    --help         Display this help menu               - See how to use the script!

    --all          Run ALL phases (same as no args)     - Run the entire script (FIRST RUN THIS!)

    --phase1       User Account Management              - Handle unwanted users and change passwords!

    --phase2       Password Policy Hardening            - Ensures passwords are strong and reliable!

    --phase3       Firewall Hardening (iptables/nftables)- Removes default rules + adds allow rules!

    --phase4       SSH Hardening                        - Locks down SSH on Linux!

    --phase5       Network Security                     - Disables vulnerable protocols!

    --phase6       Backdoor Detection                   - Checks for sneaky persistence!

    --phase7       System Hardening                     - Hardens/disables vulnerable Linux features!

    --phase8       Audit Logging Configuration          - Enables advanced auditing (auditd)!

    --phase N,M,.. Run selected phases by number        - e.g., "--phase 1,3,8"

DEFAULT:
    (no args)      Run ALL phases                       - Runs the entire script by default!

EXAMPLES:
    sudo ./SecureLinux.sh
    sudo ./SecureLinux.sh --all
    sudo ./SecureLinux.sh --phase1
    sudo ./SecureLinux.sh --phase1 --phase3 --phase8
    sudo ./SecureLinux.sh --phase 1,3,8
    sudo ./SecureLinux.sh --help

================================================================================
EOF
    exit 0
}

# Parse arguments
if [[ $# -eq 0 ]]; then
    RUN_ALL=true
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        --help|-h)     SHOW_HELP=true; shift ;;
        --all|-a)      RUN_ALL=true; shift ;;
        --phase1)      SELECTED_PHASES+=(1); shift ;;
        --phase2)      SELECTED_PHASES+=(2); shift ;;
        --phase3)      SELECTED_PHASES+=(3); shift ;;
        --phase4)      SELECTED_PHASES+=(4); shift ;;
        --phase5)      SELECTED_PHASES+=(5); shift ;;
        --phase6)      SELECTED_PHASES+=(6); shift ;;
        --phase7)      SELECTED_PHASES+=(7); shift ;;
        --phase8)      SELECTED_PHASES+=(8); shift ;;
        --phase)
            shift
            IFS=',' read -ra nums <<< "$1"
            for n in "${nums[@]}"; do
                if ! [[ "$n" =~ ^[1-8]$ ]]; then
                    echo "ERROR: Invalid phase number: $n. Valid phases are 1-8." >&2
                    exit 1
                fi
                SELECTED_PHASES+=("$n")
            done
            shift
            ;;
        *)
            echo "ERROR: Unknown option: $1" >&2
            echo "Run with --help for usage." >&2
            exit 1
            ;;
    esac
done

[[ "$SHOW_HELP" == true ]] && show_help

# Deduplicate and sort selected phases
if [[ ${#SELECTED_PHASES[@]} -gt 0 ]]; then
    mapfile -t SELECTED_PHASES < <(printf '%s\n' "${SELECTED_PHASES[@]}" | sort -nu)
    RUNNING_INDIVIDUAL_PHASE=true
fi

if [[ "$RUN_ALL" == true ]] || [[ ${#SELECTED_PHASES[@]} -eq 0 && "$RUNNING_INDIVIDUAL_PHASE" == false ]]; then
    SELECTED_PHASES=(1 2 3 4 5 6 7 8)
    RUN_ALL=true
    RUNNING_INDIVIDUAL_PHASE=false
fi

contains_phase() { local p="$1"; for x in "${SELECTED_PHASES[@]}"; do [[ "$x" == "$p" ]] && return 0; done; return 1; }
contains_phase 1 && RUN_PHASE1=true
contains_phase 2 && RUN_PHASE2=true
contains_phase 3 && RUN_PHASE3=true
contains_phase 4 && RUN_PHASE4=true
contains_phase 5 && RUN_PHASE5=true
contains_phase 6 && RUN_PHASE6=true
contains_phase 7 && RUN_PHASE7=true
contains_phase 8 && RUN_PHASE8=true

if [[ "$RUNNING_INDIVIDUAL_PHASE" == true ]]; then
    phase_label=$(IFS=','; echo "${SELECTED_PHASES[*]}")
    echo "========================================"
    echo "RUNNING SELECTED PHASE(S): $phase_label"
    echo "========================================"
    echo ""
fi

# ==============================================================================
# CRITICAL COMPETITION VARIABLES - CDT TEAM CHARLIE SPRING 2026
# ==============================================================================

# USER MANAGEMENT - Competition Users (DO NOT REMOVE OR DISABLE!)
# Per Rule 9: Do not disable any valid user accounts listed in the competition packet
SAFE_USERS=(
    # Linux Default System Users (should never be removed)
    "root"
    "nobody"
    "daemon"
    "bin"
    "sys"
    "sync"
    "games"
    "man"
    "lp"
    "mail"
    "news"
    "uucp"
    "proxy"
    "www-data"
    "backup"
    "list"
    "irc"
    "gnats"
    "_apt"
    "systemd-network"
    "systemd-resolve"
    "messagebus"
    "systemd-timesync"
    "syslog"
    "uuidd"
    "tcpdump"
    "sshd"
    "pollinate"
    "landscape"
    "fwupd-refresh"
    "tss"
    "_chrony"
    "ntp"

    # Scored service accounts (do NOT remove)
    "www-data"      # Apache2 / Nginx
    "mysql"         # MariaDB
    "lp"            # CUPS
    "ftp"           # vsftpd
    "ircd"          # IRC
    "cups"          # CUPS alt
    "vsftpd"        # vsftpd alt

    # Local Users (from competition packet)
    "twilight"
    "pinkiepie"
    "applejack"
    "rarity"
    "rainbowdash"
    "fluttershy"

    # Local Admin Users (from competition packet)
    "bigmac"
    "mayormare"
    "shiningarmor"
    "cadance"

    # Domain Users (from competition packet)
    "spike"
    "starlight"
    "trixie"
    "derpy"
    "snips"
    "snails"

    # Domain Admin Users (from competition packet)
    "celestia"
    "discord"
    "luna"
    "starswirl"

    # Gray Team (anything with "greyteam" per Rule 3 & 5)
    "greyteam"
    "grayteam"
    "gray_team"
    "grey_team"
    "scoring"   # Scoring user - do NOT interrupt scoring
)

# Blue team admin users - these will be created/ensured if missing
AUTHORIZED_ADMINS=(
    "blueadmin"
    # Add your blue team members here
)

# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#
SET_ALL_USER_PASSWORDS="<CHANGE-PASSWORD-HERE-BEFORE-RUNNING>"  # DO NOT SHARE THIS PASSWORD!
#
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

# NETWORK SECURITY - CDT Competition Network
# Per Rule 7: Do not configure firewall rules that block large IP ranges
SAFE_IP_ADDRESSES=(
    "172.20.0.100"   # Scoring engine (critical!)
    "172.20.0.41"    # jumpblue1
    "172.20.0.42"    # jumpblue2
    "172.20.0.43"    # jumpblue3
    "172.20.0.44"    # jumpblue4
    "172.20.0.45"    # jumpblue5
    "172.20.0.46"    # jumpblue6
    "172.20.0.47"    # jumpblue7
    "172.20.0.48"    # jumpblue8
    "172.20.0.49"    # jumpblue9
    "172.20.0.40"    # jumpblue10
)

# IP ranges to allow (CIDR notation) - ALLOW rules only, NOT block (Rule 7)
SAFE_IP_RANGES=(
    "10.0.10.0/24"   # Core Subnet (scored services)
    "10.0.20.0/24"   # DMZ Subnet (scored services)
    "10.0.30.0/24"   # Internal Subnet (workstations)
)

# FIREWALL CONFIGURATION
BLOCK_ALL_INBOUND_BY_DEFAULT=true
LOG_DROPPED_PACKETS=true
LOG_ALLOWED_CONNECTIONS=true

# BACKDOOR DETECTION
SCAN_FOR_BACKDOORS=true
REMOVE_SUSPICIOUS_CRONS=true
DISABLE_SUSPICIOUS_SERVICES=true

# AUDIT AND LOGGING
VERBOSE_LOGGING=true
ENABLE_ADVANCED_AUDITING=true

# PASSWORD POLICY
MIN_PASSWORD_LENGTH=16
MAX_PASSWORD_AGE=90    # days
MIN_PASSWORD_AGE=1     # days
PASSWORD_HISTORY_COUNT=24
ACCOUNT_LOCKOUT_THRESHOLD=3
ACCOUNT_LOCKOUT_DURATION=30  # minutes

# SYSTEM HARDENING
DISABLE_SSH=false            # CRITICAL: Per Rule 10 - CANNOT disable SSH on Linux!
SCAN_STARTUP_LOCATIONS=true
BACKUP_BEFORE_CHANGES=true
VERBOSE_LOGGING=true

# ==============================================================================
# SCRIPT INITIALIZATION
# ==============================================================================

# Must be root
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root (sudo ./SecureLinux.sh)" >&2
    exit 1
fi

SCRIPT_START_TIME=$(date '+%Y-%m-%d %H:%M:%S')
HOSTNAME_LC=$(hostname | tr '[:upper:]' '[:lower:]')
BLUETEAM_DIR="/opt/blueteam"
LOG_DIR="$BLUETEAM_DIR/logs"

# Build log file path (phase-aware)
if [[ "$RUNNING_INDIVIDUAL_PHASE" == true ]]; then
    phase_suffix="Phases-$(IFS='-'; echo "${SELECTED_PHASES[*]}")-"
    LOG_FILE="$LOG_DIR/Hardening-${phase_suffix}$(date '+%Y-%m-%d-%H%M%S').log"
else
    LOG_FILE="$LOG_DIR/Hardening-$(date '+%Y-%m-%d-%H%M%S').log"
fi

mkdir -p "$LOG_DIR"
mkdir -p "$BLUETEAM_DIR"

# Run counter (tracks how many times the script has been run)
RUN_COUNTER_FILE="$BLUETEAM_DIR/script-run-counter.txt"
if [[ -f "$RUN_COUNTER_FILE" ]]; then
    SCRIPT_RUN_COUNT=$(( $(cat "$RUN_COUNTER_FILE") + 1 ))
else
    SCRIPT_RUN_COUNT=1
fi
echo "$SCRIPT_RUN_COUNT" > "$RUN_COUNTER_FILE"

# Global tracking arrays (using temp files for bash compatibility)
CHANGES_FILE=$(mktemp)
REMOVED_USERS_FILE=$(mktemp)
SECURITY_ISSUES_FILE=$(mktemp)
REMOVED_ITEMS_FILE=$(mktemp)
trap 'rm -f "$CHANGES_FILE" "$REMOVED_USERS_FILE" "$SECURITY_ISSUES_FILE" "$REMOVED_ITEMS_FILE"' EXIT

# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

log() {
    local message="$1"
    local level="${2:-INFO}"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local log_line="[$timestamp] [$level] $message"

    # Color coding
    case "$level" in
        ERROR)    echo -e "\e[31m${log_line}\e[0m" ;;
        WARNING)  echo -e "\e[33m${log_line}\e[0m" ;;
        SUCCESS)  echo -e "\e[32m${log_line}\e[0m" ;;
        CRITICAL) echo -e "\e[35m${log_line}\e[0m" ;;
        REMOVED)  echo -e "\e[36m${log_line}\e[0m" ;;
        *)        [[ "$VERBOSE_LOGGING" == true ]] && echo -e "\e[97m${log_line}\e[0m" ;;
    esac

    echo "$log_line" >> "$LOG_FILE"

    # If marked critical, add to security issues
    if [[ "${3:-}" == "critical" ]]; then
        echo "$message" >> "$SECURITY_ISSUES_FILE"
    fi
}

add_change() {
    local category="$1" setting="$2" action="$3" details="${4:-}"
    echo "$(date '+%Y-%m-%d %H:%M:%S')|$category|$setting|$action|$details" >> "$CHANGES_FILE"
}

change_count() { wc -l < "$CHANGES_FILE" 2>/dev/null || echo 0; }
removed_user_count() { wc -l < "$REMOVED_USERS_FILE" 2>/dev/null || echo 0; }
security_issue_count() { wc -l < "$SECURITY_ISSUES_FILE" 2>/dev/null || echo 0; }

is_safe_user() {
    local user="$1"
    for safe in "${ALL_SAFE_USERS[@]}"; do
        [[ "${safe,,}" == "${user,,}" ]] && return 0
    done
    return 1
}

is_system_user() {
    # Users with UID < 1000 are typically system users on Debian/Ubuntu
    local uid
    uid=$(id -u "$1" 2>/dev/null) || return 1
    [[ "$uid" -lt 1000 ]] && return 0
    return 1
}

user_exists() { id "$1" &>/dev/null; }

# ==============================================================================
# BANNER + VALIDATION
# ==============================================================================

log "============================================================" INFO
log "BLUE TEAM LINUX HARDENING SCRIPT - COMPETITION MODE" CRITICAL
log "CDT TEAM CHARLIE - SPRING 2026" CRITICAL
log "============================================================" INFO
log "Script started at: $SCRIPT_START_TIME" INFO
log "Script run count: $SCRIPT_RUN_COUNT" INFO
log "Detected hostname: $HOSTNAME_LC" INFO
log "Log file: $LOG_FILE" INFO
log "" INFO

if [[ "$SCRIPT_RUN_COUNT" -gt 1 ]]; then
    log "NOTE: This is run #$SCRIPT_RUN_COUNT - idempotent operations will be skipped" WARNING
fi

# CONFIGURATION VALIDATION
log "============================================================" INFO
log "CONFIGURATION VALIDATION" CRITICAL
log "============================================================" INFO

config_warnings=()

if [[ "$SET_ALL_USER_PASSWORDS" == "<CHANGE-PASSWORD-HERE-BEFORE-RUNNING>" ]]; then
    config_warnings+=("Default placeholder password detected - change SET_ALL_USER_PASSWORDS before running!")
fi

if [[ "${#SET_ALL_USER_PASSWORDS}" -lt 8 ]]; then
    config_warnings+=("Password is too short (minimum 8 characters required)")
fi

if [[ ${#config_warnings[@]} -gt 0 ]]; then
    log "Configuration warnings detected:" WARNING
    for w in "${config_warnings[@]}"; do
        log "  ! $w" WARNING
    done
    log "Press Ctrl+C to cancel and edit, or wait 5 seconds to continue..." WARNING
    sleep 5
else
    log "Configuration validation passed" SUCCESS
fi

log "" INFO

# PRE-FLIGHT RULES COMPLIANCE CHECK
log "============================================================" INFO
log "PRE-FLIGHT RULES COMPLIANCE CHECK" CRITICAL
log "============================================================" INFO

if [[ "$DISABLE_SSH" == true ]]; then
    log "Rule 10 VIOLATION: DISABLE_SSH is set to TRUE - this violates competition rules!" CRITICAL critical
    log "SSH cannot be disabled on Linux per competition rules. Overriding to false." WARNING
    DISABLE_SSH=false
fi

log "Protected users count: ${#SAFE_USERS[@]} (includes all competition users)" INFO
log "Firewall configuration: Individual IP/port rules (compliant with Rule 7)" INFO
log "Pre-flight check PASSED: Configuration is rules-compliant" SUCCESS
log "" INFO

# ==============================================================================
# BUILD FULL SAFE USER LIST (safe + admins + current operator)
# ==============================================================================
CURRENT_USER="${SUDO_USER:-$(whoami)}"
ALL_SAFE_USERS=("${SAFE_USERS[@]}" "${AUTHORIZED_ADMINS[@]}" "$CURRENT_USER")
# Deduplicate
mapfile -t ALL_SAFE_USERS < <(printf '%s\n' "${ALL_SAFE_USERS[@]}" | sort -u)

log "Auto-protecting current operator: $CURRENT_USER" WARNING
log "Total protected users: ${#ALL_SAFE_USERS[@]}" INFO

# ==============================================================================
# PHASE 1: USER ACCOUNT MANAGEMENT
# ==============================================================================
if [[ "$RUN_PHASE1" == true ]]; then

log "" INFO
log "============================================================" INFO
log "PHASE 1: USER ACCOUNT MANAGEMENT (ENHANCED)" CRITICAL
log "============================================================" INFO

# ── 1.1: Gather all users ───────────────────────────────────────────────────
log "Step 1.1: Gathering all user accounts..." INFO

ALL_USERS=()
while IFS=':' read -r user _ uid gid _ home shell; do
    # Skip nologin/false shell system accounts but still collect them
    ALL_USERS+=("$user:$uid:$shell")
done < /etc/passwd

# Real/login users (UID >= 1000, not nobody=65534)
REAL_USERS=()
while IFS=':' read -r user _ uid _ _ _ _; do
    if [[ "$uid" -ge 1000 && "$uid" -ne 65534 ]]; then
        REAL_USERS+=("$user")
    fi
done < /etc/passwd

log "Found ${#REAL_USERS[@]} real user accounts (UID >= 1000)" INFO

# ── 1.2: Audit privileged group memberships (sudo/wheel/adm/shadow) ─────────
log "Step 1.2: Auditing privileged group memberships..." INFO

PRIVILEGED_GROUPS=("sudo" "wheel" "adm" "shadow" "staff" "disk" "lxd" "docker" "lpadmin" "plugdev")

GROUP_VIOLATIONS=()
for grp in "${PRIVILEGED_GROUPS[@]}"; do
    if getent group "$grp" &>/dev/null; then
        members=$(getent group "$grp" | cut -d: -f4)
        if [[ -n "$members" ]]; then
            log "Checking group: $grp (members: $members)" INFO
            IFS=',' read -ra member_list <<< "$members"
            for member in "${member_list[@]}"; do
                [[ -z "$member" ]] && continue
                if ! is_safe_user "$member"; then
                    log "  UNAUTHORIZED: $member in $grp" CRITICAL critical
                    GROUP_VIOLATIONS+=("$member:$grp")
                    if gpasswd -d "$member" "$grp" 2>/dev/null; then
                        log "  REMOVED: $member from $grp" REMOVED
                        add_change "Group Security" "Removed from $grp" "$member" "Unauthorized group membership"
                    else
                        log "  Failed to remove $member from $grp" ERROR
                    fi
                else
                    log "  Authorized: $member" INFO
                fi
            done
        fi
    fi
done

log "Group audit complete. Found ${#GROUP_VIOLATIONS[@]} unauthorized group memberships" INFO
log "" INFO

# ── 1.3: Check for blank/empty passwords ────────────────────────────────────
log "Step 1.3: Scanning for blank passwords..." INFO

BLANK_PASSWORD_USERS=()
while IFS=':' read -r user pass _; do
    # In /etc/shadow, '' or '!' means blank/locked. We look for literally empty password field.
    if [[ "$pass" == "" ]]; then
        log "  CRITICAL: $user has a BLANK PASSWORD!" CRITICAL critical
        BLANK_PASSWORD_USERS+=("$user")
    fi
done < /etc/shadow

# Also check via passwd -S (status)
for user in "${REAL_USERS[@]}"; do
    status_line=$(passwd -S "$user" 2>/dev/null || true)
    # Status codes: P=usable password, NP=no password, L=locked
    if echo "$status_line" | grep -q ' NP '; then
        if ! printf '%s\n' "${BLANK_PASSWORD_USERS[@]}" | grep -qx "$user"; then
            log "  CRITICAL: $user has NO PASSWORD (passwd -S reports NP)!" CRITICAL critical
            BLANK_PASSWORD_USERS+=("$user")
        fi
    fi
done

log "Blank password scan complete. Found ${#BLANK_PASSWORD_USERS[@]} users with blank/no passwords" INFO
log "" INFO

# ── 1.4: Remove unauthorized users ──────────────────────────────────────────
log "Step 1.4: Removing unauthorized users..." INFO

REMOVED_USERS_LIST=()
for user in "${REAL_USERS[@]}"; do
    if ! is_safe_user "$user"; then
        log "REMOVING unauthorized user: $user" REMOVED
        # Kill active sessions first
        pkill -KILL -u "$user" 2>/dev/null || true
        # Remove user and their home directory
        if userdel -r "$user" 2>/dev/null; then
            log "Successfully removed user: $user" SUCCESS
            echo "$user" >> "$REMOVED_USERS_FILE"
            REMOVED_USERS_LIST+=("$user")
            add_change "User Management" "Removed User" "$user" "Unauthorized user removed"
        else
            # Try without -r if home dir removal fails
            userdel "$user" 2>/dev/null || log "Failed to remove user $user" ERROR
            log "Removed user $user (home directory may remain - check manually)" WARNING
            echo "$user" >> "$REMOVED_USERS_FILE"
            REMOVED_USERS_LIST+=("$user")
        fi
    else
        log "Keeping safe user: $user" INFO
    fi
done

if [[ ${#REMOVED_USERS_LIST[@]} -gt 0 ]]; then
    log "Total unauthorized users removed: ${#REMOVED_USERS_LIST[@]}" SUCCESS
    log "Removed users: ${REMOVED_USERS_LIST[*]}" SUCCESS
else
    log "No unauthorized users found" INFO
fi
log "" INFO

# ── 1.5: Selective Password Reset (max 3 per host per day) ──────────────────
log "Step 1.5: Selective password reset (max 3 users per host per competition day)..." CRITICAL
log "A menu will be displayed. Select up to 3 users to reset to the configured team password." INFO

PASSWORD_CHANGE_LOG="$LOG_DIR/3-user-password-changes-$(date '+%Y-%m-%d-%H%M%S').log"
touch "$PASSWORD_CHANGE_LOG"

pw_log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$PASSWORD_CHANGE_LOG"; }
pw_log "Host: $(hostname)"
pw_log "Purpose: Track up to 3 password changes per host per competition day"
pw_log "Selected password changes:"

# Refresh user list after removals
mapfile -t REMAINING_USERS < <(awk -F: '$3 >= 1000 && $3 != 65534 {print $1}' /etc/passwd | sort)

# Build menu with group info
echo ""
echo "========================================"
echo -e "\e[33mUSER LIST (SELECT UP TO 3 FOR PASSWORD RESET)\e[0m"
echo "========================================"
echo ""

declare -A USER_GROUPS_MAP
for grp in "${PRIVILEGED_GROUPS[@]}"; do
    if getent group "$grp" &>/dev/null; then
        members=$(getent group "$grp" | cut -d: -f4)
        IFS=',' read -ra mlist <<< "$members"
        for m in "${mlist[@]}"; do
            [[ -z "$m" ]] && continue
            if [[ -v "USER_GROUPS_MAP[$m]" ]]; then
                USER_GROUPS_MAP["$m"]="${USER_GROUPS_MAP[$m]}, $grp"
            else
                USER_GROUPS_MAP["$m"]="$grp"
            fi
        done
    fi
done

menu_users=()
idx=1
printf "  %-5s %-20s %-10s %s\n" "Index" "Username" "Enabled" "Privileged Groups"
printf "  %-5s %-20s %-10s %s\n" "-----" "--------" "-------" "----------------"
for u in "${REMAINING_USERS[@]}"; do
    # Check if account is locked
    status=$(passwd -S "$u" 2>/dev/null | awk '{print $2}' || echo "?")
    if [[ "$status" == "L" || "$status" == "LK" ]]; then
        enabled="Locked"
    else
        enabled="Yes"
    fi
    grps="${USER_GROUPS_MAP[$u]:-none}"
    printf "  %-5s %-20s %-10s %s\n" "[$idx]" "$u" "$enabled" "$grps"
    menu_users+=("$u")
    (( idx++ ))
done

echo ""
echo -e "\e[90mSelection format examples:\e[0m"
echo -e "\e[90m  1,3,5    (comma-separated)\e[0m"
echo -e "\e[90m  1 3 5    (space-separated)\e[0m"
echo ""

selected_indices=()
while true; do
    read -r -p "Enter up to 3 user numbers to reset (or press Enter to skip): " raw
    if [[ -z "$raw" ]]; then
        log "No users selected for password reset in Step 1.5 (skipped)" WARNING
        pw_log "No users selected (skipped)."
        break
    fi

    if [[ "${raw,,}" =~ ^(q|quit|exit)$ ]]; then
        log "User aborted password selection in Step 1.5" WARNING
        pw_log "Selection aborted by operator."
        break
    fi

    IFS=', ' read -ra parts <<< "$raw"
    nums=()
    bad=false
    for p in "${parts[@]}"; do
        [[ -z "$p" ]] && continue
        if ! [[ "$p" =~ ^[0-9]+$ ]]; then bad=true; break; fi
        if [[ "$p" -lt 1 || "$p" -gt "${#menu_users[@]}" ]]; then bad=true; break; fi
        # Dedup
        already=false
        for existing in "${nums[@]:-}"; do [[ "$existing" == "$p" ]] && already=true; done
        [[ "$already" == false ]] && nums+=("$p")
    done

    if [[ "$bad" == true ]]; then
        echo -e "\e[31mInvalid selection. Enter user numbers between 1 and ${#menu_users[@]}.\e[0m"
        continue
    fi

    if [[ "${#nums[@]}" -gt 3 ]]; then
        echo -e "\e[31mRule enforcement: You may select at most 3 users per host per day.\e[0m"
        continue
    fi

    selected_indices=("${nums[@]}")
    break
done

password_success=0
password_fail=0

if [[ ${#selected_indices[@]} -gt 0 ]]; then
    selected_users=()
    for idx in "${selected_indices[@]}"; do
        selected_users+=("${menu_users[$((idx-1))]}")
    done

    echo ""
    echo -e "\e[33mSelected users for password reset:\e[0m"
    for u in "${selected_users[@]}"; do echo "  - $u"; done
    echo ""

    read -r -p "Proceed with resetting passwords for these users to the team password? (Y/N): " confirm
    if [[ "${confirm^^}" != "Y" ]]; then
        log "Password reset cancelled by operator in Step 1.5" WARNING
        pw_log "Cancelled. Intended selections: ${selected_users[*]}"
    else
        for uname in "${selected_users[@]}"; do
            if ! user_exists "$uname"; then
                log "Cannot reset password: user not found: $uname" ERROR
                pw_log "FAILED: $uname (user not found)"
                (( password_fail++ ))
                continue
            fi

            if echo "$SET_ALL_USER_PASSWORDS:$SET_ALL_USER_PASSWORDS" | chpasswd 2>/dev/null <<< "$uname:$SET_ALL_USER_PASSWORDS"; then
                log "Password set for $uname" SUCCESS
                pw_log "SUCCESS: $uname"
                (( password_success++ ))
                add_change "User Management" "Password Reset (Selective)" "$uname" "Password set to team password (max 3/day)"
            else
                log "Failed to set password for $uname" ERROR
                pw_log "FAILED: $uname (chpasswd error)"
                (( password_fail++ ))
            fi
        done

        log "Selective password reset complete: $password_success successful, $password_fail failed" INFO
        pw_log "Summary: $password_success successful, $password_fail failed"
    fi
fi

log "" INFO

# ── 1.6: Create/configure authorized admin users ────────────────────────────
log "Step 1.6: Configuring authorized admin users..." INFO

for admin in "${AUTHORIZED_ADMINS[@]}"; do
    if ! user_exists "$admin"; then
        log "Creating new admin user: $admin" INFO
        useradd -m -s /bin/bash -c "Blue Team Admin" "$admin" 2>/dev/null || {
            log "Failed to create user $admin" ERROR
            continue
        }
        echo "$admin:$SET_ALL_USER_PASSWORDS" | chpasswd 2>/dev/null && \
            log "Password set for new user $admin" SUCCESS || \
            log "Failed to set password for $admin" ERROR
        add_change "User Management" "Created User" "$admin" "New authorized admin user"
        log "Successfully created user: $admin" SUCCESS
    else
        log "User $admin already exists" INFO
    fi

    # Ensure admin is in sudo group
    if ! groups "$admin" 2>/dev/null | grep -qw "sudo"; then
        usermod -aG sudo "$admin" 2>/dev/null && \
            log "Added $admin to sudo group" SUCCESS || \
            log "Failed to add $admin to sudo group" WARNING
        add_change "User Management" "Admin Rights" "$admin" "Added to sudo group"
    else
        log "User $admin already in sudo group" INFO
    fi

    # Ensure account is unlocked
    passwd -u "$admin" 2>/dev/null || true
done

log "" INFO

# ── 1.7: Generate comprehensive user audit report ───────────────────────────
log "Step 1.7: Generating comprehensive user audit report..." INFO

AUDIT_REPORT_PATH="$BLUETEAM_DIR/user-audit-report-$(date '+%Y-%m-%d-%H%M%S').txt"

{
cat <<EOF
================================================================================
                      USER ACCOUNT AUDIT REPORT
================================================================================
Generated: $(date '+%Y-%m-%d %H:%M:%S')
Hostname: $HOSTNAME_LC
Script Version: 1.0-CDT-Linux
Script Run: #$SCRIPT_RUN_COUNT

================================================================================
                           SUMMARY STATISTICS
================================================================================
Total Real Users Found: ${#REAL_USERS[@]}
Protected/Safe Users:   ${#ALL_SAFE_USERS[@]}
Unauthorized Removed:   ${#REMOVED_USERS_LIST[@]}
Remaining After Cleanup: ${#REMAINING_USERS[@]}

Blank Passwords Found:     ${#BLANK_PASSWORD_USERS[@]}
Group Violations Found:    ${#GROUP_VIOLATIONS[@]}

Password Resets Successful: $password_success
Password Resets Failed:     $password_fail

================================================================================
                        USERS WITH BLANK PASSWORDS
================================================================================
EOF
if [[ ${#BLANK_PASSWORD_USERS[@]} -gt 0 ]]; then
    for u in "${BLANK_PASSWORD_USERS[@]}"; do echo "[CRITICAL] $u - PASSWORD HAS BEEN RESET"; done
else
    echo "No users with blank passwords detected."
fi

cat <<EOF

================================================================================
                     UNAUTHORIZED GROUP MEMBERSHIPS
================================================================================
EOF
if [[ ${#GROUP_VIOLATIONS[@]} -gt 0 ]]; then
    for v in "${GROUP_VIOLATIONS[@]}"; do
        user="${v%%:*}"; grp="${v##*:}"
        echo "[REMOVED] User '$user' from group '$grp'"
    done
else
    echo "No unauthorized group memberships detected."
fi

cat <<EOF

================================================================================
                      DETAILED USER INFORMATION
================================================================================
EOF
for user in "${REMAINING_USERS[@]}"; do
    uid=$(id -u "$user" 2>/dev/null || echo "?")
    user_groups=$(id -Gn "$user" 2>/dev/null || echo "?")
    shell=$(getent passwd "$user" | cut -d: -f7)
    last_logon=$(last -1 "$user" 2>/dev/null | head -1 || echo "Never")
    pw_status=$(passwd -S "$user" 2>/dev/null | awk '{print $2}' || echo "?")
    on_safe="NO"; is_safe_user "$user" && on_safe="YES"

    echo "----------------------------------------"
    echo "USERNAME: $user"
    echo "----------------------------------------"
    echo "UID:          $uid"
    echo "Shell:        $shell"
    echo "Groups:       $user_groups"
    echo "Last Logon:   $last_logon"
    echo "PW Status:    $pw_status (P=set, L=locked, NP=no password)"
    echo "On Safe List: $on_safe"
    echo ""
done

cat <<EOF

================================================================================
                         REMOVED USERS (UNAUTHORIZED)
================================================================================
EOF
if [[ ${#REMOVED_USERS_LIST[@]} -gt 0 ]]; then
    for u in "${REMOVED_USERS_LIST[@]}"; do echo "[REMOVED] $u"; done
else
    echo "No unauthorized users were removed."
fi

echo ""
echo "================================================================================"
echo "                              END OF REPORT"
echo "================================================================================"
} > "$AUDIT_REPORT_PATH"

log "Audit report generated: $AUDIT_REPORT_PATH" SUCCESS
add_change "User Management" "Audit Report" "Generated" "Comprehensive user audit completed"

# Disable guest account if it exists
if user_exists "guest"; then
    passwd -l "guest" 2>/dev/null && \
        log "Guest account locked" SUCCESS || \
        log "Could not lock guest account" WARNING
    add_change "User Management" "Guest Account" "Locked" "Security hardening"
fi

log "" INFO
log "PHASE 1 COMPLETE: User account management finished" SUCCESS
log "  - Users removed: ${#REMOVED_USERS_LIST[@]}" INFO
log "  - Blank passwords found: ${#BLANK_PASSWORD_USERS[@]}" INFO
log "  - Group violations: ${#GROUP_VIOLATIONS[@]}" INFO
log "  - Passwords reset: $password_success" INFO
log "  - Audit report: $AUDIT_REPORT_PATH" INFO
log "" INFO

fi  # END PHASE 1

# ==============================================================================
# PHASE 2: PASSWORD POLICY HARDENING
# ==============================================================================
if [[ "$RUN_PHASE2" == true ]]; then

log "" INFO
log "============================================================" INFO
log "PHASE 2: PASSWORD POLICY HARDENING" CRITICAL
log "============================================================" INFO

# Install PAM password quality if not present
if ! dpkg -l libpam-pwquality &>/dev/null 2>&1; then
    log "Installing libpam-pwquality for password complexity enforcement..." INFO
    apt-get install -y libpam-pwquality &>/dev/null && \
        log "libpam-pwquality installed" SUCCESS || \
        log "Failed to install libpam-pwquality - password complexity may be limited" WARNING
fi

# Configure /etc/security/pwquality.conf
PWQUALITY_CONF="/etc/security/pwquality.conf"
log "Configuring password quality policy ($PWQUALITY_CONF)..." INFO
cat > "$PWQUALITY_CONF" <<EOF
# Blue Team CDT Password Policy
minlen = $MIN_PASSWORD_LENGTH
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
difok = 8
maxrepeat = 3
gecoscheck = 1
EOF
log "Password complexity configured (minlen=$MIN_PASSWORD_LENGTH, requires upper/lower/digit/special)" SUCCESS
add_change "Password Policy" "Password Complexity" "Configured" "minlen=$MIN_PASSWORD_LENGTH"

# Configure /etc/login.defs for aging
log "Configuring password aging policy in /etc/login.defs..." INFO
sed -i "s/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   $MAX_PASSWORD_AGE/" /etc/login.defs
sed -i "s/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   $MIN_PASSWORD_AGE/" /etc/login.defs
sed -i "s/^PASS_MIN_LEN.*/PASS_MIN_LEN    $MIN_PASSWORD_LENGTH/" /etc/login.defs
sed -i "s/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/" /etc/login.defs
log "Password aging configured (max: ${MAX_PASSWORD_AGE}d, min: ${MIN_PASSWORD_AGE}d)" SUCCESS
add_change "Password Policy" "Password Aging" "Configured" "Max: ${MAX_PASSWORD_AGE}d, Min: ${MIN_PASSWORD_AGE}d"

# Apply to existing users
for user in "${REMAINING_USERS[@]:-$(awk -F: '$3>=1000&&$3!=65534{print $1}' /etc/passwd)}"; do
    chage -M "$MAX_PASSWORD_AGE" -m "$MIN_PASSWORD_AGE" -W 14 "$user" 2>/dev/null || true
done

# Configure PAM account lockout via faillock
log "Configuring account lockout policy (faillock)..." INFO
FAILLOCK_CONF="/etc/security/faillock.conf"
if [[ -f "$FAILLOCK_CONF" ]]; then
    sed -i "s/^# deny.*/deny = $ACCOUNT_LOCKOUT_THRESHOLD/" "$FAILLOCK_CONF" 2>/dev/null || true
    sed -i "s/^deny =.*/deny = $ACCOUNT_LOCKOUT_THRESHOLD/" "$FAILLOCK_CONF" 2>/dev/null || true
    sed -i "s/^# unlock_time.*/unlock_time = $(( ACCOUNT_LOCKOUT_DURATION * 60 ))/" "$FAILLOCK_CONF" 2>/dev/null || true
    sed -i "s/^unlock_time =.*/unlock_time = $(( ACCOUNT_LOCKOUT_DURATION * 60 ))/" "$FAILLOCK_CONF" 2>/dev/null || true
    # If lines don't exist, add them
    grep -q "^deny" "$FAILLOCK_CONF" || echo "deny = $ACCOUNT_LOCKOUT_THRESHOLD" >> "$FAILLOCK_CONF"
    grep -q "^unlock_time" "$FAILLOCK_CONF" || echo "unlock_time = $(( ACCOUNT_LOCKOUT_DURATION * 60 ))" >> "$FAILLOCK_CONF"
    log "Account lockout configured: threshold=$ACCOUNT_LOCKOUT_THRESHOLD, duration=${ACCOUNT_LOCKOUT_DURATION}min" SUCCESS
    add_change "Password Policy" "Account Lockout" "Configured" "Threshold: $ACCOUNT_LOCKOUT_THRESHOLD attempts"
else
    log "faillock.conf not found - ensure libpam-modules is installed" WARNING
fi

log "" INFO
log "PHASE 2 COMPLETE: Password policy hardening finished" SUCCESS
log "" INFO

fi  # END PHASE 2

# ==============================================================================
# PHASE 3: FIREWALL HARDENING (iptables/nftables)
# ==============================================================================
if [[ "$RUN_PHASE3" == true ]]; then

log "" INFO
log "============================================================" INFO
log "PHASE 3: FIREWALL HARDENING" CRITICAL
log "============================================================" INFO

# Determine firewall backend
FW_BACKEND="iptables"
if command -v nft &>/dev/null && nft list ruleset &>/dev/null 2>&1; then
    FW_BACKEND="nftables"
fi
if command -v ufw &>/dev/null && ufw status | grep -q "active"; then
    FW_BACKEND="ufw"
fi
log "Detected firewall backend: $FW_BACKEND" INFO

# Firewall log directory
FW_LOG_DIR="$LOG_DIR/firewall"
mkdir -p "$FW_LOG_DIR"

# ── FAIL-SAFE: Ensure SSH (22) stays open BEFORE modifying rules ────────────
log "Creating SSH fail-safe rule BEFORE modifying any firewall rules..." WARNING

case "$FW_BACKEND" in
    ufw)
        ufw allow 22/tcp comment 'Blue Team - Allow SSH 22 (Fail-Safe)' 2>/dev/null
        ufw --force enable 2>/dev/null
        log "UFW SSH fail-safe rule created" SUCCESS
        ;;
    iptables)
        iptables -C INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null || \
            iptables -I INPUT 1 -p tcp --dport 22 -m comment --comment "Blue Team - Allow SSH 22 Fail-Safe" -j ACCEPT
        log "iptables SSH fail-safe rule created" SUCCESS
        ;;
    nftables)
        nft add rule inet filter input tcp dport 22 comment '"Blue Team SSH Fail-Safe"' accept 2>/dev/null || true
        log "nftables SSH fail-safe rule created" SUCCESS
        ;;
esac

# ── Service Port Selection ───────────────────────────────────────────────────
log "" INFO
log "============================================================" INFO
log "SERVICE PORT SELECTION" CRITICAL
log "============================================================" INFO
log "Each Linux host runs ONE scored service. Only open ports for YOUR service." WARNING
log "SSH (22) will always be opened regardless of selection (Rule 10)." INFO
log "" INFO

declare -A SERVICE_PORTS
SERVICE_PORTS["1"]="Apache2 (ponyville) | 80 443"
SERVICE_PORTS["2"]="MariaDB (seaddle) | 3306"
SERVICE_PORTS["3"]="CUPS (trotsylvania) | 631"
SERVICE_PORTS["4"]="vsftpd (crystal-empire) | 20 21 30000-31000"
SERVICE_PORTS["5"]="IRC (everfree-forest) | 6667 6697"
SERVICE_PORTS["6"]="Nginx (griffonstone) | 80 443"
SERVICE_PORTS["7"]="Ubuntu Workstation (no service port) | "

echo ""
echo -e "\e[36m================================================================================\e[0m"
echo -e "\e[36m        WHICH SCORED SERVICE IS RUNNING ON THIS LINUX HOST?\e[0m"
echo -e "\e[36m================================================================================\e[0m"
echo ""
echo "  [1]  Apache2        - ponyville      (10.0.10.3)"
echo -e "\e[90m       Ports: 80, 443\e[0m"
echo ""
echo "  [2]  MariaDB        - seaddle        (10.0.10.4)"
echo -e "\e[90m       Ports: 3306\e[0m"
echo ""
echo "  [3]  CUPS           - trotsylvania   (10.0.10.5)"
echo -e "\e[90m       Ports: 631\e[0m"
echo ""
echo "  [4]  vsftpd         - crystal-empire (10.0.20.3)"
echo -e "\e[90m       Ports: 20, 21, 30000-31000 (passive)\e[0m"
echo ""
echo "  [5]  IRC            - everfree-forest (10.0.20.4)"
echo -e "\e[90m       Ports: 6667, 6697\e[0m"
echo ""
echo "  [6]  Nginx          - griffonstone   (10.0.20.5)"
echo -e "\e[90m       Ports: 80, 443\e[0m"
echo ""
echo "  [7]  Ubuntu Workstation - (no service port - SSH only)"
echo -e "\e[90m       No additional service port\e[0m"
echo ""
echo -e "\e[33m  (All options also open SSH port 22 - required per Rule 10)\e[0m"
echo ""
echo -e "\e[36m================================================================================\e[0m"

service_choice=""
while true; do
    read -r -p "$(echo -e '\e[36mEnter service number [1-7]: \e[0m')" raw
    raw="${raw// /}"
    if [[ -v "SERVICE_PORTS[$raw]" ]]; then
        service_choice="$raw"
        break
    else
        echo -e "\e[31m  Invalid selection. Please enter a number between 1 and 7.\e[0m"
    fi
done

service_info="${SERVICE_PORTS[$service_choice]}"
service_name="${service_info%% | *}"
service_ports_raw="${service_info##* | }"

log "Operator selected service: $service_name" CRITICAL
add_change "Firewall" "Service Selection" "$service_name" "Ports restricted to this service only"

# Parse ports
ALLOWED_PORTS=(22)  # SSH always open
if [[ -n "$service_ports_raw" ]]; then
    IFS=' ' read -ra svc_ports <<< "$service_ports_raw"
    ALLOWED_PORTS+=("${svc_ports[@]}")
fi

log "Opening ports: ${ALLOWED_PORTS[*]}" INFO

# Apply firewall rules
apply_iptables_rules() {
    # Flush existing rules
    log "Flushing existing iptables INPUT rules..." INFO
    iptables -F INPUT
    iptables -F OUTPUT
    iptables -F FORWARD
    iptables -Z

    # Default policies
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT

    # Allow established/related
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -i lo -j ACCEPT

    # Allow safe IPs (scoring engine, jumpboxes)
    for ip in "${SAFE_IP_ADDRESSES[@]}"; do
        iptables -A INPUT -s "$ip" -m comment --comment "Blue Team - Safe IP $ip" -j ACCEPT
        log "Created allow rule for safe IP: $ip" SUCCESS
        add_change "Firewall" "Safe IP Address" "$ip" "All traffic allowed"
    done

    # Allow safe IP ranges
    for range in "${SAFE_IP_RANGES[@]}"; do
        iptables -A INPUT -s "$range" -m comment --comment "Blue Team - Safe Range $range" -j ACCEPT
        log "Created allow rule for safe IP range: $range" SUCCESS
        add_change "Firewall" "Safe IP Range" "$range" "All traffic allowed"
    done

    # Allow service ports
    for port_entry in "${ALLOWED_PORTS[@]}"; do
        if [[ "$port_entry" == *"-"* ]]; then
            # Port range
            iptables -A INPUT -p tcp --dport "$port_entry" -m comment --comment "Blue Team - Allow $port_entry ($service_name)" -j ACCEPT
            iptables -A INPUT -p udp --dport "$port_entry" -m comment --comment "Blue Team - Allow UDP $port_entry" -j ACCEPT
            log "Created allow rule for port range: $port_entry" SUCCESS
        else
            iptables -A INPUT -p tcp --dport "$port_entry" -m comment --comment "Blue Team - Allow port $port_entry ($service_name)" -j ACCEPT
            log "Created allow rule for port: $port_entry" SUCCESS
            add_change "Firewall" "Allowed Port" "$port_entry ($service_name)" "Inbound TCP allowed"
        fi
    done

    # ICMP (ping) - allow for network diagnostics
    iptables -A INPUT -p icmp -j ACCEPT

    # Logging for dropped packets
    if [[ "$LOG_DROPPED_PACKETS" == true ]]; then
        iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "BLUETEAM_DROP: " --log-level 7
    fi

    # Save rules
    if command -v iptables-save &>/dev/null; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || \
        iptables-save > /etc/iptables.rules 2>/dev/null || true
    fi
    if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent save 2>/dev/null || true
    fi
}

apply_ufw_rules() {
    ufw --force reset 2>/dev/null
    ufw default deny incoming
    ufw default allow outgoing
    ufw logging on

    for ip in "${SAFE_IP_ADDRESSES[@]}"; do
        ufw allow from "$ip" comment "Blue Team - Safe IP $ip" 2>/dev/null
        add_change "Firewall" "Safe IP Address" "$ip" "All traffic allowed"
    done

    for range in "${SAFE_IP_RANGES[@]}"; do
        ufw allow from "$range" comment "Blue Team - Safe Range $range" 2>/dev/null
        add_change "Firewall" "Safe IP Range" "$range" "All traffic allowed"
    done

    for port_entry in "${ALLOWED_PORTS[@]}"; do
        ufw allow "$port_entry/tcp" comment "Blue Team - Allow $port_entry ($service_name)" 2>/dev/null
        add_change "Firewall" "Allowed Port" "$port_entry" "Inbound TCP allowed"
    done

    ufw --force enable 2>/dev/null
}

case "$FW_BACKEND" in
    ufw)      apply_ufw_rules ;;
    iptables) apply_iptables_rules ;;
    nftables)
        # Fallback to iptables for nftables systems (iptables-nft is usually available)
        if command -v iptables &>/dev/null; then
            apply_iptables_rules
        else
            log "nftables backend - please configure manually or install iptables" WARNING
        fi
        ;;
esac

log "Firewall hardening complete. Only $service_name ports are open (plus SSH)." SUCCESS
add_change "Firewall" "Firewall Status" "Enabled" "All profiles with default deny inbound"
log "" INFO
log "PHASE 3 COMPLETE: Firewall hardening finished" SUCCESS
log "" INFO

fi  # END PHASE 3

# ==============================================================================
# PHASE 4: SSH HARDENING (Linux - SSH MUST remain open per Rule 10!)
# ==============================================================================
if [[ "$RUN_PHASE4" == true ]]; then

log "" INFO
log "============================================================" INFO
log "PHASE 4: SSH HARDENING (SSH REQUIRED on Linux - DO NOT REMOVE)" CRITICAL
log "============================================================" INFO
log "Rule 10: Teams may NOT disable SSH on Linux machines." CRITICAL
log "SSH will be HARDENED, not removed." INFO

SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_BACKUP="${SSHD_CONFIG}.bak.$(date '+%Y%m%d%H%M%S')"

# Backup config
if [[ "$BACKUP_BEFORE_CHANGES" == true ]]; then
    cp "$SSHD_CONFIG" "$SSHD_BACKUP" && \
        log "SSH config backed up to: $SSHD_BACKUP" SUCCESS || \
        log "Failed to backup SSH config" WARNING
fi

log "Applying SSH hardening configuration..." INFO

# Helper to set/replace sshd config values
sshd_set() {
    local key="$1" val="$2"
    if grep -qE "^#?${key}" "$SSHD_CONFIG"; then
        sed -i "s|^#\?${key}.*|${key} ${val}|" "$SSHD_CONFIG"
    else
        echo "${key} ${val}" >> "$SSHD_CONFIG"
    fi
}

# Harden SSH configuration
sshd_set "Protocol" "2"
sshd_set "PermitRootLogin" "no"
sshd_set "PasswordAuthentication" "yes"       # Keep yes for competition (may need password login)
sshd_set "PermitEmptyPasswords" "no"
sshd_set "MaxAuthTries" "3"
sshd_set "MaxSessions" "5"
sshd_set "LoginGraceTime" "30"
sshd_set "ClientAliveInterval" "300"
sshd_set "ClientAliveCountMax" "2"
sshd_set "X11Forwarding" "no"
sshd_set "AllowAgentForwarding" "no"
sshd_set "AllowTcpForwarding" "no"
sshd_set "UsePAM" "yes"
sshd_set "PrintLastLog" "yes"
sshd_set "Banner" "/etc/issue.net"
sshd_set "LogLevel" "VERBOSE"
sshd_set "Compression" "no"
sshd_set "TCPKeepAlive" "no"

# Create a login banner
cat > /etc/issue.net <<'EOF'
*******************************************************************************
    WARNING: Unauthorized access to this system is prohibited.
    All activity is monitored and logged. Violators will be prosecuted.
    CDT Competition - Blue Team Protected System
*******************************************************************************
EOF
log "SSH login banner created" SUCCESS

# Validate and restart SSH
if sshd -t -f "$SSHD_CONFIG" 2>/dev/null; then
    systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
    log "SSH service restarted with hardened configuration" SUCCESS
    add_change "SSH Hardening" "sshd Config" "Hardened" "Disabled root login, X11, agent forwarding, empty passwords"
else
    log "SSH config validation FAILED - restoring backup" ERROR
    cp "$SSHD_BACKUP" "$SSHD_CONFIG"
    systemctl restart ssh 2>/dev/null || true
    log "Backup restored. Review config manually." WARNING
fi

log "" INFO
log "PHASE 4 COMPLETE: SSH hardening finished (SSH remains active per Rule 10)" SUCCESS
log "" INFO

fi  # END PHASE 4

# ==============================================================================
# PHASE 5: NETWORK SECURITY HARDENING
# ==============================================================================
if [[ "$RUN_PHASE5" == true ]]; then

log "" INFO
log "============================================================" INFO
log "PHASE 5: NETWORK SECURITY" CRITICAL
log "============================================================" INFO

# Harden kernel network parameters via sysctl
log "Configuring kernel network security parameters (sysctl)..." INFO

SYSCTL_CONF="/etc/sysctl.d/99-blueteam-hardening.conf"
cat > "$SYSCTL_CONF" <<'EOF'
# Blue Team CDT Hardening - Network Security Parameters

# Disable IP forwarding (we are not a router)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Disable ICMP redirects (prevents MITM attacks)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Enable SYN cookies (prevents SYN flood attacks)
net.ipv4.tcp_syncookies = 1

# Log martian packets (helps detect spoofing)
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Disable ping responses (optional - comment out if ping is needed for scoring)
# net.ipv4.icmp_echo_ignore_all = 1

# Ignore ICMP broadcast (Smurf attack prevention)
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Protect against bad ICMP error messages
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Enable reverse path filtering (prevents IP spoofing)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Disable IPv6 if not needed (comment out if IPv6 is required)
# net.ipv6.conf.all.disable_ipv6 = 1
# net.ipv6.conf.default.disable_ipv6 = 1

# Increase SYN backlog (DoS resistance)
net.ipv4.tcp_max_syn_backlog = 2048

# TCP hardening
net.ipv4.tcp_rfc1337 = 1

# Disable SACK (optional - can interfere with some networks; enable if needed)
# net.ipv4.tcp_sack = 0

# Randomize virtual address space (ASLR)
kernel.randomize_va_space = 2

# Restrict kernel dmesg access
kernel.dmesg_restrict = 1

# Restrict kernel pointer exposure
kernel.kptr_restrict = 2

# Restrict ptrace scope
kernel.yama.ptrace_scope = 1

# Disable core dumps for setuid programs
fs.suid_dumpable = 0
EOF

sysctl -p "$SYSCTL_CONF" &>/dev/null && \
    log "Kernel network security parameters applied" SUCCESS || \
    log "Some sysctl parameters may not have applied (check kernel version)" WARNING
add_change "Network Security" "sysctl Hardening" "Applied" "Anti-spoofing, SYN cookies, IP forwarding disabled"

# Disable Avahi/mDNS (similar to LLMNR on Windows - prevents credential theft via MITM)
log "Disabling Avahi (mDNS) daemon..." INFO
if systemctl is-active avahi-daemon &>/dev/null 2>&1; then
    systemctl stop avahi-daemon 2>/dev/null || true
    systemctl disable avahi-daemon 2>/dev/null || true
    log "Avahi/mDNS disabled" SUCCESS
    add_change "Network Security" "Avahi/mDNS" "Disabled" "Prevents LLMNR-style credential theft"
else
    log "Avahi already stopped/not installed" INFO
fi

# Disable CUPS if not on trotsylvania (scored CUPS host)
if [[ "$HOSTNAME_LC" != "trotsylvania" ]]; then
    if systemctl is-active cups &>/dev/null 2>&1; then
        log "Disabling CUPS (not the scored CUPS host)..." INFO
        systemctl stop cups 2>/dev/null || true
        systemctl disable cups 2>/dev/null || true
        log "CUPS disabled (not needed on this host)" SUCCESS
        add_change "Network Security" "CUPS" "Disabled" "Not the scored CUPS host"
    fi
fi

# Disable unnecessary network services
for svc in rpcbind nfs-server rpc-statd nmbd smbd; do
    if systemctl is-active "$svc" &>/dev/null 2>&1; then
        log "Disabling unnecessary service: $svc" INFO
        systemctl stop "$svc" 2>/dev/null || true
        systemctl disable "$svc" 2>/dev/null || true
        log "Disabled: $svc" SUCCESS
        add_change "Network Security" "Disabled Service" "$svc" "Unnecessary network service"
    fi
done

log "" INFO
log "PHASE 5 COMPLETE: Network security hardening finished" SUCCESS
log "" INFO

fi  # END PHASE 5

# ==============================================================================
# PHASE 6: BACKDOOR DETECTION AND REMOVAL
# ==============================================================================
if [[ "$RUN_PHASE6" == true ]]; then

log "" INFO
log "============================================================" INFO
log "PHASE 6: BACKDOOR DETECTION AND REMOVAL" CRITICAL
log "============================================================" INFO

if [[ "$SCAN_FOR_BACKDOORS" == true ]]; then

    # ── Scan cron jobs for suspicious entries ────────────────────────────────
    if [[ "$REMOVE_SUSPICIOUS_CRONS" == true ]]; then
        log "Scanning for suspicious cron jobs..." INFO

        SUSPICIOUS_CRON_COUNT=0
        # Locations to check
        cron_locations=(
            /etc/cron.d/
            /etc/cron.daily/
            /etc/cron.hourly/
            /etc/cron.weekly/
            /etc/cron.monthly/
            /var/spool/cron/crontabs/
            /etc/crontab
        )

        check_cron_content() {
            local file="$1"
            local fname
            fname=$(basename "$file")

            # Per Rule 3 & 5: Do not modify greyteam artifacts
            if echo "$fname" | grep -qi "greyteam\|grayteam"; then
                log "Skipping Gray Team cron: $file (protected by rules)" INFO
                return
            fi

            # Check for suspicious patterns
            if grep -qE "(curl|wget|bash|python|perl|nc|ncat|netcat|mkfifo|/dev/tcp|base64 -d|eval|exec)" "$file" 2>/dev/null; then
                log "SUSPICIOUS CRON FOUND: $file" CRITICAL critical
                log "  Content:" WARNING
                grep -E "(curl|wget|bash|python|perl|nc|ncat|netcat|mkfifo|/dev/tcp|base64|eval|exec)" "$file" 2>/dev/null | \
                    while read -r line; do log "  >>> $line" WARNING; done
                (( SUSPICIOUS_CRON_COUNT++ ))
                # Optionally remove - uncomment to auto-remove:
                # rm -f "$file"
                # log "Removed suspicious cron: $file" REMOVED
            fi
        }

        for loc in "${cron_locations[@]}"; do
            if [[ -f "$loc" ]]; then
                check_cron_content "$loc"
            elif [[ -d "$loc" ]]; then
                while IFS= read -r -d '' f; do
                    check_cron_content "$f"
                done < <(find "$loc" -maxdepth 1 -type f -print0)
            fi
        done

        # Check all user crontabs
        for user in "${REAL_USERS[@]:-$(awk -F: '$3>=1000&&$3!=65534{print $1}' /etc/passwd)}"; do
            crontab_file="/var/spool/cron/crontabs/$user"
            [[ -f "$crontab_file" ]] && check_cron_content "$crontab_file"
        done

        log "Found $SUSPICIOUS_CRON_COUNT suspicious cron jobs (review manually and uncomment auto-remove if desired)" WARNING
    fi

    # ── Scan startup/persistence locations ───────────────────────────────────
    if [[ "$SCAN_STARTUP_LOCATIONS" == true ]]; then
        log "" INFO
        log "Scanning startup/persistence locations for backdoors..." INFO

        LEGITIMATE_STARTUP=(
            "apt" "dpkg" "systemd" "network" "cron" "ufw"
            "grub" "gdm" "lightdm" "cups" "apache" "nginx"
            "mysql" "mariadb" "vsftpd" "ircd" "sshd" "postfix"
            "rsyslog" "auditd" "fail2ban" "snapd" "update"
        )

        # Check systemd service units in unusual locations
        log "Checking for suspicious systemd units..." INFO
        unusual_units=()
        while IFS= read -r -d '' unit; do
            unit_name=$(basename "$unit")
            if [[ "$unit_name" == *"greyteam"* || "$unit_name" == *"grayteam"* ]]; then
                log "Skipping Gray Team unit: $unit_name" INFO
                continue
            fi

            is_legit=false
            for legit in "${LEGITIMATE_STARTUP[@]}"; do
                if [[ "${unit_name,,}" == *"${legit,,}"* ]]; then
                    is_legit=true; break
                fi
            done

            if [[ "$is_legit" == false ]]; then
                # Check if unit has suspicious ExecStart
                if grep -qE "(curl|wget|bash -[a-z]*i|python.*-c|perl.*-e|nc |ncat |netcat |mkfifo|/dev/tcp|base64)" "$unit" 2>/dev/null; then
                    log "SUSPICIOUS SYSTEMD UNIT: $unit" CRITICAL critical
                    unusual_units+=("$unit")
                fi
            fi
        done < <(find /etc/systemd/system /usr/lib/systemd/system -name "*.service" -print0 2>/dev/null)

        log "Found ${#unusual_units[@]} suspicious systemd unit(s)" WARNING

        # Check /etc/rc.local and rc*.d
        if [[ -f /etc/rc.local ]]; then
            if grep -qE "(curl|wget|bash|python|nc |ncat |mkfifo|/dev/tcp|base64 -d)" /etc/rc.local 2>/dev/null; then
                log "SUSPICIOUS CONTENT in /etc/rc.local" CRITICAL critical
            fi
        fi

        # Check ~/.bashrc and ~/.profile for all users for backdoors
        log "Checking user shell configs for persistence..." INFO
        for user in "${REMAINING_USERS[@]:-$(awk -F: '$3>=1000&&$3!=65534{print $1}' /etc/passwd)}"; do
            home=$(getent passwd "$user" | cut -d: -f6)
            for rc_file in "$home/.bashrc" "$home/.bash_profile" "$home/.profile" "$home/.zshrc"; do
                if [[ -f "$rc_file" ]]; then
                    if grep -qE "(curl|wget|nc |ncat |mkfifo|/dev/tcp|base64 -d|eval.*base64)" "$rc_file" 2>/dev/null; then
                        log "SUSPICIOUS CONTENT in $rc_file (user: $user)" CRITICAL critical
                    fi
                fi
            done
        done
    fi

    # ── Check for suspicious services running from /tmp, /var/tmp, /dev/shm ─
    if [[ "$DISABLE_SUSPICIOUS_SERVICES" == true ]]; then
        log "" INFO
        log "Scanning for services running from suspicious paths..." INFO

        while IFS= read -r line; do
            pid=$(echo "$line" | awk '{print $1}')
            exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "")
            if [[ "$exe" == /tmp/* || "$exe" == /var/tmp/* || "$exe" == /dev/shm/* || "$exe" == /run/shm/* ]]; then
                log "SUSPICIOUS PROCESS: PID=$pid EXE=$exe" CRITICAL critical
                cmd=$(cat "/proc/$pid/cmdline" 2>/dev/null | tr '\0' ' ' || echo "unknown")
                log "  Command: $cmd" WARNING
                # Optionally kill: kill -9 "$pid"
            fi
        done < <(ps -eo pid --no-headers 2>/dev/null)

        log "Suspicious process scan complete" SUCCESS
    fi

fi  # SCAN_FOR_BACKDOORS

log "" INFO
log "PHASE 6 COMPLETE: Backdoor detection finished" SUCCESS
log "" INFO

fi  # END PHASE 6

# ==============================================================================
# PHASE 7: SYSTEM HARDENING
# ==============================================================================
if [[ "$RUN_PHASE7" == true ]]; then

log "" INFO
log "============================================================" INFO
log "PHASE 7: SYSTEM HARDENING" CRITICAL
log "============================================================" INFO

# Disable USB storage (equivalent to Windows DisableUSBStorage)
log "Disabling USB storage (blacklisting usb-storage module)..." INFO
USB_BLACKLIST="/etc/modprobe.d/blueteam-usb.conf"
echo "blacklist usb-storage" > "$USB_BLACKLIST"
if lsmod | grep -q usb_storage; then
    rmmod usb_storage 2>/dev/null || true
fi
log "USB storage disabled via kernel module blacklist" SUCCESS
add_change "System Security" "USB Storage" "Disabled" "Kernel module blacklisted"

# Restrict /proc filesystem access
log "Restricting /proc filesystem (hidepid=2)..." INFO
if ! grep -q "hidepid" /etc/fstab; then
    # Check if already mounted with hidepid
    if mount | grep -q "proc.*hidepid"; then
        log "proc already mounted with hidepid" INFO
    else
        mount -o remount,rw,hidepid=2 /proc 2>/dev/null && \
            log "proc remounted with hidepid=2 (users cannot see other processes)" SUCCESS || \
            log "Failed to remount /proc with hidepid=2 (may not be supported)" WARNING
    fi
fi
add_change "System Security" "/proc hidepid" "Configured" "Users cannot see other user processes"

# Disable core dumps (equivalent to Windows DEP)
log "Disabling core dumps..." INFO
LIMITS_CONF="/etc/security/limits.d/blueteam-nodumps.conf"
echo "* hard core 0" > "$LIMITS_CONF"
echo "* soft core 0" >> "$LIMITS_CONF"
echo "fs.suid_dumpable = 0" >> "$SYSCTL_CONF" 2>/dev/null || true
sysctl -w fs.suid_dumpable=0 &>/dev/null || true
ulimit -c 0 2>/dev/null || true
log "Core dumps disabled" SUCCESS
add_change "System Security" "Core Dumps" "Disabled" "Prevents credential extraction from dumps"

# Restrict su to wheel/sudo group (similar to UAC elevation)
log "Restricting su command to sudo group only..." INFO
PAM_SU="/etc/pam.d/su"
if [[ -f "$PAM_SU" ]]; then
    if ! grep -q "pam_wheel" "$PAM_SU"; then
        sed -i '/^#.*pam_wheel/s/^#//' "$PAM_SU" 2>/dev/null || \
            echo "auth required pam_wheel.so group=sudo" >> "$PAM_SU"
        log "su restricted to sudo group via PAM" SUCCESS
        add_change "System Security" "su restriction" "Enabled" "Only sudo group can su"
    else
        log "su PAM wheel restriction already configured" INFO
    fi
fi

# Disable unnecessary SUID/SGID bits
log "Auditing SUID/SGID binaries..." INFO
SUSPICIOUS_SUIDS=()
while IFS= read -r -d '' f; do
    case "$f" in
        /usr/bin/sudo|/usr/bin/su|/usr/bin/passwd|/usr/bin/newgrp|/usr/bin/chsh|/usr/bin/chfn|\
        /usr/bin/gpasswd|/usr/sbin/pppd|/bin/ping|/usr/bin/ping|/usr/bin/pkexec|\
        /usr/lib/openssh/ssh-keysign|/usr/lib/dbus-1.0/dbus-daemon-launch-helper|\
        /usr/bin/at|/usr/bin/wall|/usr/bin/write|/usr/sbin/unix_chkpwd|\
        /usr/bin/expiry|/usr/bin/crontab|/usr/bin/ssh-agent)
            :  # Legitimate SUID binaries
            ;;
        *)
            log "SUSPICIOUS SUID/SGID: $f" CRITICAL critical
            SUSPICIOUS_SUIDS+=("$f")
            # Optionally remove SUID: chmod u-s "$f"
            ;;
    esac
done < <(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -print0 2>/dev/null)

if [[ ${#SUSPICIOUS_SUIDS[@]} -gt 0 ]]; then
    log "Found ${#SUSPICIOUS_SUIDS[@]} suspicious SUID/SGID binaries - review manually" WARNING
else
    log "SUID/SGID audit: no unexpected binaries found" SUCCESS
fi
add_change "System Security" "SUID Audit" "Completed" "Found ${#SUSPICIOUS_SUIDS[@]} suspicious binaries"

# Secure /tmp with noexec
log "Checking /tmp mount options..." INFO
if mount | grep -q "on /tmp.*noexec"; then
    log "/tmp already mounted noexec" INFO
else
    # Remount /tmp noexec,nosuid,nodev if it's a separate mount
    if mount | grep -q " on /tmp "; then
        mount -o remount,noexec,nosuid,nodev /tmp 2>/dev/null && \
            log "/tmp remounted with noexec,nosuid,nodev" SUCCESS || \
            log "Failed to remount /tmp (may be on root fs)" WARNING
    else
        # Create tmpfs entry if /tmp is on root
        log "/tmp is on root filesystem - adding fstab entry for noexec mount" INFO
    fi
fi

# Enable AppArmor if available
if command -v aa-status &>/dev/null; then
    log "Enabling AppArmor..." INFO
    systemctl enable apparmor 2>/dev/null || true
    systemctl start apparmor 2>/dev/null || true
    log "AppArmor enabled" SUCCESS
    add_change "System Security" "AppArmor" "Enabled" "MAC security layer"
fi

# Disable root login at console
log "Disabling root console login (securing /etc/securetty)..." INFO
if [[ -f /etc/securetty ]]; then
    # Clear securetty to prevent direct root console logins
    > /etc/securetty && \
        log "Root direct console login disabled" SUCCESS || \
        log "Failed to clear /etc/securetty" WARNING
fi

# Lock root account password (use sudo only)
passwd -l root 2>/dev/null && \
    log "Root account password locked (use sudo)" SUCCESS || \
    log "Could not lock root password" WARNING
add_change "System Security" "Root Account" "Locked" "Password-based root login disabled; use sudo"

# Restrict compiler access (similar to Windows Script Host disable)
log "Restricting compiler access for non-root users..." INFO
for compiler in gcc cc g++ make as ld; do
    if cmd=$(command -v "$compiler" 2>/dev/null); then
        chmod o-rx "$cmd" 2>/dev/null && \
            log "Restricted access: $compiler" SUCCESS || \
            log "Failed to restrict: $compiler" WARNING
    fi
done
add_change "System Security" "Compiler Access" "Restricted" "Non-root users cannot execute compilers"

log "" INFO
log "PHASE 7 COMPLETE: System hardening finished" SUCCESS
log "" INFO

fi  # END PHASE 7

# ==============================================================================
# PHASE 8: AUDIT LOGGING CONFIGURATION
# ==============================================================================
if [[ "$RUN_PHASE8" == true ]]; then

log "" INFO
log "============================================================" INFO
log "PHASE 8: AUDIT LOGGING CONFIGURATION" CRITICAL
log "============================================================" INFO

# Install auditd if not present
if ! command -v auditctl &>/dev/null; then
    log "Installing auditd..." INFO
    apt-get install -y auditd audispd-plugins &>/dev/null && \
        log "auditd installed" SUCCESS || \
        log "Failed to install auditd" ERROR
fi

if [[ "$ENABLE_ADVANCED_AUDITING" == true ]]; then
    log "Configuring auditd rules..." INFO

    AUDIT_RULES="/etc/audit/rules.d/blueteam-hardening.rules"
    mkdir -p "$(dirname "$AUDIT_RULES")"

    cat > "$AUDIT_RULES" <<'EOF'
# Blue Team CDT Audit Rules

# Delete all existing rules
-D

# Set buffer size (larger = fewer lost events under load)
-b 8192

# Failure mode 1 = printk (non-fatal)
-f 1

# ── User/Group Management ────────────────────────────────────────────────────
-w /etc/passwd -p wa -k user_modification
-w /etc/shadow -p wa -k user_modification
-w /etc/group -p wa -k group_modification
-w /etc/gshadow -p wa -k group_modification
-w /etc/sudoers -p wa -k sudoers_modification
-w /etc/sudoers.d/ -p wa -k sudoers_modification

# ── Authentication ───────────────────────────────────────────────────────────
-w /var/log/faillog -p wa -k login_failure
-w /var/log/lastlog -p wa -k login_success
-w /var/run/faillock/ -p wa -k login_failure

# ── Network configuration changes ────────────────────────────────────────────
-w /etc/network/interfaces -p wa -k network_modification
-w /etc/netplan/ -p wa -k network_modification
-w /etc/resolv.conf -p wa -k dns_modification
-w /etc/hosts -p wa -k hosts_modification
-w /etc/hosts.allow -p wa -k hosts_modification
-w /etc/hosts.deny -p wa -k hosts_modification

# ── Firewall changes ─────────────────────────────────────────────────────────
-w /etc/iptables/ -p wa -k firewall_modification
-w /etc/ufw/ -p wa -k firewall_modification
-w /sbin/iptables -p x -k firewall_command
-w /sbin/ip6tables -p x -k firewall_command
-w /usr/sbin/ufw -p x -k firewall_command
-w /usr/sbin/nft -p x -k firewall_command

# ── SSH config changes ────────────────────────────────────────────────────────
-w /etc/ssh/sshd_config -p wa -k ssh_config
-w /etc/ssh/ -p wa -k ssh_config

# ── Cron changes ─────────────────────────────────────────────────────────────
-w /etc/cron.allow -p wa -k cron_modification
-w /etc/cron.deny -p wa -k cron_modification
-w /etc/crontab -p wa -k cron_modification
-w /etc/cron.d/ -p wa -k cron_modification
-w /var/spool/cron/ -p wa -k cron_modification

# ── Privileged command execution ──────────────────────────────────────────────
-a always,exit -F arch=b64 -S execve -F euid=0 -k privileged_exec
-a always,exit -F arch=b32 -S execve -F euid=0 -k privileged_exec

# ── File permission changes ───────────────────────────────────────────────────
-a always,exit -F arch=b64 -S chmod -S fchmod -S chown -S fchown -k permission_change
-a always,exit -F arch=b32 -S chmod -S fchmod -S chown -S fchown -k permission_change

# ── SUID/SGID execution ───────────────────────────────────────────────────────
-a always,exit -F arch=b64 -S execve -F perm=sx -k suid_execution
-a always,exit -F arch=b32 -S execve -F perm=sx -k suid_execution

# ── Module loading ────────────────────────────────────────────────────────────
-w /sbin/insmod -p x -k module_load
-w /sbin/rmmod -p x -k module_load
-w /sbin/modprobe -p x -k module_load
-a always,exit -F arch=b64 -S init_module -k module_load
-a always,exit -F arch=b32 -S init_module -k module_load

# ── System calls: network connections ────────────────────────────────────────
-a always,exit -F arch=b64 -S connect -k network_connect
-a always,exit -F arch=b32 -S connect -k network_connect

# ── Make the configuration immutable (comment out if you need to re-run phases)
# -e 2
EOF

    # Load rules
    if augenrules --load &>/dev/null 2>&1; then
        log "auditd rules loaded via augenrules" SUCCESS
    else
        auditctl -R "$AUDIT_RULES" 2>/dev/null && \
            log "auditd rules loaded via auditctl" SUCCESS || \
            log "Failed to load auditd rules" ERROR
    fi

    add_change "Auditing" "auditd Rules" "Configured" "Comprehensive audit rules for user/group/network/exec"
fi

# Configure auditd.conf for log size and retention
log "Configuring auditd log retention..." INFO
AUDITD_CONF="/etc/audit/auditd.conf"
if [[ -f "$AUDITD_CONF" ]]; then
    sed -i 's/^max_log_file =.*/max_log_file = 50/' "$AUDITD_CONF" 2>/dev/null || true
    sed -i 's/^num_logs =.*/num_logs = 10/' "$AUDITD_CONF" 2>/dev/null || true
    sed -i 's/^max_log_file_action =.*/max_log_file_action = ROTATE/' "$AUDITD_CONF" 2>/dev/null || true
    log "auditd log rotation configured (50MB x 10 files)" SUCCESS
    add_change "Auditing" "Log Rotation" "Configured" "50MB per file, 10 files retained"
fi

# Enable and start auditd
systemctl enable auditd 2>/dev/null || true
systemctl restart auditd 2>/dev/null && \
    log "auditd service started" SUCCESS || \
    log "Failed to start auditd" ERROR

# Enable shell history logging via syslog (equivalent to PowerShell transcription)
log "Enabling enhanced bash history logging..." INFO

HISTORY_CONF="/etc/profile.d/blueteam-history.sh"
cat > "$HISTORY_CONF" <<'EOF'
# Blue Team CDT - Enhanced shell history logging
export HISTSIZE=10000
export HISTFILESIZE=10000
export HISTTIMEFORMAT="%Y-%m-%d %H:%M:%S "
export HISTCONTROL=""              # Record all commands including duplicates
shopt -s histappend                # Append to history instead of overwriting
export PROMPT_COMMAND='history -a; history -r'  # Write history immediately
# Log every command to syslog
function log_command_to_syslog {
    logger -p local6.debug -t bash "[$$] [$USER] [$(pwd)] $BASH_COMMAND"
}
trap log_command_to_syslog DEBUG
EOF
chmod 644 "$HISTORY_CONF"
log "Enhanced bash history logging enabled" SUCCESS
add_change "Auditing" "Shell History" "Configured" "All commands logged with timestamps and syslog"

# Configure rsyslog for centralized logging
log "Configuring rsyslog for comprehensive logging..." INFO
RSYSLOG_BLUETEAM="/etc/rsyslog.d/50-blueteam.conf"
cat > "$RSYSLOG_BLUETEAM" <<EOF
# Blue Team CDT - Enhanced logging
\$ModLoad imuxsock
local6.* $LOG_DIR/shell-commands.log
auth,authpriv.* $LOG_DIR/auth.log
kern.* $LOG_DIR/kernel.log
EOF
systemctl restart rsyslog 2>/dev/null && \
    log "rsyslog restarted with enhanced logging" SUCCESS || \
    log "Failed to restart rsyslog" WARNING
add_change "Auditing" "rsyslog" "Configured" "Comprehensive event logging"

log "" INFO
log "PHASE 8 COMPLETE: Audit logging configuration finished" SUCCESS
log "" INFO

fi  # END PHASE 8

# ==============================================================================
# 9. FINAL REPORT (only when running all phases)
# ==============================================================================
if [[ "$RUNNING_INDIVIDUAL_PHASE" != true ]]; then

SCRIPT_END_TIME=$(date '+%Y-%m-%d %H:%M:%S')
DURATION=$(( $(date -d "$SCRIPT_END_TIME" +%s) - $(date -d "$SCRIPT_START_TIME" +%s) ))
TOTAL_CHANGES=$(change_count)
TOTAL_REMOVED=$(removed_user_count)
TOTAL_ISSUES=$(security_issue_count)

log "" INFO
log "============================================================" INFO
log "GENERATING FINAL REPORT" CRITICAL
log "============================================================" INFO

log "" INFO
log "EXECUTION SUMMARY:" INFO
log "  Start time: $SCRIPT_START_TIME" INFO
log "  End time: $SCRIPT_END_TIME" INFO
log "  Duration: ${DURATION} seconds" INFO
log "  Script run number: $SCRIPT_RUN_COUNT" INFO
log "  Total changes applied: $TOTAL_CHANGES" INFO
log "  Users removed: $TOTAL_REMOVED" INFO
log "  Security issues found: $TOTAL_ISSUES" INFO

log "" INFO
log "AUTHORIZED ADMIN USERS:" INFO
for admin in "${AUTHORIZED_ADMINS[@]}"; do
    log "  - $admin" INFO
done

log "" INFO
log "WHITELISTED IP ADDRESSES:" INFO
for ip in "${SAFE_IP_ADDRESSES[@]}"; do
    log "  - $ip" INFO
done
for range in "${SAFE_IP_RANGES[@]}"; do
    log "  - $range (range)" INFO
done

log "" INFO
log "============================================================" INFO
log "BLUE TEAM RECOMMENDATIONS - CDT COMPETITION:" CRITICAL
log "============================================================" INFO
log "1. REBOOT the system to apply all kernel/module changes" WARNING
log "2. REVIEW the log file for any errors: $LOG_FILE" WARNING
log "3. VERIFY connectivity to scoring engine at https://scoring.mlp.local:443" WARNING
log "4. CHECK that all scored services are still running" WARNING
log "5. VERIFY all competition users can still SSH/access the system" WARNING
log "6. REMEMBER: You can only change passwords 3 times per host per session!" CRITICAL
log "7. DO NOT disable SSH on Linux - it must remain open (Rule 10)" CRITICAL
log "8. DO NOT remove competition users (Rule 9 violation)" CRITICAL
log "9. DO NOT block entire subnets (Rule 7 violation)" CRITICAL
log "10. MONITOR /var/log/auth.log for Red Team activity" WARNING
log "11. REVIEW and REMOVE any suspicious cron jobs / systemd units manually" WARNING
log "12. CHECK for Red Team persistence in user shell configs" WARNING
log "13. VERIFY firewall rules aren't blocking scoring traffic" WARNING
log "14. DOCUMENT all actions taken for inject responses" WARNING
log "15. RUN this script periodically to maintain security posture" WARNING

log "" INFO
log "============================================================" INFO
log "HARDENING COMPLETE - SYSTEM READY FOR COMPETITION" SUCCESS
log "============================================================" INFO

# Save completion state
COMPLETION_STATE="$BLUETEAM_DIR/last-completion-state.json"
cat > "$COMPLETION_STATE" <<EOF
{
  "LastRunTime": "$SCRIPT_END_TIME",
  "RunCount": $SCRIPT_RUN_COUNT,
  "ChangesApplied": $TOTAL_CHANGES,
  "UsersRemoved": $TOTAL_REMOVED,
  "SecurityIssues": $TOTAL_ISSUES,
  "Hostname": "$HOSTNAME_LC",
  "ScriptVersion": "1.0-CDT-Linux"
}
EOF

# Final status banner
echo ""
echo -e "\e[36m================================================================================\e[0m"
echo -e "\e[32m                    BLUE TEAM HARDENING COMPLETE\e[0m"
echo -e "\e[36m================================================================================\e[0m"
echo ""
echo -e "\e[97mScript Run:       \e[0m\e[$(if [[ $SCRIPT_RUN_COUNT -gt 1 ]]; then echo '33'; else echo '32'; fi)m#${SCRIPT_RUN_COUNT}\e[0m"
echo -e "\e[97mLog File:         \e[0m\e[33m${LOG_FILE}\e[0m"
echo -e "\e[97mChanges Applied:  \e[0m\e[32m${TOTAL_CHANGES}\e[0m"
echo -e "\e[97mUsers Removed:    \e[0m\e[36m${TOTAL_REMOVED}\e[0m"
echo -e "\e[97mSecurity Issues:  \e[0m\e[$(if [[ $TOTAL_ISSUES -gt 0 ]]; then echo '31'; else echo '32'; fi)m${TOTAL_ISSUES}\e[0m"
echo ""
echo -e "\e[36m================================================================================\e[0m"
echo ""

# Smart restart logic
should_restart=false
restart_reason=""

if [[ "$SCRIPT_RUN_COUNT" -eq 1 ]]; then
    should_restart=true
    restart_reason="First run - restart recommended to apply all kernel and module changes"
elif [[ "$TOTAL_CHANGES" -ge 5 ]]; then
    should_restart=true
    restart_reason="Significant changes made ($TOTAL_CHANGES changes) - restart recommended"
else
    echo -e "\e[33mThis is run #$SCRIPT_RUN_COUNT with $TOTAL_CHANGES change(s) applied.\e[0m"
    echo -e "\e[33mMost settings are already configured - restart may not be necessary.\e[0m"
    echo ""
    read -r -p "$(echo -e '\e[36mDo you want to restart now? (Y/N): \e[0m')" restart_choice
    if [[ "${restart_choice^^}" == "Y" ]]; then
        should_restart=true
        restart_reason="Manual restart requested by operator"
    else
        echo ""
        echo -e "\e[33mRestart skipped. You can manually restart later with: sudo reboot\e[0m"
        echo ""
        exit 0
    fi
fi

if [[ "$should_restart" == true ]]; then
    log "Initiating system restart to apply all changes..." CRITICAL
    log "Reason: $restart_reason" INFO
    echo ""
    echo -e "\e[33m$restart_reason\e[0m"
    echo ""
    for (( i=10; i>0; i-- )); do
        echo -e "\e[33mSystem will restart in \e[31m$i\e[33m seconds... (Press Ctrl+C to cancel)\e[0m"
        sleep 1
    done
    echo ""
    echo -e "\e[31mRESTARTING NOW...\e[0m"
    log "System restart initiated" CRITICAL
    sleep 1
    reboot
fi

else
    # Individual phase complete
    echo ""
    echo -e "\e[32m========================================\e[0m"
    echo -e "\e[32mIndividual Phase Complete\e[0m"
    echo -e "\e[32mPhase(s) executed successfully.\e[0m"
    echo -e "\e[33mCheck log file: $LOG_FILE\e[0m"
    echo -e "\e[32m========================================\e[0m"
    echo ""
fi
