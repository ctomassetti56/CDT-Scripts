#!/usr/bin/env bash
# ==============================================================================
# SecureLinux.sh — CDT Blue Team Linux Hardening Tool
# CDT Team Alpha — Spring 2026
#
# CRITICAL COMPETITION RULES THIS SCRIPT RESPECTS:
#   Rule 7:  No subnet blocking. Only individual IP allow-rules.
#   Rule 9:  Never disable/remove valid packet users. Admins keep admin.
#   Rule 10: SSH must remain enabled and accessible at all times.
#   Rule 14: Max 3 password changes per host per comp session.
#            ALL changes must be logged in scoring portal FIRST.
#   Rule 5:  Never touch any file/artifact with "greyteam" in the name.
#   Rule 6:  Do not migrate scored services to other hosts.
#
# USAGE:
#   sudo ./SecureLinux.sh                     # Run all phases
#   sudo ./SecureLinux.sh --all               # Same as above
#   sudo ./SecureLinux.sh --phase1            # Single phase
#   sudo ./SecureLinux.sh --phase 1,3,5       # Multiple phases
#   sudo ./SecureLinux.sh --phase1 --phase3   # Multiple phases (flag style)
#   sudo ./SecureLinux.sh --help              # Show help
#
# PHASES:
#   1 — User account management (audit, remove unauthorized, password resets)
#   2 — SSH hardening (hardens config; SSH stays ON per Rule 10)
#   3 — Firewall hardening (iptables; per-service ports; no subnet blocks)
#   4 — Kernel / sysctl network hardening
#   5 — Persistence / backdoor detection (cron, systemd, processes)
#   6 — System hardening (suid audit, usb, compiler restriction, apparmor)
#   7 — Audit logging (auditd, bash history, rsyslog)
# ==============================================================================

set -euo pipefail
IFS=$'\n\t'

# ── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m';  YELLOW='\033[0;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; WHITE='\033[0;97m'
BOLD='\033[1m';    RESET='\033[0m'

# ── Root check ────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}ERROR: Run as root — sudo ./SecureLinux.sh${RESET}" >&2
    exit 1
fi

# ==============================================================================
# ARGUMENT PARSING
# ==============================================================================
SELECTED_PHASES=()
RUN_ALL=false
SHOW_HELP=false

usage() {
cat <<EOF

${BOLD}${CYAN}==============================================================================
  SecureLinux.sh — CDT Blue Team Linux Hardening Tool — Spring 2026
==============================================================================${RESET}

${BOLD}USAGE:${RESET}
  sudo ./SecureLinux.sh [OPTIONS]

${BOLD}OPTIONS:${RESET}
  --help            Show this help menu
  --all             Run all phases (default when no args given)
  --phase1          Phase 1: User account management
  --phase2          Phase 2: SSH hardening (stays ON per Rule 10)
  --phase3          Phase 3: Firewall hardening (iptables; no subnet blocks)
  --phase4          Phase 4: Kernel/sysctl network hardening
  --phase5          Phase 5: Persistence & backdoor detection
  --phase6          Phase 6: System hardening (suid, usb, compilers, apparmor)
  --phase7          Phase 7: Audit logging (auditd, bash history)
  --phase N[,M...]  Run specific phase numbers (e.g., --phase 1,3,5)

${BOLD}EXAMPLES:${RESET}
  sudo ./SecureLinux.sh
  sudo ./SecureLinux.sh --all
  sudo ./SecureLinux.sh --phase1
  sudo ./SecureLinux.sh --phase1 --phase3 --phase7
  sudo ./SecureLinux.sh --phase 1,3,5

${BOLD}${YELLOW}IMPORTANT — READ BEFORE RUNNING:${RESET}
  • Password changes (Phase 1) require you to log them in the scoring portal
    at https://scoring.mlp.local:443 BEFORE applying them on the host.
  • SSH will never be disabled. Rule 10 forbids it.
  • Packet users are hard-coded as protected and will never be removed.

EOF
    exit 0
}

if [[ $# -eq 0 ]]; then
    RUN_ALL=true
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        --help|-h)   SHOW_HELP=true; shift ;;
        --all)       RUN_ALL=true; shift ;;
        --phase1)    SELECTED_PHASES+=(1); shift ;;
        --phase2)    SELECTED_PHASES+=(2); shift ;;
        --phase3)    SELECTED_PHASES+=(3); shift ;;
        --phase4)    SELECTED_PHASES+=(4); shift ;;
        --phase5)    SELECTED_PHASES+=(5); shift ;;
        --phase6)    SELECTED_PHASES+=(6); shift ;;
        --phase7)    SELECTED_PHASES+=(7); shift ;;
        --phase)
            shift
            if [[ $# -eq 0 ]]; then
                echo -e "${RED}ERROR: --phase requires a value (e.g., --phase 1,3,5)${RESET}" >&2
                exit 1
            fi
            IFS=',' read -ra _nums <<< "$1"
            for _n in "${_nums[@]}"; do
                _n="${_n// /}"
                if ! [[ "$_n" =~ ^[1-7]$ ]]; then
                    echo -e "${RED}ERROR: Invalid phase '$_n'. Valid: 1-7${RESET}" >&2
                    exit 1
                fi
                SELECTED_PHASES+=("$_n")
            done
            shift
            ;;
        *)
            echo -e "${RED}ERROR: Unknown option '$1'. Run --help for usage.${RESET}" >&2
            exit 1
            ;;
    esac
done

[[ "$SHOW_HELP" == true ]] && usage

# Deduplicate + sort
if [[ ${#SELECTED_PHASES[@]} -gt 0 ]]; then
    mapfile -t SELECTED_PHASES < <(printf '%s\n' "${SELECTED_PHASES[@]}" | sort -nu)
fi

# If --all or no specific phases given, run everything
if [[ "$RUN_ALL" == true ]] || [[ ${#SELECTED_PHASES[@]} -eq 0 ]]; then
    SELECTED_PHASES=(1 2 3 4 5 6 7)
    RUN_ALL=true
fi

# Helper: check if a phase is selected
run_phase() { printf '%s\n' "${SELECTED_PHASES[@]}" | grep -qx "$1"; }

# ==============================================================================
# INFRASTRUCTURE / WORKING DIRS
# ==============================================================================
BLUETEAM_DIR="/opt/blueteam"
LOG_DIR="$BLUETEAM_DIR/logs"
RUN_COUNTER_FILE="$BLUETEAM_DIR/.run_count"

mkdir -p "$LOG_DIR"

# Run counter
if [[ -f "$RUN_COUNTER_FILE" ]]; then
    RUN_COUNT=$(( $(cat "$RUN_COUNTER_FILE") + 1 ))
else
    RUN_COUNT=1
fi
echo "$RUN_COUNT" > "$RUN_COUNTER_FILE"

# Phase-aware log name
if [[ "$RUN_ALL" == true ]]; then
    LOG_FILE="$LOG_DIR/hardening-$(date '+%Y-%m-%d-%H%M%S').log"
else
    _phase_str=$(IFS='-'; echo "${SELECTED_PHASES[*]}")
    LOG_FILE="$LOG_DIR/hardening-phases-${_phase_str}-$(date '+%Y-%m-%d-%H%M%S').log"
fi
touch "$LOG_FILE"

HOSTNAME_LC=$(hostname | tr '[:upper:]' '[:lower:]')
SCRIPT_START=$(date '+%Y-%m-%d %H:%M:%S')
CURRENT_OPERATOR="${SUDO_USER:-root}"

# ==============================================================================
# LOGGING + CHANGE TRACKING
# ==============================================================================
CHANGES_FILE=$(mktemp)
REMOVED_USERS_FILE=$(mktemp)
SECURITY_ISSUES_FILE=$(mktemp)
trap 'rm -f "$CHANGES_FILE" "$REMOVED_USERS_FILE" "$SECURITY_ISSUES_FILE"' EXIT

log() {
    local msg="$1"
    local level="${2:-INFO}"
    local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')
    local line="[$ts][$level] $msg"

    case "$level" in
        ERROR)    echo -e "${RED}${line}${RESET}" ;;
        WARNING)  echo -e "${YELLOW}${line}${RESET}" ;;
        SUCCESS)  echo -e "${GREEN}${line}${RESET}" ;;
        CRITICAL) echo -e "${MAGENTA}${BOLD}${line}${RESET}" ;;
        REMOVED)  echo -e "${CYAN}${line}${RESET}" ;;
        *)        echo -e "${WHITE}${line}${RESET}" ;;
    esac
    echo "$line" >> "$LOG_FILE"

    # Mark security issues
    if [[ "${3:-}" == "sec" ]]; then
        echo "$msg" >> "$SECURITY_ISSUES_FILE"
    fi
}

add_change() {
    echo "$(date '+%H:%M:%S')|${1}|${2}|${3}" >> "$CHANGES_FILE"
}

n_changes()  { wc -l < "$CHANGES_FILE"       | tr -d ' '; }
n_removed()  { wc -l < "$REMOVED_USERS_FILE" | tr -d ' '; }
n_issues()   { wc -l < "$SECURITY_ISSUES_FILE"| tr -d ' '; }

# ==============================================================================
# BANNER
# ==============================================================================
banner() {
echo -e "
${BOLD}${CYAN}==============================================================================
  CDT Blue Team Linux Hardening — Spring 2026
  Host: ${HOSTNAME_LC}   |   Run #${RUN_COUNT}   |   Operator: ${CURRENT_OPERATOR}
  Phases: $(IFS=','; echo "${SELECTED_PHASES[*]}")
  Log: ${LOG_FILE}
==============================================================================${RESET}"
}
banner
log "Script started" INFO
log "Hostname: $HOSTNAME_LC | Run #$RUN_COUNT | Operator: $CURRENT_OPERATOR" INFO

# ==============================================================================
# ════════════════════════════════════════════════════════════════════════════
# COMPETITION SAFE USER LIST  (Rule 9 — never remove/disable these)
# ════════════════════════════════════════════════════════════════════════════
# ==============================================================================

# All users listed in the competition packet
PACKET_USERS=(
    # Local Users
    twilight pinkiepie applejack rarity rainbowdash fluttershy
    # Local Admin
    bigmac mayormare shiningarmor cadance
    # Domain Users
    spike starlight trixie derpy snips snails
    # Domain Admin
    celestia discord luna starswirl
    # Scoring / grey team accounts (Rule 5)
    greyteam grayteam grey_team gray_team scoring
)

# System accounts that must never be removed
SYSTEM_ACCOUNTS=(
    root nobody daemon bin sys sync games man lp mail news uucp proxy
    www-data backup list irc gnats _apt systemd-network systemd-resolve
    messagebus systemd-timesync syslog uuidd tcpdump sshd pollinate
    landscape fwupd-refresh tss _chrony ntp mysql ftp vsftpd cups
    ircd postfix dovecot samba netdata prometheus node_exporter
    debian-exim Debian-exim
)

# ── Phase 1 will prompt the operator to add extra users to protect ──────────
# For now build the combined safe list (will be extended during Phase 1)
SAFE_USERS=("${PACKET_USERS[@]}" "${SYSTEM_ACCOUNTS[@]}" "$CURRENT_OPERATOR")

is_safe() {
    local u="$1"
    local s
    for s in "${SAFE_USERS[@]}"; do
        [[ "${s,,}" == "${u,,}" ]] && return 0
    done
    return 1
}

user_exists() { id "$1" &>/dev/null 2>&1; }

# ==============================================================================
# ════════════════════════════════════════════════════════════════════════════
# COMPETITION SAFE IP LIST
# Jumpboxes + scoring engine from packet (Rule 7 — allow only, never block)
# ════════════════════════════════════════════════════════════════════════════
# ==============================================================================

SAFE_IPS=(
    "172.20.0.100"   # scoring engine
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

# Per-host scored service port map (used in Phase 3)
# hostname → "proto:port proto:port ..."
declare -A HOST_SERVICE_PORTS
HOST_SERVICE_PORTS["ponyville"]="tcp:80 tcp:443"
HOST_SERVICE_PORTS["seaddle"]="tcp:3306"
HOST_SERVICE_PORTS["trotsylvania"]="tcp:631 udp:631"
HOST_SERVICE_PORTS["crystal-empire"]="tcp:20 tcp:21 tcp:30000:31000"
HOST_SERVICE_PORTS["everfree-forest"]="tcp:6667 tcp:6697"
HOST_SERVICE_PORTS["griffonstone"]="tcp:80 tcp:443"
# Ubuntu workstations — SSH only
HOST_SERVICE_PORTS["cloudsdale"]=""
HOST_SERVICE_PORTS["vanhoover"]=""
HOST_SERVICE_PORTS["whinnyapolis"]=""

# ==============================================================================
# PHASE 1 — USER ACCOUNT MANAGEMENT
# ==============================================================================
if run_phase 1; then

echo -e "\n${BOLD}${MAGENTA}============================================================
PHASE 1: USER ACCOUNT MANAGEMENT
============================================================${RESET}"
log "Phase 1: User account management started" CRITICAL

# ── 1.0: Display hard-coded safe user list (packet users only) ───────────────
echo -e "\n${BOLD}${CYAN}Step 1.0 — Protected user list${RESET}"
echo -e "${WHITE}The following packet users are permanently protected and will never be removed:${RESET}"
printf '  %s\n' "${PACKET_USERS[@]}"
echo ""
log "Safe user list loaded — ${#SAFE_USERS[@]} protected entries (packet users + system accounts)" INFO

# ── 1.1: Create/verify blueadmin blue team admin account ─────────────────────
log "Step 1.1: Ensuring blueadmin account exists..." INFO

BLUEADMIN_USER="blueadmin"
BLUEADMIN_PASS="B1ueT3am!CDT2026"   # ← CHANGE THIS BEFORE COMPETITION

# Add blueadmin to the safe list so it is never removed
SAFE_USERS+=("$BLUEADMIN_USER")

if ! id "$BLUEADMIN_USER" &>/dev/null 2>&1; then
    useradd -m -s /bin/bash -c "Blue Team Admin" "$BLUEADMIN_USER" 2>/dev/null
    echo "$BLUEADMIN_USER:$BLUEADMIN_PASS" | chpasswd 2>/dev/null
    usermod -aG sudo "$BLUEADMIN_USER" 2>/dev/null || true
    log "Created blueadmin account and added to sudo group" SUCCESS
    add_change "Users" "Created" "$BLUEADMIN_USER"
else
    # Account exists — make sure it has sudo and reset its password
    usermod -aG sudo "$BLUEADMIN_USER" 2>/dev/null || true
    echo "$BLUEADMIN_USER:$BLUEADMIN_PASS" | chpasswd 2>/dev/null
    log "blueadmin already exists — sudo membership confirmed, password reset" SUCCESS
    add_change "Users" "Verified/updated" "$BLUEADMIN_USER"
fi

# Lock blueadmin out of the scored portal password counter — it's our account,
# not a competition user, so we never touch it via the scoring portal.
log "blueadmin is a blue team management account — not a competition user" INFO

# ── 1.2: Enumerate ALL accounts on the machine (no UID floor) ─────────────────
# Red Team may plant backdoor accounts at low UIDs (e.g. 500, 999) to dodge
# the typical UID>=1000 check. We scan every account in /etc/passwd and remove
# anything not on the safe list, skipping only root (UID 0).
log "Step 1.2: Enumerating ALL user accounts (no UID floor — catches low-UID backdoors)..." INFO

ALL_REAL_USERS=()
while IFS=':' read -r _u _ _uid _gid _comment _home _shell; do
    # Skip root (uid 0) — always protected
    [[ "$_uid" -eq 0 ]] && continue
    # Skip accounts with no valid login shell (nologin / false)
    case "$_shell" in
        */nologin|*/false|"") continue ;;
    esac
    # Skip nobody (uid 65534 / 65535)
    [[ "$_uid" -eq 65534 || "$_uid" -eq 65535 ]] && continue
    ALL_REAL_USERS+=("$_u")
done < /etc/passwd

log "Found ${#ALL_REAL_USERS[@]} login-capable account(s): ${ALL_REAL_USERS[*]:-none}" INFO

# ── 1.3: Check for blank / no-password accounts ─────────────────────────────
log "Step 1.3: Scanning for blank/no-password accounts..." INFO

BLANK_PW_USERS=()
while IFS=':' read -r _u _pw _; do
    # NP = no password; empty field also means no password
    if [[ -z "$_pw" || "$_pw" == "" ]]; then
        log "BLANK PASSWORD: $_u" CRITICAL sec
        BLANK_PW_USERS+=("$_u")
    fi
done < /etc/shadow

# Double-check ALL login-capable accounts via passwd -S
for _u in "${ALL_REAL_USERS[@]}"; do
    _st=$(passwd -S "$_u" 2>/dev/null | awk '{print $2}' || true)
    if [[ "$_st" == "NP" ]]; then
        if ! printf '%s\n' "${BLANK_PW_USERS[@]}" | grep -qx "$_u"; then
            log "NO PASSWORD (passwd -S): $_u" CRITICAL sec
            BLANK_PW_USERS+=("$_u")
        fi
    fi
done

log "Blank/no-password accounts found: ${#BLANK_PW_USERS[@]}" INFO

# ── 1.4: Audit privileged group memberships (sudo/adm/etc.) ─────────────────
log "Step 1.4: Auditing privileged group memberships..." INFO

PRIV_GROUPS=(sudo wheel adm shadow disk lxd docker lpadmin plugdev)
GROUP_VIOLATIONS=()

for _grp in "${PRIV_GROUPS[@]}"; do
    if ! getent group "$_grp" &>/dev/null; then continue; fi
    _members=$(getent group "$_grp" | cut -d: -f4)
    [[ -z "$_members" ]] && continue
    IFS=',' read -ra _mlist <<< "$_members"
    log "Checking group '$_grp': members=${_mlist[*]:-none}" INFO
    for _m in "${_mlist[@]}"; do
        [[ -z "$_m" ]] && continue
        if ! is_safe "$_m"; then
            log "UNAUTHORIZED: '$_m' in group '$_grp'" CRITICAL sec
            GROUP_VIOLATIONS+=("$_m:$_grp")
            if gpasswd -d "$_m" "$_grp" &>/dev/null 2>&1; then
                log "Removed '$_m' from group '$_grp'" REMOVED
                add_change "Group" "Removed from $grp" "$_m"
            else
                log "Failed to remove '$_m' from '$_grp'" ERROR
            fi
        else
            log "  Authorized: $_m in $_grp" INFO
        fi
    done
done

log "Group audit done. Violations fixed: ${#GROUP_VIOLATIONS[@]}" INFO

# ── 1.5: Remove unauthorized users (ALL login-capable accounts, no UID floor) ─
log "Step 1.5: Removing unauthorized user accounts..." INFO

for _u in "${ALL_REAL_USERS[@]}"; do
    if is_safe "$_u"; then
        log "  Keeping safe user: $_u" INFO
    else
        log "REMOVING unauthorized user: $_u" REMOVED
        # Kill active sessions first
        pkill -KILL -u "$_u" 2>/dev/null || true
        if userdel -r "$_u" 2>/dev/null; then
            log "Successfully removed: $_u" SUCCESS
        else
            userdel "$_u" 2>/dev/null || log "userdel failed for $_u" ERROR
            log "Removed $_u (home may remain — check manually)" WARNING
        fi
        echo "$_u" >> "$REMOVED_USERS_FILE"
        add_change "Users" "Removed" "$_u"
    fi
done

# ── 1.6: Selective password reset (Rule 14 — max 3 per host per session) ────
echo -e "\n${BOLD}${MAGENTA}Step 1.6 — Password Reset (Rule 14: max 3 per host per session)${RESET}"

# RULE 14 WARNING — scoring portal must be updated first (warn, do not block)
echo -e "${BOLD}${YELLOW}╔══════════════════════════════════════════════════════════════╗
║  ⚠  COMPETITION RULE 14 — IMPORTANT REMINDER                ║
║                                                              ║
║  ALL user password changes MUST be logged in the scoring     ║
║  portal at https://scoring.mlp.local:443 BEFORE you apply   ║
║  them here. The portal tracks your remaining changes.        ║
║                                                              ║
║  You are limited to 3 password changes per host per          ║
║  competition session. Continuing without updating the        ║
║  portal first may cost you scoring points.                   ║
╚══════════════════════════════════════════════════════════════╝${RESET}"
echo ""
read -r -p "$(echo -e "${BOLD}${CYAN}Have you already updated the scoring portal? (y/N): ${RESET}")" _portal_confirm
if [[ "${_portal_confirm,,}" != "y" ]]; then
    log "Operator has NOT confirmed scoring portal update — proceeding anyway with warning" WARNING
    echo -e "${YELLOW}⚠ WARNING: Proceeding without portal confirmation. Update the portal at${RESET}"
    echo -e "${YELLOW}  https://scoring.mlp.local:443 to avoid losing scoring points.${RESET}"
    echo ""
fi
# Always continue into the password reset section regardless of portal confirmation
{
    # Refresh user list post-removals
    # Rebuild from ALL login-capable accounts (same logic as removal scan)
    mapfile -t _remaining < <(
        while IFS=':' read -r _u _ _uid _ _ _ _sh; do
            [[ "$_uid" -eq 0 ]] && continue
            case "$_sh" in */nologin|*/false|"") continue ;; esac
            [[ "$_uid" -eq 65534 || "$_uid" -eq 65535 ]] && continue
            echo "$_u"
        done < /etc/passwd | sort
    )

    if [[ ${#_remaining[@]} -eq 0 ]]; then
        log "No remaining real user accounts to reset passwords for." INFO
    else
        # Display menu
        echo -e "\n${BOLD}${CYAN}Available users (select up to 3):${RESET}"
        echo ""
        printf "  ${BOLD}%-6s %-22s %-10s %s${RESET}\n" "Index" "Username" "PW Status" "Groups"
        printf "  %-6s %-22s %-10s %s\n" "-----" "--------" "---------" "------"

        _idx=1
        declare -A _menu_map
        for _u in "${_remaining[@]}"; do
            _st=$(passwd -S "$_u" 2>/dev/null | awk '{print $2}' || echo "?")
            _grps=$(id -Gn "$_u" 2>/dev/null || echo "?")
            printf "  %-6s %-22s %-10s %s\n" "[$_idx]" "$_u" "$_st" "$_grps"
            _menu_map["$_idx"]="$_u"
            (( _idx++ ))
        done

        echo ""
        echo -e "${WHITE}Comma or space separated index numbers (max 3). Press Enter to skip.${RESET}"
        read -r -p "Select users: " _sel_raw

        _pw_success=0
        _pw_fail=0
        _pw_log="$LOG_DIR/password-changes-$(date '+%Y%m%d-%H%M%S').log"
        echo "Host: $HOSTNAME_LC | $(date)" > "$_pw_log"

        if [[ -n "$_sel_raw" ]]; then
            IFS=', ' read -ra _sel_parts <<< "$_sel_raw"
            _sel_nums=()
            _valid=true

            for _p in "${_sel_parts[@]}"; do
                _p="${_p// /}"
                [[ -z "$_p" ]] && continue
                if ! [[ "$_p" =~ ^[0-9]+$ ]] || [[ -z "${_menu_map[$_p]:-}" ]]; then
                    echo -e "${RED}Invalid selection: '$_p'${RESET}"
                    _valid=false; break
                fi
                # Deduplicate
                if ! printf '%s\n' "${_sel_nums[@]:-}" | grep -qx "$_p"; then
                    _sel_nums+=("$_p")
                fi
            done

            if [[ "$_valid" == true && ${#_sel_nums[@]} -gt 3 ]]; then
                echo -e "${RED}Rule 14: You selected ${#_sel_nums[@]} users — maximum is 3. Aborting.${RESET}"
                log "Rule 14 enforced: operator tried to reset ${#_sel_nums[@]} passwords" WARNING
                _valid=false
            fi

            if [[ "$_valid" == true && ${#_sel_nums[@]} -gt 0 ]]; then
                # Show selections and confirm
                echo -e "\n${YELLOW}Selected for password reset:${RESET}"
                for _n in "${_sel_nums[@]}"; do
                    echo -e "  • ${_menu_map[$_n]}"
                done
                echo ""
                read -r -p "$(echo -e "${BOLD}Enter the new password to apply to all selected users: ${RESET}")" -s _new_pw
                echo ""
                if [[ -z "$_new_pw" ]]; then
                    echo -e "${RED}Empty password entered — aborting password reset.${RESET}"
                    log "Empty password entered — reset aborted" WARNING
                else
                    read -r -p "$(echo -e "${BOLD}Confirm password: ${RESET}")" -s _new_pw2
                    echo ""
                    if [[ "$_new_pw" != "$_new_pw2" ]]; then
                        echo -e "${RED}Passwords do not match — aborting password reset.${RESET}"
                        log "Password mismatch — reset aborted" WARNING
                    else
                        for _n in "${_sel_nums[@]}"; do
                            _u="${_menu_map[$_n]}"
                            if echo "$_u:$_new_pw" | chpasswd 2>/dev/null; then
                                log "Password reset: $_u" SUCCESS
                                echo "[$(date '+%H:%M:%S')] SUCCESS: $_u" >> "$_pw_log"
                                (( _pw_success++ ))
                                add_change "Password" "Reset" "$_u"
                            else
                                log "Password reset FAILED: $_u" ERROR
                                echo "[$(date '+%H:%M:%S')] FAILED: $_u" >> "$_pw_log"
                                (( _pw_fail++ ))
                            fi
                        done
                        echo "[$(date '+%H:%M:%S')] Summary: $_pw_success ok / $_pw_fail failed" >> "$_pw_log"
                        log "Password resets — Success: $_pw_success | Failed: $_pw_fail" INFO
                        echo -e "${CYAN}Password change log: $_pw_log${RESET}"
                    fi
                fi
            else
                log "No valid users selected for password reset (skipped)" INFO
            fi
        else
            log "Password reset skipped by operator" WARNING
        fi
    fi
}  # end always-run password reset section

# ── 1.6: Lock blank-password accounts ───────────────────────────────────────
if [[ ${#BLANK_PW_USERS[@]} -gt 0 ]]; then
    log "Step 1.6: Locking accounts with blank/no passwords..." INFO
    for _u in "${BLANK_PW_USERS[@]}"; do
        # Only lock if the account still exists
        if user_exists "$_u"; then
            if passwd -l "$_u" &>/dev/null 2>&1; then
                log "Locked blank-password account: $_u" SUCCESS
                add_change "Users" "Locked (blank pw)" "$_u"
            else
                log "Failed to lock $_u" ERROR
            fi
        fi
    done
fi

# ── 1.7: Disable guest account if it exists ─────────────────────────────────
if user_exists "guest"; then
    passwd -l "guest" &>/dev/null 2>&1 && \
        log "Locked guest account" SUCCESS || \
        log "Could not lock guest account" WARNING
    add_change "Users" "Locked" "guest"
fi

# ── 1.8: Generate user audit report ─────────────────────────────────────────
_audit_report="$BLUETEAM_DIR/user-audit-$(date '+%Y%m%d-%H%M%S').txt"
{
    echo "USER AUDIT REPORT — $HOSTNAME_LC — $(date)"
    echo "======================================================"
    echo ""
    echo "SAFE USER LIST (${#SAFE_USERS[@]} entries):"
    printf '  %s\n' "${SAFE_USERS[@]}"
    echo ""
    echo "REMAINING REAL ACCOUNTS:"
    while IFS=':' read -r _ru _ _ruid _ _ _ _rsh; do
        [[ "$_ruid" -eq 0 ]] && continue
        case "$_rsh" in */nologin|*/false|"") continue ;; esac
        [[ "$_ruid" -eq 65534 || "$_ruid" -eq 65535 ]] && continue
        echo "  $_ru (uid=$_ruid)"
    done < /etc/passwd
    echo ""
    echo "REMOVED ACCOUNTS ($(n_removed)):"
    cat "$REMOVED_USERS_FILE" 2>/dev/null | sed 's/^/  /' || echo "  none"
    echo ""
    echo "BLANK/NO-PASSWORD ACCOUNTS FOUND (locked):"
    printf '  %s\n' "${BLANK_PW_USERS[@]:-none}"
    echo ""
    echo "PRIVILEGED GROUP VIOLATIONS FIXED (${#GROUP_VIOLATIONS[@]}):"
    printf '  %s\n' "${GROUP_VIOLATIONS[@]:-none}"
} > "$_audit_report"

log "User audit report saved: $_audit_report" SUCCESS
log "Phase 1 complete — Removed: $(n_removed) | Issues: ${#GROUP_VIOLATIONS[@]}" SUCCESS

fi  # end Phase 1

# ==============================================================================
# PHASE 2 — SSH HARDENING
# Rule 10: SSH MUST remain active. We harden, never disable.
# ==============================================================================
if run_phase 2; then

echo -e "\n${BOLD}${MAGENTA}============================================================
PHASE 2: SSH HARDENING  (SSH stays ON — Rule 10)
============================================================${RESET}"
log "Phase 2: SSH hardening started" CRITICAL

SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_BACKUP="${SSHD_CONFIG}.blueteam.$(date '+%Y%m%d%H%M%S').bak"
cp "$SSHD_CONFIG" "$SSHD_BACKUP"
log "sshd_config backed up: $SSHD_BACKUP" SUCCESS

# Helper: idempotently set or replace a sshd_config directive
sshd_set() {
    local key="$1" val="$2"
    if grep -qE "^#?[[:space:]]*${key}[[:space:]]" "$SSHD_CONFIG" 2>/dev/null; then
        sed -i "s|^#\?[[:space:]]*${key}[[:space:]].*|${key} ${val}|" "$SSHD_CONFIG"
    else
        echo "${key} ${val}" >> "$SSHD_CONFIG"
    fi
}

log "Applying SSH hardening directives..." INFO
sshd_set "Protocol"                "2"
sshd_set "PermitRootLogin"         "no"
# Keep PasswordAuthentication yes — scoring engine / jumpboxes need password SSH
sshd_set "PasswordAuthentication"  "yes"
sshd_set "PermitEmptyPasswords"    "no"
sshd_set "MaxAuthTries"            "4"
sshd_set "MaxSessions"             "10"
sshd_set "LoginGraceTime"          "30"
sshd_set "ClientAliveInterval"     "300"
sshd_set "ClientAliveCountMax"     "2"
sshd_set "X11Forwarding"           "no"
sshd_set "AllowAgentForwarding"    "no"
sshd_set "AllowTcpForwarding"      "no"
sshd_set "UsePAM"                  "yes"
sshd_set "PrintLastLog"            "yes"
sshd_set "LogLevel"                "VERBOSE"
sshd_set "Compression"             "no"
sshd_set "TCPKeepAlive"            "no"
sshd_set "Banner"                  "/etc/issue.net"

# Warning banner
cat > /etc/issue.net <<'BANNER'
*******************************************************************************
 WARNING: Unauthorized access prohibited. All activity is monitored & logged.
 CDT Competition — Blue Team Protected System
*******************************************************************************
BANNER
log "SSH login banner written to /etc/issue.net" SUCCESS

# Validate and restart
if sshd -t -f "$SSHD_CONFIG" 2>/dev/null; then
    systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
    log "SSH service restarted with hardened config" SUCCESS
    add_change "SSH" "Hardened config applied" "sshd_config"
else
    log "sshd config validation FAILED — restoring backup!" ERROR
    cp "$SSHD_BACKUP" "$SSHD_CONFIG"
    systemctl restart ssh 2>/dev/null || true
    log "Backup restored. Review config manually." WARNING
fi

log "Phase 2 complete — SSH hardened and remains active" SUCCESS

fi  # end Phase 2

# ==============================================================================
# PHASE 3 — FIREWALL HARDENING
# Rule 7:  No subnet blocking — individual ALLOW rules only.
# Rule 10: Port 22 must always be open.
# ==============================================================================
if run_phase 3; then

echo -e "\n${BOLD}${MAGENTA}============================================================
PHASE 3: FIREWALL HARDENING
(iptables — no subnet blocks — Rule 7)
============================================================${RESET}"
log "Phase 3: Firewall hardening started" CRITICAL

# ── 3.0: Ensure iptables-persistent is available ────────────────────────────
if ! command -v iptables &>/dev/null; then
    log "iptables not found — attempting install" WARNING
    apt-get install -y iptables iptables-persistent &>/dev/null || \
        { log "Could not install iptables. Skipping Phase 3." ERROR; }
fi

# ── FAIL-SAFE: Allow SSH before touching any other rules ────────────────────
log "Creating SSH fail-safe ALLOW rule before any changes..." WARNING
iptables -C INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null || \
    iptables -I INPUT 1 -p tcp --dport 22 \
        -m comment --comment "BLUETEAM-SSH-FAILSAFE" -j ACCEPT
log "SSH fail-safe rule in place (port 22 guaranteed open)" SUCCESS

# ── 3.1: Determine which service this host runs ──────────────────────────────
echo -e "\n${BOLD}${CYAN}Step 3.1 — Service port selection${RESET}"
echo -e "${WHITE}Running on host: ${BOLD}${HOSTNAME_LC}${RESET}"
echo ""

echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════════╗
║        WHICH SCORED SERVICE RUNS ON THIS HOST?               ║
╚══════════════════════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "  ${BOLD}[1]${RESET}  Apache2       — ponyville       (10.0.10.3)  ports: 80, 443"
echo -e "  ${BOLD}[2]${RESET}  MariaDB        — seaddle         (10.0.10.4)  port:  3306"
echo -e "  ${BOLD}[3]${RESET}  CUPS           — trotsylvania    (10.0.10.5)  port:  631"
echo -e "  ${BOLD}[4]${RESET}  vsftpd         — crystal-empire  (10.0.10.6)  ports: 20, 21, 30000-31000"
echo -e "  ${BOLD}[5]${RESET}  IRC            — everfree-forest (10.0.20.3)  ports: 6667, 6697"
echo -e "  ${BOLD}[6]${RESET}  Nginx          — griffonstone    (10.0.20.4)  ports: 80, 443"
echo -e "  ${BOLD}[7]${RESET}  Ubuntu WS      — cloudsdale / vanhoover / whinnyapolis  SSH only"
echo ""
echo -e "${YELLOW}  SSH (port 22) is always opened regardless of selection (Rule 10).${RESET}"
echo ""

_detected_ports=""
while true; do
    read -r -p "$(echo -e "${BOLD}Enter choice [1-7]: ${RESET}")" _svc_choice
    case "$_svc_choice" in
        1) _detected_ports="tcp:80 tcp:443";         _svc_label="Apache2 (80, 443)"; break ;;
        2) _detected_ports="tcp:3306";               _svc_label="MariaDB (3306)"; break ;;
        3) _detected_ports="tcp:631 udp:631";        _svc_label="CUPS (631)"; break ;;
        4) _detected_ports="tcp:20 tcp:21 tcp:30000:31000"; _svc_label="vsftpd (20, 21, 30000-31000)"; break ;;
        5) _detected_ports="tcp:6667 tcp:6697";      _svc_label="IRC (6667, 6697)"; break ;;
        6) _detected_ports="tcp:80 tcp:443";         _svc_label="Nginx (80, 443)"; break ;;
        7) _detected_ports="";                       _svc_label="Ubuntu Workstation (SSH only)"; break ;;
        *) echo -e "${RED}Invalid choice. Enter a number 1-7.${RESET}" ;;
    esac
done

log "Operator selected service: $_svc_label" CRITICAL
add_change "Firewall" "Service selected" "$_svc_label"

# ── 3.2: Prompt operator to add extra safe IPs beyond the packet list ────────
echo -e "\n${BOLD}${CYAN}Step 3.2 — Extra IP allowlist (scoring engine + jumpboxes pre-loaded)${RESET}"
echo -e "${WHITE}Pre-loaded safe IPs:${RESET}"
printf '  %s\n' "${SAFE_IPS[@]}"
echo ""
echo -e "${YELLOW}Add any extra IPs to allow? (space-separated, or Enter to skip):${RESET}"
read -r -p "Extra IPs: " _extra_ips_raw
if [[ -n "$_extra_ips_raw" ]]; then
    IFS=' ' read -ra _extra_ips <<< "$_extra_ips_raw"
    for _ip in "${_extra_ips[@]}"; do
        SAFE_IPS+=("$_ip")
        log "Operator added safe IP: $_ip" SUCCESS
    done
fi

# ── 3.3: Apply firewall rules ────────────────────────────────────────────────
log "Flushing and rebuilding iptables INPUT chain..." INFO

# Flush INPUT (not OUTPUT — leave outbound open)
iptables -F INPUT
iptables -F FORWARD
iptables -Z INPUT 2>/dev/null || true

# Default policies: drop inbound, allow outbound, drop forward
iptables -P INPUT   DROP
iptables -P FORWARD DROP
iptables -P OUTPUT  ACCEPT

# Allow established/related (essential — lets existing connections work)
iptables -A INPUT -m state --state ESTABLISHED,RELATED \
    -m comment --comment "BLUETEAM-ESTABLISHED" -j ACCEPT
log "Rule: ALLOW ESTABLISHED/RELATED" SUCCESS

# Loopback
iptables -A INPUT -i lo \
    -m comment --comment "BLUETEAM-LOOPBACK" -j ACCEPT
log "Rule: ALLOW loopback" SUCCESS

# ICMP — allow ping (scoring engine pings hosts; blocking kills uptime score)
iptables -A INPUT -p icmp --icmp-type echo-request \
    -m comment --comment "BLUETEAM-ICMP-PING" -j ACCEPT
log "Rule: ALLOW ICMP ping (required for scoring)" SUCCESS

# SSH — always open (Rule 10). Per-IP restriction: safe IPs only.
# We allow from safe IPs explicitly, then allow from everywhere else
# (competing teams and scoring engine need to reach SSH too).
# Rule 7 says no subnet blocks so we can't block non-safe sources wholesale.
iptables -A INPUT -p tcp --dport 22 \
    -m comment --comment "BLUETEAM-SSH-ALWAYS-OPEN" -j ACCEPT
log "Rule: ALLOW SSH port 22 (all sources — Rule 10)" SUCCESS

# Safe IPs — allow ALL traffic from scoring engine and jumpboxes
# (Rule 7: these are individual IPs, not subnet blocks)
for _ip in "${SAFE_IPS[@]}"; do
    iptables -A INPUT -s "$_ip" \
        -m comment --comment "BLUETEAM-SAFE-IP-${_ip}" -j ACCEPT
    log "Rule: ALLOW all from safe IP $_ip" SUCCESS
    add_change "Firewall" "Allow safe IP" "$_ip"
done

# Service-specific ports
if [[ -n "$_detected_ports" ]]; then
    for _entry in $_detected_ports; do
        _proto="${_entry%%:*}"          # tcp or udp
        _portpart="${_entry#*:}"        # port or port:portend (range)
        if [[ "$_portpart" == *:* ]]; then
            # Port range (e.g. 30000:31000)
            iptables -A INPUT -p "$_proto" --dport "$_portpart" \
                -m comment --comment "BLUETEAM-SVC-RANGE-${_portpart}" -j ACCEPT
            log "Rule: ALLOW $_proto range $_portpart" SUCCESS
        else
            iptables -A INPUT -p "$_proto" --dport "$_portpart" \
                -m comment --comment "BLUETEAM-SVC-${_portpart}" -j ACCEPT
            log "Rule: ALLOW $_proto port $_portpart" SUCCESS
        fi
        add_change "Firewall" "Allow service port" "$_proto:$_portpart"
    done
fi

# Log dropped packets (helps detect Red Team activity)
iptables -A INPUT -m limit --limit 10/min \
    -m comment --comment "BLUETEAM-DROP-LOG" \
    -j LOG --log-prefix "BLUETEAM_DROP: " --log-level 7
iptables -A INPUT -j DROP

log "Default INPUT policy: DROP (all non-matched traffic)" SUCCESS

# Persist rules
mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules.v4 2>/dev/null || \
    iptables-save > /etc/iptables.rules 2>/dev/null || true

if command -v netfilter-persistent &>/dev/null; then
    netfilter-persistent save &>/dev/null || true
fi

add_change "Firewall" "Rebuilt iptables rules" "INPUT DROP with service/safe-IP ACCEPT"
log "Phase 3 complete — Firewall active. SSH guaranteed open. Safe IPs allowed." SUCCESS

fi  # end Phase 3

# ==============================================================================
# PHASE 4 — KERNEL / SYSCTL NETWORK HARDENING
# ==============================================================================
if run_phase 4; then

echo -e "\n${BOLD}${MAGENTA}============================================================
PHASE 4: KERNEL / SYSCTL NETWORK HARDENING
============================================================${RESET}"
log "Phase 4: Kernel/sysctl hardening started" CRITICAL

SYSCTL_FILE="/etc/sysctl.d/99-blueteam.conf"

cat > "$SYSCTL_FILE" <<'SYSCTL'
# CDT Blue Team Hardening — sysctl

# ── IP Forwarding (we are not a router) ──────────────────────────────────────
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# ── Source routing — disable (prevents routing attacks) ──────────────────────
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# ── ICMP redirects — disable (prevents MITM) ─────────────────────────────────
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# ── SYN cookies — prevent SYN flood ──────────────────────────────────────────
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048

# ── Log martians (spoofed packets) ───────────────────────────────────────────
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# ── Smurf attack prevention ───────────────────────────────────────────────────
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# ── Reverse path filtering (prevent IP spoofing) ──────────────────────────────
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# ── TCP hardening ─────────────────────────────────────────────────────────────
net.ipv4.tcp_rfc1337 = 1

# ── Kernel hardening ──────────────────────────────────────────────────────────
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1

# ── No core dumps for setuid ──────────────────────────────────────────────────
fs.suid_dumpable = 0
SYSCTL

if sysctl -p "$SYSCTL_FILE" &>/dev/null 2>&1; then
    log "sysctl parameters applied from $SYSCTL_FILE" SUCCESS
else
    # Apply individually — some params may not exist on all kernels
    while IFS= read -r _line; do
        [[ "$_line" =~ ^#.*$ || -z "$_line" ]] && continue
        sysctl -w "$_line" &>/dev/null 2>&1 || true
    done < "$SYSCTL_FILE"
    log "sysctl applied (some params may not apply on this kernel — normal)" SUCCESS
fi
add_change "Kernel" "sysctl hardening" "$SYSCTL_FILE"

# Disable Avahi/mDNS (like LLMNR on Windows — enables MITM credential theft)
for _svc in avahi-daemon avahi-dnsconfd; do
    if systemctl is-active "$_svc" &>/dev/null 2>&1; then
        systemctl stop "$_svc" 2>/dev/null && \
        systemctl disable "$_svc" 2>/dev/null && \
            log "Disabled service: $_svc" SUCCESS || \
            log "Failed to disable: $_svc" WARNING
        add_change "Services" "Disabled" "$_svc"
    fi
done

# Disable unnecessary network services (if not the scored host for that service)
declare -A SERVICE_HOST_MAP
SERVICE_HOST_MAP["cups"]="trotsylvania"
SERVICE_HOST_MAP["vsftpd"]="crystal-empire"
SERVICE_HOST_MAP["apache2"]="ponyville"
SERVICE_HOST_MAP["nginx"]="griffonstone"
SERVICE_HOST_MAP["mariadb"]="seaddle"
SERVICE_HOST_MAP["mysql"]="seaddle"

for _svc in cups vsftpd apache2 nginx mariadb mysql; do
    _scored_host="${SERVICE_HOST_MAP[$_svc]:-}"
    if [[ "$HOSTNAME_LC" == "$_scored_host" ]]; then
        log "Keeping service '$_svc' (this is the scored host)" INFO
        continue
    fi
    if systemctl is-active "$_svc" &>/dev/null 2>&1; then
        log "Disabling '$_svc' (not the scored host for this service)" INFO
        systemctl stop "$_svc" 2>/dev/null || true
        systemctl disable "$_svc" 2>/dev/null || true
        log "Disabled: $_svc" SUCCESS
        add_change "Services" "Disabled" "$_svc"
    fi
done

log "Phase 4 complete — Kernel hardened, unnecessary services stopped" SUCCESS

fi  # end Phase 4

# ==============================================================================
# PHASE 5 — PERSISTENCE & BACKDOOR DETECTION
# Rule 5: Skip anything with "greyteam" in the name.
# ==============================================================================
if run_phase 5; then

echo -e "\n${BOLD}${MAGENTA}============================================================
PHASE 5: PERSISTENCE & BACKDOOR DETECTION
============================================================${RESET}"
log "Phase 5: Backdoor/persistence detection started" CRITICAL

# Helper: skip greyteam artifacts (Rule 5)
is_greyteam() { echo "$1" | grep -qi "greyteam\|grayteam"; }

# ── 5.1: Scan cron jobs ──────────────────────────────────────────────────────
log "5.1: Scanning cron jobs for suspicious entries..." INFO
_suspicious_crons=0

check_cron_file() {
    local _f="$1"
    is_greyteam "$_f" && { log "  Skipping greyteam cron: $_f (Rule 5)" INFO; return; }
    [[ ! -f "$_f" ]] && return
    if grep -qE "(curl|wget|bash|python|perl|ruby|nc |ncat |netcat |mkfifo|/dev/tcp|base64 -d|eval|IEX)" \
        "$_f" 2>/dev/null; then
        log "SUSPICIOUS CRON: $_f" CRITICAL sec
        grep -nE "(curl|wget|bash|python|perl|ruby|nc |ncat |netcat |mkfifo|/dev/tcp|base64 -d|eval|IEX)" \
            "$_f" 2>/dev/null | while read -r _l; do
            log "  Line: $_l" WARNING
        done
        (( _suspicious_crons++ )) || true
    fi
}

for _loc in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
    [[ -d "$_loc" ]] && find "$_loc" -maxdepth 1 -type f | while read -r _f; do check_cron_file "$_f"; done
done
check_cron_file /etc/crontab

# Per-user crontabs
while IFS=':' read -r _u _ _uid _ _ _ _sh; do
    [[ "$_uid" -eq 0 ]] && continue
    case "$_sh" in */nologin|*/false|"") continue ;; esac
    [[ "$_uid" -eq 65534 || "$_uid" -eq 65535 ]] && continue
    _cf="/var/spool/cron/crontabs/$_u"
    check_cron_file "$_cf"
done

log "Cron scan done. Suspicious files found: $_suspicious_crons (review manually)" INFO
[[ $_suspicious_crons -gt 0 ]] && echo -e "${YELLOW}⚠ Review the flagged cron files above and remove manually if malicious.${RESET}"

# ── 5.2: Scan systemd units for suspicious ExecStart ────────────────────────
log "5.2: Scanning systemd units for suspicious commands..." INFO
_suspicious_units=0

find /etc/systemd/system /usr/lib/systemd/system \
    -name "*.service" 2>/dev/null | while read -r _unit; do

    is_greyteam "$_unit" && { log "  Skipping greyteam unit: $_unit (Rule 5)" INFO; continue; }

    if grep -qE "(ExecStart|ExecStartPre).*?(curl|wget|bash -[a-z]*i|python.*-c|perl.*-e|nc |ncat |mkfifo|/dev/tcp|base64)" \
        "$_unit" 2>/dev/null; then
        log "SUSPICIOUS SYSTEMD UNIT: $_unit" CRITICAL sec
        grep -nE "(ExecStart|ExecStartPre)" "$_unit" 2>/dev/null | \
            while read -r _l; do log "  $_l" WARNING; done
        (( _suspicious_units++ )) || true
    fi
done

log "Systemd unit scan done" INFO

# ── 5.3: Check user shell configs for backdoors ──────────────────────────────
log "5.3: Checking user shell configs (.bashrc/.profile) for persistence..." INFO

while IFS=':' read -r _u _ _uid _ _ _ _sh; do
    [[ "$_uid" -eq 0 ]] && continue
    case "$_sh" in */nologin|*/false|"") continue ;; esac
    [[ "$_uid" -eq 65534 || "$_uid" -eq 65535 ]] && continue
    _home=$(getent passwd "$_u" | cut -d: -f6)
    for _rc in "$_home/.bashrc" "$_home/.bash_profile" "$_home/.profile" \
               "$_home/.zshrc" "$_home/.bash_logout"; do
        [[ ! -f "$_rc" ]] && continue
        is_greyteam "$_rc" && continue
        if grep -qE "(curl|wget|nc |ncat |mkfifo|/dev/tcp|base64 -d|eval.*base64)" \
            "$_rc" 2>/dev/null; then
            log "SUSPICIOUS SHELL CONFIG: $_rc (user: $_u)" CRITICAL sec
            grep -n "." "$_rc" 2>/dev/null | grep -E "(curl|wget|nc |ncat |mkfifo|/dev/tcp|base64 -d|eval.*base64)" | \
                while read -r _l; do log "  $_l" WARNING; done
        fi
    done
done

# ── 5.4: Check /etc/rc.local ────────────────────────────────────────────────
if [[ -f /etc/rc.local ]]; then
    if grep -qE "(curl|wget|bash|python|nc |ncat |mkfifo|/dev/tcp|base64 -d)" /etc/rc.local 2>/dev/null; then
        log "SUSPICIOUS CONTENT in /etc/rc.local" CRITICAL sec
    fi
fi

# ── 5.5: Processes running from suspicious paths ─────────────────────────────
log "5.5: Scanning for processes running from /tmp, /var/tmp, /dev/shm..." INFO

_susp_procs=0
while read -r _pid; do
    _exe=$(readlink -f "/proc/$_pid/exe" 2>/dev/null) || continue
    if [[ "$_exe" == /tmp/* || "$_exe" == /var/tmp/* || \
          "$_exe" == /dev/shm/* || "$_exe" == /run/shm/* ]]; then
        _cmd=$(cat "/proc/$_pid/cmdline" 2>/dev/null | tr '\0' ' ' | head -c 200) || true
        log "SUSPICIOUS PROCESS: PID=$_pid EXE=$_exe CMD=$_cmd" CRITICAL sec
        (( _susp_procs++ )) || true
    fi
done < <(ls /proc | grep -E '^[0-9]+$')

log "Suspicious process scan done. Found: $_susp_procs" INFO
[[ $_susp_procs -gt 0 ]] && echo -e "${RED}⚠ Review suspicious processes above and kill them manually if malicious.${RESET}"

# ── 5.6: Check /etc/passwd and /etc/sudoers for modifications ───────────────
log "5.6: Checking sudoers for unauthorized entries..." INFO

if [[ -f /etc/sudoers ]]; then
    while IFS= read -r _line; do
        [[ "$_line" =~ ^#.*$ || -z "$_line" ]] && continue
        _user=$(echo "$_line" | awk '{print $1}')
        # Lines starting with % are group entries
        if [[ "$_user" != %* ]] && ! is_safe "$_user"; then
            log "SUSPICIOUS SUDOERS ENTRY: $_line" CRITICAL sec
        fi
    done < /etc/sudoers
fi

# Also check sudoers.d/
if [[ -d /etc/sudoers.d ]]; then
    find /etc/sudoers.d -type f | while read -r _sf; do
        is_greyteam "$_sf" && continue
        log "Sudoers.d file found: $_sf — review manually" WARNING
    done
fi

log "Phase 5 complete — persistence locations scanned" SUCCESS

fi  # end Phase 5

# ==============================================================================
# PHASE 6 — SYSTEM HARDENING
# ==============================================================================
if run_phase 6; then

echo -e "\n${BOLD}${MAGENTA}============================================================
PHASE 6: SYSTEM HARDENING
============================================================${RESET}"
log "Phase 6: System hardening started" CRITICAL

# ── 6.1: SUID/SGID audit ─────────────────────────────────────────────────────
log "6.1: Auditing SUID/SGID binaries..." INFO

# Known-legitimate SUID/SGID binaries on Debian/Ubuntu
_legit_suids=(
    /usr/bin/sudo /usr/bin/su /usr/bin/passwd /usr/bin/newgrp
    /usr/bin/chsh /usr/bin/chfn /usr/bin/gpasswd /usr/bin/pkexec
    /usr/bin/at /usr/bin/crontab /usr/bin/expiry /usr/bin/wall
    /usr/bin/write /usr/bin/ssh-agent /usr/bin/ping
    /usr/lib/openssh/ssh-keysign
    /usr/lib/dbus-1.0/dbus-daemon-launch-helper
    /usr/lib/x86_64-linux-gnu/utempter/utempter
    /sbin/unix_chkpwd /usr/sbin/unix_chkpwd
    /bin/ping /bin/su
)

_susp_suids=0
while IFS= read -r -d '' _f; do
    _known=false
    for _l in "${_legit_suids[@]}"; do
        [[ "$_f" == "$_l" ]] && { _known=true; break; }
    done
    if [[ "$_known" == false ]]; then
        log "UNEXPECTED SUID/SGID: $_f" CRITICAL sec
        (( _susp_suids++ )) || true
    fi
done < <(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -print0 2>/dev/null)

log "SUID/SGID audit done. Unexpected: $_susp_suids (review manually before removing)" SUCCESS
add_change "System" "SUID audit" "Found: $_susp_suids unexpected"

# ── 6.2: Restrict compiler access to root ────────────────────────────────────
log "6.2: Restricting compiler access to root only..." INFO
for _cc in gcc cc g++ make as ld python3 python perl ruby; do
    if _p=$(command -v "$_cc" 2>/dev/null); then
        chmod o-rx "$_p" 2>/dev/null && \
            log "  Restricted: $_cc ($p)" SUCCESS || \
            log "  Could not restrict: $_cc" WARNING
    fi
done
add_change "System" "Compiler access restricted" "root only"

# ── 6.3: Disable USB storage ─────────────────────────────────────────────────
log "6.3: Blacklisting USB storage kernel module..." INFO
echo "blacklist usb-storage" > /etc/modprobe.d/blueteam-usb.conf
rmmod usb_storage 2>/dev/null || true
log "USB storage blacklisted" SUCCESS
add_change "System" "USB storage" "Blacklisted"

# ── 6.4: Disable core dumps ──────────────────────────────────────────────────
log "6.4: Disabling core dumps..." INFO
cat > /etc/security/limits.d/blueteam-nodumps.conf <<'EOF'
* hard core 0
* soft core 0
EOF
ulimit -c 0 2>/dev/null || true
log "Core dumps disabled" SUCCESS
add_change "System" "Core dumps" "Disabled"

# ── 6.5: Lock root account password (sudo only) ──────────────────────────────
log "6.5: Locking root password (sudo still works)..." INFO
passwd -l root 2>/dev/null && \
    log "Root password locked — sudo remains functional" SUCCESS || \
    log "Could not lock root password" WARNING
add_change "System" "Root password" "Locked (sudo intact)"

# ── 6.6: Enable AppArmor if available ────────────────────────────────────────
if command -v aa-status &>/dev/null; then
    log "6.6: Enabling AppArmor..." INFO
    systemctl enable apparmor 2>/dev/null || true
    systemctl start apparmor 2>/dev/null && \
        log "AppArmor enabled" SUCCESS || \
        log "AppArmor failed to start" WARNING
    add_change "System" "AppArmor" "Enabled"
fi

# ── 6.7: Secure /tmp (noexec remount if separate partition) ──────────────────
log "6.7: Checking /tmp mount options..." INFO
if mount | grep -q " on /tmp "; then
    mount -o remount,noexec,nosuid,nodev /tmp 2>/dev/null && \
        log "/tmp remounted noexec,nosuid,nodev" SUCCESS || \
        log "Could not remount /tmp — may be on root fs" WARNING
    add_change "System" "/tmp" "noexec,nosuid,nodev"
else
    log "/tmp is on root filesystem — fstab entry would be needed for persistence" INFO
fi

# ── 6.8: Restrict su to sudo group via PAM ──────────────────────────────────
log "6.8: Restricting 'su' to sudo group via PAM..." INFO
_pam_su="/etc/pam.d/su"
if [[ -f "$_pam_su" ]]; then
    if ! grep -q "pam_wheel" "$_pam_su"; then
        sed -i '1s/^/auth required pam_wheel.so group=sudo\n/' "$_pam_su"
        log "su restricted to sudo group" SUCCESS
        add_change "System" "su restriction" "sudo group only"
    else
        log "su PAM wheel restriction already configured" INFO
    fi
fi

log "Phase 6 complete — System hardened" SUCCESS

fi  # end Phase 6

# ==============================================================================
# PHASE 7 — AUDIT LOGGING
# ==============================================================================
if run_phase 7; then

echo -e "\n${BOLD}${MAGENTA}============================================================
PHASE 7: AUDIT LOGGING
============================================================${RESET}"
log "Phase 7: Audit logging setup started" CRITICAL

# ── 7.1: Install auditd if needed ────────────────────────────────────────────
if ! command -v auditctl &>/dev/null; then
    log "Installing auditd..." INFO
    apt-get install -y auditd audispd-plugins 2>/dev/null && \
        log "auditd installed" SUCCESS || \
        log "auditd install failed — audit logging limited" ERROR
fi

# ── 7.2: Write auditd rules ──────────────────────────────────────────────────
log "7.2: Writing auditd rules..." INFO
AUDIT_RULES_FILE="/etc/audit/rules.d/99-blueteam.rules"
mkdir -p /etc/audit/rules.d

cat > "$AUDIT_RULES_FILE" <<'AUDRULES'
# CDT Blue Team — auditd Rules

# Flush existing rules and set buffer
-D
-b 8192
-f 1

# ── User/Group modifications ──────────────────────────────────────────────────
-w /etc/passwd   -p wa -k user_modification
-w /etc/shadow   -p wa -k user_modification
-w /etc/group    -p wa -k group_modification
-w /etc/gshadow  -p wa -k group_modification
-w /etc/sudoers  -p wa -k sudoers_change
-w /etc/sudoers.d/ -p wa -k sudoers_change

# ── Authentication events ─────────────────────────────────────────────────────
-w /var/log/faillog  -p wa -k login_failure
-w /var/log/lastlog  -p wa -k login_success
-w /var/run/faillock/ -p wa -k login_failure

# ── SSH configuration ─────────────────────────────────────────────────────────
-w /etc/ssh/sshd_config -p wa -k ssh_config
-w /etc/ssh/           -p wa -k ssh_config

# ── Cron changes ──────────────────────────────────────────────────────────────
-w /etc/crontab    -p wa -k cron_change
-w /etc/cron.d/    -p wa -k cron_change
-w /etc/cron.daily/   -p wa -k cron_change
-w /etc/cron.hourly/  -p wa -k cron_change
-w /var/spool/cron/   -p wa -k cron_change

# ── Firewall changes ──────────────────────────────────────────────────────────
-w /etc/iptables/  -p wa -k firewall_change
-w /sbin/iptables  -p x  -k firewall_cmd
-w /usr/sbin/ufw   -p x  -k firewall_cmd
-w /usr/sbin/nft   -p x  -k firewall_cmd

# ── Kernel module loading ─────────────────────────────────────────────────────
-w /sbin/insmod   -p x -k module_load
-w /sbin/rmmod    -p x -k module_load
-w /sbin/modprobe -p x -k module_load
-a always,exit -F arch=b64 -S init_module  -k module_load
-a always,exit -F arch=b32 -S init_module  -k module_load

# ── Privileged execution (root) ───────────────────────────────────────────────
-a always,exit -F arch=b64 -S execve -F euid=0 -k root_exec
-a always,exit -F arch=b32 -S execve -F euid=0 -k root_exec

# ── SUID/SGID execution ───────────────────────────────────────────────────────
-a always,exit -F arch=b64 -S execve -F perm=sx -k suid_exec
-a always,exit -F arch=b32 -S execve -F perm=sx -k suid_exec

# ── File permission changes ───────────────────────────────────────────────────
-a always,exit -F arch=b64 -S chmod -S fchmod -S chown -S fchown -k perm_change
-a always,exit -F arch=b32 -S chmod -S fchmod -S chown -S fchown -k perm_change

# ── Network connections ────────────────────────────────────────────────────────
-a always,exit -F arch=b64 -S connect -k net_connect
-a always,exit -F arch=b32 -S connect -k net_connect

# ── Network config changes ────────────────────────────────────────────────────
-w /etc/network/interfaces -p wa -k net_config
-w /etc/netplan/           -p wa -k net_config
-w /etc/resolv.conf        -p wa -k net_config
-w /etc/hosts              -p wa -k net_config
AUDRULES

# Load rules
if augenrules --load &>/dev/null 2>&1; then
    log "auditd rules loaded via augenrules" SUCCESS
elif command -v auditctl &>/dev/null; then
    auditctl -R "$AUDIT_RULES_FILE" 2>/dev/null && \
        log "auditd rules loaded via auditctl" SUCCESS || \
        log "Failed to load auditd rules" ERROR
fi

# ── 7.3: Configure auditd log rotation ───────────────────────────────────────
log "7.3: Configuring auditd log rotation..." INFO
AUDITD_CONF="/etc/audit/auditd.conf"
if [[ -f "$AUDITD_CONF" ]]; then
    sed -i 's/^max_log_file =.*/max_log_file = 50/'         "$AUDITD_CONF" 2>/dev/null || true
    sed -i 's/^num_logs =.*/num_logs = 10/'                 "$AUDITD_CONF" 2>/dev/null || true
    sed -i 's/^max_log_file_action =.*/max_log_file_action = ROTATE/' "$AUDITD_CONF" 2>/dev/null || true
    log "auditd log rotation: 50MB x 10 files" SUCCESS
fi

systemctl enable auditd 2>/dev/null || true
systemctl restart auditd 2>/dev/null && \
    log "auditd restarted" SUCCESS || \
    log "auditd restart failed" WARNING
add_change "Audit" "auditd rules" "Comprehensive rule set loaded"

# ── 7.4: Enhanced bash history ───────────────────────────────────────────────
log "7.4: Configuring enhanced bash history logging..." INFO
cat > /etc/profile.d/blueteam-history.sh <<'HISTCONF'
# CDT Blue Team — enhanced shell history
export HISTSIZE=50000
export HISTFILESIZE=50000
export HISTTIMEFORMAT="%Y-%m-%d %H:%M:%S  "
export HISTCONTROL=""       # Record all commands including duplicates
shopt -s histappend         # Append, don't overwrite
export PROMPT_COMMAND='history -a; history -r'

# Log every command to syslog
_bt_log_cmd() {
    logger -p local6.debug -t "bash[$$]" "[${USER}@$(hostname)] [$(pwd)] ${BASH_COMMAND}" 2>/dev/null || true
}
trap '_bt_log_cmd' DEBUG
HISTCONF
chmod 644 /etc/profile.d/blueteam-history.sh
log "Enhanced bash history configured for all users" SUCCESS
add_change "Audit" "bash history" "Enhanced logging to syslog"

# ── 7.5: rsyslog — capture command log to blueteam log dir ──────────────────
log "7.5: Configuring rsyslog for command capture..." INFO
cat > /etc/rsyslog.d/50-blueteam.conf <<EOF
local6.* $LOG_DIR/shell-commands.log
auth,authpriv.* $LOG_DIR/auth.log
EOF
systemctl restart rsyslog 2>/dev/null && \
    log "rsyslog restarted with blueteam logging" SUCCESS || \
    log "rsyslog restart failed" WARNING
add_change "Audit" "rsyslog" "Command and auth logging to $LOG_DIR"

log "Phase 7 complete — Audit logging active" SUCCESS

fi  # end Phase 7

# ==============================================================================
# FINAL REPORT
# ==============================================================================
SCRIPT_END=$(date '+%Y-%m-%d %H:%M:%S')

echo -e "\n${BOLD}${CYAN}============================================================
HARDENING COMPLETE — FINAL REPORT
============================================================${RESET}"

_nc=$(n_changes)
_nr=$(n_removed)
_ni=$(n_issues)

log "End time: $SCRIPT_END" INFO
log "Changes applied: $_nc" INFO
log "Users removed: $_nr" INFO
log "Security issues flagged: $_ni" INFO

echo ""
echo -e "${BOLD}${WHITE}Changes applied:    ${GREEN}${_nc}${RESET}"
echo -e "${BOLD}${WHITE}Users removed:      ${CYAN}${_nr}${RESET}"
echo -e "${BOLD}${WHITE}Security issues:    $([ "$_ni" -gt 0 ] && echo "${RED}" || echo "${GREEN}")${_ni}${RESET}"
echo -e "${BOLD}${WHITE}Log file:           ${YELLOW}${LOG_FILE}${RESET}"
echo ""

if [[ "$_ni" -gt 0 ]]; then
    echo -e "${BOLD}${RED}Security issues flagged (manual review needed):${RESET}"
    cat "$SECURITY_ISSUES_FILE" | sed 's/^/  ⚠  /'
    echo ""
fi

echo -e "${BOLD}${YELLOW}Post-hardening checklist:${RESET}"
echo "  1. Verify scoring engine reachability:  curl -k https://scoring.mlp.local:443"
echo "  2. Verify SSH still works from a jumpbox before closing this session"
echo "  3. Confirm scored service is still running (systemctl status <service>)"
echo "  4. Check $LOG_DIR/ for detailed logs"
echo ""

# Restart prompt — only when all phases ran
if [[ "$RUN_ALL" == true ]]; then
    echo -e "${YELLOW}Some changes (kernel module blacklisting, sysctl) benefit from a reboot.${RESET}"
    read -r -p "$(echo -e "${BOLD}Reboot now? (y/N): ${RESET}")" _reboot_choice
    if [[ "${_reboot_choice,,}" == "y" ]]; then
        log "Operator requested reboot" CRITICAL
        echo -e "${RED}Rebooting in 10 seconds... Ctrl+C to cancel.${RESET}"
        for (( _i=10; _i>0; _i-- )); do echo -ne "\r  ${_i}s "; sleep 1; done
        echo ""
        reboot
    else
        echo -e "${YELLOW}Reboot skipped. Some settings fully active after next reboot.${RESET}"
    fi
fi

echo -e "\n${BOLD}${GREEN}Done. Log: $LOG_FILE${RESET}\n"
