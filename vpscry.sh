#!/usr/bin/env bash

set -uo pipefail

PROGRAM="vpscry"
DISPLAY_NAME="VPScry"
VERSION="1.0.0"
REPORT_TITLE="VPScry Report"
TAGLINE="See what your VPS is hiding."
AUTHOR="Hoek"
WEBSITE="0ut3r.space"
DEFAULT_FORMATS="text,markdown,json,html,actions"
OUTPUT_DIR=""
FORMATS="$DEFAULT_FORMATS"
COLOR_MODE="auto"
ONLINE=0
FAIL_ON="none"
EXPECTED_PORTS_RAW=""
TERMINAL_MODE="progress"
STAGE_TOTAL=14
STAGE_CURRENT=0
REPORT_OWNER_UID="${SUDO_UID:-}"
REPORT_OWNER_GID="${SUDO_GID:-}"
CONFIG_FILE=""
BASELINE_FILE=""
WRITE_BASELINE_FILE=""
SEVERITY_PROFILE="balanced"
EVIDENCE_LIMIT=1600
COMMAND_TIMEOUT_MAX=90
DISK_WARN_PERCENT=80
DISK_FAIL_PERCENT=95
INODE_WARN_PERCENT=80
INODE_FAIL_PERCENT=95
BACKUP_MAX_AGE_DAYS=30
LOG_GROWTH_MIB=20
TOR_CONFIG_ROOT="${VPSCRY_TOR_CONFIG_ROOT:-/etc/tor}"
EXPECTED_SERVICES_RAW=""
EXPECTED_WEBSITES_RAW=""
EXPECTED_TIMERS_RAW=""
EXPECTED_BACKUPS_RAW=""
declare -a REDACT_LITERALS=()
declare -A SUPPRESS_UNTIL=()
declare -A SUPPRESS_REASON=()
declare -A EXPIRED_SUPPRESSIONS=()
START_EPOCH="$(date +%s)"
START_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
HOSTNAME_VALUE="$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || printf 'unknown')"
RUN_AS_ROOT=0
NETWORK_GUARD_AVAILABLE=0
[[ ${EUID:-$(id -u)} -eq 0 ]] && RUN_AS_ROOT=1

TMP_DIR=""
declare -a R_ID=()
declare -a R_CATEGORY=()
declare -a R_STATUS=()
declare -a R_SEVERITY=()
declare -a R_CONFIDENCE=()
declare -a R_TITLE=()
declare -a R_EVIDENCE=()
declare -a R_VERIFY=()
declare -a R_RECOMMENDATION=()
declare -A COUNTS=([PASS]=0 [WARN]=0 [FAIL]=0 [INFO]=0 [SKIP]=0)
declare -A SEEN_RESULT_ID=()
declare -A NET_EXPECTED_PORTS=()
declare -A NET_FW_ALLOW_V4=()
declare -A NET_FW_ALLOW_V6=()
declare -a NET_FW_RANGE_V4=()
declare -a NET_FW_RANGE_V6=()
declare -a NET_FW_SOURCES=()
NET_PUBLIC_V4_COUNT=0
NET_PRIVATE_V4_COUNT=0
NET_PUBLIC_V6_COUNT=0
NET_PRIVATE_V6_COUNT=0
NET_IPV4_DEFAULT_ROUTE=0
NET_IPV6_DEFAULT_ROUTE=0
NET_FW_V4_POLICY="unknown"
NET_FW_V6_POLICY="unknown"
NET_UFW_ACTIVE=0
NET_UFW_IPV6="unknown"
NET_FIREWALLD_ACTIVE=0
NET_FW_COMPLEX=0
UFW_DEFAULT_FILE="${VPSCRY_UFW_DEFAULT_FILE:-/etc/default/ufw}"
MYSQL_CONFIG_ROOT="${VPSCRY_MYSQL_CONFIG_ROOT:-/etc/mysql}"
POSTGRES_CONFIG_ROOT="${VPSCRY_POSTGRES_CONFIG_ROOT:-/etc/postgresql}"
REDIS_CONFIG_ROOT="${VPSCRY_REDIS_CONFIG_ROOT:-/etc/redis}"
MONGODB_CONFIG_FILE="${VPSCRY_MONGODB_CONFIG_FILE:-/etc/mongod.conf}"
ELASTIC_CONFIG_ROOT="${VPSCRY_ELASTIC_CONFIG_ROOT:-/etc}"
UNATTENDED_LOG="${VPSCRY_UNATTENDED_LOG:-/var/log/unattended-upgrades/unattended-upgrades.log}"
declare -a WEB_PUBLIC_NAMES=()
declare -a WEB_TLS_NAMES=()
declare -A WEB_NAME_SEEN=()
declare -A WEB_TLS_NAME_SEEN=()

C_RESET=""
C_RED=""
C_YELLOW=""
C_GREEN=""
C_BLUE=""
C_GRAY=""
C_BOLD=""

print_banner() {
    cat <<BANNER
 __     ______  ____
 \ \   / /  _ \/ ___|  ___ _ __ _   _
  \ \ / /| |_) \___ \ / __| '__| | | |
   \ V / |  __/ ___) | (__| |  | |_| |
    \_/  |_|   |____/ \___|_|   \__, |
                                |___/

             ${DISPLAY_NAME} v${VERSION}
       Debian VPS Health & Security Audit
          ${TAGLINE}

        Created by ${AUTHOR} · ${WEBSITE}
BANNER
}

usage() {
    cat <<USAGE
$DISPLAY_NAME $VERSION

Read-only VPS health and security audit for Debian 12 and Debian 13.

Usage:
  sudo ./vpscry.sh [options]

Options:
  --output-dir DIR       Report directory. Default: ./vpscry-HOST-TIMESTAMP
  --formats LIST         Comma-separated: text,markdown,json,html,actions,sarif,all
                         Default: $DEFAULT_FORMATS
  --online               Permit optional clearnet outbound checks. Offline remains the default.
                         .onion names are excluded from this mode.
  --config FILE          Safe data-only policy file; parsed, never sourced
  --expected-ports LIST  Expected listeners, e.g. tcp:22,tcp:80,tcp:443,udp:51820
  --baseline FILE        Compare this run with a VPScry baseline snapshot
  --write-baseline FILE  Write a deterministic baseline snapshot
  --severity-profile P   balanced, strict or relaxed
  --evidence-limit N     Stored evidence limit per finding (400-12000)
  --timeout N            Maximum per-command timeout (2-300 seconds)
  --sarif                 Also write report.sarif
  --fail-on LEVEL         Exit 2 after reports when LEVEL is fail or warn and matched
                         Values: none (default), fail, warn
  --no-color             Disable terminal colors
  --verbose              Print every finding and its evidence while scanning
  --quiet                Print only the final summary
  --version              Print version
  -h, --help             Show help

Exit codes:
  0  Audit completed
  1  Invalid arguments or fatal runtime error
  2  Audit completed, but --fail-on threshold was met
  130 Interrupted

The script does not modify configuration, install packages, restart services,
rotate logs, update APT metadata, or send report data anywhere.
USAGE
}

literal_replace() {
    local value="${1-}" needle="${2-}" replacement="${3-}"
    [[ -n "$needle" ]] || { printf '%s' "$value"; return; }
    while [[ "$value" == *"$needle"* ]]; do
        value="${value%%"$needle"*}${replacement}${value#*"$needle"}"
    done
    printf '%s' "$value"
}

redact_text() {
    local value="${1-}" literal
    for literal in "${REDACT_LITERALS[@]:-}"; do
        [[ -n "$literal" ]] || continue
        value="$(literal_replace "$value" "$literal" '[REDACTED]')"
    done
    printf '%s' "$value"
}

load_config_file() {
    local file="$1" line key value lineno=0 sid until reason
    [[ -r "$file" ]] || fatal "Cannot read config file: $file"
    while IFS= read -r line || [[ -n "$line" ]]; do
        lineno=$((lineno+1)); line="${line%$'\r'}"
        [[ "$line" =~ ^[[:space:]]*$ || "$line" =~ ^[[:space:]]*# ]] && continue
        [[ "$line" == *=* ]] || fatal "Invalid config line $lineno in $file"
        key="$(trim "${line%%=*}")"; value="$(trim "${line#*=}")"
        case "$key" in
            fail_on) FAIL_ON="${value,,}" ;;
            expected_ports) EXPECTED_PORTS_RAW="$value" ;;
            expected_services) EXPECTED_SERVICES_RAW="$value" ;;
            expected_websites) EXPECTED_WEBSITES_RAW="$value" ;;
            expected_timers) EXPECTED_TIMERS_RAW="$value" ;;
            expected_backups) EXPECTED_BACKUPS_RAW="$value" ;;
            severity_profile) SEVERITY_PROFILE="$value" ;;
            evidence_limit) EVIDENCE_LIMIT="$value" ;;
            command_timeout) COMMAND_TIMEOUT_MAX="$value" ;;
            baseline_file) BASELINE_FILE="$value" ;;
            write_baseline_file) WRITE_BASELINE_FILE="$value" ;;
            formats) FORMATS="$value" ;;
            output_dir) OUTPUT_DIR="$value" ;;
            sarif) case "${value,,}" in 1|yes|true|on) [[ ",$FORMATS," == *,sarif,* ]] || FORMATS="$FORMATS,sarif";; 0|no|false|off|'') ;; *) fatal "Invalid sarif value at $file:$lineno";; esac ;;
            disk_warn_percent) DISK_WARN_PERCENT="$value" ;;
            disk_fail_percent) DISK_FAIL_PERCENT="$value" ;;
            inode_warn_percent) INODE_WARN_PERCENT="$value" ;;
            inode_fail_percent) INODE_FAIL_PERCENT="$value" ;;
            backup_max_age_days) BACKUP_MAX_AGE_DAYS="$value" ;;
            log_growth_mib) LOG_GROWTH_MIB="$value" ;;
            redact_literal) [[ -n "$value" ]] && REDACT_LITERALS+=("$value") ;;
            suppress)
                IFS='|' read -r sid until reason <<< "$value"
                sid="$(trim "$sid")"; until="$(trim "$until")"; reason="$(trim "$reason")"
                [[ "$sid" =~ ^[A-Z0-9][A-Z0-9-]+$ ]] || fatal "Invalid suppression ID at $file:$lineno"
                [[ "$until" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || fatal "Suppression expiry must be YYYY-MM-DD at $file:$lineno"
                [[ -n "$reason" ]] || fatal "Suppression reason is required at $file:$lineno"
                SUPPRESS_UNTIL["$sid"]="$until"; SUPPRESS_REASON["$sid"]="$reason"
                ;;
            *) fatal "Unknown config key '$key' at $file:$lineno" ;;
        esac
    done < "$file"
}

validate_policy_settings() {
    [[ "$SEVERITY_PROFILE" =~ ^(balanced|strict|relaxed)$ ]] || fatal "Invalid severity profile: $SEVERITY_PROFILE"
    [[ "$FAIL_ON" =~ ^(none|fail|warn)$ ]] || fatal "Invalid fail_on policy: $FAIL_ON"
    [[ "$EVIDENCE_LIMIT" =~ ^[0-9]+$ ]] && (( EVIDENCE_LIMIT>=400 && EVIDENCE_LIMIT<=12000 )) || fatal "evidence_limit must be 400-12000"
    [[ "$COMMAND_TIMEOUT_MAX" =~ ^[0-9]+$ ]] && (( COMMAND_TIMEOUT_MAX>=2 && COMMAND_TIMEOUT_MAX<=300 )) || fatal "command_timeout must be 2-300"
    [[ "$DISK_WARN_PERCENT" =~ ^[0-9]+$ && "$DISK_FAIL_PERCENT" =~ ^[0-9]+$ ]] || fatal "disk thresholds must be numeric"
    [[ "$INODE_WARN_PERCENT" =~ ^[0-9]+$ && "$INODE_FAIL_PERCENT" =~ ^[0-9]+$ ]] || fatal "inode thresholds must be numeric"
    (( DISK_WARN_PERCENT<DISK_FAIL_PERCENT && DISK_FAIL_PERCENT<=100 )) || fatal "invalid disk thresholds"
    (( INODE_WARN_PERCENT<INODE_FAIL_PERCENT && INODE_FAIL_PERCENT<=100 )) || fatal "invalid inode thresholds"
    [[ "$BACKUP_MAX_AGE_DAYS" =~ ^[0-9]+$ ]] || fatal "backup_max_age_days must be numeric"
    [[ "$LOG_GROWTH_MIB" =~ ^[0-9]+$ ]] || fatal "log_growth_mib must be numeric"
}

fatal() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

cleanup() {
    if [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]]; then
        rm -rf -- "$TMP_DIR"
    fi
    return 0
}
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    trap cleanup EXIT
    trap 'cleanup; exit 130' INT TERM
fi

have() {
    command -v "$1" >/dev/null 2>&1
}

trim() {
    local value="${1-}"
    value="${value//$'\r'/ }"
    value="${value//$'\n'/; }"
    value="${value//$'\t'/ }"
    while [[ "$value" == *"  "* ]]; do value="${value//  / }"; done
    value="${value# }"
    value="${value% }"
    printf '%s' "$value"
}

shorten() {
    local value max
    value="$(trim "${1-}")"
    max="${2:-$EVIDENCE_LIMIT}"
    if (( ${#value} > max )); then
        printf '%s…' "${value:0:max}"
    else
        printf '%s' "$value"
    fi
}

json_escape() {
    local value="${1-}"
    value=${value//\\/\\\\}
    value=${value//\"/\\\"}
    value=${value//$'\n'/\\n}
    value=${value//$'\r'/\\r}
    value=${value//$'\t'/\\t}
    printf '%s' "$value"
}

html_escape() {
    local value="${1-}"
    value=${value//&/\&amp;}
    value=${value//</\&lt;}
    value=${value//>/\&gt;}
    value=${value//\"/\&quot;}
    value=${value//$'\''/\&#39;}
    printf '%s' "$value"
}

md_escape() {
    local value
    value="$(trim "${1-}")"
    value=${value//\\/\\\\}
    value=${value//\|/\\|}
    value=${value//\`/\\\`}
    printf '%s' "$value"
}


stable_suffix() {
    local input="$1" value
    if have sha256sum; then
        value="$(printf '%s' "$input" | sha256sum | awk '{print substr($1,1,8)}')"
    elif have cksum; then
        value="$(printf '%s' "$input" | cksum | awk '{printf "%08x", $1}')"
    else
        value="$(printf '%s' "$input" | tr -cd 'A-Za-z0-9' | cut -c1-8)"
    fi
    printf '%s' "${value^^}"
}

shell_quote() {
    printf '%q' "$1"
}

is_world_readable() {
    local mode="$1"
    [[ "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
    mode="${mode: -3}"
    (( (8#${mode:2:1} & 4) != 0 ))
}

init_colors() {
    local enable=0
    case "$COLOR_MODE" in
        never) enable=0 ;;
        always) enable=1 ;;
        auto) [[ -t 1 && -z "${NO_COLOR:-}" ]] && enable=1 ;;
    esac
    if (( enable )); then
        C_RESET=$'\033[0m'
        C_RED=$'\033[31m'
        C_YELLOW=$'\033[33m'
        C_GREEN=$'\033[32m'
        C_BLUE=$'\033[34m'
        C_GRAY=$'\033[90m'
        C_BOLD=$'\033[1m'
    fi
}

status_color() {
    case "$1" in
        FAIL) printf '%s' "$C_RED" ;;
        WARN) printf '%s' "$C_YELLOW" ;;
        PASS) printf '%s' "$C_GREEN" ;;
        INFO) printf '%s' "$C_BLUE" ;;
        SKIP) printf '%s' "$C_GRAY" ;;
        *) printf '%s' "$C_RESET" ;;
    esac
}

add_result() {
    local id category status severity confidence title evidence verify recommendation color
    id="$1"
    category="$2"
    status="$3"
    severity="$4"
    confidence="$5"
    title="$6"
    evidence="$(shorten "$(redact_text "${7-}")")"
    verify="$(shorten "$(redact_text "${8-}")" 800)"
    recommendation="$(shorten "$(redact_text "${9-}")")"

    if [[ "$SEVERITY_PROFILE" == "strict" && "$status" == "WARN" && "$severity" == "LOW" ]]; then
        severity="MEDIUM"
    elif [[ "$SEVERITY_PROFILE" == "relaxed" && "$status" == "WARN" && "$severity" == "LOW" ]]; then
        status="INFO"; severity="INFO"; title="Advisory: $title"
    fi
    if [[ -n "${SUPPRESS_UNTIL[$id]+x}" ]]; then
        local today original_status original_severity
        today="$(date -u +%Y-%m-%d)"
        if [[ "$today" > "${SUPPRESS_UNTIL[$id]}" ]]; then
            EXPIRED_SUPPRESSIONS["$id"]="${SUPPRESS_UNTIL[$id]}|${SUPPRESS_REASON[$id]}"
        else
            original_status="$status"; original_severity="$severity"
            status="INFO"; severity="INFO"; title="Suppressed: $title"
            evidence="$(shorten "$evidence; suppression_until=${SUPPRESS_UNTIL[$id]}; suppression_reason=${SUPPRESS_REASON[$id]}; original_status=$original_status; original_severity=$original_severity.")"
        fi
    fi

    if [[ -n "${SEEN_RESULT_ID[$id]+x}" ]]; then
        return 0
    fi
    SEEN_RESULT_ID["$id"]=1

    R_ID+=("$id")
    R_CATEGORY+=("$category")
    R_STATUS+=("$status")
    R_SEVERITY+=("$severity")
    R_CONFIDENCE+=("$confidence")
    R_TITLE+=("$title")
    R_EVIDENCE+=("$evidence")
    R_VERIFY+=("$verify")
    R_RECOMMENDATION+=("$recommendation")
    COUNTS[$status]=$(( ${COUNTS[$status]:-0} + 1 ))

    if [[ "$TERMINAL_MODE" == "verbose" ]]; then
        color="$(status_color "$status")"
        printf '%s[%-4s]%s %-9s %-13s %s\n' "$color" "$status" "$C_RESET" "[$category]" "$id" "$title"
        [[ -n "$evidence" ]] && printf '       %s\n' "$evidence"
    fi
}

capture() {
    local seconds="$1"
    shift
    if [[ "$COMMAND_TIMEOUT_MAX" =~ ^[0-9]+$ ]] && (( seconds > COMMAND_TIMEOUT_MAX )); then seconds="$COMMAND_TIMEOUT_MAX"; fi
    if have timeout; then
        timeout --signal=TERM "$seconds" "$@" 2>&1
    else
        "$@" 2>&1
    fi
}

capture_stdin_null() {
    local seconds="$1"
    shift
    if [[ "$COMMAND_TIMEOUT_MAX" =~ ^[0-9]+$ ]] && (( seconds > COMMAND_TIMEOUT_MAX )); then seconds="$COMMAND_TIMEOUT_MAX"; fi
    if have timeout; then
        timeout --signal=TERM "$seconds" "$@" </dev/null 2>&1
    else
        "$@" </dev/null 2>&1
    fi
}

init_network_guard() {
    if (( ONLINE )); then
        NETWORK_GUARD_AVAILABLE=0
    elif (( RUN_AS_ROOT )) && have unshare && unshare -n -- true >/dev/null 2>&1; then
        NETWORK_GUARD_AVAILABLE=1
    else
        NETWORK_GUARD_AVAILABLE=0
    fi
}

capture_potentially_networked() {
    local seconds="$1"
    shift
    if (( ONLINE )); then
        capture "$seconds" "$@"
    elif (( NETWORK_GUARD_AVAILABLE )); then
        capture "$seconds" unshare -n -- "$@"
    else
        return 125
    fi
}

read_os_value() {
    local key="$1"
    [[ -r /etc/os-release ]] || return 0
    awk -F= -v key="$key" '$1 == key {value=$2; gsub(/^"|"$/, "", value); print value; exit}' /etc/os-release
}

is_group_or_world_writable() {
    local mode="$1"
    [[ "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
    mode="${mode: -3}"
    (( (8#${mode:1:1} & 2) != 0 || (8#${mode:2:1} & 2) != 0 ))
}

is_world_writable() {
    local mode="$1"
    [[ "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
    mode="${mode: -3}"
    (( (8#${mode:2:1} & 2) != 0 ))
}

audit_root_executed_path() {
    local path="$1"
    local source="$2"
    local runner="$3"
    local stat_out owner group mode parent parent_stat parent_mode parent_group suffix quoted_path

    [[ "$runner" == "root" || "$runner" == "0" || -z "$runner" ]] || return 0
    [[ "$path" == /* ]] || return 0
    quoted_path="$(shell_quote "$path")"

    if [[ ! -e "$path" ]]; then
        case "$path" in
            *.sh|*.bash|*.py|*.php|*.pl|*.rb|*.js|*.mjs|*.cjs|*/bin/*)
                suffix="$(stable_suffix "$source|$path|missing")"
                add_result "EXEC-MISSING-$suffix" "execution" "WARN" "MEDIUM" "MEDIUM" \
                    "Referenced executable or script does not exist" \
                    "$source references $path for execution as root." \
                    "stat -- $quoted_path; grep -R -- $quoted_path /etc/systemd/system /etc/cron*" \
                    "Correct or remove the stale execution reference."
                ;;
        esac
        return 0
    fi
    [[ -f "$path" ]] || return 0
    if [[ ! -x "$path" ]]; then
        case "$path" in
            *.sh|*.bash|*.py|*.php|*.pl|*.rb|*.js|*.mjs|*.cjs) ;;
            *) return 0 ;;
        esac
    fi

    stat_out="$(stat -Lc '%U|%G|%a' -- "$path" 2>/dev/null || true)"
    IFS='|' read -r owner group mode <<< "$stat_out"
    if [[ -n "$mode" ]]; then
        if is_world_writable "$mode"; then
            suffix="$(stable_suffix "$source|$path|world-writable")"
            add_result "EXEC-PERM-$suffix" "execution" "FAIL" "CRITICAL" "HIGH" \
                "Root-executed file is world-writable" \
                "$source executes $path as root; owner=$owner group=$group mode=$mode." \
                "stat -Lc '%U %G %a %n' -- $quoted_path" \
                "Remove world write permission and ensure only a trusted administrative owner can modify the file."
        elif is_group_or_world_writable "$mode" && [[ "$group" != "root" ]]; then
            suffix="$(stable_suffix "$source|$path|group-writable")"
            add_result "EXEC-PERM-$suffix" "execution" "FAIL" "HIGH" "HIGH" \
                "Root-executed file is writable by a non-root group" \
                "$source executes $path as root; owner=$owner group=$group mode=$mode." \
                "stat -Lc '%U %G %a %n' -- $quoted_path; getent group $(shell_quote "$group")" \
                "Restrict write access to root or a tightly controlled administrative group."
        elif [[ "$owner" != "root" ]]; then
            suffix="$(stable_suffix "$source|$path|owner")"
            add_result "EXEC-OWNER-$suffix" "execution" "WARN" "HIGH" "HIGH" \
                "Root-executed file is not owned by root" \
                "$source executes $path as root; owner=$owner group=$group mode=$mode." \
                "stat -Lc '%U %G %a %n' -- $quoted_path" \
                "If root privileges are required, make the script and its writable parent path root-owned; otherwise run the job as the script owner."
        fi
    fi

    parent="$(dirname -- "$path")"
    while [[ "$parent" != "/" && -n "$parent" ]]; do
        parent_stat="$(stat -Lc '%G|%a' -- "$parent" 2>/dev/null || true)"
        IFS='|' read -r parent_group parent_mode <<< "$parent_stat"
        if [[ -n "$parent_mode" ]] && is_world_writable "$parent_mode"; then
            suffix="$(stable_suffix "$source|$path|$parent|world-dir")"
            add_result "EXEC-DIR-$suffix" "execution" "FAIL" "HIGH" "HIGH" \
                "Parent directory of a root-executed file is world-writable" \
                "$source executes $path as root; writable parent=$parent mode=$parent_mode." \
                "namei -l -- $quoted_path" \
                "Remove untrusted write permission from the directory path."
            break
        elif [[ -n "$parent_mode" ]] && is_group_or_world_writable "$parent_mode" && [[ "$parent_group" != "root" ]]; then
            suffix="$(stable_suffix "$source|$path|$parent|group-dir")"
            add_result "EXEC-DIR-$suffix" "execution" "WARN" "HIGH" "HIGH" \
                "Parent directory of a root-executed file is group-writable" \
                "$source executes $path as root; group-writable parent=$parent group=$parent_group mode=$parent_mode." \
                "namei -l -- $quoted_path" \
                "Confirm that every member of the writable group is trusted to alter root-executed code."
            break
        fi
        parent="$(dirname -- "$parent")"
    done
}

extract_absolute_paths() {
    grep -Eo '/[^[:space:]"'"'"';|&<>]+' 2>/dev/null | sed -E 's/[),]+$//' | awk '!seen[$0]++'
}

check_system_identity() {
    local os_id version_id pretty kernel arch virt uptime_text
    os_id="$(read_os_value ID)"
    version_id="$(read_os_value VERSION_ID)"
    pretty="$(read_os_value PRETTY_NAME)"

    if [[ "$os_id" == "debian" && ( "$version_id" == "12" || "$version_id" == "13" ) ]]; then
        add_result "SYS-OS-001" "system" "PASS" "INFO" "HIGH" \
            "Supported Debian release detected" \
            "${pretty:-Debian $version_id}." \
            "cat /etc/os-release" \
            "No action required."
    elif [[ "$os_id" == "debian" ]]; then
        add_result "SYS-OS-001" "system" "WARN" "LOW" "HIGH" \
            "Debian release is outside the tested support range" \
            "${pretty:-Debian $version_id}; tested releases are Debian 12 and 13." \
            "cat /etc/os-release" \
            "Review findings manually because defaults and command output may differ."
    else
        add_result "SYS-OS-001" "system" "WARN" "MEDIUM" "HIGH" \
            "Unsupported operating system detected" \
            "${pretty:-unknown operating system}; this version targets Debian 12 and 13." \
            "cat /etc/os-release" \
            "Run only for evaluation and verify every result manually."
    fi

    if (( RUN_AS_ROOT )); then
        add_result "SYS-PRIV-001" "system" "PASS" "INFO" "HIGH" \
            "Audit has sufficient local privileges" \
            "Running as root; protected configuration and process ownership can be inspected." \
            "id" \
            "No action required."
    else
        add_result "SYS-PRIV-001" "system" "WARN" "LOW" "HIGH" \
            "Audit is running with limited privileges" \
            "Some evidence, process ownership, user crontabs, logs and protected configuration may be unavailable." \
            "id" \
            "Re-run with sudo for a complete audit."
    fi

    kernel="$(uname -r 2>/dev/null || true)"
    arch="$(uname -m 2>/dev/null || true)"
    virt="$(systemd-detect-virt 2>/dev/null || printf 'unknown')"
    uptime_text="$(uptime -p 2>/dev/null || true)"
    add_result "SYS-INFO-001" "system" "INFO" "INFO" "HIGH" \
        "System inventory" \
        "hostname=$HOSTNAME_VALUE; kernel=$kernel; architecture=$arch; virtualization=$virt; ${uptime_text:-uptime unavailable}." \
        "hostnamectl; uname -a; systemd-detect-virt; uptime" \
        "Use this inventory to interpret platform-specific findings."
}

check_storage() {
    local line fs type blocks used avail pct mount usage status severity title
    local disk_rows=0 inode_rows=0

    if ! have df; then
        add_result "STOR-DISK-001" "storage" "SKIP" "INFO" "HIGH" \
            "Disk usage could not be checked" "df is unavailable." "command -v df" "Install coreutils."
        return
    fi

    while IFS= read -r line; do
        read -r fs type blocks used avail pct mount <<< "$line"
        [[ -n "${mount:-}" ]] || continue
        [[ "$mount" == /var/lib/docker/overlay2/* || "$mount" == /run/* ]] && continue
        usage="${pct%%%}"
        [[ "$usage" =~ ^[0-9]+$ ]] || continue
        status="PASS"; severity="INFO"; title="Filesystem usage is within the configured threshold"
        if (( usage >= DISK_FAIL_PERCENT )); then
            status="FAIL"; severity="HIGH"; title="Filesystem is critically full"
        elif (( usage >= DISK_WARN_PERCENT )); then
            status="WARN"; severity="MEDIUM"; title="Filesystem usage is high"
        fi
        add_result "STOR-DISK-$(printf '%03d' "$disk_rows")" "storage" "$status" "$severity" "HIGH" \
            "$title" \
            "mount=$mount filesystem=$fs type=$type used=$pct available_kib=$avail." \
            "df -hT -- '$mount'" \
            "Keep normal filesystems below 80% where practical; investigate growth before reaching 95%."
        disk_rows=$((disk_rows + 1))
    done < <(df -PT -x tmpfs -x devtmpfs -x squashfs 2>/dev/null | awk 'NR > 1')

    (( disk_rows > 0 )) || add_result "STOR-DISK-001" "storage" "SKIP" "INFO" "MEDIUM" \
        "No filesystem usage data was collected" "df returned no usable rows." "df -PT" "Check mount visibility and permissions."

    while IFS= read -r line; do
        read -r fs blocks used avail pct mount <<< "$line"
        [[ -n "${mount:-}" ]] || continue
        [[ "$mount" == /var/lib/docker/overlay2/* || "$mount" == /run/* ]] && continue
        usage="${pct%%%}"
        [[ "$usage" =~ ^[0-9]+$ ]] || continue
        if (( usage >= INODE_FAIL_PERCENT )); then
            add_result "STOR-INODE-$(printf '%03d' "$inode_rows")" "storage" "FAIL" "HIGH" "HIGH" \
                "Filesystem is critically low on inodes" \
                "mount=$mount inode_usage=$pct available_inodes=$avail." \
                "df -ih -- '$mount'" \
                "Locate directories containing very large numbers of small files."
        elif (( usage >= INODE_WARN_PERCENT )); then
            add_result "STOR-INODE-$(printf '%03d' "$inode_rows")" "storage" "WARN" "MEDIUM" "HIGH" \
                "Filesystem inode usage is high" \
                "mount=$mount inode_usage=$pct available_inodes=$avail." \
                "df -ih -- '$mount'" \
                "Investigate inode growth before it prevents file creation."
        fi
        inode_rows=$((inode_rows + 1))
    done < <(df -Pi -x tmpfs -x devtmpfs -x squashfs 2>/dev/null | awk 'NR > 1')

    if (( inode_rows > 0 )); then
        add_result "STOR-INODE-SUM" "storage" "INFO" "INFO" "HIGH" \
            "Filesystem inode usage was inspected" \
            "$inode_rows mounted filesystems were checked; only threshold violations are listed separately." \
            "df -ih" \
            "No action is required when no inode warning appears."
    fi
}

check_memory() {
    local total available swap_total swap_free available_pct total_mib swap_mib pressure evidence
    total="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || true)"
    available="$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo 2>/dev/null || true)"
    swap_total="$(awk '/^SwapTotal:/ {print $2}' /proc/meminfo 2>/dev/null || true)"
    swap_free="$(awk '/^SwapFree:/ {print $2}' /proc/meminfo 2>/dev/null || true)"

    if [[ "$total" =~ ^[0-9]+$ && "$available" =~ ^[0-9]+$ && "$total" -gt 0 ]]; then
        available_pct=$(( available * 100 / total ))
        total_mib=$(( total / 1024 ))
        evidence="memory_total_mib=$total_mib; memory_available_percent=$available_pct"
        if (( available_pct < 10 )); then
            add_result "MEM-RAM-001" "memory" "FAIL" "HIGH" "HIGH" \
                "Available memory is critically low" "$evidence." \
                "free -h; cat /proc/pressure/memory" \
                "Identify sustained memory consumers and confirm whether the system is swapping or invoking the OOM killer."
        elif (( available_pct < 20 )); then
            add_result "MEM-RAM-001" "memory" "WARN" "MEDIUM" "HIGH" \
                "Available memory is low" "$evidence." \
                "free -h; cat /proc/pressure/memory" \
                "Observe memory pressure over time before increasing capacity or changing services."
        else
            add_result "MEM-RAM-001" "memory" "PASS" "INFO" "HIGH" \
                "Available memory is healthy" "$evidence." \
                "free -h" \
                "No action required."
        fi
    else
        add_result "MEM-RAM-001" "memory" "SKIP" "INFO" "MEDIUM" \
            "Memory usage could not be evaluated" "/proc/meminfo did not contain expected values." \
            "cat /proc/meminfo" \
            "Inspect memory manually."
    fi

    if [[ "$swap_total" =~ ^[0-9]+$ ]]; then
        swap_mib=$(( swap_total / 1024 ))
        if (( swap_total == 0 )) && [[ "${total:-0}" =~ ^[0-9]+$ ]] && (( total < 2097152 )); then
            add_result "MEM-SWAP-001" "memory" "WARN" "LOW" "MEDIUM" \
                "Small VPS has no swap configured" \
                "memory_total_mib=$(( total / 1024 )); swap_total_mib=0." \
                "free -h; swapon --show" \
                "Consider a small encrypted or local swap area if workload behavior makes OOM termination likely."
        else
            add_result "MEM-SWAP-001" "memory" "INFO" "INFO" "HIGH" \
                "Swap inventory" \
                "swap_total_mib=$swap_mib; swap_free_mib=$(( ${swap_free:-0} / 1024 ))." \
                "free -h; swapon --show" \
                "No universal swap requirement is enforced."
        fi
    fi

    pressure="$(cat /proc/pressure/memory 2>/dev/null | tr '\n' '; ' || true)"
    [[ -n "$pressure" ]] && add_result "MEM-PSI-001" "memory" "INFO" "INFO" "HIGH" \
        "Memory pressure information" "$pressure" "cat /proc/pressure/memory" \
        "Use sustained avg10/avg60 pressure, not a single RAM percentage, to evaluate contention."

    local oom_count
    oom_count="$(journalctl -k --since '-7 days' --no-pager 2>/dev/null | grep -Eic 'out of memory|oom-killer|killed process' || true)"
    if [[ "$oom_count" =~ ^[0-9]+$ ]] && (( oom_count > 0 )); then
        add_result "MEM-OOM-001" "memory" "FAIL" "HIGH" "MEDIUM" \
            "Recent out-of-memory events were detected" \
            "$oom_count matching kernel log lines were found in the last 7 days." \
            "journalctl -k --since '-7 days' | grep -Ei 'out of memory|oom-killer|killed process'" \
            "Identify the affected process and address memory exhaustion or unsafe limits."
    else
        add_result "MEM-OOM-001" "memory" "PASS" "INFO" "MEDIUM" \
            "No recent OOM event was found" \
            "No matching kernel log line was visible for the last 7 days." \
            "journalctl -k --since '-7 days' | grep -Ei 'out of memory|oom-killer|killed process'" \
            "No action required; limited journal retention may reduce confidence."
    fi
}

check_time_and_reboot() {
    local sync active
    if have timedatectl; then
        sync="$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)"
        active="$(timedatectl show -p NTP --value 2>/dev/null || true)"
        if [[ "$sync" == "yes" ]]; then
            add_result "TIME-NTP-001" "system" "PASS" "INFO" "HIGH" \
                "System clock is synchronized" "NTP enabled=$active; synchronized=$sync." \
                "timedatectl status" "No action required."
        elif [[ "$active" == "yes" ]]; then
            add_result "TIME-NTP-001" "system" "WARN" "MEDIUM" "MEDIUM" \
                "Time synchronization is enabled but not synchronized" "NTP enabled=$active; synchronized=${sync:-unknown}." \
                "timedatectl status; systemctl status systemd-timesyncd chrony --no-pager" \
                "Check the active time synchronization service and upstream reachability."
        else
            add_result "TIME-NTP-001" "system" "WARN" "MEDIUM" "MEDIUM" \
                "No synchronized system clock was confirmed" "NTP enabled=${active:-unknown}; synchronized=${sync:-unknown}." \
                "timedatectl status; systemctl status systemd-timesyncd chrony --no-pager" \
                "Enable one trusted time synchronization mechanism."
        fi
    else
        add_result "TIME-NTP-001" "system" "SKIP" "INFO" "HIGH" \
            "Time synchronization could not be checked" "timedatectl is unavailable." \
            "command -v timedatectl" "Inspect the active NTP or chrony service manually."
    fi

    if [[ -e /run/reboot-required ]]; then
        add_result "SYS-REBOOT-001" "updates" "WARN" "MEDIUM" "HIGH" \
            "A system reboot is required" \
            "$(cat /run/reboot-required 2>/dev/null || printf 'The reboot-required marker exists.')." \
            "cat /run/reboot-required; cat /run/reboot-required.pkgs 2>/dev/null" \
            "Schedule a controlled reboot after validating service impact."
    else
        add_result "SYS-REBOOT-001" "updates" "PASS" "INFO" "HIGH" \
            "No reboot-required marker is present" "/run/reboot-required does not exist." \
            "test -e /run/reboot-required" "No action required."
    fi
}

check_systemd() {
    local state failed_services failed_timers running_count restart_units unit nrestarts custom_count unsafe_units=0
    if ! have systemctl; then
        add_result "SVC-SYSTEMD-001" "services" "SKIP" "INFO" "HIGH" \
            "systemd service state could not be checked" "systemctl is unavailable." \
            "command -v systemctl" "This script expects systemd on Debian."
        return
    fi

    state="$(systemctl is-system-running 2>/dev/null || true)"
    case "$state" in
        running)
            add_result "SVC-SYSTEMD-001" "services" "PASS" "INFO" "HIGH" \
                "systemd reports a healthy system state" "is-system-running=$state." \
                "systemctl is-system-running" "No action required."
            ;;
        degraded)
            add_result "SVC-SYSTEMD-001" "services" "FAIL" "HIGH" "HIGH" \
                "systemd reports a degraded system state" "is-system-running=$state." \
                "systemctl --failed --all" "Investigate failed units and their dependency chain."
            ;;
        *)
            add_result "SVC-SYSTEMD-001" "services" "WARN" "MEDIUM" "MEDIUM" \
                "systemd is not in the normal running state" "is-system-running=${state:-unknown}." \
                "systemctl is-system-running; systemctl --failed --all" \
                "Confirm whether the state is expected for this boot or virtualization environment."
            ;;
    esac

    failed_services="$(systemctl --failed --type=service --no-legend --plain 2>/dev/null | sed '/^[[:space:]]*$/d' || true)"
    if [[ -n "$failed_services" ]]; then
        add_result "SVC-FAILED-001" "services" "FAIL" "HIGH" "HIGH" \
            "One or more systemd services are failed" \
            "$failed_services" \
            "systemctl --failed --type=service --all; journalctl -u UNIT -b --no-pager" \
            "Resolve failed services or disable and remove obsolete units. Successful inactive oneshot units are not treated as failures."
    else
        add_result "SVC-FAILED-001" "services" "PASS" "INFO" "HIGH" \
            "No failed systemd service is recorded" \
            "systemctl --failed --type=service returned no service." \
            "systemctl --failed --type=service --all" \
            "No action required."
    fi

    failed_timers="$(systemctl --failed --type=timer --no-legend --plain 2>/dev/null | sed '/^[[:space:]]*$/d' || true)"
    if [[ -n "$failed_timers" ]]; then
        add_result "SVC-TIMER-001" "services" "FAIL" "HIGH" "HIGH" \
            "One or more systemd timers are failed" "$failed_timers" \
            "systemctl --failed --type=timer --all; systemctl list-timers --all" \
            "Inspect the failed timer and its triggered service."
    else
        add_result "SVC-TIMER-001" "services" "PASS" "INFO" "HIGH" \
            "No failed systemd timer is recorded" \
            "systemctl --failed --type=timer returned no timer." \
            "systemctl --failed --type=timer --all" \
            "No action required."
    fi

    running_count="$(systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null | wc -l | tr -d ' ')"
    add_result "SVC-INVENTORY-001" "services" "INFO" "INFO" "HIGH" \
        "Running service inventory" "$running_count services are currently in the running state." \
        "systemctl list-units --type=service --state=running --no-pager" \
        "Service count alone is not scored; review actual purpose and exposure."

    restart_units=""
    while IFS= read -r unit; do
        [[ -n "$unit" ]] || continue
        nrestarts="$(systemctl show "$unit" -p NRestarts --value 2>/dev/null || true)"
        if [[ "$nrestarts" =~ ^[0-9]+$ ]] && (( nrestarts >= 5 )); then
            restart_units+="$unit NRestarts=$nrestarts; "
        fi
    done < <(systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null | awk '{print $1}')

    if [[ -n "$restart_units" ]]; then
        add_result "SVC-RESTART-001" "services" "WARN" "MEDIUM" "MEDIUM" \
            "Services with repeated automatic restarts were detected" "$restart_units" \
            "systemctl show UNIT -p NRestarts,Restart,Result; journalctl -u UNIT -b" \
            "Determine whether restarts are expected or indicate a crash loop."
    else
        add_result "SVC-RESTART-001" "services" "PASS" "INFO" "MEDIUM" \
            "No high restart count was detected" "No running service reported NRestarts >= 5." \
            "systemctl show UNIT -p NRestarts" "No action required."
    fi

    custom_count="$(find /etc/systemd/system -xdev -type f \( -name '*.service' -o -name '*.timer' -o -name '*.socket' -o -name '*.path' \) 2>/dev/null | wc -l | tr -d ' ')"
    add_result "SVC-CUSTOM-001" "services" "INFO" "INFO" "HIGH" \
        "Custom systemd unit inventory" "$custom_count custom unit file(s) were found under /etc/systemd/system." \
        "find /etc/systemd/system -xdev -type f" \
        "Review locally maintained units after application changes."

    local file owner group mode user command path unit_name effective
    while IFS= read -r file; do
        [[ -f "$file" ]] || continue
        IFS='|' read -r owner group mode < <(stat -Lc '%U|%G|%a' -- "$file" 2>/dev/null || printf '||')
        if is_world_writable "$mode"; then
            add_result "SVC-UNIT-PERM-$(printf '%03d' "$unsafe_units")" "services" "FAIL" "CRITICAL" "HIGH" \
                "Custom systemd unit file is world-writable" \
                "$file owner=$owner group=$group mode=$mode." \
                "stat -Lc '%U %G %a %n' -- '$file'" \
                "Remove world write permission and restore root ownership."
            unsafe_units=$((unsafe_units + 1))
        elif is_group_or_world_writable "$mode" && [[ "$group" != "root" ]]; then
            add_result "SVC-UNIT-PERM-$(printf '%03d' "$unsafe_units")" "services" "FAIL" "HIGH" "HIGH" \
                "Custom systemd unit file is writable by a non-root group" \
                "$file owner=$owner group=$group mode=$mode." \
                "stat -Lc '%U %G %a %n' -- '$file'; getent group '$group'" \
                "Restrict unit file modification to trusted administrators."
            unsafe_units=$((unsafe_units + 1))
        elif [[ "$owner" != "root" ]]; then
            add_result "SVC-UNIT-OWNER-$(printf '%03d' "$unsafe_units")" "services" "WARN" "HIGH" "HIGH" \
                "Custom systemd unit file is not owned by root" \
                "$file owner=$owner group=$group mode=$mode." \
                "stat -Lc '%U %G %a %n' -- '$file'" \
                "Confirm ownership is intentional and cannot be changed by a service account."
            unsafe_units=$((unsafe_units + 1))
        fi

        unit_name="$(basename -- "$file")"
        effective="$(systemctl cat "$unit_name" 2>/dev/null || cat "$file" 2>/dev/null || true)"
        user="$(systemctl show "$unit_name" -p User --value 2>/dev/null || true)"
        if [[ -z "$user" ]]; then
            user="$(awk -F= '/^[[:space:]]*User=/ {gsub(/[[:space:]]/, "", $2); print $2; exit}' <<< "$effective")"
        fi
        [[ -n "$user" ]] || user="root"
        while IFS= read -r command; do
            [[ -n "$command" ]] || continue
            while IFS= read -r path; do
                case "$path" in
                    /usr/local/*|/opt/*|/root/*|/home/*|/var/www/*|/srv/*)
                        audit_root_executed_path "$path" "$file" "$user"
                        ;;
                esac
            done < <(printf '%s\n' "$command" | extract_absolute_paths)
        done < <(awk -F= '/^[[:space:]]*Exec(Start|StartPre|StartPost|Reload|Stop|StopPost)=/ {sub(/^[^=]*=/, ""); print}' <<< "$effective")
    done < <(find /etc/systemd/system -xdev -type f -name '*.service' 2>/dev/null)

    if (( unsafe_units == 0 )); then
        add_result "SVC-UNIT-PERM-SUM" "services" "PASS" "INFO" "HIGH" \
            "No unsafe custom systemd unit permission was found" \
            "Regular service unit files under /etc/systemd/system were checked." \
            "find /etc/systemd/system -type f -name '*.service' -exec stat -c '%U %G %a %n' {} +" \
            "No action required."
    fi
}

systemd_prop() {
    local data="$1" key="$2"
    awk -F= -v key="$key" '$1 == key {sub(/^[^=]*=/, ""); print; exit}' <<< "$data"
}

service_socket_evidence() {
    local unit="$1" props="$2" main_pid cgroup pid line output="" seen=" "
    local -a pids=()
    have ss || return 0
    main_pid="$(systemd_prop "$props" MainPID)"
    cgroup="$(systemd_prop "$props" ControlGroup)"
    if [[ "$main_pid" =~ ^[1-9][0-9]*$ ]]; then
        pids+=("$main_pid")
    fi
    if [[ -n "$cgroup" && -d "/sys/fs/cgroup$cgroup" ]]; then
        while IFS= read -r pid; do
            [[ "$pid" =~ ^[1-9][0-9]*$ ]] && pids+=("$pid")
        done < <(find "/sys/fs/cgroup$cgroup" -name cgroup.procs -type f -exec cat {} + 2>/dev/null | sort -u)
    fi
    for pid in "${pids[@]}"; do
        [[ "$seen" == *" $pid "* ]] && continue
        seen+="$pid "
        while IFS= read -r line; do
            [[ -n "$line" ]] || continue
            output+="$(awk '{print $1 " " $5}' <<< "$line") pid=$pid; "
        done < <(ss -H -lntup 2>/dev/null | grep -F "pid=$pid," || true)
    done
    printf '%s' "$output"
}

check_systemd_service_mapping() {
    local units unit props type active sub load result restarts unit_count=0 active_count=0 inactive_count=0 failed_count=0 oneshot_ok=0
    local generated_count user_unit_count types_summary="" custom_count=0 mapped_count=0 validation_count=0
    local -A type_counts=()

    have systemctl || return 0
    units="$(systemctl list-units --type=service --all --no-legend --plain 2>/dev/null | awk '{print $1}' | sed '/^[[:space:]]*$/d' | sort -u)"
    if [[ -z "$units" ]]; then
        add_result "SVC-MAP-001" "services" "SKIP" "INFO" "MEDIUM" \
            "Detailed service mapping is unavailable" \
            "systemctl returned no loaded service units; systemd may not be PID 1 in this environment." \
            "systemctl list-units --type=service --all" \
            "Run VPScry on the target Debian host rather than inside a non-systemd container."
        return 0
    fi

    while IFS= read -r unit; do
        [[ -n "$unit" ]] || continue
        props="$(systemctl show "$unit" -p Type -p ActiveState -p SubState -p LoadState -p Result -p NRestarts -p RemainAfterExit 2>/dev/null || true)"
        type="$(systemd_prop "$props" Type)"; [[ -n "$type" ]] || type="unknown"
        active="$(systemd_prop "$props" ActiveState)"; [[ -n "$active" ]] || active="unknown"
        sub="$(systemd_prop "$props" SubState)"
        load="$(systemd_prop "$props" LoadState)"
        result="$(systemd_prop "$props" Result)"
        restarts="$(systemd_prop "$props" NRestarts)"
        unit_count=$((unit_count + 1))
        type_counts["$type"]=$(( ${type_counts[$type]:-0} + 1 ))
        case "$active" in
            active) active_count=$((active_count + 1)) ;;
            failed) failed_count=$((failed_count + 1)) ;;
            inactive) inactive_count=$((inactive_count + 1)) ;;
        esac
        if [[ "$type" == "oneshot" && "$active" != "failed" && "$load" == "loaded" && ( "$result" == "success" || -z "$result" ) ]]; then
            oneshot_ok=$((oneshot_ok + 1))
        fi
        if [[ "$restarts" =~ ^[0-9]+$ ]] && (( restarts >= 5 )); then
            local restart_suffix restart_status restart_severity
            restart_suffix="$(stable_suffix "$unit|restart-loop")"
            restart_status="WARN"
            restart_severity="MEDIUM"
            if (( restarts >= 20 )); then
                restart_status="FAIL"
                restart_severity="HIGH"
            fi
            add_result "SVC-RESTART-$restart_suffix" "services" "$restart_status" "$restart_severity" "HIGH" \
                "Service has a high restart count" \
                "unit=$unit; active=$active; substate=${sub:-unknown}; result=${result:-unknown}; NRestarts=$restarts." \
                "systemctl show $(shell_quote "$unit") -p ActiveState,SubState,Result,NRestarts,Restart,ExecMainStartTimestamp; journalctl -u $(shell_quote "$unit") -b --no-pager" \
                "Determine whether restarts are expected or indicate repeated process failure."
        fi
    done <<< "$units"

    for type in "${!type_counts[@]}"; do
        types_summary+="$type:${type_counts[$type]},"
    done
    types_summary="${types_summary%,}"
    add_result "SVC-TYPES-001" "services" "INFO" "INFO" "HIGH" \
        "systemd service type and state inventory" \
        "loaded_services=$unit_count; active=$active_count; inactive=$inactive_count; failed=$failed_count; types=$types_summary." \
        "systemctl list-units --type=service --all; systemctl show UNIT -p Type,ActiveState,SubState,Result" \
        "Service type and inactive state are interpreted contextually; counts alone are not scored."

    if (( oneshot_ok > 0 )); then
        add_result "SVC-ONESHOT-001" "services" "PASS" "INFO" "HIGH" \
            "Successful oneshot services are not treated as failures" \
            "$oneshot_ok loaded oneshot service(s) are inactive or completed without a failed state." \
            "systemctl list-units --type=service --all; systemctl show UNIT -p Type,ActiveState,SubState,Result,RemainAfterExit" \
            "No action required."
    else
        add_result "SVC-ONESHOT-001" "services" "INFO" "INFO" "MEDIUM" \
            "No completed oneshot service was identified" \
            "No loaded oneshot unit matched the successful completed-state criteria." \
            "systemctl list-units --type=service --all" \
            "No action required."
    fi

    generated_count="$(find /run/systemd/generator /run/systemd/generator.early /run/systemd/generator.late -maxdepth 1 -type f 2>/dev/null | wc -l | tr -d ' ')"
    add_result "SVC-GENERATED-001" "services" "INFO" "INFO" "HIGH" \
        "Generated systemd unit inventory" \
        "generated_unit_files=${generated_count:-0}; generated units are distinguished from locally maintained files." \
        "find /run/systemd/generator* -maxdepth 1 -type f -ls" \
        "Review generated units through their source configuration rather than editing generated files directly."

    while IFS= read -r unit; do
        [[ -n "$unit" ]] || continue
        custom_count=$((custom_count + 1))
        local file enabled preset user group workdir fragment dropins exec_data exec_path env_data triggered main_pid sockets suffix evidence
        local security_output exposure security_status security_severity
        file="/etc/systemd/system/$unit"
        props="$(systemctl show "$unit" -p LoadState -p ActiveState -p SubState -p UnitFileState -p UnitFilePreset -p Type -p User -p Group -p WorkingDirectory -p FragmentPath -p DropInPaths -p ExecStart -p EnvironmentFiles -p TriggeredBy -p MainPID -p ControlGroup -p NRestarts -p Result 2>/dev/null || true)"
        load="$(systemd_prop "$props" LoadState)"
        active="$(systemd_prop "$props" ActiveState)"
        sub="$(systemd_prop "$props" SubState)"
        enabled="$(systemd_prop "$props" UnitFileState)"
        preset="$(systemd_prop "$props" UnitFilePreset)"
        type="$(systemd_prop "$props" Type)"
        user="$(systemd_prop "$props" User)"
        group="$(systemd_prop "$props" Group)"
        workdir="$(systemd_prop "$props" WorkingDirectory)"
        fragment="$(systemd_prop "$props" FragmentPath)"
        dropins="$(systemd_prop "$props" DropInPaths)"
        exec_data="$(systemd_prop "$props" ExecStart)"
        env_data="$(systemd_prop "$props" EnvironmentFiles)"
        triggered="$(systemd_prop "$props" TriggeredBy)"
        main_pid="$(systemd_prop "$props" MainPID)"
        [[ -n "$user" ]] || user="root"
        [[ -n "$group" ]] || group="default"
        [[ -n "$fragment" ]] || fragment="$file"
        exec_path="$(sed -n 's/.*path=\([^ ;}]*\).*/\1/p' <<< "$exec_data" | head -n 1)"
        if [[ -z "$exec_path" && -r "$file" ]]; then
            exec_path="$(awk -F= '/^[[:space:]]*ExecStart=/ {sub(/^[^=]*=/, ""); gsub(/^[-+!@]+/, ""); print $1; exit}' "$file" 2>/dev/null || true)"
        fi
        sockets="$(service_socket_evidence "$unit" "$props")"
        suffix="$(stable_suffix "$unit|map")"
        evidence="unit=$unit; load=${load:-unknown}; active=${active:-unknown}/${sub:-unknown}; enabled=${enabled:-unknown}; preset=${preset:-unknown}; type=${type:-unknown}; user=$user; group=$group; main_pid=${main_pid:-0}; exec=${exec_path:-unresolved}; workdir=${workdir:-default}; fragment=$fragment; dropins=${dropins:-none}; triggered_by=${triggered:-none}; listeners=${sockets%; }."
        add_result "SVC-MAP-$suffix" "services" "INFO" "INFO" "HIGH" \
            "Custom service execution map" "$evidence" \
            "systemctl show $(shell_quote "$unit") -p LoadState,ActiveState,SubState,UnitFileState,UnitFilePreset,Type,User,Group,MainPID,ExecStart,WorkingDirectory,EnvironmentFiles,FragmentPath,DropInPaths,TriggeredBy,NRestarts,Result; systemctl cat $(shell_quote "$unit")" \
            "Confirm the mapped identity, executable, paths, triggers and listeners match the intended deployment."
        mapped_count=$((mapped_count + 1))

        if [[ "$load" == "not-found" || "$load" == "error" || "$load" == "bad-setting" ]]; then
            add_result "SVC-LOAD-$(stable_suffix "$unit|load")" "services" "FAIL" "HIGH" "HIGH" \
                "Custom service unit could not be loaded correctly" \
                "unit=$unit; LoadState=${load:-unknown}; fragment=$fragment." \
                "systemctl status $(shell_quote "$unit") --no-pager; systemd-analyze verify $(shell_quote "$fragment")" \
                "Correct the unit syntax, referenced paths or missing dependencies."
            validation_count=$((validation_count + 1))
        fi

        if [[ "$user" != "root" && "$user" != *'%'* && "$user" != *'$'* ]] && ! getent passwd "$user" >/dev/null 2>&1; then
            add_result "SVC-USER-$(stable_suffix "$unit|$user")" "services" "FAIL" "HIGH" "HIGH" \
                "Custom service references a missing user" \
                "unit=$unit; User=$user." \
                "getent passwd $(shell_quote "$user"); systemctl cat $(shell_quote "$unit")" \
                "Create the intended service account or correct the User directive."
            validation_count=$((validation_count + 1))
        fi
        if [[ "$group" != "default" && "$group" != *'%'* && "$group" != *'$'* ]] && ! getent group "$group" >/dev/null 2>&1; then
            add_result "SVC-GROUP-$(stable_suffix "$unit|$group")" "services" "FAIL" "HIGH" "HIGH" \
                "Custom service references a missing group" \
                "unit=$unit; Group=$group." \
                "getent group $(shell_quote "$group"); systemctl cat $(shell_quote "$unit")" \
                "Create the intended service group or correct the Group directive."
            validation_count=$((validation_count + 1))
        fi

        if [[ "$exec_path" == /* ]]; then
            if [[ ! -e "$exec_path" ]]; then
                add_result "SVC-EXEC-$(stable_suffix "$unit|$exec_path|missing")" "services" "FAIL" "HIGH" "HIGH" \
                    "Custom service executable does not exist" \
                    "unit=$unit; executable=$exec_path." \
                    "stat -- $(shell_quote "$exec_path"); systemctl cat $(shell_quote "$unit")" \
                    "Install or restore the executable, or correct ExecStart."
                validation_count=$((validation_count + 1))
            elif [[ ! -x "$exec_path" ]]; then
                add_result "SVC-EXEC-$(stable_suffix "$unit|$exec_path|not-executable")" "services" "FAIL" "HIGH" "HIGH" \
                    "Custom service executable is not executable" \
                    "unit=$unit; executable=$exec_path; mode=$(stat -Lc '%a' -- "$exec_path" 2>/dev/null || printf unknown)." \
                    "stat -Lc '%U %G %a %n' -- $(shell_quote "$exec_path")" \
                    "Restore the intended executable permission after confirming file integrity."
                validation_count=$((validation_count + 1))
            fi
            audit_root_executed_path "$exec_path" "$fragment" "$user"
        fi

        if [[ "$workdir" == /* ]]; then
            if [[ ! -d "$workdir" ]]; then
                add_result "SVC-WORKDIR-$(stable_suffix "$unit|$workdir|missing")" "services" "FAIL" "HIGH" "HIGH" \
                    "Custom service working directory does not exist" \
                    "unit=$unit; WorkingDirectory=$workdir." \
                    "stat -- $(shell_quote "$workdir"); systemctl cat $(shell_quote "$unit")" \
                    "Create the intended directory with controlled ownership or correct WorkingDirectory."
                validation_count=$((validation_count + 1))
            elif (( RUN_AS_ROOT )) && [[ "$user" != "root" && "$user" != *'%'* && "$user" != *'$'* ]] && have runuser && ! runuser -u "$user" -- test -x "$workdir" 2>/dev/null; then
                add_result "SVC-WORKDIR-$(stable_suffix "$unit|$workdir|access")" "services" "FAIL" "HIGH" "HIGH" \
                    "Service account cannot access its working directory" \
                    "unit=$unit; User=$user; WorkingDirectory=$workdir." \
                    "runuser -u $(shell_quote "$user") -- test -x $(shell_quote "$workdir"); namei -l $(shell_quote "$workdir")" \
                    "Correct ownership, ACLs or directory traversal permissions without broadening access unnecessarily."
                validation_count=$((validation_count + 1))
            fi
        fi

        if [[ -n "$env_data" ]]; then
            local env_token env_path env_ignore env_owner env_group env_mode
            while IFS= read -r env_token; do
                [[ -n "$env_token" ]] || continue
                env_path="${env_token%% *}"
                env_path="${env_path#-}"
                [[ "$env_path" == /* ]] || continue
                env_ignore=0
                [[ "$env_token" == *'ignore_errors=yes'* || "${env_token%% *}" == -* ]] && env_ignore=1
                if [[ ! -e "$env_path" ]]; then
                    if (( ! env_ignore )); then
                        add_result "SVC-ENVFILE-$(stable_suffix "$unit|$env_path|missing")" "services" "WARN" "HIGH" "HIGH" \
                            "Required service environment file is missing" \
                            "unit=$unit; EnvironmentFile=$env_path; ignore_errors=no." \
                            "stat -- $(shell_quote "$env_path"); systemctl cat $(shell_quote "$unit")" \
                            "Restore the required file or remove the stale EnvironmentFile reference."
                        validation_count=$((validation_count + 1))
                    fi
                    continue
                fi
                IFS='|' read -r env_owner env_group env_mode < <(stat -Lc '%U|%G|%a' -- "$env_path" 2>/dev/null || printf '||')
                if is_world_writable "$env_mode"; then
                    add_result "SVC-ENVPERM-$(stable_suffix "$unit|$env_path|world-write")" "services" "FAIL" "CRITICAL" "HIGH" \
                        "Service environment file is world-writable" \
                        "unit=$unit; file=$env_path; owner=$env_owner group=$env_group mode=$env_mode." \
                        "stat -Lc '%U %G %a %n' -- $(shell_quote "$env_path")" \
                        "Remove world write access and restrict modification to the service owner or administrators."
                    validation_count=$((validation_count + 1))
                elif is_group_or_world_writable "$env_mode" && [[ "$env_group" != "root" && "$env_group" != "$group" ]]; then
                    add_result "SVC-ENVPERM-$(stable_suffix "$unit|$env_path|group-write")" "services" "WARN" "HIGH" "HIGH" \
                        "Service environment file is writable by an unexpected group" \
                        "unit=$unit; file=$env_path; owner=$env_owner group=$env_group mode=$env_mode." \
                        "stat -Lc '%U %G %a %n' -- $(shell_quote "$env_path"); getent group $(shell_quote "$env_group")" \
                        "Restrict modification to the service identity or a tightly controlled administrative group."
                    validation_count=$((validation_count + 1))
                fi
                if is_world_readable "$env_mode"; then
                    add_result "SVC-ENVREAD-$(stable_suffix "$unit|$env_path|world-read")" "services" "WARN" "MEDIUM" "MEDIUM" \
                        "Service environment file is readable by all local users" \
                        "unit=$unit; file=$env_path; owner=$env_owner group=$env_group mode=$env_mode; file content was not read." \
                        "stat -Lc '%U %G %a %n' -- $(shell_quote "$env_path")" \
                        "If the file can contain secrets, restrict read access to the service identity and trusted administrators."
                    validation_count=$((validation_count + 1))
                fi
            done < <(grep -Eo '(-?/[^ ]+)( \(ignore_errors=(yes|no)\))?' <<< "$env_data" || true)
        fi

        if have systemd-analyze && [[ "$active" == "active" && "$type" != "oneshot" ]]; then
            security_output="$(capture 25 systemd-analyze security --no-pager "$unit")"
            exposure="$(grep -E 'Overall exposure level for' <<< "$security_output" | sed -nE 's/.*: ([0-9]+([.][0-9]+)?).*/\1/p' | tail -n 1)"
            if [[ "$exposure" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
                security_status="INFO"
                security_severity="INFO"
                if awk -v value="$exposure" 'BEGIN {exit !(value >= 9.0)}'; then
                    security_status="WARN"
                    security_severity="LOW"
                fi
                add_result "SVC-HARDEN-$(stable_suffix "$unit|systemd-analyze")" "services" "$security_status" "$security_severity" "MEDIUM" \
                    "Contextual systemd sandboxing assessment" \
                    "unit=$unit; systemd_analyze_exposure=$exposure/10; this is a hardening exposure metric, not proof of a vulnerability." \
                    "systemd-analyze security --no-pager $(shell_quote "$unit")" \
                    "Review applicable sandboxing directives without breaking required filesystem, network or capability access."
            fi
        fi
    done < <(find /etc/systemd/system -xdev -type f -name '*.service' -printf '%f\n' 2>/dev/null | sort -u)

    user_unit_count="$(find /etc/systemd/user /root/.config/systemd/user /home/*/.config/systemd/user -type f \( -name '*.service' -o -name '*.timer' -o -name '*.socket' -o -name '*.path' \) 2>/dev/null | wc -l | tr -d ' ')"
    add_result "SVC-USER-UNITS-001" "services" "INFO" "INFO" "MEDIUM" \
        "User systemd unit inventory" \
        "user_unit_files=${user_unit_count:-0}; active user managers are not assumed from file presence alone." \
        "find /etc/systemd/user /root/.config/systemd/user /home/*/.config/systemd/user -type f" \
        "Review unexpected user services and timers, especially persistent jobs using login-independent lingering."

    local user_file expected_owner user_owner user_group user_mode linger_users
    while IFS= read -r user_file; do
        [[ -f "$user_file" ]] || continue
        case "$user_file" in
            /root/.config/systemd/user/*) expected_owner="root" ;;
            /home/*/.config/systemd/user/*) expected_owner="${user_file#/home/}"; expected_owner="${expected_owner%%/*}" ;;
            *) expected_owner="root" ;;
        esac
        IFS='|' read -r user_owner user_group user_mode < <(stat -Lc '%U|%G|%a' -- "$user_file" 2>/dev/null || printf '||')
        if is_world_writable "$user_mode"; then
            add_result "SVC-USER-PERM-$(stable_suffix "$user_file|world-write")" "services" "FAIL" "HIGH" "HIGH" \
                "User systemd unit is world-writable" \
                "file=$user_file; owner=$user_owner group=$user_group mode=$user_mode." \
                "stat -Lc '%U %G %a %n' -- $(shell_quote "$user_file")" \
                "Remove world write access and restore ownership to the intended user or root."
            validation_count=$((validation_count + 1))
        elif is_group_or_world_writable "$user_mode" && [[ "$user_group" != "$expected_owner" && "$user_group" != "root" ]]; then
            add_result "SVC-USER-PERM-$(stable_suffix "$user_file|group-write")" "services" "WARN" "HIGH" "HIGH" \
                "User systemd unit is writable by an unexpected group" \
                "file=$user_file; expected_owner=$expected_owner; owner=$user_owner group=$user_group mode=$user_mode." \
                "stat -Lc '%U %G %a %n' -- $(shell_quote "$user_file"); getent group $(shell_quote "$user_group")" \
                "Restrict modification to the intended user or trusted administrators."
            validation_count=$((validation_count + 1))
        elif [[ "$user_owner" != "$expected_owner" && "$user_owner" != "root" ]]; then
            add_result "SVC-USER-OWNER-$(stable_suffix "$user_file|owner")" "services" "WARN" "MEDIUM" "HIGH" \
                "User systemd unit has unexpected ownership" \
                "file=$user_file; expected_owner=$expected_owner; owner=$user_owner group=$user_group mode=$user_mode." \
                "stat -Lc '%U %G %a %n' -- $(shell_quote "$user_file")" \
                "Restore ownership to the intended account or root after confirming the deployment model."
            validation_count=$((validation_count + 1))
        fi
    done < <(find /etc/systemd/user /root/.config/systemd/user /home/*/.config/systemd/user -type f \( -name '*.service' -o -name '*.timer' -o -name '*.socket' -o -name '*.path' \) 2>/dev/null)

    linger_users="$(find /var/lib/systemd/linger -maxdepth 1 -type f -printf '%f ' 2>/dev/null | sed 's/[[:space:]]*$//')"
    add_result "SVC-USER-LINGER-001" "services" "INFO" "INFO" "HIGH" \
        "Persistent user manager inventory" \
        "linger_users=${linger_users:-none}; lingering allows user services to run without an active login session." \
        "loginctl list-users; find /var/lib/systemd/linger -maxdepth 1 -type f -printf '%f\\n'" \
        "Confirm lingering is enabled only for accounts that require persistent user services."

    add_result "SVC-MAP-SUMMARY" "services" "INFO" "INFO" "HIGH" \
        "Custom service mapping summary" \
        "custom_services=$custom_count; mapped=$mapped_count; validation_findings=$validation_count." \
        "find /etc/systemd/system -xdev -type f -name '*.service'; systemctl show UNIT" \
        "Use the individual service maps and findings to review locally maintained workloads."
}

net_ipv4_class() {
    local addr="$1" a b c d
    IFS=. read -r a b c d <<< "$addr"
    [[ "$a" =~ ^[0-9]+$ && "$b" =~ ^[0-9]+$ && "$c" =~ ^[0-9]+$ && "$d" =~ ^[0-9]+$ ]] || { printf 'unknown'; return; }
    a=$((10#$a)); b=$((10#$b)); c=$((10#$c)); d=$((10#$d))
    if (( a == 127 )); then printf 'loopback'
    elif (( a == 10 || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168) )); then printf 'private'
    elif (( a == 169 && b == 254 )); then printf 'link-local'
    elif (( a == 100 && b >= 64 && b <= 127 )); then printf 'cgnat'
    elif (( a == 0 || a >= 224 )); then printf 'special'
    elif (( a == 192 && b == 0 && c == 2 )) || (( a == 198 && b == 51 && c == 100 )) || (( a == 203 && b == 0 && c == 113 )); then printf 'documentation'
    else printf 'public'
    fi
}

net_ipv6_class() {
    local addr="${1,,}"
    addr="${addr%%%*}"
    if [[ "$addr" == "::1" ]]; then printf 'loopback'
    elif [[ "$addr" == fe8* || "$addr" == fe9* || "$addr" == fea* || "$addr" == feb* ]]; then printf 'link-local'
    elif [[ "$addr" == fc* || "$addr" == fd* ]]; then printf 'private'
    elif [[ "$addr" == 2001:db8:* ]]; then printf 'documentation'
    elif [[ "$addr" == 2* || "$addr" == 3* ]]; then printf 'public'
    elif [[ "$addr" == "::" ]]; then printf 'wildcard'
    else printf 'special'
    fi
}

net_interface_kind() {
    local iface="${1%%@*}"
    case "$iface" in
        lo) printf 'loopback' ;;
        wg*|tun*|tap*|tailscale*|zt*|ipsec*|ppp*) printf 'vpn' ;;
        docker*|podman*|cni*|virbr*|veth*|br-*|lxc*|incus*) printf 'container' ;;
        *) printf 'host' ;;
    esac
}

net_endpoint_parts() {
    local endpoint="$1" addr port
    if [[ "$endpoint" == \[*\]:* ]]; then
        addr="${endpoint#\[}"
        addr="${addr%%\]*}"
        port="${endpoint##*:}"
    else
        addr="${endpoint%:*}"
        port="${endpoint##*:}"
    fi
    printf '%s|%s' "$addr" "$port"
}

net_find_iface_for_addr() {
    local needle="${1%%%*}"
    ip -o addr show up 2>/dev/null | awk -v needle="$needle" '
        {
            iface=$2; sub(/@.*/, "", iface)
            for (i=1; i<=NF; i++) {
                if ($i=="inet" || $i=="inet6") {
                    addr=$(i+1); sub(/\/.*/, "", addr)
                    if (addr==needle) {print iface; exit}
                }
            }
        }'
}

net_pid_unit() {
    local pid="$1" unit
    [[ "$pid" =~ ^[1-9][0-9]*$ && -r "/proc/$pid/cgroup" ]] || return 0
    unit="$(awk -F/ '{for(i=NF;i>=1;i--) if($i ~ /\.service$/){print $i; exit}}' "/proc/$pid/cgroup" 2>/dev/null || true)"
    printf '%s' "$unit"
}

net_expected_add() {
    local token="$1" proto port
    token="${token//[[:space:]]/}"
    [[ -n "$token" ]] || return 0
    if [[ "$token" == */* ]]; then
        port="${token%/*}"; proto="${token##*/}"
    elif [[ "$token" == *:* ]]; then
        proto="${token%%:*}"; port="${token##*:}"
    else
        proto="tcp"; port="$token"
    fi
    proto="${proto,,}"
    [[ "$proto" == "tcp" || "$proto" == "udp" ]] || fatal "Invalid expected-port protocol: $token"
    [[ "$port" =~ ^[0-9]+$ ]] || fatal "Invalid expected port: $token"
    (( port >= 1 && port <= 65535 )) || fatal "Expected port outside 1-65535: $token"
    NET_EXPECTED_PORTS["$proto:$port"]=1
}

net_parse_expected_ports() {
    local token
    NET_EXPECTED_PORTS=()
    [[ -n "$EXPECTED_PORTS_RAW" ]] || return 0
    while IFS= read -r token; do
        net_expected_add "$token"
    done < <(tr ',' '\n' <<< "$EXPECTED_PORTS_RAW")
}

net_add_fw_port() {
    local family="$1" proto="$2" port="$3"
    [[ "$proto" == "tcp" || "$proto" == "udp" ]] || return 0
    [[ "$port" =~ ^[0-9]+$ ]] || return 0
    (( port >= 1 && port <= 65535 )) || return 0
    case "$family" in
        v4) NET_FW_ALLOW_V4["$proto:$port"]=1 ;;
        v6) NET_FW_ALLOW_V6["$proto:$port"]=1 ;;
        both)
            NET_FW_ALLOW_V4["$proto:$port"]=1
            NET_FW_ALLOW_V6["$proto:$port"]=1
            ;;
    esac
}

net_add_fw_range() {
    local family="$1" proto="$2" start="$3" end="$4"
    [[ "$start" =~ ^[0-9]+$ && "$end" =~ ^[0-9]+$ ]] || return 0
    (( start >= 1 && end <= 65535 && start <= end )) || return 0
    case "$family" in
        v4) NET_FW_RANGE_V4+=("$proto|$start|$end") ;;
        v6) NET_FW_RANGE_V6+=("$proto|$start|$end") ;;
        both)
            NET_FW_RANGE_V4+=("$proto|$start|$end")
            NET_FW_RANGE_V6+=("$proto|$start|$end")
            ;;
    esac
}

net_add_fw_spec() {
    local family="$1" proto="$2" spec="$3" item start end
    spec="${spec//\{/}"
    spec="${spec//\}/}"
    spec="${spec// /}"
    spec="${spec//;/,}"
    [[ -n "$spec" ]] || return 0
    while IFS= read -r item; do
        [[ -n "$item" ]] || continue
        if [[ "$item" =~ ^([0-9]+)[:-]([0-9]+)$ ]]; then
            start="${BASH_REMATCH[1]}"; end="${BASH_REMATCH[2]}"
            if (( end - start <= 256 )); then
                local p
                for ((p=start; p<=end; p++)); do net_add_fw_port "$family" "$proto" "$p"; done
            else
                net_add_fw_range "$family" "$proto" "$start" "$end"
            fi
        elif [[ "$item" =~ ^[0-9]+$ ]]; then
            net_add_fw_port "$family" "$proto" "$item"
        fi
    done < <(tr ',' '\n' <<< "$spec")
}

net_fw_allows() {
    local family="$1" proto="$2" port="$3" entry ep es ee
    if [[ "$family" == "v4" ]]; then
        [[ -n "${NET_FW_ALLOW_V4[$proto:$port]+x}" ]] && return 0
        for entry in "${NET_FW_RANGE_V4[@]}"; do
            IFS='|' read -r ep es ee <<< "$entry"
            [[ "$ep" == "$proto" ]] && (( port >= es && port <= ee )) && return 0
        done
    else
        [[ -n "${NET_FW_ALLOW_V6[$proto:$port]+x}" ]] && return 0
        for entry in "${NET_FW_RANGE_V6[@]}"; do
            IFS='|' read -r ep es ee <<< "$entry"
            [[ "$ep" == "$proto" ]] && (( port >= es && port <= ee )) && return 0
        done
    fi
    return 1
}

net_ufw_profile_specs() {
    local profile="$1" file
    for file in /etc/ufw/applications.d/*; do
        [[ -f "$file" && -r "$file" ]] || continue
        awk -v section="$profile" '
            /^\[/ {current=$0; gsub(/^\[|\]$/, "", current); next}
            current==section && /^[[:space:]]*ports=/ {sub(/^[^=]*=/, ""); print; exit}
        ' "$file"
    done | head -n 1
}

net_parse_ufw_target() {
    local family="$1" target="$2" proto spec profile_specs token
    target="$(trim "$target")"
    target="${target% (v6)}"
    if [[ "$target" =~ ([0-9][0-9,:-]*)(/(tcp|udp))?$ ]]; then
        spec="${BASH_REMATCH[1]}"
        proto="${BASH_REMATCH[3]:-both}"
        if [[ "$proto" == "both" ]]; then
            net_add_fw_spec "$family" tcp "$spec"
            net_add_fw_spec "$family" udp "$spec"
        else
            net_add_fw_spec "$family" "$proto" "$spec"
        fi
        return 0
    fi
    profile_specs="$(net_ufw_profile_specs "$target")"
    [[ -n "$profile_specs" ]] || return 0
    while IFS= read -r token; do
        if [[ "$token" == */* ]]; then
            spec="${token%/*}"; proto="${token##*/}"
            net_add_fw_spec "$family" "$proto" "$spec"
        else
            net_add_fw_spec "$family" tcp "$token"
            net_add_fw_spec "$family" udp "$token"
        fi
    done < <(tr '|' '\n' <<< "$profile_specs")
}

net_parse_ufw() {
    local status verbose numbered default_line ipv6 line family target action
    have ufw || return 0
    status="$(ufw status 2>/dev/null | head -n 1 || true)"
    [[ "$status" == "Status: active" ]] || return 0
    NET_UFW_ACTIVE=1
    NET_FW_SOURCES+=("ufw")
    verbose="$(ufw status verbose 2>/dev/null || true)"
    default_line="$(grep -E '^Default:' <<< "$verbose" | head -n 1 || true)"
    if grep -Eqi '^Default: (deny|reject) \(incoming\)' <<< "$default_line"; then
        NET_FW_V4_POLICY="restrictive"
    elif grep -Eqi '^Default: allow \(incoming\)' <<< "$default_line"; then
        NET_FW_V4_POLICY="permissive"
    fi
    NET_UFW_IPV6="$(awk -F= '/^[[:space:]]*IPV6=/ {print tolower($2); exit}' "$UFW_DEFAULT_FILE" 2>/dev/null | tr -d '[:space:]"' || true)"
    if [[ "$NET_UFW_IPV6" == "yes" ]]; then
        NET_FW_V6_POLICY="$NET_FW_V4_POLICY"
    fi
    numbered="$(ufw status numbered 2>/dev/null || true)"
    while IFS= read -r line; do
        line="$(sed -E 's/^\[[[:space:]]*[0-9]+\][[:space:]]*//' <<< "$line")"
        [[ "$line" =~ [[:space:]](ALLOW|LIMIT)[[:space:]] ]] || continue
        family="v4"
        [[ "$line" == *"(v6)"* ]] && family="v6"
        line="${line// (v6)/}"
        if [[ "$line" =~ ^(.+)[[:space:]]+(ALLOW|LIMIT)[[:space:]]+(IN[[:space:]]+)?(.+)$ ]]; then
            target="$(trim "${BASH_REMATCH[1]}")"
            action="${BASH_REMATCH[2]}"
            [[ "$action" == "ALLOW" || "$action" == "LIMIT" ]] && net_parse_ufw_target "$family" "$target"
        fi
    done <<< "$numbered"
}

net_parse_nft() {
    local rules family="both" line proto spec policy
    have nft || return 0
    rules="$(nft list ruleset 2>/dev/null || true)"
    [[ -n "$rules" ]] || return 0
    NET_FW_SOURCES+=("nftables")
    while IFS= read -r line; do
        if [[ "$line" =~ ^[[:space:]]*table[[:space:]]+(inet|ip|ip6)[[:space:]] ]]; then
            case "${BASH_REMATCH[1]}" in
                inet) family="both" ;;
                ip) family="v4" ;;
                ip6) family="v6" ;;
            esac
        fi
        if [[ "$line" == *"hook input"* && "$line" =~ policy[[:space:]]+(drop|reject|accept) ]]; then
            policy="${BASH_REMATCH[1]}"
            case "$family:$policy" in
                v4:drop|v4:reject) NET_FW_V4_POLICY="restrictive" ;;
                v4:accept) [[ "$NET_FW_V4_POLICY" == "unknown" ]] && NET_FW_V4_POLICY="permissive" ;;
                v6:drop|v6:reject) NET_FW_V6_POLICY="restrictive" ;;
                v6:accept) [[ "$NET_FW_V6_POLICY" == "unknown" ]] && NET_FW_V6_POLICY="permissive" ;;
                both:drop|both:reject) NET_FW_V4_POLICY="restrictive"; NET_FW_V6_POLICY="restrictive" ;;
                both:accept)
                    [[ "$NET_FW_V4_POLICY" == "unknown" ]] && NET_FW_V4_POLICY="permissive"
                    [[ "$NET_FW_V6_POLICY" == "unknown" ]] && NET_FW_V6_POLICY="permissive"
                    ;;
            esac
        fi
        if [[ "$line" == *" accept"* && ( "$line" == *"dport @"* || "$line" == *" vmap "* || "$line" == *" verdict map "* ) ]]; then
            NET_FW_COMPLEX=1
        fi
        if [[ "$line" == *" accept"* && "$line" != *" dport "* && ( "$line" == *"iifname"* || "$line" == *" saddr "* ) ]]; then
            NET_FW_COMPLEX=1
        fi
        if [[ "$line" == *" accept"* && "$line" =~ (tcp|udp)[[:space:]]+dport[[:space:]]+(\{[^\}]+\}|[0-9]+([:-][0-9]+)?) ]]; then
            proto="${BASH_REMATCH[1]}"; spec="${BASH_REMATCH[2]}"
            net_add_fw_spec "$family" "$proto" "$spec"
        fi
    done <<< "$rules"
}

net_parse_iptables_family() {
    local family="$1" command_name="$2" rules policy line proto port
    have "$command_name" || return 0
    rules="$($command_name -S INPUT 2>/dev/null || true)"
    [[ -n "$rules" ]] || return 0
    NET_FW_SOURCES+=("$command_name")
    policy="$(awk '$1=="-P" && $2=="INPUT" {print tolower($3); exit}' <<< "$rules")"
    case "$family:$policy" in
        v4:drop|v4:reject) NET_FW_V4_POLICY="restrictive" ;;
        v4:accept) [[ "$NET_FW_V4_POLICY" == "unknown" ]] && NET_FW_V4_POLICY="permissive" ;;
        v6:drop|v6:reject) NET_FW_V6_POLICY="restrictive" ;;
        v6:accept) [[ "$NET_FW_V6_POLICY" == "unknown" ]] && NET_FW_V6_POLICY="permissive" ;;
    esac
    while IFS= read -r line; do
        if [[ "$line" =~ -j[[:space:]]+([A-Za-z0-9_-]+) ]]; then
            case "${BASH_REMATCH[1]}" in ACCEPT|DROP|REJECT|RETURN) ;; *) NET_FW_COMPLEX=1 ;; esac
        fi
        [[ "$line" == *"-j ACCEPT"* ]] || continue
        if [[ "$line" =~ -p[[:space:]]+(tcp|udp) ]]; then proto="${BASH_REMATCH[1]}"; else continue; fi
        if [[ "$line" =~ --dport[[:space:]]+([0-9]+([:-][0-9]+)?) ]]; then
            port="${BASH_REMATCH[1]}"
            net_add_fw_spec "$family" "$proto" "$port"
        fi
    done <<< "$rules"
}

net_firewalld_service_specs() {
    local service="$1" file line proto port
    file="/usr/lib/firewalld/services/$service.xml"
    [[ -r "$file" ]] || file="/etc/firewalld/services/$service.xml"
    [[ -r "$file" ]] || return 0
    while IFS= read -r line; do
        proto="$(sed -nE 's/.*protocol="([^"]+)".*/\1/p' <<< "$line")"
        port="$(sed -nE 's/.*port="([^"]+)".*/\1/p' <<< "$line")"
        [[ -n "$proto" && -n "$port" ]] && printf '%s/%s\n' "$port" "$proto"
    done < <(grep '<port ' "$file" 2>/dev/null || true)
}

net_parse_firewalld() {
    local state zones zone ports services token spec proto
    have firewall-cmd || return 0
    state="$(firewall-cmd --state 2>/dev/null || true)"
    [[ "$state" == "running" ]] || return 0
    NET_FIREWALLD_ACTIVE=1
    NET_FW_SOURCES+=("firewalld")
    [[ "$NET_FW_V4_POLICY" == "unknown" ]] && NET_FW_V4_POLICY="restrictive"
    [[ "$NET_FW_V6_POLICY" == "unknown" ]] && NET_FW_V6_POLICY="restrictive"
    zones="$(firewall-cmd --get-active-zones 2>/dev/null | awk '!/^[[:space:]]/ {print $1}')"
    while IFS= read -r zone; do
        [[ -n "$zone" ]] || continue
        ports="$(firewall-cmd --zone="$zone" --list-ports 2>/dev/null || true)"
        for token in $ports; do
            spec="${token%/*}"; proto="${token##*/}"
            net_add_fw_spec both "$proto" "$spec"
        done
        services="$(firewall-cmd --zone="$zone" --list-services 2>/dev/null || true)"
        for token in $services; do
            while IFS= read -r spec; do
                [[ -n "$spec" ]] || continue
                net_add_fw_spec both "${spec##*/}" "${spec%/*}"
            done < <(net_firewalld_service_specs "$token")
        done
    done <<< "$zones"
}

net_listener_exposure() {
    local family="$1" addr="$2" iface="$3" class kind
    kind="$(net_interface_kind "$iface")"
    if [[ "$kind" == "vpn" ]]; then printf 'vpn'; return; fi
    if [[ "$kind" == "container" ]]; then printf 'container'; return; fi
    if [[ "$family" == "v4" ]]; then
        if [[ "$addr" == "0.0.0.0" || "$addr" == "*" ]]; then
            if (( NET_PUBLIC_V4_COUNT > 0 )); then printf 'public'
            elif (( NET_PRIVATE_V4_COUNT > 0 )); then printf 'private'
            else printf 'wildcard'
            fi
            return
        fi
        class="$(net_ipv4_class "$addr")"
    else
        if [[ "$addr" == "::" || "$addr" == "*" ]]; then
            if (( NET_PUBLIC_V6_COUNT > 0 && NET_IPV6_DEFAULT_ROUTE > 0 )); then printf 'public'
            elif (( NET_PRIVATE_V6_COUNT > 0 )); then printf 'private'
            else printf 'unrouted-ipv6'
            fi
            return
        fi
        class="$(net_ipv6_class "$addr")"
    fi
    printf '%s' "$class"
}

net_policy_result() {
    local family="$1" reachable="$2" policy="$3" id title evidence verify
    id="NET-FW-POLICY-${family^^}"
    title="Normalized $family inbound firewall policy"
    evidence="policy=$policy; sources=$(IFS=,; printf '%s' "${NET_FW_SOURCES[*]:-none}")."
    verify="ufw status verbose; nft list ruleset; iptables -S INPUT; ip6tables -S INPUT; firewall-cmd --list-all-zones"
    if (( ! reachable )); then
        add_result "$id" "network" "INFO" "INFO" "HIGH" "$title" \
            "$evidence No routed public $family address was detected." "$verify" \
            "Keep policy parity documented before enabling public $family connectivity."
    elif [[ "$policy" == "restrictive" ]]; then
        add_result "$id" "network" "PASS" "INFO" "HIGH" "$title" "$evidence" "$verify" \
            "Review explicit allow rules against intended services."
    elif [[ "$policy" == "permissive" ]]; then
        add_result "$id" "network" "WARN" "HIGH" "HIGH" "$title" "$evidence" "$verify" \
            "Use a default-deny or default-reject inbound policy with explicit required ports."
    else
        add_result "$id" "network" "WARN" "MEDIUM" "MEDIUM" "$title" "$evidence" "$verify" \
            "Confirm local or provider firewall coverage and document the effective inbound policy."
    fi
}

check_network() {
    local sockets line proto endpoint parts addr port family pid process unit iface exposure class kind
    local public_count=0 private_count=0 loopback_count=0 vpn_count=0 container_count=0 unrouted_v6_count=0
    local listener_evidence="" sensitive_suffix fw_sources_text
    local ipv4_forward ipv6_forward rp_all rp_default forwarding_context="none"
    local dns_nameservers dns_target dns_public=0 dns_private=0 dns_loopback=0
    local allowed_count=0 restricted_count=0 unknown_count=0 expected_seen_count=0 unexpected_allowed_count=0
    local policy allow_state key suffix status severity expected_count=0 missing_expected=0
    local docker_inventory="" docker_published=0 docker_hostnet=0 podman_inventory="" podman_published=0
    local online_dns online_http display_endpoint
    local -a L_PROTO=() L_ADDR=() L_PORT=() L_FAMILY=() L_PID=() L_PROCESS=() L_UNIT=() L_IFACE=() L_EXPOSURE=()
    local -A LISTEN_KEYS=()

    NET_PUBLIC_V4_COUNT=0; NET_PRIVATE_V4_COUNT=0; NET_PUBLIC_V6_COUNT=0; NET_PRIVATE_V6_COUNT=0
    NET_IPV4_DEFAULT_ROUTE=0; NET_IPV6_DEFAULT_ROUTE=0
    NET_FW_V4_POLICY="unknown"; NET_FW_V6_POLICY="unknown"
    NET_UFW_ACTIVE=0; NET_UFW_IPV6="unknown"; NET_FIREWALLD_ACTIVE=0; NET_FW_COMPLEX=0
    NET_FW_ALLOW_V4=(); NET_FW_ALLOW_V6=(); NET_FW_RANGE_V4=(); NET_FW_RANGE_V6=(); NET_FW_SOURCES=()

    if ! have ip; then
        add_result "NET-IFACE-001" "network" "SKIP" "INFO" "HIGH" \
            "Interface inventory could not be created" "ip is unavailable." \
            "command -v ip" "Install iproute2."
    else
        local iface_data="" fam cidr scope address iface_name addr_class iface_kind
        while IFS='|' read -r iface_name fam cidr scope; do
            [[ -n "$iface_name" && -n "$fam" && -n "$cidr" ]] || continue
            address="${cidr%%/*}"
            iface_name="${iface_name%%@*}"
            iface_kind="$(net_interface_kind "$iface_name")"
            if [[ "$fam" == "inet" ]]; then
                addr_class="$(net_ipv4_class "$address")"
                [[ "$addr_class" == "public" ]] && NET_PUBLIC_V4_COUNT=$((NET_PUBLIC_V4_COUNT + 1))
                [[ "$addr_class" == "private" || "$addr_class" == "cgnat" ]] && NET_PRIVATE_V4_COUNT=$((NET_PRIVATE_V4_COUNT + 1))
            else
                addr_class="$(net_ipv6_class "$address")"
                [[ "$addr_class" == "public" ]] && NET_PUBLIC_V6_COUNT=$((NET_PUBLIC_V6_COUNT + 1))
                [[ "$addr_class" == "private" ]] && NET_PRIVATE_V6_COUNT=$((NET_PRIVATE_V6_COUNT + 1))
            fi
            iface_data+="$iface_name $fam $address class=$addr_class kind=$iface_kind scope=$scope; "
        done < <(ip -o addr show up 2>/dev/null | awk '
            {
                iface=$2; fam=""; cidr=""; scope="unknown"
                for(i=1;i<=NF;i++) {
                    if($i=="inet" || $i=="inet6") {fam=$i; cidr=$(i+1)}
                    if($i=="scope") {scope=$(i+1)}
                }
                if(fam!="" && cidr!="") print iface "|" fam "|" cidr "|" scope
            }')
        ip -4 route show default 2>/dev/null | grep -q '^default' && NET_IPV4_DEFAULT_ROUTE=1
        ip -6 route show default 2>/dev/null | grep -q '^default' && NET_IPV6_DEFAULT_ROUTE=1
        add_result "NET-IFACE-001" "network" "INFO" "INFO" "HIGH" \
            "Network interface and address inventory" \
            "public_ipv4=$NET_PUBLIC_V4_COUNT; private_ipv4=$NET_PRIVATE_V4_COUNT; public_ipv6=$NET_PUBLIC_V6_COUNT; private_ipv6=$NET_PRIVATE_V6_COUNT; default_route_v4=$NET_IPV4_DEFAULT_ROUTE; default_route_v6=$NET_IPV6_DEFAULT_ROUTE; $iface_data" \
            "ip -o addr show up; ip -4 route show default; ip -6 route show default" \
            "Use interface classes to interpret listener and firewall exposure."
    fi

    if ! have ss; then
        add_result "NET-LISTEN-001" "network" "SKIP" "INFO" "HIGH" \
            "Listening sockets could not be enumerated" "ss is unavailable." \
            "command -v ss" "Install iproute2."
        return
    fi

    sockets="$(ss -H -lntup 2>/dev/null || true)"
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        proto="$(awk '{print $1}' <<< "$line")"
        endpoint="$(awk '{print $5}' <<< "$line")"
        [[ "$proto" == "tcp" || "$proto" == "udp" ]] || continue
        [[ -n "$endpoint" ]] || continue
        parts="$(net_endpoint_parts "$endpoint")"
        addr="${parts%%|*}"; port="${parts##*|}"
        [[ "$port" =~ ^[0-9]+$ ]] || continue
        family="v4"; [[ "$addr" == *:* ]] && family="v6"
        pid="$(sed -nE 's/.*pid=([0-9]+).*/\1/p' <<< "$line" | head -n 1)"
        process="$(sed -nE 's/.*users:\(\(\"([^\"]+)\".*/\1/p' <<< "$line" | head -n 1)"
        unit="$(net_pid_unit "$pid")"
        iface=""
        [[ "$addr" != "0.0.0.0" && "$addr" != "::" && "$addr" != "*" ]] && iface="$(net_find_iface_for_addr "$addr")"
        exposure="$(net_listener_exposure "$family" "$addr" "$iface")"
        L_PROTO+=("$proto"); L_ADDR+=("$addr"); L_PORT+=("$port"); L_FAMILY+=("$family")
        L_PID+=("${pid:-unknown}"); L_PROCESS+=("${process:-unknown}"); L_UNIT+=("${unit:-unknown}")
        L_IFACE+=("${iface:-wildcard}"); L_EXPOSURE+=("$exposure")
        LISTEN_KEYS["$proto:$port"]=1
        display_endpoint="$addr:$port"; [[ "$family" == "v6" ]] && display_endpoint="[$addr]:$port"
        listener_evidence+="$proto $display_endpoint family=$family exposure=$exposure iface=${iface:-wildcard} process=${process:-unknown} pid=${pid:-unknown} unit=${unit:-unknown}; "
        case "$exposure" in
            public|wildcard) public_count=$((public_count + 1)) ;;
            private|cgnat) private_count=$((private_count + 1)) ;;
            loopback) loopback_count=$((loopback_count + 1)) ;;
            vpn) vpn_count=$((vpn_count + 1)) ;;
            container) container_count=$((container_count + 1)) ;;
            unrouted-ipv6) unrouted_v6_count=$((unrouted_v6_count + 1)) ;;
        esac
        if [[ "$exposure" == "public" || "$exposure" == "private" || "$exposure" == "wildcard" ]]; then
            case "$port" in
                2375)
                    sensitive_suffix="$(stable_suffix "$proto|$addr|$port|docker-api")"
                    add_result "NET-SENSITIVE-$sensitive_suffix" "network" "FAIL" "CRITICAL" "HIGH" \
                        "Unauthenticated Docker API may be exposed" \
                        "$proto listener $display_endpoint exposure=$exposure process=${process:-unknown} unit=${unit:-unknown}." \
                        "ss -lntup '( sport = :2375 )'; systemctl cat docker" \
                        "Bind the Docker API to a protected local or management interface and require authenticated TLS where remote access is unavoidable."
                    ;;
                2376)
                    sensitive_suffix="$(stable_suffix "$proto|$addr|$port|docker-tls")"
                    add_result "NET-SENSITIVE-$sensitive_suffix" "network" "WARN" "HIGH" "HIGH" \
                        "Docker TLS API is not loopback-bound" \
                        "$proto listener $display_endpoint exposure=$exposure process=${process:-unknown} unit=${unit:-unknown}." \
                        "ss -lntup '( sport = :2376 )'; systemctl cat docker" \
                        "Confirm mutual TLS, authorization and firewall restriction to management sources."
                    ;;
                3306|5432|6379|27017|11211|9200|9300)
                    sensitive_suffix="$(stable_suffix "$proto|$addr|$port|data-service")"
                    add_result "NET-SENSITIVE-$sensitive_suffix" "network" "WARN" "HIGH" "HIGH" \
                        "Database or cache service is not loopback-bound" \
                        "$proto listener $display_endpoint exposure=$exposure process=${process:-unknown} unit=${unit:-unknown}." \
                        "ss -lntup '( sport = :$port )'" \
                        "Confirm authentication, TLS and source-restricted firewall rules; prefer loopback or a private management interface when remote access is unnecessary."
                    ;;
                9050|9150)
                    sensitive_suffix="$(stable_suffix "$proto|$addr|$port|tor-socks")"
                    add_result "NET-SENSITIVE-$sensitive_suffix" "network" "FAIL" "HIGH" "HIGH" \
                        "Tor SOCKS proxy is not loopback-bound" \
                        "$proto listener $display_endpoint exposure=$exposure process=${process:-unknown} unit=${unit:-unknown}." \
                        "ss -lntup '( sport = :$port )'; grep -R '^SocksPort' /etc/tor" \
                        "Bind SocksPort to loopback or a strictly controlled interface."
                    ;;
                9051)
                    sensitive_suffix="$(stable_suffix "$proto|$addr|$port|tor-control")"
                    add_result "NET-SENSITIVE-$sensitive_suffix" "network" "FAIL" "CRITICAL" "HIGH" \
                        "Tor control port is not loopback-bound" \
                        "$proto listener $display_endpoint exposure=$exposure process=${process:-unknown} unit=${unit:-unknown}." \
                        "ss -lntup '( sport = :9051 )'; grep -R '^ControlPort' /etc/tor" \
                        "Bind the control port to loopback and require strong cookie or password authentication."
                    ;;
            esac
        fi
    done <<< "$sockets"

    if (( ${#L_PROTO[@]} == 0 )); then
        add_result "NET-LISTEN-001" "network" "INFO" "INFO" "MEDIUM" \
            "No listening TCP or UDP socket was visible" \
            "ss returned no socket; restricted privileges may hide process metadata." \
            "ss -lntup" "Confirm this is expected."
    else
        add_result "NET-LISTEN-001" "network" "INFO" "INFO" "HIGH" \
            "Normalized listening socket inventory" "$listener_evidence" \
            "ss -lntup; systemctl status PID; cat /proc/PID/cgroup" \
            "Review exposure class, owning process and systemd unit against the intended service inventory."
    fi
    add_result "NET-EXPOSURE-001" "network" "INFO" "INFO" "HIGH" \
        "Listener exposure summary" \
        "public_or_wildcard=$public_count; private_or_cgnat=$private_count; loopback=$loopback_count; vpn=$vpn_count; container=$container_count; unrouted_ipv6=$unrouted_v6_count." \
        "ss -lntup; ip -o addr show up; ip -4 route; ip -6 route" \
        "A wildcard bind is interpreted together with configured addresses and routes rather than treated as automatically public."

    net_parse_ufw
    net_parse_nft
    net_parse_iptables_family v4 iptables
    net_parse_iptables_family v6 ip6tables
    net_parse_firewalld

    local fw_v4_list="" fw_v6_list="" fw_stale="" fw_stale_count=0 fw_key
    for fw_key in "${!NET_FW_ALLOW_V4[@]}"; do fw_v4_list+="$fw_key,"; [[ -z "${LISTEN_KEYS[$fw_key]+x}" ]] && { fw_stale+="v4:$fw_key,"; fw_stale_count=$((fw_stale_count + 1)); }; done
    for fw_key in "${!NET_FW_ALLOW_V6[@]}"; do fw_v6_list+="$fw_key,"; [[ -z "${LISTEN_KEYS[$fw_key]+x}" ]] && { fw_stale+="v6:$fw_key,"; fw_stale_count=$((fw_stale_count + 1)); }; done
    fw_v4_list="${fw_v4_list%,}"; fw_v6_list="${fw_v6_list%,}"; fw_stale="${fw_stale%,}"
    fw_sources_text="$(IFS=,; printf '%s' "${NET_FW_SOURCES[*]:-none}")"
    if [[ "$fw_sources_text" == "none" ]]; then
        if (( NET_PUBLIC_V4_COUNT > 0 || NET_PUBLIC_V6_COUNT > 0 )); then
            add_result "NET-FW-001" "network" "WARN" "HIGH" "MEDIUM" \
                "No active host firewall backend was confirmed" \
                "sources=none; public_ipv4=$NET_PUBLIC_V4_COUNT; public_ipv6=$NET_PUBLIC_V6_COUNT." \
                "ufw status verbose; nft list ruleset; iptables -S; ip6tables -S; firewall-cmd --state" \
                "Confirm a provider firewall exists or configure a restrictive host-level inbound policy."
        else
            add_result "NET-FW-001" "network" "INFO" "INFO" "MEDIUM" \
                "No active host firewall backend was confirmed" \
                "sources=none; no routed public address was detected." \
                "ufw status verbose; nft list ruleset; iptables -S; ip6tables -S; firewall-cmd --state" \
                "Document whether isolation is provided by the surrounding network or provider firewall."
        fi
    else
        local fw_aggregate_status="PASS" fw_aggregate_severity="INFO"
        if (( NET_PUBLIC_V4_COUNT > 0 && NET_IPV4_DEFAULT_ROUTE > 0 )) && [[ "$NET_FW_V4_POLICY" != "restrictive" ]]; then
            fw_aggregate_status="WARN"; fw_aggregate_severity="HIGH"
        fi
        if (( NET_PUBLIC_V6_COUNT > 0 && NET_IPV6_DEFAULT_ROUTE > 0 )) && [[ "$NET_FW_V6_POLICY" != "restrictive" ]]; then
            fw_aggregate_status="WARN"; fw_aggregate_severity="HIGH"
        fi
        if [[ "$NET_FW_V4_POLICY" == "unknown" && "$NET_FW_V6_POLICY" == "unknown" && "$fw_aggregate_status" == "PASS" ]]; then
            fw_aggregate_status="INFO"
        fi
        add_result "NET-FW-001" "network" "$fw_aggregate_status" "$fw_aggregate_severity" "MEDIUM" \
            "Host firewall backend inventory completed" \
            "sources=$fw_sources_text; v4_policy=$NET_FW_V4_POLICY; v6_policy=$NET_FW_V6_POLICY; complex_rules=$NET_FW_COMPLEX." \
            "ufw status verbose; nft list ruleset; iptables -S; ip6tables -S; firewall-cmd --list-all-zones" \
            "Review normalized policies and listener correlation; backend detection alone does not prove complete protection."
    fi
    add_result "NET-FW-RULES-001" "network" "INFO" "INFO" "MEDIUM" \
        "Normalized inbound allow-rule inventory" \
        "v4_exact=${fw_v4_list:-none}; v6_exact=${fw_v6_list:-none}; v4_ranges=${#NET_FW_RANGE_V4[@]}; v6_ranges=${#NET_FW_RANGE_V6[@]}; rules_without_listener=$fw_stale_count; stale_candidates=${fw_stale:-none}; complex_rules=$NET_FW_COMPLEX." \
        "ufw status numbered; nft list ruleset; iptables -S; ip6tables -S; firewall-cmd --list-all-zones" \
        "Rules without a current listener are informational because services may be intermittent or source/interface scoped."

    net_policy_result v4 "$(( NET_PUBLIC_V4_COUNT > 0 && NET_IPV4_DEFAULT_ROUTE > 0 ))" "$NET_FW_V4_POLICY"
    net_policy_result v6 "$(( NET_PUBLIC_V6_COUNT > 0 && NET_IPV6_DEFAULT_ROUTE > 0 ))" "$NET_FW_V6_POLICY"

    if (( NET_UFW_ACTIVE )); then
        if [[ "$NET_UFW_IPV6" == "yes" ]]; then
            add_result "NET-UFW-IPV6-001" "network" "PASS" "INFO" "HIGH" \
                "UFW IPv6 processing is enabled" \
                "IPV6=yes; normalized_v6_policy=$NET_FW_V6_POLICY." \
                "grep '^IPV6=' /etc/default/ufw; ufw status verbose" \
                "Confirm IPv6 allow rules match the intended exposure."
        elif (( NET_PUBLIC_V6_COUNT > 0 && NET_IPV6_DEFAULT_ROUTE > 0 )) && [[ "$NET_FW_V6_POLICY" != "restrictive" ]]; then
            add_result "NET-UFW-IPV6-001" "network" "WARN" "HIGH" "HIGH" \
                "Routed public IPv6 exists without confirmed equivalent filtering" \
                "UFW_IPV6=${NET_UFW_IPV6:-unknown}; public_ipv6=$NET_PUBLIC_V6_COUNT; default_route_v6=$NET_IPV6_DEFAULT_ROUTE; normalized_v6_policy=$NET_FW_V6_POLICY." \
                "grep '^IPV6=' /etc/default/ufw; ip -6 addr show scope global; ip -6 route show default; ip6tables -S; nft list ruleset" \
                "Enable equivalent IPv6 filtering or disable public IPv6 connectivity and unintended IPv6 listeners."
        else
            add_result "NET-UFW-IPV6-001" "network" "INFO" "INFO" "HIGH" \
                "UFW IPv6 processing is disabled, but no routed public IPv6 was detected" \
                "UFW_IPV6=${NET_UFW_IPV6:-unknown}; public_ipv6=$NET_PUBLIC_V6_COUNT; default_route_v6=$NET_IPV6_DEFAULT_ROUTE; normalized_v6_policy=$NET_FW_V6_POLICY." \
                "grep '^IPV6=' /etc/default/ufw; ip -6 addr show scope global; ip -6 route show default" \
                "Reassess firewall parity before enabling public IPv6 connectivity."
        fi
    fi

    local i reachable
    for ((i=0; i<${#L_PROTO[@]}; i++)); do
        exposure="${L_EXPOSURE[$i]}"; family="${L_FAMILY[$i]}"; proto="${L_PROTO[$i]}"; port="${L_PORT[$i]}"
        [[ "$exposure" == "public" || "$exposure" == "private" || "$exposure" == "wildcard" ]] || continue
        policy="$([[ "$family" == "v4" ]] && printf '%s' "$NET_FW_V4_POLICY" || printf '%s' "$NET_FW_V6_POLICY")"
        allow_state="unknown"
        if [[ "$policy" == "permissive" ]]; then
            allow_state="allowed"
        elif [[ "$policy" == "restrictive" ]]; then
            if net_fw_allows "$family" "$proto" "$port"; then
                allow_state="allowed"
            elif (( NET_FW_COMPLEX )); then
                allow_state="unknown"
            else
                allow_state="restricted"
            fi
        fi
        case "$allow_state" in
            allowed) allowed_count=$((allowed_count + 1)) ;;
            restricted) restricted_count=$((restricted_count + 1)) ;;
            unknown) unknown_count=$((unknown_count + 1)) ;;
        esac
        key="$proto:$port"
        if (( ${#NET_EXPECTED_PORTS[@]} > 0 )); then
            if [[ -n "${NET_EXPECTED_PORTS[$key]+x}" ]]; then
                expected_seen_count=$((expected_seen_count + 1))
                if [[ "$allow_state" == "restricted" && "$exposure" == "public" ]]; then
                    suffix="$(stable_suffix "$key|expected-blocked|${L_ADDR[$i]}")"
                    add_result "NET-PORT-BLOCKED-$suffix" "network" "WARN" "MEDIUM" "HIGH" \
                        "Expected listener has no normalized explicit allow rule" \
                        "$key address=${L_ADDR[$i]} exposure=$exposure process=${L_PROCESS[$i]} unit=${L_UNIT[$i]}; firewall_policy=$policy." \
                        "ss -lntup '( sport = :$port )'; ufw status numbered; nft list ruleset; iptables -S; ip6tables -S" \
                        "Confirm source/interface-scoped rules manually, then add an explicit allow rule if the service must be reachable."
                fi
            elif [[ "$allow_state" != "restricted" ]]; then
                unexpected_allowed_count=$((unexpected_allowed_count + 1))
                suffix="$(stable_suffix "$family|$proto|${L_ADDR[$i]}|$port|unexpected")"
                severity="LOW"; [[ "$exposure" == "public" ]] && severity="MEDIUM"
                add_result "NET-PORT-UNEXPECTED-$suffix" "network" "WARN" "$severity" "HIGH" \
                    "Listener is outside the expected-port baseline" \
                    "$key address=${L_ADDR[$i]} exposure=$exposure process=${L_PROCESS[$i]} pid=${L_PID[$i]} unit=${L_UNIT[$i]}; firewall_state=$allow_state." \
                    "ss -lntup '( sport = :$port )'; systemctl status ${L_UNIT[$i]}; ufw status numbered; nft list ruleset" \
                    "Confirm the service is required, then add it to the explicit baseline or restrict/disable the listener."
            fi
        fi
    done
    add_result "NET-FW-CORRELATION-001" "network" "INFO" "INFO" "MEDIUM" \
        "Listener and host-firewall correlation summary" \
        "allowed_or_default_accept=$allowed_count; no_explicit_allow_under_restrictive_policy=$restricted_count; policy_or_rule_unknown=$unknown_count; expected_seen=$expected_seen_count; unexpected_allowed=$unexpected_allowed_count; complex_rules=$NET_FW_COMPLEX." \
        "ss -lntup; ufw status numbered; nft list ruleset; iptables -S; ip6tables -S" \
        "Treat correlation as host-level evidence; provider firewalls and complex named nftables sets may require manual verification."

    expected_count=${#NET_EXPECTED_PORTS[@]}
    if (( expected_count > 0 )); then
        for key in "${!NET_EXPECTED_PORTS[@]}"; do
            if [[ -z "${LISTEN_KEYS[$key]+x}" ]]; then
                missing_expected=$((missing_expected + 1))
                suffix="$(stable_suffix "$key|missing-expected")"
                add_result "NET-PORT-MISSING-$suffix" "network" "WARN" "MEDIUM" "HIGH" \
                    "Expected port is not listening" \
                    "$key is present in --expected-ports but no matching local listener was found." \
                    "ss -lntup; systemctl --failed --type=service; systemctl list-units --type=service --state=running" \
                    "Confirm the related service is intentionally stopped or investigate its startup and binding configuration."
            fi
        done
        add_result "NET-PORT-MODEL-001" "network" "$([[ $missing_expected -eq 0 && $unexpected_allowed_count -eq 0 ]] && printf PASS || printf INFO)" "INFO" "HIGH" \
            "Expected-port baseline evaluation" \
            "configured=$expected_count; observed=$expected_seen_count; missing=$missing_expected; unexpected_allowed=$unexpected_allowed_count; baseline=$EXPECTED_PORTS_RAW." \
            "sudo ./vpscry.sh --expected-ports '$EXPECTED_PORTS_RAW'" \
            "Keep the expected-port list limited to intentionally reachable TCP and UDP services."
    else
        add_result "NET-PORT-MODEL-001" "network" "INFO" "INFO" "HIGH" \
            "No explicit expected-port baseline was supplied" \
            "Listener inventory and firewall correlation were completed without classifying ordinary application ports as unexpected." \
            "sudo ./vpscry.sh --expected-ports tcp:22,tcp:80,tcp:443" \
            "Use --expected-ports when you want deterministic missing and unexpected listener findings."
    fi

    ipv4_forward="$(sysctl -n net.ipv4.ip_forward 2>/dev/null || printf unknown)"
    ipv6_forward="$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null || printf unknown)"
    if (( vpn_count > 0 || container_count > 0 )) || have docker || have podman || have wg || have tailscale; then forwarding_context="vpn-or-container"; fi
    if [[ "$ipv4_forward" == "1" || "$ipv6_forward" == "1" ]]; then
        if [[ "$forwarding_context" == "vpn-or-container" ]]; then
            add_result "NET-FORWARD-001" "network" "INFO" "INFO" "MEDIUM" \
                "IP forwarding is enabled with a detected VPN or container context" \
                "ipv4_forward=$ipv4_forward; ipv6_forward=$ipv6_forward; context=$forwarding_context." \
                "sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding; ip route; ip -6 route; nft list ruleset" \
                "Confirm forwarding and NAT rules are limited to the intended VPN or container paths."
        else
            add_result "NET-FORWARD-001" "network" "WARN" "MEDIUM" "MEDIUM" \
                "IP forwarding is enabled without a detected routing use case" \
                "ipv4_forward=$ipv4_forward; ipv6_forward=$ipv6_forward; context=$forwarding_context." \
                "sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding; ip route; ip -6 route; nft list ruleset" \
                "Disable forwarding when unused or document the intended router/NAT role and filter forwarded traffic."
        fi
    else
        add_result "NET-FORWARD-001" "network" "PASS" "INFO" "HIGH" \
            "Kernel IP forwarding is disabled" \
            "ipv4_forward=$ipv4_forward; ipv6_forward=$ipv6_forward." \
            "sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding" \
            "No action required unless the host is intended to route VPN or container traffic."
    fi

    rp_all="$(sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null || printf unknown)"
    rp_default="$(sysctl -n net.ipv4.conf.default.rp_filter 2>/dev/null || printf unknown)"
    if (( NET_PUBLIC_V4_COUNT > 0 )) && [[ "$rp_all" == "0" && "$rp_default" == "0" && "$forwarding_context" == "none" ]]; then
        add_result "NET-RPFILTER-001" "network" "WARN" "LOW" "MEDIUM" \
            "IPv4 reverse-path filtering is disabled on a public host" \
            "all=$rp_all; default=$rp_default; routing_context=$forwarding_context." \
            "sysctl net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter; ip rule; ip route show table all" \
            "Consider strict or loose reverse-path filtering after confirming asymmetric routing is not required."
    else
        add_result "NET-RPFILTER-001" "network" "INFO" "INFO" "MEDIUM" \
            "IPv4 reverse-path filtering inventory" \
            "all=$rp_all; default=$rp_default; routing_context=$forwarding_context." \
            "sysctl net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter" \
            "Values 1 or 2 may be appropriate depending on asymmetric routing, VPN and policy-routing requirements."
    fi

    dns_target="$(readlink -f /etc/resolv.conf 2>/dev/null || printf /etc/resolv.conf)"
    dns_nameservers="$(awk '/^[[:space:]]*nameserver[[:space:]]+/ {print $2}' /etc/resolv.conf 2>/dev/null | paste -sd, - || true)"
    for ((i=0; i<${#L_PROTO[@]}; i++)); do
        [[ "${L_PORT[$i]}" == "53" ]] || continue
        case "${L_EXPOSURE[$i]}" in
            public|wildcard) dns_public=$((dns_public + 1)) ;;
            private|cgnat) dns_private=$((dns_private + 1)) ;;
            loopback) dns_loopback=$((dns_loopback + 1)) ;;
        esac
    done
    add_result "NET-DNS-001" "network" "INFO" "INFO" "HIGH" \
        "DNS resolver configuration inventory" \
        "resolv_conf_target=$dns_target; nameservers=${dns_nameservers:-none}; dns_listeners_public=$dns_public; private=$dns_private; loopback=$dns_loopback." \
        "readlink -f /etc/resolv.conf; cat /etc/resolv.conf; ss -lnutp '( sport = :53 )'" \
        "Confirm configured resolvers are trusted and local stub resolvers are bound only where intended."
    if (( dns_public > 0 )); then
        add_result "NET-DNS-EXPOSE-001" "network" "WARN" "HIGH" "HIGH" \
            "DNS service is bound to a public or wildcard address" \
            "$dns_public DNS listener(s) have public or wildcard exposure." \
            "ss -lnutp '( sport = :53 )'; systemctl status systemd-resolved unbound bind9 dnsmasq" \
            "Restrict recursion and listener addresses, and permit queries only from intended clients."
    elif (( dns_loopback > 0 && dns_private == 0 )); then
        add_result "NET-DNS-EXPOSE-001" "network" "PASS" "INFO" "HIGH" \
            "Local DNS listener is loopback-bound" \
            "loopback_dns_listeners=$dns_loopback; private_dns_listeners=$dns_private; public_dns_listeners=$dns_public." \
            "ss -lnutp '( sport = :53 )'" \
            "No action required."
    fi

    if have docker && capture 5 docker info >/dev/null 2>&1; then
        docker_inventory="$(capture 8 docker ps --format '{{.ID}}|{{.Names}}|{{.Ports}}' 2>/dev/null || true)"
        docker_published="$(grep -Ec '(0\.0\.0\.0:|\[::\]:|:::)[0-9]+->' <<< "$docker_inventory" || true)"
        local docker_ids docker_id network_mode
        docker_ids="$(capture 8 docker ps -q 2>/dev/null || true)"
        while IFS= read -r docker_id; do
            [[ -n "$docker_id" ]] || continue
            network_mode="$(capture 5 docker inspect -f '{{.HostConfig.NetworkMode}}' "$docker_id" 2>/dev/null || true)"
            [[ "$network_mode" == "host" ]] && docker_hostnet=$((docker_hostnet + 1))
        done <<< "$docker_ids"
        add_result "NET-DOCKER-001" "network" "INFO" "INFO" "MEDIUM" \
            "Docker network exposure inventory" \
            "published_containers=$docker_published; host_network_containers=$docker_hostnet; ${docker_inventory:-no running containers or no published ports}." \
            "docker ps --format '{{.ID}}|{{.Names}}|{{.Ports}}'; docker inspect CONTAINER --format '{{.HostConfig.NetworkMode}} {{json .HostConfig.PortBindings}}'" \
            "Review wildcard-published ports, host networking and firewall traversal independently from ordinary host listeners."
        if (( NET_UFW_ACTIVE && docker_published > 0 )); then
            add_result "NET-DOCKER-UFW-001" "network" "WARN" "MEDIUM" "HIGH" \
                "Docker-published ports require separate UFW review" \
                "ufw_active=yes; containers_with_wildcard_published_ports=$docker_published." \
                "docker ps --format '{{.Names}} {{.Ports}}'; nft list ruleset; iptables -S DOCKER-USER; ufw status numbered" \
                "Use Docker-aware filtering, source-restricted publishing or the DOCKER-USER path; do not assume an ordinary UFW deny rule covers every published container port."
        fi
        if (( docker_hostnet > 0 )); then
            add_result "NET-DOCKER-HOST-001" "network" "WARN" "LOW" "HIGH" \
                "Docker container uses host networking" \
                "host_network_containers=$docker_hostnet." \
                "docker ps -q | xargs -r docker inspect -f '{{.Name}} {{.HostConfig.NetworkMode}}'" \
                "Confirm host networking is necessary because it removes network namespace isolation and exposes container listeners directly on the host."
        fi
    fi

    if have podman && capture 5 podman info >/dev/null 2>&1; then
        podman_inventory="$(capture 8 podman ps --format '{{.ID}}|{{.Names}}|{{.Ports}}' 2>/dev/null || true)"
        podman_published="$(grep -Ec '(0\.0\.0\.0:|\[::\]:|:::)[0-9]+->' <<< "$podman_inventory" || true)"
        add_result "NET-PODMAN-001" "network" "INFO" "INFO" "MEDIUM" \
            "Podman published-port inventory" \
            "containers_with_wildcard_published_ports=$podman_published; ${podman_inventory:-no running containers or no published ports}." \
            "podman ps --format '{{.ID}}|{{.Names}}|{{.Ports}}'; podman inspect CONTAINER" \
            "Review rootless and rootful publishing, host networking and firewall integration separately."
    fi

    if (( ONLINE )); then
        online_dns="$(capture 10 getent ahosts deb.debian.org 2>/dev/null | head -n 3 || true)"
        if [[ -n "$online_dns" ]]; then
            add_result "NET-ONLINE-DNS-001" "network" "PASS" "INFO" "HIGH" \
                "Online DNS resolution succeeded" "$online_dns" \
                "getent ahosts deb.debian.org" "No action required."
        else
            add_result "NET-ONLINE-DNS-001" "network" "WARN" "MEDIUM" "MEDIUM" \
                "Online DNS resolution failed" "No address was returned for deb.debian.org." \
                "getent ahosts deb.debian.org" "Check resolver configuration, firewall egress and provider DNS reachability."
        fi
        if have curl; then
            online_http="$(capture 12 curl -fsSI --max-time 10 https://deb.debian.org/ 2>/dev/null | head -n 1 || true)"
            if [[ "$online_http" =~ ^HTTP/ ]]; then
                add_result "NET-ONLINE-HTTPS-001" "network" "PASS" "INFO" "HIGH" \
                    "Online HTTPS egress check succeeded" "$online_http" \
                    "curl -fsSI --max-time 10 https://deb.debian.org/" "No action required."
            else
                add_result "NET-ONLINE-HTTPS-001" "network" "WARN" "LOW" "MEDIUM" \
                    "Online HTTPS egress check failed" "No HTTP status line was returned from deb.debian.org." \
                    "curl -vI --max-time 10 https://deb.debian.org/" "Check DNS, routing, proxy configuration and outbound firewall policy."
            fi
        else
            add_result "NET-ONLINE-HTTPS-001" "network" "SKIP" "INFO" "HIGH" \
                "Online HTTPS egress check was skipped" "curl is unavailable." \
                "command -v curl" "Install curl only if this optional check is required."
        fi
    fi
}
find_sshd() {
    if have sshd; then command -v sshd; return; fi
    [[ -x /usr/sbin/sshd ]] && { printf '/usr/sbin/sshd'; return; }
    [[ -x /sbin/sshd ]] && { printf '/sbin/sshd'; return; }
    return 1
}

sshd_value() {
    local data="$1" key="$2"
    awk -v key="$key" '$1 == key {print $2; exit}' <<< "$data"
}

check_ssh() {
    local sshd_bin config_test effective root_login password_auth kbd_auth empty_password pubkey maxtries allowusers
    sshd_bin="$(find_sshd 2>/dev/null || true)"
    if [[ -z "$sshd_bin" ]]; then
        add_result "SSH-DETECT-001" "ssh" "INFO" "INFO" "HIGH" \
            "OpenSSH server was not detected" "No sshd executable was found." \
            "command -v sshd; dpkg -l openssh-server" \
            "No SSH-specific action is required if the server is intentionally managed another way."
        return
    fi

    config_test="$(capture 15 "$sshd_bin" -t)"
    if [[ $? -eq 0 ]]; then
        add_result "SSH-CONFIG-001" "ssh" "PASS" "INFO" "HIGH" \
            "OpenSSH server configuration syntax is valid" \
            "sshd -t completed without an error." \
            "$sshd_bin -t" "No action required."
    else
        add_result "SSH-CONFIG-001" "ssh" "FAIL" "HIGH" "HIGH" \
            "OpenSSH server configuration validation failed" "$config_test" \
            "$sshd_bin -t" \
            "Correct the configuration before reloading or restarting SSH."
    fi

    effective="$(capture 15 "$sshd_bin" -T)"
    if [[ $? -ne 0 || -z "$effective" ]]; then
        add_result "SSH-EFFECTIVE-001" "ssh" "SKIP" "INFO" "MEDIUM" \
            "Effective OpenSSH configuration could not be read" "$effective" \
            "$sshd_bin -T" \
            "Run the audit as root and resolve any configuration validation error."
        return
    fi

    root_login="$(sshd_value "$effective" permitrootlogin)"
    password_auth="$(sshd_value "$effective" passwordauthentication)"
    kbd_auth="$(sshd_value "$effective" kbdinteractiveauthentication)"
    empty_password="$(sshd_value "$effective" permitemptypasswords)"
    pubkey="$(sshd_value "$effective" pubkeyauthentication)"
    maxtries="$(sshd_value "$effective" maxauthtries)"
    allowusers="$(sshd_value "$effective" allowusers)"

    if [[ "$empty_password" == "yes" ]]; then
        add_result "SSH-AUTH-001" "ssh" "FAIL" "CRITICAL" "HIGH" \
            "SSH permits accounts with empty passwords" \
            "PermitEmptyPasswords=$empty_password." \
            "$sshd_bin -T | grep '^permitemptypasswords '" \
            "Set PermitEmptyPasswords no and verify no account has an empty password."
    else
        add_result "SSH-AUTH-001" "ssh" "PASS" "INFO" "HIGH" \
            "SSH rejects empty passwords" "PermitEmptyPasswords=${empty_password:-unknown}." \
            "$sshd_bin -T | grep '^permitemptypasswords '" "No action required."
    fi

    if [[ "$root_login" == "yes" && ( "$password_auth" == "yes" || "$kbd_auth" == "yes" ) ]]; then
        add_result "SSH-ROOT-001" "ssh" "FAIL" "HIGH" "HIGH" \
            "Direct root SSH login can use interactive authentication" \
            "PermitRootLogin=$root_login; PasswordAuthentication=$password_auth; KbdInteractiveAuthentication=$kbd_auth." \
            "$sshd_bin -T | grep -E '^(permitrootlogin|passwordauthentication|kbdinteractiveauthentication) '" \
            "Disable direct root login or at minimum prohibit password and keyboard-interactive authentication for root."
    elif [[ "$root_login" == "yes" ]]; then
        add_result "SSH-ROOT-001" "ssh" "WARN" "MEDIUM" "HIGH" \
            "Direct root SSH login is enabled" \
            "PermitRootLogin=$root_login; interactive password methods appear disabled globally." \
            "$sshd_bin -T | grep -E '^(permitrootlogin|passwordauthentication|kbdinteractiveauthentication) '" \
            "Prefer a named administrative account with sudo unless direct root key login is an explicit operational decision."
    elif [[ "$root_login" == "prohibit-password" || "$root_login" == "without-password" ]]; then
        add_result "SSH-ROOT-001" "ssh" "WARN" "LOW" "HIGH" \
            "Root SSH login is restricted to non-password authentication" \
            "PermitRootLogin=$root_login." \
            "$sshd_bin -T | grep '^permitrootlogin '" \
            "This can be acceptable; a named sudo account provides stronger attribution and is generally preferable."
    else
        add_result "SSH-ROOT-001" "ssh" "PASS" "INFO" "HIGH" \
            "Direct root SSH login is disabled or tightly restricted" \
            "PermitRootLogin=${root_login:-unknown}." \
            "$sshd_bin -T | grep '^permitrootlogin '" "No action required."
    fi

    if [[ "$password_auth" == "yes" || "$kbd_auth" == "yes" ]]; then
        add_result "SSH-PASSWORD-001" "ssh" "WARN" "LOW" "HIGH" \
            "SSH interactive authentication is enabled" \
            "PasswordAuthentication=$password_auth; KbdInteractiveAuthentication=$kbd_auth; PubkeyAuthentication=$pubkey." \
            "$sshd_bin -T | grep -E '^(passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication) '" \
            "Prefer public-key or certificate authentication where operationally possible; password authentication is not treated as an automatic critical failure."
    else
        add_result "SSH-PASSWORD-001" "ssh" "PASS" "INFO" "HIGH" \
            "SSH password and keyboard-interactive authentication are disabled" \
            "PasswordAuthentication=$password_auth; KbdInteractiveAuthentication=$kbd_auth; PubkeyAuthentication=$pubkey." \
            "$sshd_bin -T | grep -E '^(passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication) '" \
            "No action required."
    fi

    if [[ "$pubkey" == "no" ]]; then
        add_result "SSH-PUBKEY-001" "ssh" "WARN" "MEDIUM" "HIGH" \
            "SSH public-key authentication is disabled" "PubkeyAuthentication=$pubkey." \
            "$sshd_bin -T | grep '^pubkeyauthentication '" \
            "Enable public-key authentication unless another strong authentication mechanism is deliberately used."
    else
        add_result "SSH-PUBKEY-001" "ssh" "PASS" "INFO" "HIGH" \
            "SSH public-key authentication is enabled" "PubkeyAuthentication=${pubkey:-unknown}." \
            "$sshd_bin -T | grep '^pubkeyauthentication '" "No action required."
    fi

    if [[ "$maxtries" =~ ^[0-9]+$ ]] && (( maxtries > 6 )); then
        add_result "SSH-TRIES-001" "ssh" "WARN" "LOW" "HIGH" \
            "SSH allows a high number of authentication attempts per connection" "MaxAuthTries=$maxtries." \
            "$sshd_bin -T | grep '^maxauthtries '" \
            "Consider reducing MaxAuthTries while accounting for clients that offer multiple keys."
    else
        add_result "SSH-TRIES-001" "ssh" "PASS" "INFO" "HIGH" \
            "SSH authentication attempt limit is reasonable" "MaxAuthTries=${maxtries:-unknown}." \
            "$sshd_bin -T | grep '^maxauthtries '" "No action required."
    fi

    add_result "SSH-ALLOW-001" "ssh" "INFO" "INFO" "MEDIUM" \
        "SSH login allow-list inventory" \
        "AllowUsers=${allowusers:-not configured in the default effective context}." \
        "$sshd_bin -T | grep -E '^(allowusers|allowgroups|denyusers|denygroups) '" \
        "An allow-list is optional; use one when the server has many local accounts but only a small SSH user set."

    local user uid home shell sshdir authfile mode owner bad=0
    while IFS=: read -r user _ uid _ _ home shell; do
        [[ "$uid" =~ ^[0-9]+$ ]] || continue
        (( uid == 0 || uid >= 1000 )) || continue
        [[ "$shell" != */nologin && "$shell" != */false ]] || continue
        sshdir="$home/.ssh"
        authfile="$sshdir/authorized_keys"
        if [[ -d "$sshdir" ]]; then
            IFS='|' read -r owner mode < <(stat -Lc '%U|%a' -- "$sshdir" 2>/dev/null || printf '||')
            if is_group_or_world_writable "$mode" || [[ "$owner" != "$user" && "$user" != "root" ]]; then
                add_result "SSH-KEYPERM-$(printf '%03d' "$bad")" "ssh" "WARN" "HIGH" "HIGH" \
                    "SSH directory has unsafe ownership or write permissions" \
                    "user=$user path=$sshdir owner=$owner mode=$mode." \
                    "stat -Lc '%U %G %a %n' -- '$sshdir'" \
                    "Set ownership to the account and remove group/world write permission."
                bad=$((bad + 1))
            fi
        fi
        if [[ -e "$authfile" ]]; then
            IFS='|' read -r owner mode < <(stat -Lc '%U|%a' -- "$authfile" 2>/dev/null || printf '||')
            if is_group_or_world_writable "$mode" || [[ "$owner" != "$user" && "$user" != "root" ]]; then
                add_result "SSH-KEYPERM-$(printf '%03d' "$bad")" "ssh" "WARN" "HIGH" "HIGH" \
                    "authorized_keys has unsafe ownership or write permissions" \
                    "user=$user path=$authfile owner=$owner mode=$mode." \
                    "stat -Lc '%U %G %a %n' -- '$authfile'" \
                    "Set ownership to the account and remove group/world write permission."
                bad=$((bad + 1))
            fi
        fi
    done < /etc/passwd
    if (( bad == 0 )); then
        add_result "SSH-KEYPERM-SUM" "ssh" "PASS" "INFO" "MEDIUM" \
            "No unsafe SSH key file permission was found" \
            "Login-capable root and UID >= 1000 accounts were inspected where accessible." \
            "find /root /home -maxdepth 3 -name authorized_keys -exec stat -c '%U %G %a %n' {} +" \
            "No action required."
    fi
}

check_accounts_and_sudo() {
    local uid0 users empty_accounts visudo_out
    uid0="$(awk -F: '$3 == 0 {print $1}' /etc/passwd 2>/dev/null | paste -sd, -)"
    users="$(awk -F: '$3 == 0 {count++} END {print count+0}' /etc/passwd 2>/dev/null)"
    if [[ "$users" =~ ^[0-9]+$ ]] && (( users > 1 )); then
        add_result "AUTH-UID0-001" "accounts" "FAIL" "CRITICAL" "HIGH" \
            "Multiple UID 0 accounts exist" "UID 0 accounts: $uid0." \
            "awk -F: '\$3 == 0 {print \$1}' /etc/passwd" \
            "Remove unintended UID 0 accounts and preserve a single controlled root identity."
    else
        add_result "AUTH-UID0-001" "accounts" "PASS" "INFO" "HIGH" \
            "A single UID 0 account exists" "UID 0 account: ${uid0:-root}." \
            "awk -F: '\$3 == 0 {print \$1}' /etc/passwd" "No action required."
    fi

    if [[ -r /etc/shadow ]]; then
        empty_accounts="$(awk -F: '$2 == "" {print $1}' /etc/shadow | paste -sd, -)"
        if [[ -n "$empty_accounts" ]]; then
            add_result "AUTH-EMPTY-001" "accounts" "FAIL" "CRITICAL" "HIGH" \
                "Accounts with an empty password field exist" "Accounts: $empty_accounts." \
                "sudo awk -F: '\$2 == \"\" {print \$1}' /etc/shadow" \
                "Lock the accounts or set strong authentication immediately."
        else
            add_result "AUTH-EMPTY-001" "accounts" "PASS" "INFO" "HIGH" \
                "No empty password field was found" "/etc/shadow contained no empty password field." \
                "sudo awk -F: '\$2 == \"\" {print \$1}' /etc/shadow" "No action required."
        fi
    else
        add_result "AUTH-EMPTY-001" "accounts" "SKIP" "INFO" "HIGH" \
            "Empty password fields could not be checked" "/etc/shadow is not readable." \
            "sudo awk -F: '\$2 == \"\" {print \$1}' /etc/shadow" \
            "Re-run with sudo."
    fi

    if have visudo; then
        visudo_out="$(capture 15 visudo -cf /etc/sudoers)"
        if [[ $? -eq 0 ]]; then
            add_result "AUTH-SUDO-001" "accounts" "PASS" "INFO" "HIGH" \
                "sudoers configuration syntax is valid" "$visudo_out" \
                "visudo -cf /etc/sudoers" "No action required."
        else
            add_result "AUTH-SUDO-001" "accounts" "FAIL" "HIGH" "HIGH" \
                "sudoers configuration validation failed" "$visudo_out" \
                "visudo -cf /etc/sudoers" \
                "Correct the syntax using visudo before relying on sudo access."
        fi
    else
        add_result "AUTH-SUDO-001" "accounts" "INFO" "INFO" "HIGH" \
            "sudoers validation was not available" "visudo is not installed or not in PATH." \
            "command -v visudo" "No action is required if sudo is intentionally not installed."
    fi
}

check_updates() {
    local apt_sim pending security_pending newest now age_days package periodic timer_enabled timer_active apt_config reboot_auto reboot_time reboot_auto_value reboot_time_value
    if ! have apt-get; then
        add_result "APT-DETECT-001" "updates" "SKIP" "INFO" "HIGH" \
            "APT update state could not be checked" "apt-get is unavailable." \
            "command -v apt-get" "This script expects APT on Debian."
        return
    fi

    apt_sim="$(capture 90 apt-get -s -o Debug::NoLocking=1 upgrade)"
    if [[ $? -eq 0 ]]; then
        pending="$(grep -c '^Inst ' <<< "$apt_sim" || true)"
        security_pending="$(grep '^Inst ' <<< "$apt_sim" | grep -Eic 'security|Debian-Security' || true)"
        if (( security_pending > 0 )); then
            add_result "APT-PENDING-001" "updates" "WARN" "HIGH" "MEDIUM" \
                "Security updates are pending in the local APT cache" \
                "pending_packages=$pending; security_related=$security_pending; no repository refresh was performed." \
                "apt-get -s upgrade | grep '^Inst '" \
                "Refresh package metadata during the normal maintenance process and apply verified security updates."
        elif (( pending > 0 )); then
            add_result "APT-PENDING-001" "updates" "WARN" "LOW" "MEDIUM" \
                "Package updates are pending in the local APT cache" \
                "pending_packages=$pending; security_related=$security_pending; no repository refresh was performed." \
                "apt-get -s upgrade | grep '^Inst '" \
                "Review and apply updates during a controlled maintenance window."
        else
            add_result "APT-PENDING-001" "updates" "PASS" "INFO" "MEDIUM" \
                "No package update is pending in the local APT cache" \
                "apt-get simulation listed no package installation; metadata may still be stale." \
                "apt-get -s upgrade" \
                "No action required after confirming metadata freshness."
        fi
    else
        add_result "APT-PENDING-001" "updates" "WARN" "MEDIUM" "MEDIUM" \
            "APT upgrade simulation failed" "$apt_sim" \
            "apt-get -s -o Debug::NoLocking=1 upgrade" \
            "Resolve APT or dpkg state before relying on update status."
    fi

    newest="$(find /var/lib/apt/lists -maxdepth 1 -type f \( -name '*InRelease' -o -name '*Release' \) -printf '%T@\n' 2>/dev/null | sort -nr | head -n 1 | cut -d. -f1)"
    now="$(date +%s)"
    if [[ "$newest" =~ ^[0-9]+$ ]]; then
        age_days=$(( (now - newest) / 86400 ))
        if (( age_days > 14 )); then
            add_result "APT-FRESH-001" "updates" "WARN" "MEDIUM" "HIGH" \
                "APT package metadata is stale" "newest_release_metadata_age_days=$age_days." \
                "find /var/lib/apt/lists -maxdepth 1 -type f -printf '%TY-%Tm-%Td %p\n' | sort" \
                "Run apt update through the normal controlled maintenance process."
        elif (( age_days > 7 )); then
            add_result "APT-FRESH-001" "updates" "WARN" "LOW" "HIGH" \
                "APT package metadata is older than one week" "newest_release_metadata_age_days=$age_days." \
                "find /var/lib/apt/lists -maxdepth 1 -type f -printf '%TY-%Tm-%Td %p\n' | sort" \
                "Confirm the configured update cadence is intentional."
        else
            add_result "APT-FRESH-001" "updates" "PASS" "INFO" "HIGH" \
                "APT package metadata is recent" "newest_release_metadata_age_days=$age_days." \
                "find /var/lib/apt/lists -maxdepth 1 -type f -printf '%TY-%Tm-%Td %p\n' | sort" \
                "No action required."
        fi
    else
        add_result "APT-FRESH-001" "updates" "WARN" "MEDIUM" "MEDIUM" \
            "APT package metadata age could not be determined" "/var/lib/apt/lists contained no release metadata timestamp." \
            "ls -la /var/lib/apt/lists" \
            "Check whether package metadata has ever been refreshed."
    fi

    package="$(dpkg-query -W -f='${Status}' unattended-upgrades 2>/dev/null || true)"
    apt_config="$(apt-config dump 2>/dev/null || true)"
    periodic="$(grep -E '^APT::Periodic::Unattended-Upgrade[[:space:]]+"1";' <<< "$apt_config" || true)"
    timer_enabled="$(systemctl is-enabled apt-daily-upgrade.timer 2>/dev/null || true)"
    timer_active="$(systemctl is-active apt-daily-upgrade.timer 2>/dev/null || true)"

    if [[ "$package" == *"install ok installed"* && -n "$periodic" && "$timer_enabled" == "enabled" ]]; then
        add_result "APT-AUTO-001" "updates" "PASS" "INFO" "HIGH" \
            "Automatic unattended upgrades are configured" \
            "package=installed; APT::Periodic::Unattended-Upgrade=1; timer_enabled=$timer_enabled; timer_active=$timer_active." \
            "apt-config dump | grep -E 'APT::Periodic|Unattended-Upgrade'; systemctl status apt-daily-upgrade.timer" \
            "Review allowed origins, exclusions and recent unattended-upgrades logs."
    elif [[ "$package" == *"install ok installed"* ]]; then
        add_result "APT-AUTO-001" "updates" "WARN" "MEDIUM" "HIGH" \
            "unattended-upgrades is installed but full scheduling was not confirmed" \
            "package=installed; periodic_setting=${periodic:-missing}; timer_enabled=${timer_enabled:-unknown}; timer_active=${timer_active:-unknown}." \
            "apt-config dump | grep -E 'APT::Periodic|Unattended-Upgrade'; systemctl status apt-daily-upgrade.timer" \
            "Enable and test the desired automatic security update policy or document a manual patch process."
    else
        add_result "APT-AUTO-001" "updates" "WARN" "LOW" "HIGH" \
            "Automatic unattended upgrades are not installed" \
            "unattended-upgrades package was not detected." \
            "dpkg-query -W unattended-upgrades" \
            "Use unattended security updates or document an equally reliable patching process."
    fi

    reboot_auto="$(grep -E '^Unattended-Upgrade::Automatic-Reboot[[:space:]]+' <<< "$apt_config" | head -n 1 || true)"
    reboot_time="$(grep -E '^Unattended-Upgrade::Automatic-Reboot-Time[[:space:]]+' <<< "$apt_config" | head -n 1 || true)"
    reboot_auto_value="$(awk '{value=$2; gsub(/[";]/, "", value); print value}' <<< "$reboot_auto")"
    reboot_time_value="$(awk '{value=$2; gsub(/[";]/, "", value); print value}' <<< "$reboot_time")"
    if [[ "$reboot_auto_value" == "true" ]]; then
        add_result "APT-REBOOT-001" "updates" "INFO" "INFO" "HIGH" \
            "Automatic reboot after unattended upgrades is enabled" \
            "enabled=true; time=${reboot_time_value:-default or unspecified}." \
            "apt-config dump | grep 'Unattended-Upgrade::Automatic-Reboot'" \
            "Confirm the reboot time, service startup behavior and maintenance expectations."
    else
        add_result "APT-REBOOT-001" "updates" "INFO" "INFO" "HIGH" \
            "Automatic reboot after unattended upgrades is not enabled" \
            "enabled=${reboot_auto_value:-false or absent}; configured_time=${reboot_time_value:-none}. A time value alone does not enable automatic reboot." \
            "apt-config dump | grep 'Unattended-Upgrade::Automatic-Reboot'" \
            "A manual reboot process is acceptable when reboot-required markers are monitored and acted upon."
    fi

}

check_logs() {
    local usage persistent logrotate_ok debug_out large_files file size mode rotation_available=0
    if have journalctl; then
        usage="$(journalctl --disk-usage 2>/dev/null || true)"
        add_result "LOG-JOURNAL-001" "logs" "INFO" "INFO" "HIGH" \
            "systemd journal disk usage" "${usage%.}" \
            "journalctl --disk-usage" \
            "Compare actual use with SystemMaxUse, SystemKeepFree and available disk space."
    else
        add_result "LOG-JOURNAL-001" "logs" "SKIP" "INFO" "HIGH" \
            "systemd journal usage could not be checked" "journalctl is unavailable." \
            "command -v journalctl" "Inspect the active logging system manually."
    fi

    if [[ -d /var/log/journal ]]; then
        add_result "LOG-PERSIST-001" "logs" "PASS" "INFO" "HIGH" \
            "Persistent systemd journal storage is available" "/var/log/journal exists." \
            "ls -ld /var/log/journal; grep -R '^Storage=' /etc/systemd/journald.conf*" \
            "No action required."
    else
        add_result "LOG-PERSIST-001" "logs" "WARN" "LOW" "HIGH" \
            "Persistent systemd journal storage was not detected" "/var/log/journal does not exist." \
            "grep -R '^Storage=' /etc/systemd/journald.conf*; journalctl --list-boots" \
            "Consider persistent journal storage when post-reboot forensic history is required."
    fi

    if systemctl is-enabled --quiet logrotate.timer 2>/dev/null || systemctl is-active --quiet logrotate.timer 2>/dev/null; then
        rotation_available=1
    elif [[ -x /etc/cron.daily/logrotate ]]; then
        rotation_available=1
    fi

    if (( rotation_available )); then
        add_result "LOG-ROTATE-001" "logs" "PASS" "INFO" "HIGH" \
            "A logrotate schedule was detected" \
            "logrotate.timer or /etc/cron.daily/logrotate is available." \
            "systemctl status logrotate.timer; ls -l /etc/cron.daily/logrotate" \
            "No action required after validating the configuration."
    else
        add_result "LOG-ROTATE-001" "logs" "WARN" "MEDIUM" "HIGH" \
            "No logrotate schedule was confirmed" \
            "Neither an enabled/active logrotate.timer nor executable /etc/cron.daily/logrotate was detected." \
            "systemctl status logrotate.timer; ls -l /etc/cron.daily/logrotate" \
            "Enable log rotation or document another retention mechanism."
    fi

    if have logrotate && [[ -r /etc/logrotate.conf ]]; then
        debug_out="$(capture 30 logrotate -d /etc/logrotate.conf)"
        if [[ $? -eq 0 ]]; then
            add_result "LOG-CONFIG-001" "logs" "PASS" "INFO" "HIGH" \
                "logrotate configuration passed a debug validation" \
                "logrotate -d completed successfully without rotating logs." \
                "logrotate -d /etc/logrotate.conf" "No action required."
        else
            add_result "LOG-CONFIG-001" "logs" "WARN" "MEDIUM" "HIGH" \
                "logrotate configuration validation reported an error" "$debug_out" \
                "logrotate -d /etc/logrotate.conf" \
                "Correct invalid or inaccessible log rotation definitions."
        fi
    else
        add_result "LOG-CONFIG-001" "logs" "SKIP" "INFO" "HIGH" \
            "logrotate configuration could not be validated" "logrotate or /etc/logrotate.conf is unavailable." \
            "command -v logrotate; ls -l /etc/logrotate.conf" \
            "Install or inspect the configured log retention mechanism."
    fi

    large_files="$(find /var/log -xdev -type f -size +100M -printf '%s|%p\n' 2>/dev/null | sort -nr | head -n 20 || true)"
    if [[ -z "$large_files" ]]; then
        add_result "LOG-SIZE-001" "logs" "PASS" "INFO" "MEDIUM" \
            "No individual log file larger than 100 MiB was found" \
            "Accessible regular files under /var/log were inspected." \
            "find /var/log -xdev -type f -size +100M -ls" \
            "No action required."
    else
        while IFS='|' read -r size file; do
            [[ "$size" =~ ^[0-9]+$ ]] || continue
            if (( size >= 1073741824 )); then
                add_result "LOG-SIZE-$(printf '%03d' "${LOG_SIZE_COUNT:-0}")" "logs" "FAIL" "HIGH" "HIGH" \
                    "Log file exceeds 1 GiB" \
                    "path=$file size_bytes=$size." \
                    "du -h -- '$file'; grep -R -F -- '$file' /etc/logrotate.conf /etc/logrotate.d" \
                    "Confirm rotation, retention and the event causing growth."
            else
                add_result "LOG-SIZE-$(printf '%03d' "${LOG_SIZE_COUNT:-0}")" "logs" "WARN" "LOW" "HIGH" \
                    "Large log file detected" \
                    "path=$file size_bytes=$size." \
                    "du -h -- '$file'; grep -R -F -- '$file' /etc/logrotate.conf /etc/logrotate.d" \
                    "Confirm the file is rotated and its growth rate is expected."
            fi
            LOG_SIZE_COUNT=$(( ${LOG_SIZE_COUNT:-0} + 1 ))
        done <<< "$large_files"
    fi
}

check_cron_and_scheduled_execution() {
    local cron_files=0 user_cron_files=0 unsafe=0 file owner group mode lines path runner command cron_user
    local cron_sources=()
    [[ -f /etc/crontab ]] && cron_sources+=(/etc/crontab)
    if [[ -d /etc/cron.d ]]; then
        while IFS= read -r file; do cron_sources+=("$file"); done < <(find /etc/cron.d -maxdepth 1 -type f 2>/dev/null)
    fi

    for file in "${cron_sources[@]}"; do
        cron_files=$((cron_files + 1))
        IFS='|' read -r owner group mode < <(stat -Lc '%U|%G|%a' -- "$file" 2>/dev/null || printf '||')
        if is_world_writable "$mode"; then
            add_result "CRON-PERM-$(printf '%03d' "$unsafe")" "scheduling" "FAIL" "CRITICAL" "HIGH" \
                "System cron file is world-writable" \
                "$file owner=$owner group=$group mode=$mode." \
                "stat -Lc '%U %G %a %n' -- '$file'" \
                "Remove world write permission and restore trusted ownership."
            unsafe=$((unsafe + 1))
        elif is_group_or_world_writable "$mode" && [[ "$group" != "root" && "$group" != "crontab" ]]; then
            add_result "CRON-PERM-$(printf '%03d' "$unsafe")" "scheduling" "FAIL" "HIGH" "HIGH" \
                "System cron file is writable by a non-administrative group" \
                "$file owner=$owner group=$group mode=$mode." \
                "stat -Lc '%U %G %a %n' -- '$file'; getent group '$group'" \
                "Restrict modification to root or the expected cron administration group."
            unsafe=$((unsafe + 1))
        elif [[ "$owner" != "root" ]]; then
            add_result "CRON-OWNER-$(printf '%03d' "$unsafe")" "scheduling" "WARN" "HIGH" "HIGH" \
                "System cron file is not owned by root" \
                "$file owner=$owner group=$group mode=$mode." \
                "stat -Lc '%U %G %a %n' -- '$file'" \
                "Confirm ownership is intentional and cannot be changed by a service account."
            unsafe=$((unsafe + 1))
        fi

        while IFS= read -r lines; do
            [[ -n "$lines" ]] || continue
            [[ "$lines" =~ ^[[:space:]]*# ]] && continue
            [[ "$lines" =~ ^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*= ]] && continue
            if [[ "$lines" =~ ^[[:space:]]*@ ]]; then
                runner="$(awk '{print $2}' <<< "$lines")"
                command="$(cut -d' ' -f3- <<< "$lines")"
            else
                runner="$(awk '{print $6}' <<< "$lines")"
                command="$(awk '{$1=$2=$3=$4=$5=$6=""; sub(/^[[:space:]]+/, ""); print}' <<< "$lines")"
            fi
            while IFS= read -r path; do
                case "$path" in
                    /usr/local/*|/opt/*|/root/*|/home/*|/var/www/*|/srv/*)
                        audit_root_executed_path "$path" "$file" "$runner"
                        ;;
                esac
            done < <(printf '%s\n' "$command" | extract_absolute_paths)
        done < "$file"
    done

    if [[ -d /var/spool/cron/crontabs ]]; then
        while IFS= read -r file; do
            [[ -f "$file" ]] || continue
            user_cron_files=$((user_cron_files + 1))
            cron_user="$(basename -- "$file")"
            IFS='|' read -r owner group mode < <(stat -Lc '%U|%G|%a' -- "$file" 2>/dev/null || printf '||')
            if is_world_writable "$mode"; then
                add_result "CRON-USER-PERM-$(printf '%03d' "$unsafe")" "scheduling" "FAIL" "CRITICAL" "HIGH" \
                    "User crontab is world-writable" \
                    "$file owner=$owner group=$group mode=$mode." \
                    "stat -Lc '%U %G %a %n' -- '$file'" \
                    "Remove world write permission and restore ownership to the corresponding account."
                unsafe=$((unsafe + 1))
            elif is_group_or_world_writable "$mode" && [[ "$group" != "crontab" && "$group" != "root" ]]; then
                add_result "CRON-USER-PERM-$(printf '%03d' "$unsafe")" "scheduling" "FAIL" "HIGH" "HIGH" \
                    "User crontab is writable by an unexpected group" \
                    "$file owner=$owner group=$group mode=$mode." \
                    "stat -Lc '%U %G %a %n' -- '$file'; getent group '$group'" \
                    "Restrict modification to the account and the expected cron administration group."
                unsafe=$((unsafe + 1))
            elif [[ "$owner" != "$cron_user" && "$owner" != "root" ]]; then
                add_result "CRON-USER-OWNER-$(printf '%03d' "$unsafe")" "scheduling" "WARN" "HIGH" "HIGH" \
                    "User crontab has unexpected ownership" \
                    "$file expected_user=$cron_user owner=$owner group=$group mode=$mode." \
                    "stat -Lc '%U %G %a %n' -- '$file'" \
                    "Restore ownership to the corresponding account or root according to the local cron implementation."
                unsafe=$((unsafe + 1))
            fi

            if [[ "$cron_user" == "root" ]]; then
                while IFS= read -r lines; do
                    [[ -n "$lines" ]] || continue
                    [[ "$lines" =~ ^[[:space:]]*# ]] && continue
                    [[ "$lines" =~ ^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*= ]] && continue
                    if [[ "$lines" =~ ^[[:space:]]*@ ]]; then
                        command="$(cut -d' ' -f2- <<< "$lines")"
                    else
                        command="$(awk '{$1=$2=$3=$4=$5=""; sub(/^[[:space:]]+/, ""); print}' <<< "$lines")"
                    fi
                    while IFS= read -r path; do
                        case "$path" in
                            /usr/local/*|/opt/*|/root/*|/home/*|/var/www/*|/srv/*)
                                audit_root_executed_path "$path" "$file" "root"
                                ;;
                        esac
                    done < <(printf '%s\n' "$command" | extract_absolute_paths)
                done < "$file"
            fi
        done < <(find /var/spool/cron/crontabs -maxdepth 1 -type f 2>/dev/null)
    fi

    if (( unsafe == 0 )); then
        add_result "CRON-PERM-SUM" "scheduling" "PASS" "INFO" "HIGH" \
            "No unsafe cron file permission was found" \
            "$cron_files system cron files and $user_cron_files user crontabs were checked." \
            "stat -Lc '%U %G %a %n' /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* 2>/dev/null" \
            "No action required."
    fi

    local timer_count cron_entry_count at_count
    timer_count="$(systemctl list-timers --all --no-legend --plain 2>/dev/null | sed '/^[[:space:]]*$/d' | wc -l | tr -d ' ')"
    cron_entry_count="$(grep -RhsEv '^[[:space:]]*(#|$|[A-Za-z_][A-Za-z0-9_]*=)' /etc/crontab /etc/cron.d 2>/dev/null | wc -l | tr -d ' ')"
    at_count="$(atq 2>/dev/null | wc -l | tr -d ' ' || true)"
    add_result "SCHED-INVENTORY-001" "scheduling" "INFO" "INFO" "MEDIUM" \
        "Scheduled task inventory" \
        "systemd_timers=$timer_count; system_cron_entries=$cron_entry_count; user_crontabs=$user_cron_files; queued_at_jobs=${at_count:-0}." \
        "systemctl list-timers --all; grep -Rhv '^[[:space:]]*#' /etc/crontab /etc/cron.d; atq" \
        "Review unexpected custom jobs and ensure their scripts have controlled ownership and permissions."
}

report_nginx_warnings_v100() {
    local output="$1"
    local nginx_duplicate nginx_stapling nginx_other_warnings
    nginx_duplicate="$(grep -Ei '\[warn\].*duplicate (network|value|listen|server name)' <<< "$output" | head -n 12 || true)"
    nginx_stapling="$(grep -Ei '\[warn\].*ssl_stapling.*ignored.*OCSP responder' <<< "$output" | head -n 12 || true)"
    nginx_other_warnings="$(grep -Ei '\[warn\]' <<< "$output" | grep -Evi 'duplicate (network|value|listen|server name)|ssl_stapling.*ignored.*OCSP responder' | head -n 12 || true)"
    if [[ -n "$nginx_duplicate" ]]; then
        add_result "WEB-NGINX-WARN-001" "web" "WARN" "LOW" "HIGH" \
            "Nginx reported duplicate configuration entries" "$nginx_duplicate" "nginx -t" \
            "Remove or consolidate duplicate entries after confirming which generated or maintained file owns them."
    fi
    if [[ -n "$nginx_stapling" ]]; then
        add_result "WEB-NGINX-INFO-001" "web" "INFO" "INFO" "HIGH" \
            "Nginx ignored OCSP stapling for certificates without an OCSP responder" "$nginx_stapling" "nginx -t" \
            "This is commonly informational for certificates without an OCSP URL; remove obsolete ssl_stapling directives if they only create noise."
    fi
    if [[ -n "$nginx_other_warnings" ]]; then
        add_result "WEB-NGINX-WARN-002" "web" "WARN" "LOW" "HIGH" \
            "Nginx configuration test completed with additional warnings" "$nginx_other_warnings" "nginx -t" \
            "Review each warning before the next reload; warnings do not invalidate the successful syntax test."
    fi
}

filter_deleted_open_lsof_v100() {
    awk 'NR>1 && $5=="REG" && $4!="mem" && $0 !~ /\/memfd:| memfd:|\/SYSV|[[:space:]]\/dev\/zero([[:space:]]|$)/ {print}'
}

check_service_configuration() {
    local output detected=()

    if have nginx || systemctl list-unit-files 2>/dev/null | grep -q '^nginx\.service'; then
        detected+=(nginx)
        if have nginx; then
            local nginx_rc
            output="$(capture_potentially_networked 30 nginx -t)"
            nginx_rc=$?
            if (( nginx_rc == 0 )); then
                local nginx_success
                nginx_success="$(grep -E 'syntax is ok|test is successful' <<< "$output" | tail -n 2 || true)"
                add_result "WEB-NGINX-001" "web" "PASS" "INFO" "HIGH" \
                    "Nginx configuration syntax is valid" \
                    "${nginx_success:-nginx -t completed successfully.}" \
                    "nginx -t" "No action required for syntax validation."
                report_nginx_warnings_v100 "$output"
            elif (( nginx_rc == 125 )); then
                add_result "WEB-NGINX-001" "web" "SKIP" "INFO" "HIGH" \
                    "Nginx configuration validation was not run offline" \
                    "A network namespace could not be created, and --online was not supplied." \
                    "sudo unshare -n -- nginx -t; or rerun this audit with --online" \
                    "Run nginx -t manually or permit the optional online mode after reviewing the configuration."
            elif grep -Eqi 'host not found|temporary failure in name resolution|name or service not known' <<< "$output" && (( ! ONLINE )); then
                local nginx_dns_evidence
                nginx_dns_evidence="$(grep -Ei 'host not found|temporary failure in name resolution|name or service not known' <<< "$output" | tail -n 4 || true)"
                add_result "WEB-NGINX-001" "web" "SKIP" "INFO" "HIGH" \
                    "Offline Nginx syntax validation was limited by name resolution" \
                    "${nginx_dns_evidence:-A configured upstream requires DNS resolution that is intentionally unavailable in offline mode.}" \
                    "nginx -t; or rerun this audit with --online" \
                    "Use --online or run nginx -t manually when DNS-resolved upstreams must be validated."
                report_nginx_warnings_v100 "$output"
            else
                add_result "WEB-NGINX-001" "web" "FAIL" "HIGH" "HIGH" \
                    "Nginx configuration validation failed" "$output" "nginx -t" \
                    "Correct the configuration before reloading Nginx."
            fi
        else
            add_result "WEB-NGINX-001" "web" "SKIP" "INFO" "MEDIUM" \
                "Nginx configuration could not be validated" "An Nginx unit was detected but nginx is not in PATH." \
                "command -v nginx; systemctl status nginx" "Run nginx -t using the installed binary path."
        fi
    fi

    if have apache2ctl || have apachectl || systemctl list-unit-files 2>/dev/null | grep -q '^apache2\.service'; then
        detected+=(apache)
        local apache_bin
        apache_bin="$(command -v apache2ctl 2>/dev/null || command -v apachectl 2>/dev/null || true)"
        if [[ -n "$apache_bin" ]]; then
            local apache_rc
            output="$(capture_potentially_networked 30 "$apache_bin" configtest)"
            apache_rc=$?
            if (( apache_rc == 0 )); then
                add_result "WEB-APACHE-001" "web" "PASS" "INFO" "HIGH" \
                    "Apache configuration syntax is valid" "$output" "$apache_bin configtest" "No action required."
            elif (( apache_rc == 125 )); then
                add_result "WEB-APACHE-001" "web" "SKIP" "INFO" "HIGH" \
                    "Apache configuration validation was not run offline" \
                    "A network namespace could not be created, and --online was not supplied." \
                    "sudo unshare -n -- '$apache_bin' configtest; or rerun this audit with --online" \
                    "Run the config test manually or permit the optional online mode after reviewing the configuration."
            elif grep -Eqi 'could not resolve|name or service not known|temporary failure in name resolution' <<< "$output" && (( ! ONLINE )); then
                add_result "WEB-APACHE-001" "web" "WARN" "LOW" "MEDIUM" \
                    "Offline Apache validation was blocked by name resolution" "$output" "$apache_bin configtest" \
                    "Re-run with --online or validate manually; this result is not treated as a confirmed syntax failure."
            else
                add_result "WEB-APACHE-001" "web" "FAIL" "HIGH" "HIGH" \
                    "Apache configuration validation failed" "$output" "$apache_bin configtest" \
                    "Correct the configuration before reloading Apache."
            fi
        fi
    fi

    local unit_dump
    unit_dump="$(systemctl list-unit-files --no-legend --plain 2>/dev/null || true)"
    grep -Eq '^(mariadb|mysql)\.service' <<< "$unit_dump" && detected+=(mariadb/mysql)
    grep -Eq '^postgresql(@|\.)' <<< "$unit_dump" && detected+=(postgresql)
    grep -Eq '^(redis|redis-server)\.service' <<< "$unit_dump" && detected+=(redis)
    grep -Eq '^(mongod|mongodb)\.service' <<< "$unit_dump" && detected+=(mongodb)
    grep -Eq '^docker\.service' <<< "$unit_dump" && detected+=(docker)
    grep -Eq '^podman' <<< "$unit_dump" && detected+=(podman)
    grep -Eq '^certbot\.timer' <<< "$unit_dump" && detected+=(certbot)
    [[ -d /etc/letsencrypt/live ]] && detected+=(certbot)
    grep -Eq '^pm2-' <<< "$unit_dump" && detected+=(pm2)
    grep -Eq '^tor(@|\.)' <<< "$unit_dump" && detected+=(tor)
    grep -Eq '^(wg-quick@|openvpn|strongswan|tailscaled)' <<< "$unit_dump" && detected+=(vpn)
    grep -Eq '^(fail2ban|crowdsec)\.service' <<< "$unit_dump" && detected+=(intrusion-prevention)

    have pm2 && detected+=(pm2-cli)
    have borg && detected+=(borg)
    have restic && detected+=(restic)
    have rsnapshot && detected+=(rsnapshot)
    have rclone && detected+=(rclone)
    have duplicity && detected+=(duplicity)

    local unique_detected
    unique_detected="$(printf '%s\n' "${detected[@]:-}" | sed '/^$/d' | awk '!seen[$0]++' | paste -sd, -)"
    add_result "APP-DETECT-001" "applications" "INFO" "INFO" "MEDIUM" \
        "Detected server components" \
        "${unique_detected:-No selected component was detected through unit names or commands.}" \
        "systemctl list-unit-files; command -v nginx apache2ctl mariadb psql redis-server docker podman certbot pm2 tor wg borg restic rclone" \
        "Component-specific modules validate local configuration, service execution, network exposure, web/TLS topology, databases, caches and containers where supported."
}

web_register_name() {
    local name="${1,,}" tls="${2:-0}"
    name="${name%.}"
    [[ -n "$name" ]] || return 0
    case "$name" in
        _|localhost|localhost.localdomain|default|*.local|*.localhost|\$*|~*|*'/'*|*':'*) return 0 ;;
    esac
    [[ "$name" == \*.* ]] && return 0
    [[ "$name" =~ ^[a-z0-9][a-z0-9.-]*[a-z0-9]$ ]] || return 0
    if [[ -z "${WEB_NAME_SEEN[$name]+x}" ]]; then
        WEB_NAME_SEEN["$name"]=1
        WEB_PUBLIC_NAMES+=("$name")
    fi
    if (( tls )) && [[ -z "${WEB_TLS_NAME_SEEN[$name]+x}" ]]; then
        WEB_TLS_NAME_SEEN["$name"]=1
        WEB_TLS_NAMES+=("$name")
    fi
}

nginx_build_vhost_inventory() {
    local dump_file="$1" output_file="$2"
    awk '
        function strip(v) {
            sub(/[[:space:]]+#.*$/, "", v)
            sub(/^[[:space:]]+/, "", v)
            sub(/[[:space:]]+$/, "", v)
            sub(/;[[:space:]]*$/, "", v)
            return v
        }
        function append_unique(list, value, sep, count, parts, i) {
            if (value == "") return list
            count=split(list, parts, sep)
            for (i=1; i<=count; i++) if (parts[i] == value) return list
            return list (list ? sep : "") value
        }
        function braces(v, c, o, x) {
            x=v; o=gsub(/\{/, "{", x); x=v; c=gsub(/\}/, "}", x); return o-c
        }
        /^# configuration file / {
            file=$4
            sub(/:$/, "", file)
        }
        {
            line=$0
            if (!inside && line ~ /^[[:space:]]*server[[:space:]]*\{/) {
                inside=1; depth=0; names=""; listens=""; certs=""; access=""; errors=""; proxies=""; blockfile=file
            }
            if (inside) {
                depth += braces(line)
                if (line ~ /^[[:space:]]*server_name[[:space:]]+/) {
                    v=line; sub(/^[[:space:]]*server_name[[:space:]]+/, "", v); v=strip(v); names=append_unique(names, v, " ")
                } else if (line ~ /^[[:space:]]*listen[[:space:]]+/) {
                    v=line; sub(/^[[:space:]]*listen[[:space:]]+/, "", v); v=strip(v); listens=append_unique(listens, v, ",")
                } else if (line ~ /^[[:space:]]*ssl_certificate[[:space:]]+/ && line !~ /^[[:space:]]*ssl_certificate_key/) {
                    v=line; sub(/^[[:space:]]*ssl_certificate[[:space:]]+/, "", v); v=strip(v); certs=append_unique(certs, v, ",")
                } else if (line ~ /^[[:space:]]*access_log[[:space:]]+/) {
                    v=line; sub(/^[[:space:]]*access_log[[:space:]]+/, "", v); v=strip(v); access=append_unique(access, v, ",")
                } else if (line ~ /^[[:space:]]*error_log[[:space:]]+/) {
                    v=line; sub(/^[[:space:]]*error_log[[:space:]]+/, "", v); v=strip(v); errors=append_unique(errors, v, ",")
                } else if (line ~ /^[[:space:]]*proxy_pass[[:space:]]+/) {
                    v=line; sub(/^[[:space:]]*proxy_pass[[:space:]]+/, "", v); v=strip(v); proxies=append_unique(proxies, v, ",")
                }
                if (depth == 0) {
                    gsub(/\|/, "_", names); gsub(/\|/, "_", listens); gsub(/\|/, "_", certs); gsub(/\|/, "_", access); gsub(/\|/, "_", errors); gsub(/\|/, "_", proxies)
                    print blockfile "|" names "|" listens "|" certs "|" access "|" errors "|" proxies
                    inside=0
                }
            }
        }
    ' "$dump_file" > "$output_file"
}

check_nginx_topology() {
    local dump rc dump_file vhost_file count=0 tls_count=0 default_count=0 upstream_count include_count
    local file names listens certs access errors proxies name token evidence="" duplicate_names="" weak_protocols weak_ciphers protocol_lines cipher_lines
    local cert_path cert_real suffix mismatch_count=0 mapped_count=0
    local -A name_counts=() default_endpoints=()

    if ! have nginx && ! systemctl list-unit-files 2>/dev/null | grep -q '^nginx\.service'; then
        return 0
    fi
    if ! have nginx; then
        add_result "WEB-NGINX-TOPOLOGY-001" "web" "SKIP" "INFO" "MEDIUM" \
            "Nginx topology could not be collected" "An Nginx unit was detected but nginx is not in PATH." \
            "command -v nginx; nginx -T" "Run nginx -T using the installed binary path."
        return 0
    fi

    dump_file="$TMP_DIR/nginx-dump.txt"
    vhost_file="$TMP_DIR/nginx-vhosts.txt"
    dump="$(capture_potentially_networked 45 nginx -T)"; rc=$?
    if (( rc == 125 )); then
        add_result "WEB-NGINX-TOPOLOGY-001" "web" "SKIP" "INFO" "HIGH" \
            "Nginx topology collection was not run offline" \
            "A network namespace could not be created, and --online was not supplied." \
            "sudo unshare -n -- nginx -T; or rerun with --online" \
            "Run nginx -T manually when configuration includes DNS-resolved upstreams."
        return 0
    elif (( rc != 0 )) && grep -Eqi 'host not found|temporary failure in name resolution|name or service not known' <<< "$dump" && (( ! ONLINE )); then
        local nginx_topology_dns
        nginx_topology_dns="$(grep -Ei 'host not found|temporary failure in name resolution|name or service not known' <<< "$dump" | tail -n 4 || true)"
        add_result "WEB-NGINX-TOPOLOGY-001" "web" "SKIP" "INFO" "HIGH" \
            "Nginx topology collection was limited by offline name resolution" \
            "${nginx_topology_dns:-A configured upstream requires DNS resolution that is intentionally unavailable in offline mode.}" \
            "nginx -T; or rerun this audit with --online" \
            "Use --online or run nginx -T manually when DNS-resolved upstreams must be included in topology mapping."
        return 0
    elif (( rc != 0 )); then
        add_result "WEB-NGINX-TOPOLOGY-001" "web" "WARN" "MEDIUM" "MEDIUM" \
            "Nginx topology could not be collected because configuration validation failed" "$dump" "nginx -T" \
            "Correct the configuration validation problem before relying on vhost mapping."
        return 0
    fi
    printf '%s\n' "$dump" > "$dump_file"
    nginx_build_vhost_inventory "$dump_file" "$vhost_file"
    count="$(wc -l < "$vhost_file" | tr -d ' ')"
    upstream_count="$(grep -Ec '^[[:space:]]*upstream[[:space:]]+[^[:space:]]+[[:space:]]*\{' "$dump_file" || true)"
    include_count="$(grep -Ec '^[[:space:]]*include[[:space:]]+' "$dump_file" || true)"

    while IFS='|' read -r file names listens certs access errors proxies; do
        [[ -n "$file$names$listens$certs$access$errors$proxies" ]] || continue
        [[ -n "$certs" || "$listens" == *" ssl"* || "$listens" == *":443"* || "$listens" == "443"* ]] && tls_count=$((tls_count + 1))
        evidence+="file=${file:-unknown}; names=${names:-none}; listen=${listens:-inherited}; cert=${certs:-none}; access_log=${access:-inherited}; error_log=${errors:-inherited}; proxy=${proxies:-none}; "
        for name in $names; do
            name="${name%;}"
            [[ -n "$name" ]] || continue
            name_counts["$name"]=$(( ${name_counts[$name]:-0} + 1 ))
            if [[ -n "$certs" || "$listens" == *" ssl"* || "$listens" == *":443"* || "$listens" == "443"* ]]; then
                web_register_name "$name" 1
            else
                web_register_name "$name" 0
            fi
        done
        if [[ "$listens" == *default_server* ]]; then
            default_count=$((default_count + 1))
            IFS=',' read -ra _listen_tokens <<< "$listens"
            for token in "${_listen_tokens[@]}"; do
                [[ "$token" == *default_server* ]] || continue
                token="${token%% default_server*}"; token="${token%% ssl*}"; token="$(trim "$token")"
                local default_key="${token:-default}"
                default_endpoints["$default_key"]=$(( ${default_endpoints["$default_key"]:-0} + 1 ))
            done
        fi

        if [[ -n "$certs" && -n "$names" ]] && have openssl; then
            cert_path="${certs%%,*}"; cert_path="${cert_path%% *}"
            cert_real="$(readlink -f -- "$cert_path" 2>/dev/null || printf '%s' "$cert_path")"
            if [[ -r "$cert_real" ]]; then
                mapped_count=$((mapped_count + 1))
                for name in $names; do
                    name="${name%;}"
                    case "$name" in _|localhost|\$*|~*|\**|*:*|*/*) continue ;; esac
                    if ! openssl x509 -in "$cert_real" -noout -checkhost "$name" >/dev/null 2>&1; then
                        suffix="$(stable_suffix "$file|$name|$cert_real")"
                        add_result "TLS-NGINX-MAP-$suffix" "tls" "WARN" "HIGH" "HIGH" \
                            "Nginx certificate does not match a configured server name" \
                            "server_name=$name; certificate=$cert_path; configuration=$file." \
                            "openssl x509 -in $(shell_quote "$cert_real") -noout -subject -ext subjectAltName -checkhost $(shell_quote "$name")" \
                            "Deploy a certificate covering the configured name or correct the vhost certificate mapping."
                        mismatch_count=$((mismatch_count + 1))
                    fi
                done
            fi
        fi
    done < "$vhost_file"

    for name in "${!name_counts[@]}"; do
        (( name_counts[$name] > 1 )) && duplicate_names+="$name:${name_counts[$name]},"
    done
    duplicate_names="${duplicate_names%,}"
    add_result "WEB-NGINX-TOPOLOGY-001" "web" "INFO" "INFO" "HIGH" \
        "Nginx virtual host and upstream inventory" \
        "server_blocks=${count:-0}; tls_server_blocks=$tls_count; default_servers=$default_count; upstream_blocks=$upstream_count; include_directives=$include_count; vhosts=$evidence" \
        "nginx -T" \
        "Review server names, default routing, upstream targets and per-vhost log destinations against the intended deployment."

    if [[ -n "$duplicate_names" ]]; then
        add_result "WEB-NGINX-NAMES-001" "web" "INFO" "INFO" "MEDIUM" \
            "Some Nginx server names appear in multiple server blocks" \
            "name_occurrences=$duplicate_names. Separate HTTP and HTTPS blocks may be intentional." \
            "nginx -T | grep -n 'server_name'" \
            "Confirm duplicates are intentional and do not create ambiguous routing."
    fi

    local endpoint
    for endpoint in "${!default_endpoints[@]}"; do
        if (( default_endpoints[$endpoint] > 1 )); then
            add_result "WEB-NGINX-DEFAULT-$(stable_suffix "$endpoint")" "web" "WARN" "MEDIUM" "HIGH" \
                "Multiple Nginx default servers target the same listener" \
                "listener=$endpoint; default_server_occurrences=${default_endpoints[$endpoint]}." \
                "nginx -T | grep -n 'listen.*default_server'" \
                "Keep one intentional default server per address and port."
        fi
    done

    protocol_lines="$(grep -E '^[[:space:]]*ssl_protocols[[:space:]]+' "$dump_file" | sed -E 's/[[:space:]]+#.*$//; s/^[[:space:]]*//; s/[[:space:]]*;[[:space:]]*$//' | sort -u | paste -sd'; ' - || true)"
    weak_protocols="$(grep -E '^[[:space:]]*ssl_protocols[[:space:]]+' "$dump_file" | grep -E '(^|[[:space:]])(SSLv2|SSLv3|TLSv1|TLSv1\.1)([[:space:];]|$)' || true)"
    if [[ -n "$weak_protocols" ]]; then
        add_result "TLS-NGINX-PROTOCOL-001" "tls" "WARN" "HIGH" "HIGH" \
            "Nginx enables obsolete TLS protocol versions" "$weak_protocols" \
            "nginx -T | grep -n 'ssl_protocols'" \
            "Disable SSLv2, SSLv3, TLS 1.0 and TLS 1.1 unless a documented legacy dependency requires them."
    elif [[ -n "$protocol_lines" ]]; then
        add_result "TLS-NGINX-PROTOCOL-001" "tls" "PASS" "INFO" "HIGH" \
            "Nginx TLS protocol configuration excludes obsolete versions" "$protocol_lines" \
            "nginx -T | grep -n 'ssl_protocols'" "No action required."
    else
        add_result "TLS-NGINX-PROTOCOL-001" "tls" "INFO" "INFO" "MEDIUM" \
            "No explicit Nginx ssl_protocols directive was found" \
            "The effective protocol set depends on the installed Nginx and OpenSSL defaults." \
            "nginx -V; nginx -T | grep -n 'ssl_protocols'" \
            "Document the effective defaults or configure an explicit modern protocol policy."
    fi

    cipher_lines="$(grep -E '^[[:space:]]*ssl_ciphers[[:space:]]+' "$dump_file" | sed -E 's/[[:space:]]+#.*$//; s/^[[:space:]]*//; s/[[:space:]]*;[[:space:]]*$//' | sort -u | paste -sd'; ' - || true)"
    weak_ciphers="$(awk '''
        /^[[:space:]]*ssl_ciphers[[:space:]]+/ {
            original=$0
            sub(/^[[:space:]]*ssl_ciphers[[:space:]]+/, "")
            sub(/;[[:space:]]*$/, "")
            count=split($0, parts, /[:[:space:]]+/)
            for (i=1; i<=count; i++) {
                token=parts[i]
                upper=toupper(token)
                if (token ~ /^[!-]/) continue
                if (upper ~ /^(ANULL|ENULL|EXPORT|NULL|RC4|DES|3DES|MD5)$/ || upper ~ /DES-CBC3/) {
                    print original
                    break
                }
            }
        }
    ''' "$dump_file" || true)"
    if [[ -n "$weak_ciphers" ]]; then
        add_result "TLS-NGINX-CIPHER-001" "tls" "WARN" "MEDIUM" "HIGH" \
            "Nginx cipher configuration contains weak or anonymous cipher tokens" "$weak_ciphers" \
            "nginx -T | grep -n 'ssl_ciphers'" \
            "Remove anonymous, null, export, RC4, DES, 3DES and MD5-based cipher suites."
    else
        add_result "TLS-NGINX-CIPHER-001" "tls" "INFO" "INFO" "MEDIUM" \
            "Nginx cipher configuration inventory" "${cipher_lines:-No explicit ssl_ciphers directive was found.}" \
            "nginx -T | grep -n 'ssl_ciphers'" \
            "Use an explicit cipher policy only when required; TLS 1.3 ciphers are not controlled by ssl_ciphers."
    fi

    if (( mismatch_count == 0 && mapped_count > 0 )); then
        add_result "TLS-NGINX-MAP-SUMMARY" "tls" "PASS" "INFO" "HIGH" \
            "Readable Nginx certificates match configured server names" \
            "mapped_certificate_blocks=$mapped_count; mismatches=0." \
            "nginx -T; openssl x509 -in CERT -noout -checkhost NAME" \
            "No action required."
    fi
}

check_apache_topology() {
    local bin vhosts modules rc vhost_count ssl_module status_module autoindex_module protocol_lines
    bin="$(command -v apache2ctl 2>/dev/null || command -v apachectl 2>/dev/null || true)"
    [[ -n "$bin" ]] || return 0
    vhosts="$(capture_potentially_networked 30 "$bin" -S)"; rc=$?
    if (( rc == 0 )); then
        vhost_count="$(grep -Ec 'namevhost|port [0-9]+ namevhost|default server' <<< "$vhosts" || true)"
        add_result "WEB-APACHE-TOPOLOGY-001" "web" "INFO" "INFO" "HIGH" \
            "Apache virtual host inventory" \
            "vhost_lines=$vhost_count; $(shorten "$vhosts" 1400)" \
            "$bin -S" \
            "Review default vhosts, names, addresses and configuration file ownership."
    elif (( rc == 125 )); then
        add_result "WEB-APACHE-TOPOLOGY-001" "web" "SKIP" "INFO" "HIGH" \
            "Apache virtual host inventory was not run offline" \
            "A network namespace could not be created, and --online was not supplied." \
            "sudo unshare -n -- $bin -S" \
            "Run the command manually or use --online after reviewing DNS-dependent directives."
    else
        add_result "WEB-APACHE-TOPOLOGY-001" "web" "WARN" "MEDIUM" "MEDIUM" \
            "Apache virtual host inventory failed" "$vhosts" "$bin -S" \
            "Resolve the configuration issue before relying on virtual host routing."
    fi

    modules="$(capture 20 "$bin" -M)"
    ssl_module=0; status_module=0; autoindex_module=0
    grep -q 'ssl_module' <<< "$modules" && ssl_module=1
    grep -q 'status_module' <<< "$modules" && status_module=1
    grep -q 'autoindex_module' <<< "$modules" && autoindex_module=1
    add_result "WEB-APACHE-MODULES-001" "web" "INFO" "INFO" "HIGH" \
        "Apache module inventory" \
        "ssl_module=$ssl_module; status_module=$status_module; autoindex_module=$autoindex_module; loaded_modules=$(grep -c '_module' <<< "$modules" || true)." \
        "$bin -M" \
        "Confirm status and directory-index features are restricted to intended locations."

    protocol_lines="$(grep -RhsE '^[[:space:]]*SSLProtocol[[:space:]]+' /etc/apache2 2>/dev/null | sed 's/^[[:space:]]*//' | sort -u | paste -sd';' - || true)"
    if grep -Eqi '(^|[[:space:]])\+?(SSLv2|SSLv3|TLSv1|TLSv1\.1)([[:space:]]|$)' <<< "$protocol_lines"; then
        add_result "TLS-APACHE-PROTOCOL-001" "tls" "WARN" "HIGH" "MEDIUM" \
            "Apache TLS configuration may enable obsolete protocol versions" "$protocol_lines" \
            "grep -Rni '^[[:space:]]*SSLProtocol' /etc/apache2" \
            "Use a modern protocol policy and verify the effective mod_ssl configuration."
    elif (( ssl_module )); then
        add_result "TLS-APACHE-PROTOCOL-001" "tls" "INFO" "INFO" "MEDIUM" \
            "Apache TLS protocol configuration inventory" "${protocol_lines:-No explicit SSLProtocol directive was found.}" \
            "grep -Rni '^[[:space:]]*SSLProtocol' /etc/apache2" \
            "Confirm the effective protocol defaults are documented and modern."
    fi
}

php_fpm_value() {
    local file="$1" key="$2"
    awk -F= -v key="$key" '
        /^[[:space:]]*[;#]/ {next}
        {
            lhs=$1; gsub(/^[[:space:]]+|[[:space:]]+$/, "", lhs)
            if (lhs==key) {
                sub(/^[^=]*=/, ""); sub(/[[:space:]]*[;#].*$/, ""); gsub(/^[[:space:]]+|[[:space:]]+$/, ""); value=$0
            }
        }
        END {print value}
    ' "$file" 2>/dev/null
}

check_php_fpm() {
    local pool file pool_name user group listen listen_owner listen_group listen_mode clear_env limit_extensions status_path evidence=""
    local count=0 public_count=0 root_count=0 weak_socket_count=0 binary output rc suffix runtime_mode runtime_owner runtime_group
    local -a pools=()
    while IFS= read -r file; do pools+=("$file"); done < <(find /etc/php -path '*/fpm/pool.d/*.conf' -type f 2>/dev/null | sort)
    (( ${#pools[@]} > 0 )) || return 0

    for file in "${pools[@]}"; do
        pool_name="$(awk '/^[[:space:]]*\[[^]]+\][[:space:]]*$/ {gsub(/^[[:space:]]*\[|\][[:space:]]*$/, ""); print; exit}' "$file" 2>/dev/null)"
        user="$(php_fpm_value "$file" user)"; group="$(php_fpm_value "$file" group)"
        listen="$(php_fpm_value "$file" listen)"; listen_owner="$(php_fpm_value "$file" listen.owner)"
        listen_group="$(php_fpm_value "$file" listen.group)"; listen_mode="$(php_fpm_value "$file" listen.mode)"
        clear_env="$(php_fpm_value "$file" clear_env)"; limit_extensions="$(php_fpm_value "$file" security.limit_extensions)"
        status_path="$(php_fpm_value "$file" pm.status_path)"
        evidence+="pool=${pool_name:-unknown}; file=$file; user=${user:-unset}; group=${group:-unset}; listen=${listen:-unset}; socket_owner=${listen_owner:-default}; socket_group=${listen_group:-default}; socket_mode=${listen_mode:-default}; clear_env=${clear_env:-default}; limit_extensions=${limit_extensions:-default}; status_path=${status_path:-none}; "
        count=$((count + 1))
        suffix="$(stable_suffix "$file|${pool_name:-pool}")"

        if [[ "$user" == "root" ]]; then
            add_result "PHP-FPM-ROOT-$suffix" "web" "FAIL" "HIGH" "HIGH" \
                "PHP-FPM pool runs as root" "pool=${pool_name:-unknown}; file=$file; user=root." \
                "grep -nE '^[[:space:]]*(user|group)[[:space:]]*=' $(shell_quote "$file")" \
                "Run the pool under a dedicated unprivileged service account."
            root_count=$((root_count + 1))
        fi

        if [[ "$listen" =~ ^(0\.0\.0\.0|\[?::\]?|\*):?[0-9]+$ || "$listen" =~ ^[0-9]+$ ]]; then
            add_result "PHP-FPM-PUBLIC-$suffix" "web" "FAIL" "HIGH" "HIGH" \
                "PHP-FPM pool may listen on all network interfaces" \
                "pool=${pool_name:-unknown}; file=$file; listen=$listen. FastCGI is not an HTTP service." \
                "grep -n '^[[:space:]]*listen[[:space:]]*=' $(shell_quote "$file"); ss -lntp" \
                "Bind PHP-FPM to a Unix socket or loopback/private address protected from untrusted clients."
            public_count=$((public_count + 1))
        elif [[ "$listen" == /* && -S "$listen" ]]; then
            IFS='|' read -r runtime_owner runtime_group runtime_mode < <(stat -Lc '%U|%G|%a' -- "$listen" 2>/dev/null || printf '||')
            if is_world_writable "$runtime_mode"; then
                add_result "PHP-FPM-SOCKET-$suffix" "web" "WARN" "HIGH" "HIGH" \
                    "PHP-FPM socket is writable by all local users" \
                    "pool=${pool_name:-unknown}; socket=$listen; owner=$runtime_owner group=$runtime_group mode=$runtime_mode." \
                    "stat -Lc '%U %G %a %n' -- $(shell_quote "$listen")" \
                    "Restrict socket access to the web server identity and trusted administrators."
                weak_socket_count=$((weak_socket_count + 1))
            fi
        elif [[ "$listen_mode" =~ ^0?[0-7]{3}$ ]] && is_world_writable "$listen_mode"; then
            add_result "PHP-FPM-SOCKET-$suffix" "web" "WARN" "HIGH" "HIGH" \
                "PHP-FPM configured socket mode permits world write access" \
                "pool=${pool_name:-unknown}; file=$file; listen=$listen; listen.mode=$listen_mode." \
                "grep -nE '^[[:space:]]*listen\.(owner|group|mode)[[:space:]]*=' $(shell_quote "$file")" \
                "Restrict socket mode to the web server identity and trusted administrators."
            weak_socket_count=$((weak_socket_count + 1))
        fi

        if [[ "${clear_env,,}" == "no" ]]; then
            add_result "PHP-FPM-ENV-$suffix" "web" "INFO" "INFO" "MEDIUM" \
                "PHP-FPM pool inherits process environment variables" \
                "pool=${pool_name:-unknown}; file=$file; clear_env=no; environment values were not read." \
                "grep -n '^[[:space:]]*clear_env[[:space:]]*=' $(shell_quote "$file")" \
                "Confirm inherited variables are required and do not expose unrelated service secrets."
        fi
    done

    add_result "PHP-FPM-POOLS-001" "web" "INFO" "INFO" "HIGH" \
        "PHP-FPM pool inventory" \
        "pool_count=$count; public_or_wildcard_listeners=$public_count; root_pools=$root_count; weak_sockets=$weak_socket_count; pools=$evidence" \
        "find /etc/php -path '*/fpm/pool.d/*.conf' -type f -print; ss -lntxp" \
        "Confirm pool identities, socket permissions and status endpoints match each virtual host."

    binary="$(find /usr/sbin -maxdepth 1 -type f -name 'php-fpm*' -perm -111 2>/dev/null | sort -V | tail -n 1)"
    if [[ -n "$binary" ]]; then
        output="$(capture 30 "$binary" -t)"; rc=$?
        if (( rc == 0 )); then
            add_result "PHP-FPM-CONFIG-001" "web" "PASS" "INFO" "HIGH" \
                "PHP-FPM configuration syntax is valid" "$output" "$binary -t" "No action required."
        else
            add_result "PHP-FPM-CONFIG-001" "web" "FAIL" "HIGH" "HIGH" \
                "PHP-FPM configuration validation failed" "$output" "$binary -t" \
                "Correct the pool or global configuration before restarting PHP-FPM."
        fi
    fi
}

check_certbot_renewal() {
    local timer_enabled timer_active cron_present=0 renewal_count hook_count=0 unsafe_hooks=0 file owner group mode log_file log_age error_lines=""
    local missing_refs=0 cert_path key_path config suffix now
    [[ -d /etc/letsencrypt ]] || have certbot || return 0

    timer_enabled="$(systemctl is-enabled certbot.timer 2>/dev/null || true)"
    timer_active="$(systemctl is-active certbot.timer 2>/dev/null || true)"
    grep -RqsE '(^|[[:space:]])certbot([[:space:]]|$).*renew' /etc/cron.d /etc/crontab /var/spool/cron/crontabs 2>/dev/null && cron_present=1
    renewal_count="$(find /etc/letsencrypt/renewal -maxdepth 1 -type f -name '*.conf' 2>/dev/null | wc -l | tr -d ' ')"
    if [[ "$timer_enabled" == "enabled" || "$timer_active" == "active" || $cron_present -eq 1 ]]; then
        add_result "TLS-CERTBOT-SCHEDULE-001" "tls" "PASS" "INFO" "HIGH" \
            "Certbot renewal scheduling was detected" \
            "timer_enabled=${timer_enabled:-unknown}; timer_active=${timer_active:-unknown}; cron_renew=$cron_present; renewal_configs=${renewal_count:-0}." \
            "systemctl status certbot.timer; grep -Rni 'certbot.*renew' /etc/cron* /var/spool/cron/crontabs" \
            "No action required after confirming recent renewal results and deploy hooks."
    else
        add_result "TLS-CERTBOT-SCHEDULE-001" "tls" "WARN" "MEDIUM" "HIGH" \
            "No Certbot renewal schedule was confirmed" \
            "timer_enabled=${timer_enabled:-unknown}; timer_active=${timer_active:-unknown}; cron_renew=$cron_present; renewal_configs=${renewal_count:-0}." \
            "systemctl status certbot.timer; grep -Rni 'certbot.*renew' /etc/cron* /var/spool/cron/crontabs" \
            "Enable a tested renewal timer or cron job when Certbot manages active certificates."
    fi

    while IFS= read -r config; do
        [[ -r "$config" ]] || continue
        cert_path="$(awk -F= '/^[[:space:]]*cert[[:space:]]*=/{gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); print $2; exit}' "$config")"
        key_path="$(awk -F= '/^[[:space:]]*privkey[[:space:]]*=/{gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); print $2; exit}' "$config")"
        if [[ -n "$cert_path" && ! -e "$cert_path" ]] || [[ -n "$key_path" && ! -e "$key_path" ]]; then
            suffix="$(stable_suffix "$config|missing-reference")"
            add_result "TLS-CERTBOT-REF-$suffix" "tls" "WARN" "MEDIUM" "HIGH" \
                "Certbot renewal configuration references a missing file" \
                "renewal_config=$config; cert=${cert_path:-unset}; privkey=${key_path:-unset}." \
                "grep -nE '^(cert|privkey)[[:space:]]*=' $(shell_quote "$config"); stat -- $(shell_quote "${cert_path:-/nonexistent}") $(shell_quote "${key_path:-/nonexistent}")" \
                "Remove stale renewal configurations or restore the referenced certificate material."
            missing_refs=$((missing_refs + 1))
        fi
    done < <(find /etc/letsencrypt/renewal -maxdepth 1 -type f -name '*.conf' 2>/dev/null)

    while IFS= read -r file; do
        [[ -f "$file" ]] || continue
        hook_count=$((hook_count + 1))
        IFS='|' read -r owner group mode < <(stat -Lc '%U|%G|%a' -- "$file" 2>/dev/null || printf '||')
        if is_world_writable "$mode" || { is_group_or_world_writable "$mode" && [[ "$group" != "root" ]]; }; then
            suffix="$(stable_suffix "$file|hook-permission")"
            add_result "TLS-CERTBOT-HOOK-$suffix" "tls" "FAIL" "HIGH" "HIGH" \
                "Certbot renewal hook is writable by an untrusted identity" \
                "hook=$file; owner=$owner group=$group mode=$mode." \
                "stat -Lc '%U %G %a %n' -- $(shell_quote "$file")" \
                "Restrict modification to root or a tightly controlled administrative group."
            unsafe_hooks=$((unsafe_hooks + 1))
        elif [[ "$owner" != "root" ]]; then
            suffix="$(stable_suffix "$file|hook-owner")"
            add_result "TLS-CERTBOT-HOOK-$suffix" "tls" "WARN" "HIGH" "HIGH" \
                "Certbot renewal hook is not owned by root" \
                "hook=$file; owner=$owner group=$group mode=$mode." \
                "stat -Lc '%U %G %a %n' -- $(shell_quote "$file")" \
                "Confirm the hook owner cannot be modified through a lower-privileged service."
            unsafe_hooks=$((unsafe_hooks + 1))
        fi
    done < <(find /etc/letsencrypt/renewal-hooks -type f 2>/dev/null)
    add_result "TLS-CERTBOT-HOOKS-001" "tls" "INFO" "INFO" "HIGH" \
        "Certbot renewal hook inventory" \
        "hook_files=$hook_count; unsafe_hook_findings=$unsafe_hooks; missing_renewal_references=$missing_refs; hook contents were not executed." \
        "find /etc/letsencrypt/renewal-hooks -type f -exec stat -c '%U %G %a %n' {} +" \
        "Review deploy hooks for least privilege and reliable web-service reload behavior."

    log_file="/var/log/letsencrypt/letsencrypt.log"
    if [[ -r "$log_file" ]]; then
        now="$(date +%s)"; log_age=$(( (now - $(stat -c %Y "$log_file" 2>/dev/null || printf 0)) / 86400 ))
        error_lines="$(tail -n 800 "$log_file" 2>/dev/null | grep -Ei '(^|[^a-z])(error|failed|failure|unauthorized|invalid response)([^a-z]|$)' | tail -n 8 || true)"
        if [[ -n "$error_lines" && $log_age -le 14 ]]; then
            add_result "TLS-CERTBOT-LOG-001" "tls" "WARN" "MEDIUM" "MEDIUM" \
                "Recent Certbot log contains failure indicators" \
                "log_age_days=$log_age; lines=$error_lines" \
                "tail -n 800 /var/log/letsencrypt/letsencrypt.log" \
                "Confirm whether the most recent renewal attempt succeeded and correct unresolved validation or deployment errors."
        else
            add_result "TLS-CERTBOT-LOG-001" "tls" "INFO" "INFO" "MEDIUM" \
                "Certbot renewal log inventory" \
                "log_age_days=$log_age; recent_failure_indicators=$([[ -n "$error_lines" ]] && printf present-but-old || printf none)." \
                "tail -n 200 /var/log/letsencrypt/letsencrypt.log" \
                "Review the most recent renewal result periodically."
        fi
    fi
}

check_pm2() {
    local home user dump count=0 app_count=0 invalid=0 missing_exec=0 startup_units active_daemons logrotate_detected=0 large_logs="" file mode owner group suffix exec_path app
    local -a homes=()
    [[ -d /root/.pm2 ]] && homes+=(/root/.pm2)
    while IFS= read -r home; do homes+=("$home"); done < <(find /home -mindepth 2 -maxdepth 2 -type d -name .pm2 2>/dev/null | sort)
    (( ${#homes[@]} > 0 )) || { systemctl list-unit-files 2>/dev/null | grep -q '^pm2-' || return 0; }

    startup_units="$(systemctl list-unit-files --no-legend --plain 2>/dev/null | grep '^pm2-' | head -n 20 || true)"
    active_daemons="$(ps -eo user=,pid=,args= 2>/dev/null | grep -E '[P]M2 .*God Daemon|[P]M2 v[0-9].*: God Daemon' | head -n 20 || true)"
    for home in "${homes[@]}"; do
        user="$(stat -c %U "$home" 2>/dev/null || basename "$(dirname "$home")")"
        dump="$home/dump.pm2"
        [[ -d "$home/modules/pm2-logrotate" || -d "$home/node_modules/pm2-logrotate" ]] && logrotate_detected=1
        if [[ -f "$dump" ]]; then
            count=$((count + 1))
            IFS='|' read -r owner group mode < <(stat -Lc '%U|%G|%a' -- "$dump" 2>/dev/null || printf '||')
            if is_world_writable "$mode" || { is_group_or_world_writable "$mode" && [[ "$group" != "$user" && "$group" != "root" ]]; }; then
                add_result "PM2-DUMP-PERM-$(stable_suffix "$dump")" "processes" "FAIL" "HIGH" "HIGH" \
                    "PM2 saved process list is writable by an unexpected identity" \
                    "file=$dump; owner=$owner group=$group mode=$mode." \
                    "stat -Lc '%U %G %a %n' -- $(shell_quote "$dump")" \
                    "Restrict modification to the PM2 account and trusted administrators."
            fi
            if have jq && jq -e 'type == "array"' "$dump" >/dev/null 2>&1; then
                while IFS='|' read -r app exec_path; do
                    [[ -n "$app$exec_path" ]] || continue
                    app_count=$((app_count + 1))
                    if [[ "$exec_path" == /* && ! -e "$exec_path" ]]; then
                        suffix="$(stable_suffix "$dump|$app|$exec_path")"
                        add_result "PM2-EXEC-$suffix" "processes" "WARN" "MEDIUM" "HIGH" \
                            "PM2 saved application references a missing executable or script" \
                            "user=$user; app=$app; exec=$exec_path; dump=$dump." \
                            "jq -r '.[] | [.name,.pm_exec_path] | @tsv' $(shell_quote "$dump"); stat -- $(shell_quote "$exec_path")" \
                            "Correct the saved process definition and run pm2 save through the intended account."
                        missing_exec=$((missing_exec + 1))
                    fi
                done < <(jq -r '.[] | [(.name // "unnamed"),(.pm_exec_path // .script // "")] | @tsv' "$dump" 2>/dev/null | tr '\t' '|')
            else
                add_result "PM2-DUMP-$(stable_suffix "$dump|invalid")" "processes" "WARN" "MEDIUM" "HIGH" \
                    "PM2 saved process list is not valid JSON" "file=$dump; user=$user." \
                    "jq . $(shell_quote "$dump")" \
                    "Regenerate the saved process list with pm2 save after validating the active applications."
                invalid=$((invalid + 1))
            fi
        fi
        large_logs+="$(find "$home/logs" -maxdepth 1 -type f -size +100M -printf '%s %p; ' 2>/dev/null | head -n 10)"
    done

    add_result "PM2-INVENTORY-001" "processes" "INFO" "INFO" "HIGH" \
        "PM2 process manager inventory" \
        "pm2_homes=${#homes[@]}; dump_files=$count; saved_apps=$app_count; invalid_dumps=$invalid; missing_exec=$missing_exec; startup_units=${startup_units:-none}; active_daemons=${active_daemons:-none}; logrotate_module=$logrotate_detected." \
        "find /root /home -maxdepth 3 -path '*/.pm2/dump.pm2' -print; systemctl list-unit-files 'pm2-*'; ps -ef | grep '[P]M2'" \
        "Confirm the saved list, startup unit owner, application paths and active daemon identities are consistent."

    if [[ -n "$large_logs" && $logrotate_detected -eq 0 ]]; then
        add_result "PM2-LOGROTATE-001" "processes" "WARN" "MEDIUM" "HIGH" \
            "Large PM2 logs were found without the PM2 logrotate module" "$large_logs" \
            "find /root/.pm2 /home/*/.pm2 -path '*/logs/*' -type f -size +100M -ls; find /root/.pm2 /home/*/.pm2 -path '*/pm2-logrotate' -type d" \
            "Configure PM2 log rotation or another explicit rotation policy."
    elif [[ -n "$large_logs" ]]; then
        add_result "PM2-LOGROTATE-001" "processes" "INFO" "INFO" "MEDIUM" \
            "Large PM2 logs exist and a logrotate module was detected" "$large_logs" \
            "du -h /root/.pm2/logs/* /home/*/.pm2/logs/* 2>/dev/null" \
            "Confirm the configured retention and maximum size are taking effect."
    fi
}

check_public_dev_admin() {
    local sockets line endpoint parts addr port process family iface exposure suffix found=0
    have ss || return 0
    sockets="$(ss -H -lntp 2>/dev/null || true)"
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        endpoint="$(awk '{print $4}' <<< "$line")"
        [[ "$endpoint" == *:* ]] || endpoint="$(awk '{print $5}' <<< "$line")"
        parts="$(net_endpoint_parts "$endpoint")"; addr="${parts%%|*}"; port="${parts##*|}"
        [[ "$port" =~ ^[0-9]+$ ]] || continue
        family="v4"; [[ "$addr" == *:* ]] && family="v6"
        iface=""; [[ "$addr" != "0.0.0.0" && "$addr" != "::" && "$addr" != "*" ]] && iface="$(net_find_iface_for_addr "$addr")"
        exposure="$(net_listener_exposure "$family" "$addr" "$iface")"
        [[ "$exposure" == "public" || "$exposure" == "wildcard" ]] || continue
        process="$(sed -nE 's/.*users:\(\(\"([^\"]+)\".*/\1/p' <<< "$line" | head -n 1)"
        case "$port" in
            9229|9230|5678|5005)
                suffix="$(stable_suffix "$addr|$port|debug")"
                add_result "WEB-DEBUG-$suffix" "web" "FAIL" "HIGH" "HIGH" \
                    "A common remote debugging port is publicly exposed" \
                    "listener=$addr:$port; process=${process:-unknown}; exposure=$exposure." \
                    "ss -lntp '( sport = :$port )'" \
                    "Bind the debugger to loopback or a strictly controlled management interface."
                found=$((found + 1))
                ;;
            3000|3001|4000|5000|5173|8000|8001|8080|8081|8888)
                if grep -Eqi 'node|next|vite|webpack|python|php|uvicorn|flask|rails|development' <<< "$process"; then
                    suffix="$(stable_suffix "$addr|$port|$process|dev")"
                    add_result "WEB-DEV-$suffix" "web" "WARN" "MEDIUM" "MEDIUM" \
                        "A development-style application listener is publicly exposed" \
                        "listener=$addr:$port; process=${process:-unknown}; exposure=$exposure." \
                        "ss -lntp '( sport = :$port )'; systemctl status PID" \
                        "Confirm this is a production-hardened server or place it behind the intended reverse proxy and firewall."
                    found=$((found + 1))
                fi
                ;;
            5601|9001|9090|9091|9443|10000|15672)
                suffix="$(stable_suffix "$addr|$port|admin")"
                add_result "WEB-ADMIN-$suffix" "web" "INFO" "INFO" "MEDIUM" \
                    "A common administration or observability port is publicly exposed" \
                    "listener=$addr:$port; process=${process:-unknown}; exposure=$exposure." \
                    "ss -lntp '( sport = :$port )'" \
                    "Confirm authentication, TLS and source restrictions are appropriate."
                found=$((found + 1))
                ;;
        esac
    done <<< "$sockets"
    if (( found == 0 )); then
        add_result "WEB-PUBLIC-APP-001" "web" "PASS" "INFO" "MEDIUM" \
            "No obvious public debugger or development listener was identified" \
            "Common debugger, development and administration ports were correlated with public listeners." \
            "ss -lntp" \
            "No action required; application-specific panels may use other ports."
    fi
}

online_hostname_class_v010() {
    local name="${1,,}"
    name="${name%.}"
    [[ -n "$name" ]] || { printf 'invalid'; return; }
    case "$name" in
        *.onion) printf 'onion'; return ;;
        localhost|localhost.localdomain|*.localhost|*.local|*.lan|*.internal|*.home|*.invalid) printf 'internal'; return ;;
    esac
    [[ "$name" == *.* ]] || { printf 'internal'; return; }
    [[ "$name" =~ ^[0-9]+(\.[0-9]+){3}$ ]] && { printf 'address'; return; }
    [[ "$name" =~ ^[a-z0-9][a-z0-9.-]*[a-z0-9]$ ]] || { printf 'invalid'; return; }
    printf 'clearnet'
}

online_final_headers_v010() {
    local file="$1"
    awk '
        BEGIN { IGNORECASE=1; server=""; hsts=""; csp=""; xcto=""; referrer=""; permissions=""; location="" }
        /^HTTP\// { server=""; hsts=""; csp=""; xcto=""; referrer=""; permissions=""; location=""; next }
        /^[Ss]erver:/ { sub(/^[^:]+:[[:space:]]*/, ""); sub(/\r$/, ""); server=$0; next }
        /^[Ss]trict-[Tt]ransport-[Ss]ecurity:/ { hsts="present"; next }
        /^[Cc]ontent-[Ss]ecurity-[Pp]olicy:/ { csp="present"; next }
        /^[Xx]-[Cc]ontent-[Tt]ype-[Oo]ptions:/ { xcto="present"; next }
        /^[Rr]eferrer-[Pp]olicy:/ { referrer="present"; next }
        /^[Pp]ermissions-[Pp]olicy:/ { permissions="present"; next }
        /^[Ll]ocation:/ { sub(/^[^:]+:[[:space:]]*/, ""); sub(/\r$/, ""); location=$0; next }
        END {
            printf "server=%s;hsts=%s;csp=%s;x_content_type_options=%s;referrer_policy=%s;permissions_policy=%s;location=%s", \
                (server?server:"unknown"),(hsts?hsts:"absent"),(csp?csp:"absent"),(xcto?xcto:"absent"), \
                (referrer?referrer:"absent"),(permissions?permissions:"absent"),(location?location:"none")
        }
    ' "$file"
}

check_online_web() {
    local name class scheme url result rc code cert_info cert_rc checked=0 failures=0 suffix
    local skipped_onion=0 skipped_internal=0 skipped_invalid=0 http_failures=0 tls_failures=0
    local headers header_summary targets_raw="" target
    local -a targets=()
    local -A target_seen=()
    if (( ! ONLINE )); then
        add_result "WEB-ONLINE-001" "web" "INFO" "INFO" "HIGH" \
            "Online website and certificate checks were not requested" \
            "No outbound HTTP, DNS or TLS connection was made by this module." \
            "sudo ./vpscry.sh --online" \
            "Use --online only when external clearnet verification is desired."
        return 0
    fi
    if ! have curl; then
        add_result "WEB-ONLINE-001" "web" "SKIP" "INFO" "HIGH" \
            "Online website checks require curl" "curl is unavailable." "command -v curl" \
            "Install curl or verify websites manually."
        return 0
    fi

    if [[ -n "$EXPECTED_WEBSITES_RAW" ]]; then
        targets_raw="${EXPECTED_WEBSITES_RAW//,/ }"
        for target in $targets_raw; do
            target="${target#http://}"; target="${target#https://}"; target="${target%%/*}"; target="${target%%:*}"; target="${target,,}"
            [[ -n "$target" && -z "${target_seen[$target]+x}" ]] || continue
            target_seen["$target"]=1; targets+=("$target")
        done
    else
        for target in "${WEB_PUBLIC_NAMES[@]}"; do
            target="${target,,}"
            [[ -n "$target" && -z "${target_seen[$target]+x}" ]] || continue
            target_seen["$target"]=1; targets+=("$target")
        done
    fi

    for name in "${targets[@]}"; do
        class="$(online_hostname_class_v010 "$name")"
        case "$class" in
            onion) skipped_onion=$((skipped_onion + 1)); continue ;;
            internal|address) skipped_internal=$((skipped_internal + 1)); continue ;;
            invalid) skipped_invalid=$((skipped_invalid + 1)); continue ;;
        esac
        (( checked >= 8 )) && break
        scheme="http"; [[ -n "${WEB_TLS_NAME_SEEN[$name]+x}" ]] && scheme="https"
        url="$scheme://$name/"
        suffix="$(stable_suffix "$name|http-online")"
        headers="$TMP_DIR/online-headers-$suffix.txt"
        : > "$headers"
        result="$(capture 18 curl -sS -L --max-redirs 5 --connect-timeout 6 --max-time 15 \
            --proto '=http,https' --proto-redir '=http,https' -D "$headers" -o /dev/null \
            -A "VPScry/$VERSION" -w 'code=%{http_code};final=%{url_effective};remote=%{remote_ip};time=%{time_total}' "$url")"; rc=$?
        header_summary="$(online_final_headers_v010 "$headers" 2>/dev/null || true)"
        if (( rc != 0 )); then
            add_result "WEB-ONLINE-$suffix" "web" "WARN" "MEDIUM" "HIGH" \
                "Online HTTP health check failed" "url=$url; curl_exit=$rc; output=$result; ${header_summary:-headers=unavailable}." \
                "curl -I -L --proto '=http,https' --proto-redir '=http,https' --connect-timeout 6 --max-time 15 $(shell_quote "$url")" \
                "Confirm public DNS, listener availability, certificate trust and reverse-proxy routing."
            failures=$((failures + 1)); http_failures=$((http_failures + 1))
        else
            code="$(sed -nE 's/.*code=([0-9]{3}).*/\1/p' <<< "$result")"
            case "$code" in
                526)
                    add_result "WEB-ONLINE-$suffix" "web" "WARN" "MEDIUM" "HIGH" \
                        "CDN or reverse proxy rejected the origin TLS certificate" \
                        "url=$url; $result; ${header_summary:-headers=unavailable}." \
                        "curl -I -L $(shell_quote "$url"); openssl s_client -connect $(shell_quote "$name:443") -servername $(shell_quote "$name") </dev/null" \
                        "Check that the origin certificate chain is trusted by the proxy and covers the final hostname, including any www alias."
                    failures=$((failures + 1)); http_failures=$((http_failures + 1)) ;;
                525)
                    add_result "WEB-ONLINE-$suffix" "web" "WARN" "MEDIUM" "HIGH" \
                        "CDN or reverse proxy could not complete the origin TLS handshake" \
                        "url=$url; $result; ${header_summary:-headers=unavailable}." \
                        "curl -I -L $(shell_quote "$url")" \
                        "Inspect origin TLS protocol, cipher, SNI and certificate-chain configuration."
                    failures=$((failures + 1)); http_failures=$((http_failures + 1)) ;;
                521|522|523|524)
                    add_result "WEB-ONLINE-$suffix" "web" "WARN" "MEDIUM" "HIGH" \
                        "CDN or reverse proxy could not reach a healthy origin" \
                        "url=$url; $result; ${header_summary:-headers=unavailable}." \
                        "curl -I -L $(shell_quote "$url")" \
                        "Check origin reachability, firewall rules, listener state and proxy-to-origin routing."
                    failures=$((failures + 1)); http_failures=$((http_failures + 1)) ;;
                5??)
                    add_result "WEB-ONLINE-$suffix" "web" "WARN" "MEDIUM" "HIGH" \
                        "Online website returned a server error" "url=$url; $result; ${header_summary:-headers=unavailable}." \
                        "curl -I -L $(shell_quote "$url")" \
                        "Inspect reverse-proxy and application logs for the failing request."
                    failures=$((failures + 1)); http_failures=$((http_failures + 1)) ;;
                2??|3??)
                    add_result "WEB-ONLINE-$suffix" "web" "PASS" "INFO" "HIGH" \
                        "Online website responded successfully" "url=$url; $result; ${header_summary:-headers=unavailable}." \
                        "curl -I -L $(shell_quote "$url")" "No action required." ;;
                *)
                    add_result "WEB-ONLINE-$suffix" "web" "INFO" "INFO" "HIGH" \
                        "Online website returned a non-success HTTP status" "url=$url; $result; ${header_summary:-headers=unavailable}." \
                        "curl -I -L $(shell_quote "$url")" \
                        "Confirm the status is expected for an unauthenticated root request." ;;
            esac

            if [[ "$scheme" == "https" || "$result" == *"final=https://"* ]]; then
                add_result "WEB-HEADERS-$(stable_suffix "$name|headers-online")" "web" "INFO" "INFO" "MEDIUM" \
                    "Online HTTP security-header inventory" \
                    "hostname=$name; ${header_summary:-headers=unavailable}." \
                    "curl -sSIL $(shell_quote "$url")" \
                    "Treat missing headers contextually; application and CDN policy may supply them at different layers."
            fi
        fi

        if [[ "$scheme" == "https" ]] && have openssl; then
            local cert_raw
            cert_raw="$(capture_stdin_null 18 openssl s_client -connect "$name:443" -servername "$name" -verify_hostname "$name" -verify_return_error 2>&1)"; cert_rc=$?
            cert_info="$(printf '%s\n' "$cert_raw" | openssl x509 -noout -subject -issuer -enddate 2>/dev/null || true)"
            if (( cert_rc == 0 )) && [[ -n "$cert_info" ]]; then
                add_result "TLS-ONLINE-$(stable_suffix "$name|tls-online")" "tls" "PASS" "INFO" "HIGH" \
                    "Online TLS certificate matches the requested hostname" \
                    "hostname=$name; $cert_info" \
                    "openssl s_client -connect $(shell_quote "$name:443") -servername $(shell_quote "$name") -verify_hostname $(shell_quote "$name") </dev/null" \
                    "No action required."
            else
                add_result "TLS-ONLINE-$(stable_suffix "$name|tls-online")" "tls" "WARN" "HIGH" "HIGH" \
                    "Online TLS certificate verification failed" \
                    "hostname=$name; output=$(shorten "${cert_raw:-no readable peer certificate}" 900)." \
                    "openssl s_client -connect $(shell_quote "$name:443") -servername $(shell_quote "$name") -verify_hostname $(shell_quote "$name") </dev/null" \
                    "Confirm certificate deployment, SNI routing, chain completeness and hostname coverage."
                failures=$((failures + 1)); tls_failures=$((tls_failures + 1))
            fi
        fi
        checked=$((checked + 1))
    done

    if (( skipped_onion + skipped_internal + skipped_invalid > 0 )); then
        add_result "WEB-ONLINE-SCOPE-001" "web" "INFO" "INFO" "HIGH" \
            "Non-clearnet names were excluded from ordinary online checks" \
            "onion_skipped=$skipped_onion; internal_or_address_skipped=$skipped_internal; invalid_skipped=$skipped_invalid; ordinary --online never sends .onion names to public DNS or direct OpenSSL checks." \
            "Review local Nginx/Apache and TOR-* findings" \
            "Use Tor-specific local findings for onion services; no onion request is made by ordinary --online."
    fi
    if (( checked == 0 )); then
        add_result "WEB-ONLINE-001" "web" "INFO" "INFO" "MEDIUM" \
            "No eligible public web hostname was discovered for online checks" \
            "Nginx, Apache and configured expectations did not expose a concrete clearnet DNS name." \
            "nginx -T; apache2ctl -S" \
            "Verify external websites manually or configure expected_websites in the policy file."
    else
        add_result "WEB-ONLINE-SUMMARY" "web" "INFO" "INFO" "HIGH" \
            "Online website verification summary" \
            "clearnet_hostnames_checked=$checked; http_failures=$http_failures; tls_failures=$tls_failures; failed_checks=$failures; onion_skipped=$skipped_onion; internal_or_invalid_skipped=$((skipped_internal+skipped_invalid)); maximum_hostnames=8." \
            "Review individual WEB-ONLINE, WEB-HEADERS and TLS-ONLINE findings" \
            "Use individual findings rather than this summary to prioritize action."
    fi
}

check_web_tls_process_managers() {
    check_nginx_topology
    check_apache_topology
    check_php_fpm
    check_certbot_renewal
    check_pm2
    check_public_dev_admin
    check_online_web
}


listener_inventory_for_ports() {
    local ports_re="$1" line proto endpoint parts addr port family pid process unit iface exposure display
    have ss || return 0
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        proto="$(awk '{print $1}' <<< "$line")"
        endpoint="$(awk '{print $5}' <<< "$line")"
        [[ "$proto" == "tcp" || "$proto" == "udp" ]] || continue
        parts="$(net_endpoint_parts "$endpoint")"
        addr="${parts%%|*}"; port="${parts##*|}"
        [[ "$port" =~ ^($ports_re)$ ]] || continue
        family="v4"; [[ "$addr" == *:* ]] && family="v6"
        pid="$(sed -nE 's/.*pid=([0-9]+).*/\1/p' <<< "$line" | head -n 1)"
        process="$(sed -nE 's/.*users:\(\(\"([^\"]+)\".*/\1/p' <<< "$line" | head -n 1)"
        unit="$(net_pid_unit "$pid")"
        iface=""
        [[ "$addr" != "0.0.0.0" && "$addr" != "::" && "$addr" != "*" ]] && iface="$(net_find_iface_for_addr "$addr")"
        exposure="$(net_listener_exposure "$family" "$addr" "$iface")"
        display="$addr:$port"; [[ "$family" == "v6" ]] && display="[$addr]:$port"
        printf '%s %s exposure=%s process=%s pid=%s unit=%s\n' "$proto" "$display" "$exposure" "${process:-unknown}" "${pid:-unknown}" "${unit:-unknown}"
    done < <(ss -H -lntup 2>/dev/null || true)
}

path_stat_inventory() {
    local path="$1"
    [[ -e "$path" ]] || return 0
    stat -Lc 'path=%n owner=%U group=%G mode=%a type=%F' -- "$path" 2>/dev/null || true
}

run_as_local_user() {
    local seconds="$1" user="$2"
    shift 2
    if [[ "$(id -un 2>/dev/null || true)" == "$user" ]]; then
        capture "$seconds" "$@"
    elif (( RUN_AS_ROOT )) && have runuser; then
        capture "$seconds" runuser -u "$user" -- "$@"
    elif (( RUN_AS_ROOT )) && have su; then
        local command_string=""
        printf -v command_string '%q ' "$@"
        capture "$seconds" su -s /bin/sh "$user" -c "$command_string"
    else
        return 126
    fi
}

check_mysql_mariadb() {
    local unit_dump detected=0 server_bin defaults_tool client config_files defaults selected listeners public_count=0 private_count=0
    local validation_rc query auth_counts anonymous remote_root empty_auth wildcard_users variables datadir socket_path stats="" suffix
    unit_dump="$(systemctl list-unit-files --no-legend --plain 2>/dev/null || true)"
    grep -Eq '^(mariadb|mysql)\.service' <<< "$unit_dump" && detected=1
    [[ -d "$MYSQL_CONFIG_ROOT" ]] && detected=1
    server_bin="$(command -v mariadbd 2>/dev/null || command -v mysqld 2>/dev/null || true)"
    defaults_tool="$(command -v my_print_defaults 2>/dev/null || true)"
    client="$(command -v mariadb 2>/dev/null || command -v mysql 2>/dev/null || true)"
    [[ -n "$server_bin$defaults_tool$client" ]] && detected=1
    (( detected )) || return 0

    config_files="$(find "$MYSQL_CONFIG_ROOT" -xdev -type f \( -name '*.cnf' -o -name '*.conf' \) -print 2>/dev/null | sort | head -n 40)"
    defaults=""
    if [[ -n "$defaults_tool" ]]; then
        defaults="$($defaults_tool mysqld server mariadb 2>/dev/null | grep -E '^--(bind-address|skip-networking|port|socket|ssl|ssl-ca|ssl-cert|ssl-key|require-secure-transport|local-infile|symbolic-links|datadir)(=|$)' | sort -u || true)"
        $defaults_tool mysqld server mariadb >/dev/null 2>&1
        validation_rc=$?
        if (( validation_rc == 0 )); then
            add_result "DB-MYSQL-CONFIG-001" "database" "PASS" "INFO" "HIGH" \
                "MariaDB/MySQL option files were parsed successfully" \
                "config_root=$MYSQL_CONFIG_ROOT; files=$(wc -l <<< "$config_files" | tr -d ' '); selected_options=${defaults:-none}." \
                "my_print_defaults mysqld server mariadb" \
                "No action required; selected options intentionally exclude credential values."
        else
            add_result "DB-MYSQL-CONFIG-001" "database" "WARN" "MEDIUM" "HIGH" \
                "MariaDB/MySQL option-file parsing failed" \
                "my_print_defaults exit=$validation_rc; config_root=$MYSQL_CONFIG_ROOT." \
                "my_print_defaults mysqld server mariadb" \
                "Correct invalid or unsupported server options before the next restart."
        fi
    else
        selected="$(grep -RhiE '^[[:space:]]*(bind-address|skip-networking|port|socket|ssl(-ca|-cert|-key)?|require_secure_transport|local_infile|symbolic-links|datadir)[[:space:]]*=' "$MYSQL_CONFIG_ROOT" 2>/dev/null | sed -E 's/[[:space:]]+#.*$//' | sort -u | head -n 30 || true)"
        add_result "DB-MYSQL-CONFIG-001" "database" "INFO" "INFO" "MEDIUM" \
            "MariaDB/MySQL configuration inventory" \
            "config_root=$MYSQL_CONFIG_ROOT; selected_options=${selected:-none}; my_print_defaults unavailable." \
            "find $(shell_quote "$MYSQL_CONFIG_ROOT") -type f -name '*.cnf'; command -v my_print_defaults" \
            "Use the native option parser when available to confirm include and option-file syntax."
    fi

    listeners="$(listener_inventory_for_ports '3306|33060')"
    public_count="$(grep -Ec 'exposure=(public|wildcard)' <<< "$listeners" || true)"
    private_count="$(grep -Ec 'exposure=(private|cgnat|vpn)' <<< "$listeners" || true)"
    if (( public_count > 0 )); then
        add_result "DB-MYSQL-LISTEN-001" "database" "WARN" "HIGH" "HIGH" \
            "MariaDB/MySQL is listening on a public or wildcard address" \
            "$listeners" \
            "ss -lntp '( sport = :3306 or sport = :33060 )'; my_print_defaults mysqld server mariadb" \
            "Prefer loopback or a private interface, and require authentication, TLS and source-restricted firewall rules for remote database access."
    elif [[ -n "$listeners" ]]; then
        add_result "DB-MYSQL-LISTEN-001" "database" "PASS" "INFO" "HIGH" \
            "MariaDB/MySQL listener exposure is locally restricted" \
            "$listeners" \
            "ss -lntp '( sport = :3306 or sport = :33060 )'" \
            "No action required after confirming intended private or loopback clients."
    else
        add_result "DB-MYSQL-LISTEN-001" "database" "INFO" "INFO" "MEDIUM" \
            "No active MariaDB/MySQL listener was detected" \
            "Configuration or packages were detected, but ports 3306 and 33060 are not listening." \
            "systemctl status mariadb mysql; ss -lntp" \
            "Confirm whether the service is intentionally stopped or socket-only."
    fi

    if [[ -n "$client" ]]; then
        auth_counts="$(capture 7 "$client" --protocol=socket --connect-timeout=3 --batch --skip-column-names -e "SELECT CONCAT(SUM(User=''),'|',SUM(Host='%'),'|',SUM(User='root' AND Host NOT IN ('localhost','127.0.0.1','::1')),'|',SUM(COALESCE(authentication_string,'')='' AND COALESCE(plugin,'') NOT IN ('unix_socket','auth_socket'))) FROM mysql.user;" 2>/dev/null || true)"
        if [[ "$auth_counts" =~ ^[0-9]+\|[0-9]+\|[0-9]+\|[0-9]+$ ]]; then
            IFS='|' read -r anonymous wildcard_users remote_root empty_auth <<< "$auth_counts"
            if (( anonymous > 0 || empty_auth > 0 )); then
                add_result "DB-MYSQL-AUTH-001" "database" "FAIL" "CRITICAL" "HIGH" \
                    "MariaDB/MySQL contains anonymous or empty-authentication accounts" \
                    "anonymous_accounts=$anonymous; empty_authentication_accounts=$empty_auth; wildcard_host_accounts=$wildcard_users; remote_root_accounts=$remote_root." \
                    "$client --protocol=socket -e \"SELECT User,Host,plugin FROM mysql.user;\"" \
                    "Remove unused anonymous accounts and require a strong supported authentication method for every login-capable account."
            elif (( remote_root > 0 )); then
                add_result "DB-MYSQL-AUTH-001" "database" "WARN" "HIGH" "HIGH" \
                    "MariaDB/MySQL root account permits a non-local host pattern" \
                    "anonymous_accounts=0; empty_authentication_accounts=0; remote_root_accounts=$remote_root; wildcard_host_accounts=$wildcard_users." \
                    "$client --protocol=socket -e \"SELECT User,Host,plugin FROM mysql.user WHERE User='root';\"" \
                    "Restrict administrative database accounts to local or explicitly controlled management sources."
            else
                add_result "DB-MYSQL-AUTH-001" "database" "PASS" "INFO" "HIGH" \
                    "No anonymous, empty-authentication or remote-root MariaDB/MySQL account was found" \
                    "anonymous_accounts=0; empty_authentication_accounts=0; remote_root_accounts=0; wildcard_host_accounts=$wildcard_users." \
                    "$client --protocol=socket -e \"SELECT User,Host,plugin FROM mysql.user;\"" \
                    "Review wildcard application-account hosts separately; they may be intentional behind a firewall."
            fi
            variables="$(capture 7 "$client" --protocol=socket --connect-timeout=3 --batch --skip-column-names -e "SHOW VARIABLES WHERE Variable_name IN ('bind_address','skip_networking','require_secure_transport','have_ssl','tls_version','local_infile','datadir','socket');" 2>/dev/null || true)"
            datadir="$(awk '$1=="datadir" {print $2}' <<< "$variables" | head -n 1)"
            socket_path="$(awk '$1=="socket" {print $2}' <<< "$variables" | head -n 1)"
            add_result "DB-MYSQL-RUNTIME-001" "database" "INFO" "INFO" "HIGH" \
                "MariaDB/MySQL selected runtime settings" \
                "$(sed -E 's/[[:space:]]+/=/1' <<< "$variables" | paste -sd';' -)." \
                "$client --protocol=socket -e \"SHOW VARIABLES WHERE Variable_name IN ('bind_address','skip_networking','require_secure_transport','have_ssl','tls_version','local_infile','datadir','socket');\"" \
                "Confirm remote-access and transport settings match the deployment model."
        else
            add_result "DB-MYSQL-AUTH-001" "database" "SKIP" "INFO" "MEDIUM" \
                "MariaDB/MySQL account checks were not authorized" \
                "A local socket client was detected, but the read-only account query did not succeed; no password prompt was attempted." \
                "$client --protocol=socket --batch --skip-column-names -e 'SELECT User,Host,plugin FROM mysql.user;'" \
                "Run the verification command with an authorized local administrative identity if account review is required."
        fi
    fi

    [[ -z "${datadir:-}" && -d /var/lib/mysql ]] && datadir=/var/lib/mysql
    for selected in "$MYSQL_CONFIG_ROOT" "${datadir:-}" "${socket_path:-}" /etc/mysql/debian.cnf /root/.my.cnf; do
        [[ -n "$selected" && -e "$selected" ]] || continue
        stats+="$(path_stat_inventory "$selected"); "
        if [[ -f "$selected" ]]; then
            local mode
            mode="$(stat -Lc '%a' -- "$selected" 2>/dev/null || true)"
            case "$selected" in
                */debian.cnf|*/.my.cnf)
                    if [[ -n "$mode" ]] && is_world_readable "$mode"; then
                        suffix="$(stable_suffix "$selected|mysql-credential-file")"
                        add_result "DB-MYSQL-PERM-$suffix" "database" "WARN" "HIGH" "HIGH" \
                            "MariaDB/MySQL credential-style option file is world-readable" \
                            "$(path_stat_inventory "$selected")." \
                            "stat -Lc '%U %G %a %n' -- $(shell_quote "$selected")" \
                            "Restrict the file to its owning administrative or service identity."
                    fi
                    ;;
            esac
        fi
    done
    add_result "DB-MYSQL-PATHS-001" "database" "INFO" "INFO" "MEDIUM" \
        "MariaDB/MySQL path and permission inventory" \
        "${stats:-No selected configuration, data or socket path was readable.}" \
        "stat -Lc '%U %G %a %n' -- $(shell_quote "$MYSQL_CONFIG_ROOT") ${datadir:-/var/lib/mysql}" \
        "Configuration files may be world-readable, but credential files, private keys and writable data paths require tighter ownership."
}

check_postgresql() {
    local detected=0 clusters="" cluster_count=0 listeners public_count hba_files hba_active trust_host trust_local stats="" line ver name port status owner data log
    local query settings suffix
    have pg_lsclusters && clusters="$(pg_lsclusters --no-header 2>/dev/null || true)"
    [[ -n "$clusters" || -d "$POSTGRES_CONFIG_ROOT" ]] && detected=1
    systemctl list-unit-files --no-legend --plain 2>/dev/null | grep -Eq '^postgresql(@|\.)' && detected=1
    (( detected )) || return 0

    cluster_count="$(sed '/^[[:space:]]*$/d' <<< "$clusters" | wc -l | tr -d ' ')"
    if [[ -n "$clusters" ]]; then
        add_result "DB-PG-CLUSTERS-001" "database" "INFO" "INFO" "HIGH" \
            "PostgreSQL cluster inventory" \
            "clusters=$cluster_count; $(shorten "$clusters" 1300)." \
            "pg_lsclusters" \
            "Review version, status, owner, data directory and log location for every cluster."
        while read -r ver name port status owner data log; do
            [[ -n "$ver$name" ]] || continue
            if have pg_conftool; then
                if capture 8 pg_conftool "$ver" "$name" show all >/dev/null 2>&1; then
                    add_result "DB-PG-CONFIG-$(stable_suffix "$ver|$name")" "database" "PASS" "INFO" "HIGH" \
                        "PostgreSQL cluster configuration was parsed successfully" \
                        "cluster=$ver/$name; status=$status; owner=$owner; data=$data; log=$log." \
                        "pg_conftool $(shell_quote "$ver") $(shell_quote "$name") show all" \
                        "No action required."
                else
                    add_result "DB-PG-CONFIG-$(stable_suffix "$ver|$name")" "database" "WARN" "MEDIUM" "HIGH" \
                        "PostgreSQL cluster configuration parsing failed" \
                        "cluster=$ver/$name; status=$status; data=$data." \
                        "pg_conftool $(shell_quote "$ver") $(shell_quote "$name") show all" \
                        "Correct invalid settings before the next cluster restart."
                fi
            fi
            stats+="$(path_stat_inventory "$data"); $(path_stat_inventory "$log"); "
        done <<< "$clusters"
    else
        add_result "DB-PG-CLUSTERS-001" "database" "INFO" "INFO" "MEDIUM" \
            "PostgreSQL configuration was detected without pg_lsclusters inventory" \
            "config_root=$POSTGRES_CONFIG_ROOT; pg_lsclusters unavailable or returned no cluster." \
            "find $(shell_quote "$POSTGRES_CONFIG_ROOT") -type f; systemctl status postgresql" \
            "Use distribution cluster tools when available."
    fi

    listeners="$(listener_inventory_for_ports '5432|5433|5434|5435|5436|5437|5438|5439')"
    public_count="$(grep -Ec 'exposure=(public|wildcard)' <<< "$listeners" || true)"
    if (( public_count > 0 )); then
        add_result "DB-PG-LISTEN-001" "database" "WARN" "HIGH" "HIGH" \
            "PostgreSQL is listening on a public or wildcard address" "$listeners" \
            "ss -lntp | grep -E ':(5432|5433|5434|5435|5436|5437|5438|5439)[[:space:]]'" \
            "Prefer loopback or private interfaces and restrict pg_hba.conf and firewall sources."
    elif [[ -n "$listeners" ]]; then
        add_result "DB-PG-LISTEN-001" "database" "PASS" "INFO" "HIGH" \
            "PostgreSQL listener exposure is locally restricted" "$listeners" \
            "ss -lntp | grep -E ':(5432|5433|5434|5435|5436|5437|5438|5439)[[:space:]]'" \
            "No action required after confirming intended local clients."
    fi

    hba_files="$(find "$POSTGRES_CONFIG_ROOT" -xdev -type f -name pg_hba.conf -print 2>/dev/null | sort)"
    hba_active="$({ while IFS= read -r line; do [[ -r "$line" ]] && awk -v file="$line" '!/^[[:space:]]*#/ && NF {print file ":" NR ":" $0}' "$line"; done <<< "$hba_files"; } | head -n 80)"
    trust_host="$(awk 'tolower($0) ~ /:(host|hostssl|hostnossl)[[:space:]].*[[:space:]]trust([[:space:]]|$)/ {print}' <<< "$hba_active" | head -n 20)"
    trust_local="$(awk 'tolower($0) ~ /:local[[:space:]].*[[:space:]]trust([[:space:]]|$)/ {print}' <<< "$hba_active" | head -n 20)"
    if [[ -n "$trust_host" ]]; then
        add_result "DB-PG-HBA-001" "database" "FAIL" "HIGH" "HIGH" \
            "PostgreSQL host authentication uses trust" "$trust_host" \
            "grep -RniE '^[[:space:]]*host.*[[:space:]]trust([[:space:]]|$)' $(shell_quote "$POSTGRES_CONFIG_ROOT")" \
            "Replace network trust rules with SCRAM or certificate authentication and restrict source networks."
    elif [[ -n "$trust_local" ]]; then
        add_result "DB-PG-HBA-001" "database" "WARN" "MEDIUM" "HIGH" \
            "PostgreSQL local authentication uses trust" "$trust_local" \
            "grep -RniE '^[[:space:]]*local.*[[:space:]]trust([[:space:]]|$)' $(shell_quote "$POSTGRES_CONFIG_ROOT")" \
            "Confirm every local OS account is trusted or use peer/SCRAM authentication."
    elif [[ -n "$hba_files" ]]; then
        add_result "DB-PG-HBA-001" "database" "PASS" "INFO" "MEDIUM" \
            "No active PostgreSQL trust authentication rule was found" \
            "hba_files=$(wc -l <<< "$hba_files" | tr -d ' '); active_rules=$(wc -l <<< "$hba_active" | tr -d ' ')." \
            "grep -RniEv '^[[:space:]]*(#|$)' $(shell_quote "$POSTGRES_CONFIG_ROOT")/*/*/pg_hba.conf" \
            "Review broad CIDR rules and legacy md5 authentication separately."
    fi

    if have psql && getent passwd postgres >/dev/null 2>&1; then
        query="SELECT current_setting('listen_addresses'), current_setting('ssl'), current_setting('password_encryption'), current_setting('unix_socket_directories'), current_setting('data_directory'), current_setting('hba_file');"
        settings="$(run_as_local_user 8 postgres psql -X -A -t -q -d postgres -c "$query" 2>/dev/null || true)"
        if [[ -n "$settings" ]]; then
            local pg_listen pg_ssl pg_password pg_socket_dirs pg_data_dir pg_hba
            IFS='|' read -r pg_listen pg_ssl pg_password pg_socket_dirs pg_data_dir pg_hba <<< "$settings"
            add_result "DB-PG-RUNTIME-001" "database" "INFO" "INFO" "HIGH" \
                "PostgreSQL selected runtime settings" \
                "listen_addresses=${pg_listen:-unknown}; ssl=${pg_ssl:-unknown}; password_encryption=${pg_password:-unknown}; socket_directories=${pg_socket_dirs:-unknown}; data_directory=${pg_data_dir:-unknown}; hba_file=${pg_hba:-unknown}." \
                "runuser -u postgres -- psql -X -A -t -q -d postgres -c $(shell_quote "$query")" \
                "Confirm listener, TLS and password-encryption settings match the intended clients."
        else
            add_result "DB-PG-RUNTIME-001" "database" "SKIP" "INFO" "MEDIUM" \
                "PostgreSQL runtime settings were not available" \
                "A local read-only psql query did not succeed; no password prompt was attempted." \
                "runuser -u postgres -- psql -X -A -t -q -d postgres -c $(shell_quote "$query")" \
                "Run the command with an authorized local identity if runtime verification is required."
        fi
    fi

    for line in "$POSTGRES_CONFIG_ROOT" $hba_files; do
        [[ -e "$line" ]] || continue
        stats+="$(path_stat_inventory "$line"); "
    done
    add_result "DB-PG-PATHS-001" "database" "INFO" "INFO" "MEDIUM" \
        "PostgreSQL path and permission inventory" \
        "${stats:-No selected PostgreSQL path was readable.}" \
        "find $(shell_quote "$POSTGRES_CONFIG_ROOT") -maxdepth 3 -type f -name '*.conf' -exec stat -c '%U %G %a %n' {} +" \
        "Configuration can be readable, but data directories, private keys and writable paths should remain owned by the PostgreSQL service identity."
}

check_redis() {
    local detected=0 conf_files config bind="" protected="unknown" port="6379" tls_port="0" auth="absent" acl="absent" unixsocket="" dir="" logfile=""
    local listeners public_count ping="" stats="" file key value suffix
    systemctl list-unit-files --no-legend --plain 2>/dev/null | grep -Eq '^(redis|redis-server)\.service' && detected=1
    [[ -d "$REDIS_CONFIG_ROOT" ]] && detected=1
    have redis-server && detected=1
    (( detected )) || return 0
    conf_files="$(find "$REDIS_CONFIG_ROOT" -xdev -type f -name '*.conf' -print 2>/dev/null | sort)"
    while IFS= read -r file; do
        [[ -r "$file" ]] || continue
        while read -r key value _; do
            key="${key,,}"
            case "$key" in
                bind) bind="$value" ;;
                protected-mode) protected="${value,,}" ;;
                port) port="$value" ;;
                tls-port) tls_port="$value" ;;
                requirepass) auth="configured" ;;
                aclfile) acl="configured" ;;
                unixsocket) unixsocket="$value" ;;
                dir) dir="$value" ;;
                logfile) logfile="$value" ;;
            esac
        done < <(awk '!/^[[:space:]]*#/ && NF {print}' "$file")
    done <<< "$conf_files"
    listeners="$(listener_inventory_for_ports '6379|6380')"
    public_count="$(grep -Ec 'exposure=(public|wildcard)' <<< "$listeners" || true)"
    if have redis-cli; then
        if [[ -n "$unixsocket" && -S "$unixsocket" ]]; then
            ping="$(capture 5 redis-cli --no-auth-warning -s "$unixsocket" PING 2>/dev/null || true)"
        elif [[ "$port" =~ ^[0-9]+$ && "$port" != "0" ]]; then
            ping="$(capture 5 redis-cli --no-auth-warning -h 127.0.0.1 -p "$port" PING 2>/dev/null || true)"
        fi
    fi
    if (( public_count > 0 )) && [[ "$ping" == "PONG" || ( "$auth" == "absent" && "$acl" == "absent" && "$protected" != "yes" ) ]]; then
        add_result "CACHE-REDIS-AUTH-001" "cache" "FAIL" "CRITICAL" "HIGH" \
            "Public Redis listener appears accessible without authentication" \
            "listeners=$listeners; protected_mode=$protected; requirepass=$auth; aclfile=$acl; unauthenticated_ping=${ping:-not tested}." \
            "redis-cli -h 127.0.0.1 -p $(shell_quote "$port") PING; grep -RniE '^(bind|protected-mode|requirepass|aclfile|port|tls-port)' $(shell_quote "$REDIS_CONFIG_ROOT")" \
            "Bind Redis to loopback/private interfaces and require ACL authentication; use TLS or a protected tunnel for remote access."
    elif (( public_count > 0 )); then
        add_result "CACHE-REDIS-AUTH-001" "cache" "WARN" "HIGH" "HIGH" \
            "Redis is publicly or wildcard-bound" \
            "listeners=$listeners; protected_mode=$protected; requirepass=$auth; aclfile=$acl; tls_port=$tls_port; unauthenticated_ping=${ping:-not available}." \
            "ss -lntp '( sport = :6379 or sport = :6380 )'; grep -RniE '^(bind|protected-mode|requirepass|aclfile|port|tls-port)' $(shell_quote "$REDIS_CONFIG_ROOT")" \
            "Prefer loopback/private binding and verify ACL, TLS and firewall restrictions."
    elif [[ -n "$listeners" ]]; then
        add_result "CACHE-REDIS-AUTH-001" "cache" "PASS" "INFO" "MEDIUM" \
            "Redis listener exposure is locally restricted" \
            "listeners=$listeners; protected_mode=$protected; requirepass=$auth; aclfile=$acl; unauthenticated_ping=${ping:-not available}." \
            "ss -lntp '( sport = :6379 or sport = :6380 )'" \
            "No action required after confirming local application trust boundaries."
    fi
    for file in "$REDIS_CONFIG_ROOT" "$dir" "$logfile" "$unixsocket"; do
        [[ -n "$file" && -e "$file" ]] || continue
        stats+="$(path_stat_inventory "$file"); "
    done
    add_result "CACHE-REDIS-CONFIG-001" "cache" "INFO" "INFO" "MEDIUM" \
        "Redis configuration and path inventory" \
        "config_files=$(wc -l <<< "$conf_files" | tr -d ' '); bind=${bind:-default}; port=$port; tls_port=$tls_port; protected_mode=$protected; requirepass=$auth; aclfile=$acl; unixsocket=${unixsocket:-none}; paths=${stats:-none}." \
        "grep -RniE '^(bind|protected-mode|port|tls-port|requirepass|aclfile|unixsocket|dir|logfile)' $(shell_quote "$REDIS_CONFIG_ROOT")" \
        "Secret values are intentionally omitted; verify ACL files and TLS private-key permissions manually."
}

check_mongodb_search_cache() {
    local listeners mongo_public memcached public_search mongo_detected=0 auth="unknown" bind="unknown" port="27017" tls="unknown" dbpath="unknown" logpath="unknown" process_args config=""
    local es_configs es_security="unknown" es_host="unknown" es_tls="unknown"
    [[ -r "$MONGODB_CONFIG_FILE" ]] && mongo_detected=1
    have mongod && mongo_detected=1
    systemctl list-unit-files --no-legend --plain 2>/dev/null | grep -Eq '^(mongod|mongodb)\.service' && mongo_detected=1
    if (( mongo_detected )); then
        config="$(sed -E 's/[[:space:]]+#.*$//' "$MONGODB_CONFIG_FILE" 2>/dev/null || true)"
        bind="$(awk '/^[[:space:]]*bindIp(All)?[[:space:]]*:/ {sub(/^[^:]*:[[:space:]]*/,""); print; exit}' <<< "$config")"
        port="$(awk '/^[[:space:]]*port[[:space:]]*:/ {sub(/^[^:]*:[[:space:]]*/,""); print; exit}' <<< "$config")"; port="${port:-27017}"
        auth="$(awk '/^[[:space:]]*authorization[[:space:]]*:/ {sub(/^[^:]*:[[:space:]]*/,""); print tolower($0); exit}' <<< "$config")"
        tls="$(awk '/^[[:space:]]*(mode|tlsMode)[[:space:]]*:/ {sub(/^[^:]*:[[:space:]]*/,""); print tolower($0); exit}' <<< "$config")"
        dbpath="$(awk '/^[[:space:]]*dbPath[[:space:]]*:/ {sub(/^[^:]*:[[:space:]]*/,""); print; exit}' <<< "$config")"
        logpath="$(awk '/^[[:space:]]*path[[:space:]]*:/ {sub(/^[^:]*:[[:space:]]*/,""); print; exit}' <<< "$config")"
        process_args="$(ps -C mongod -o args= 2>/dev/null | head -n 3 || true)"
        grep -Eq '(^|[[:space:]])--auth([[:space:]]|$)' <<< "$process_args" && auth="enabled"
        listeners="$(listener_inventory_for_ports '27017|27018|27019')"
        mongo_public="$(grep -Ec 'exposure=(public|wildcard)' <<< "$listeners" || true)"
        if (( mongo_public > 0 )) && [[ "$auth" != "enabled" ]]; then
            add_result "DB-MONGO-AUTH-001" "database" "FAIL" "CRITICAL" "MEDIUM" \
                "Public MongoDB listener does not have confirmed authorization" \
                "listeners=$listeners; bind=${bind:-unknown}; authorization=${auth:-unknown}; tls_mode=${tls:-unknown}." \
                "ss -lntp | grep -E ':(27017|27018|27019)[[:space:]]'; grep -nE 'bindIp|authorization|tls|ssl' $(shell_quote "$MONGODB_CONFIG_FILE")" \
                "Enable authorization, bind to controlled interfaces and require TLS for remote clients."
        elif (( mongo_public > 0 )); then
            add_result "DB-MONGO-AUTH-001" "database" "WARN" "HIGH" "MEDIUM" \
                "MongoDB is publicly or wildcard-bound" \
                "listeners=$listeners; authorization=$auth; tls_mode=${tls:-unknown}." \
                "ss -lntp | grep -E ':(27017|27018|27019)[[:space:]]'; grep -nE 'bindIp|authorization|tls|ssl' $(shell_quote "$MONGODB_CONFIG_FILE")" \
                "Confirm authentication, TLS and source-restricted firewall policy."
        elif [[ -n "$listeners" ]]; then
            add_result "DB-MONGO-AUTH-001" "database" "PASS" "INFO" "MEDIUM" \
                "MongoDB listener exposure is locally restricted" \
                "listeners=$listeners; authorization=${auth:-unknown}; tls_mode=${tls:-unknown}." \
                "ss -lntp | grep -E ':(27017|27018|27019)[[:space:]]'" \
                "No action required after confirming intended clients."
        fi
        add_result "DB-MONGO-CONFIG-001" "database" "INFO" "INFO" "MEDIUM" \
            "MongoDB configuration and path inventory" \
            "config=$MONGODB_CONFIG_FILE; bind=${bind:-default}; port=$port; authorization=${auth:-unknown}; tls_mode=${tls:-unknown}; dbpath=${dbpath:-unknown}; logpath=${logpath:-unknown}; $(path_stat_inventory "$MONGODB_CONFIG_FILE"); $(path_stat_inventory "$dbpath"); $(path_stat_inventory "$logpath")." \
            "grep -nE 'bindIp|port|authorization|tls|ssl|dbPath|systemLog' $(shell_quote "$MONGODB_CONFIG_FILE")" \
            "The YAML parser is intentionally conservative; verify nested effective settings with the installed MongoDB tools."
    fi

    listeners="$(listener_inventory_for_ports '11211')"
    memcached="$(grep -Ec 'exposure=(public|wildcard)' <<< "$listeners" || true)"
    if (( memcached > 0 )); then
        add_result "CACHE-MEMCACHED-001" "cache" "FAIL" "HIGH" "HIGH" \
            "Memcached is exposed on a public or wildcard address" "$listeners" \
            "ss -lnutp '( sport = :11211 )'; systemctl cat memcached" \
            "Bind Memcached to loopback/private interfaces and restrict all access with the host firewall."
    elif [[ -n "$listeners" ]]; then
        add_result "CACHE-MEMCACHED-001" "cache" "PASS" "INFO" "HIGH" \
            "Memcached listener is locally restricted" "$listeners" \
            "ss -lnutp '( sport = :11211 )'" "No action required."
    fi

    listeners="$(listener_inventory_for_ports '9200|9300')"
    public_search="$(grep -Ec 'exposure=(public|wildcard)' <<< "$listeners" || true)"
    es_configs="$({ find "$ELASTIC_CONFIG_ROOT" -maxdepth 3 -type f \( -name elasticsearch.yml -o -name opensearch.yml \) -print 2>/dev/null; } | sort -u)"
    if [[ -n "$es_configs" || -n "$listeners" ]]; then
        while IFS= read -r config; do
            [[ -r "$config" ]] || continue
            es_host="$(awk -F: '/^[[:space:]]*(network\.host|http\.host)[[:space:]]*:/ {sub(/^[^:]*:[[:space:]]*/,""); print; exit}' "$config")"
            es_security="$(awk -F: '/^[[:space:]]*(xpack\.security\.enabled|plugins\.security\.disabled)[[:space:]]*:/ {sub(/^[^:]*:[[:space:]]*/,""); print tolower($0); exit}' "$config")"
            es_tls="$(awk -F: '/^[[:space:]]*(xpack\.security\.http\.ssl\.enabled|plugins\.security\.ssl\.http\.enabled)[[:space:]]*:/ {sub(/^[^:]*:[[:space:]]*/,""); print tolower($0); exit}' "$config")"
        done <<< "$es_configs"
        if (( public_search > 0 )) && [[ "$es_security" == "false" || "$es_security" == "true" && "$config" == *opensearch* ]]; then
            add_result "SEARCH-SECURITY-001" "search" "FAIL" "CRITICAL" "MEDIUM" \
                "Public search-service listener has security explicitly disabled" \
                "listeners=$listeners; network_host=${es_host:-unknown}; security_setting=$es_security; tls_setting=${es_tls:-unknown}." \
                "ss -lntp | grep -E ':(9200|9300)[[:space:]]'; grep -RniE 'network.host|http.host|security.*enabled|security.*disabled|ssl.*enabled' $(shell_quote "$ELASTIC_CONFIG_ROOT")" \
                "Enable the product security subsystem, TLS and source restrictions, or bind the service to a non-public interface."
        elif (( public_search > 0 )); then
            add_result "SEARCH-SECURITY-001" "search" "WARN" "HIGH" "MEDIUM" \
                "Elasticsearch/OpenSearch listener is publicly or wildcard-bound" \
                "listeners=$listeners; network_host=${es_host:-unknown}; security_setting=${es_security:-unknown}; tls_setting=${es_tls:-unknown}." \
                "ss -lntp | grep -E ':(9200|9300)[[:space:]]'; grep -RniE 'network.host|http.host|security|ssl' $(shell_quote "$ELASTIC_CONFIG_ROOT")" \
                "Confirm authentication, TLS and source-restricted firewall rules."
        else
            add_result "SEARCH-SECURITY-001" "search" "INFO" "INFO" "MEDIUM" \
                "Elasticsearch/OpenSearch configuration inventory" \
                "listeners=${listeners:-none}; network_host=${es_host:-unknown}; security_setting=${es_security:-unknown}; tls_setting=${es_tls:-unknown}." \
                "find $(shell_quote "$ELASTIC_CONFIG_ROOT") -name elasticsearch.yml -o -name opensearch.yml" \
                "Review effective settings using the installed product tools."
        fi
    fi
}

oci_inspect_field() {
    local engine="$1" id="$2" format="$3"
    capture 7 "$engine" inspect -f "$format" "$id" 2>/dev/null || true
}

check_oci_engine() {
    local engine="$1" prefix ids id meta name image state health restarts privileged network_mode pid_mode ipc_mode readonly restart_policy user healthcheck
    local caps security devices mounts env_names published suffix total=0 running=0 unhealthy=0 privileged_count=0 root_count=0 no_health=0 no_restart=0 secret_env=0
    local line type source destination rw dangerous_caps=0 socket_mounts=0 sensitive_mounts=0 exit_code finished
    have "$engine" || return 0
    capture 6 "$engine" info >/dev/null 2>&1 || return 0
    prefix="CONT-${engine^^}"
    ids="$(capture 8 "$engine" ps -aq 2>/dev/null || true)"
    if [[ "$engine" == "docker" ]]; then
        local daemon_info daemon_config_rc=0 socket_stats="" docker_group=""
        daemon_info="$(capture 7 docker info --format '{{json .SecurityOptions}}|{{.DockerRootDir}}|{{.Driver}}|{{.LoggingDriver}}|{{.LiveRestoreEnabled}}' 2>/dev/null || true)"
        [[ -S /var/run/docker.sock ]] && socket_stats="$(path_stat_inventory /var/run/docker.sock)"
        docker_group="$(getent group docker 2>/dev/null || true)"
        add_result "CONT-DOCKER-DAEMON-001" "containers" "INFO" "INFO" "HIGH" \
            "Docker daemon and socket inventory" \
            "security_options|data_root|storage_driver|logging_driver|live_restore=${daemon_info:-unknown}; socket=${socket_stats:-not found}; docker_group=${docker_group:-not found}." \
            "docker info; stat -Lc '%U %G %a %n' /var/run/docker.sock; getent group docker" \
            "Membership in the Docker control group is effectively host-administrative access; keep it narrowly assigned."
        if [[ -r /etc/docker/daemon.json ]]; then
            if have jq; then
                jq empty /etc/docker/daemon.json >/dev/null 2>&1 || daemon_config_rc=$?
            elif have python3; then
                python3 -m json.tool /etc/docker/daemon.json >/dev/null 2>&1 || daemon_config_rc=$?
            fi
            if (( daemon_config_rc == 0 )); then
                add_result "CONT-DOCKER-CONFIG-001" "containers" "PASS" "INFO" "HIGH" \
                    "Docker daemon JSON configuration is syntactically valid" \
                    "$(path_stat_inventory /etc/docker/daemon.json)." \
                    "jq empty /etc/docker/daemon.json" \
                    "No action required."
            else
                add_result "CONT-DOCKER-CONFIG-001" "containers" "FAIL" "HIGH" "HIGH" \
                    "Docker daemon JSON configuration is invalid" \
                    "file=/etc/docker/daemon.json; parser_exit=$daemon_config_rc." \
                    "jq empty /etc/docker/daemon.json" \
                    "Correct the JSON before restarting Docker."
            fi
        fi
        if [[ -n "$socket_stats" ]]; then
            local docker_socket_mode
            docker_socket_mode="$(stat -Lc '%a' /var/run/docker.sock 2>/dev/null || true)"
            if [[ -n "$docker_socket_mode" ]] && is_world_writable "$docker_socket_mode"; then
                add_result "CONT-DOCKER-SOCKET-PERM-001" "containers" "FAIL" "CRITICAL" "HIGH" \
                    "Docker daemon socket is world-writable" \
                    "$socket_stats." \
                    "stat -Lc '%U %G %a %n' /var/run/docker.sock" \
                    "Remove world access and restrict the socket to root and a narrowly controlled administrative group."
            fi
        fi
    fi
    if [[ -z "$ids" ]]; then
        add_result "$prefix-SUMMARY" "containers" "INFO" "INFO" "HIGH" \
            "${engine^} container inventory" "No container was returned by $engine ps -aq." \
            "$engine ps -a" "No action required."
        return 0
    fi
    while IFS= read -r id; do
        [[ -n "$id" ]] || continue
        total=$((total + 1)); suffix="$(stable_suffix "$engine|$id")"
        meta="$(oci_inspect_field "$engine" "$id" '{{.Name}}|{{.Config.Image}}|{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}|{{.RestartCount}}|{{.HostConfig.Privileged}}|{{.HostConfig.NetworkMode}}|{{.HostConfig.PidMode}}|{{.HostConfig.IpcMode}}|{{.HostConfig.ReadonlyRootfs}}|{{.HostConfig.RestartPolicy.Name}}|{{.Config.User}}|{{if .Config.Healthcheck}}yes{{else}}no{{end}}|{{.State.ExitCode}}|{{.State.FinishedAt}}')"
        IFS='|' read -r name image state health restarts privileged network_mode pid_mode ipc_mode readonly restart_policy user healthcheck exit_code finished <<< "$meta"
        name="${name#/}"; [[ -n "$name" ]] || name="$id"
        [[ "$state" == "running" ]] && running=$((running + 1))
        [[ "$health" == "unhealthy" ]] && unhealthy=$((unhealthy + 1))
        [[ "$healthcheck" != "yes" ]] && no_health=$((no_health + 1))
        [[ -z "$restart_policy" || "$restart_policy" == "no" ]] && no_restart=$((no_restart + 1))
        published="$(capture 5 "$engine" port "$id" 2>/dev/null | head -n 20 || true)"
        caps="$(oci_inspect_field "$engine" "$id" '{{json .HostConfig.CapAdd}}')"
        security="$(oci_inspect_field "$engine" "$id" '{{json .HostConfig.SecurityOpt}}')"
        devices="$(oci_inspect_field "$engine" "$id" '{{json .HostConfig.Devices}}')"
        mounts="$(oci_inspect_field "$engine" "$id" '{{range .Mounts}}{{printf "%s|%s|%s|%t\\n" .Type .Source .Destination .RW}}{{end}}')"
        env_names="$($engine inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$id" 2>/dev/null | sed 's/=.*//' | grep -Ei '(^|_)(PASS(WOR)?D|TOKEN|SECRET|PRIVATE_KEY|API_KEY|ACCESS_KEY|CREDENTIAL|AUTH|COOKIE|DATABASE_URL|DSN)($|_)' | sort -u | paste -sd, - || true)"
        [[ -n "$env_names" ]] && secret_env=$((secret_env + 1))

        if [[ "$state" == "unhealthy" || "$health" == "unhealthy" ]]; then
            add_result "$prefix-HEALTH-$suffix" "containers" "FAIL" "HIGH" "HIGH" \
                "Container is unhealthy" \
                "engine=$engine; container=$name; image=$image; state=$state; health=$health; restarts=${restarts:-0}." \
                "$engine inspect $(shell_quote "$id"); $engine logs --tail 100 $(shell_quote "$id")" \
                "Correct the health-check failure and application dependency before relying on the workload."
        elif [[ "$state" == "dead" || "$state" == "restarting" ]]; then
            add_result "$prefix-STATE-$suffix" "containers" "FAIL" "HIGH" "HIGH" \
                "Container is in an abnormal runtime state" \
                "engine=$engine; container=$name; image=$image; state=$state; health=$health; restarts=${restarts:-0}." \
                "$engine inspect $(shell_quote "$id"); $engine logs --tail 100 $(shell_quote "$id")" \
                "Investigate the runtime error and restart loop."
        elif [[ "$state" == "exited" && "${exit_code:-0}" != "0" ]]; then
            add_result "$prefix-STATE-$suffix" "containers" "WARN" "MEDIUM" "HIGH" \
                "Container exited with a non-zero status" \
                "engine=$engine; container=$name; image=$image; exit_code=${exit_code:-unknown}; finished=${finished:-unknown}." \
                "$engine inspect $(shell_quote "$id"); $engine logs --tail 100 $(shell_quote "$id")" \
                "Confirm whether the container is an expected one-shot job or a failed persistent service."
        fi
        if [[ "${restarts:-0}" =~ ^[0-9]+$ ]] && (( restarts >= 5 )); then
            add_result "$prefix-RESTART-$suffix" "containers" "WARN" "MEDIUM" "HIGH" \
                "Container has restarted repeatedly" \
                "engine=$engine; container=$name; restart_count=$restarts; state=$state; health=$health." \
                "$engine inspect -f '{{.RestartCount}} {{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}' $(shell_quote "$id")" \
                "Inspect application logs, resource limits and dependency availability."
        fi
        if [[ "$privileged" == "true" ]]; then
            privileged_count=$((privileged_count + 1))
            add_result "$prefix-PRIV-$suffix" "containers" "FAIL" "HIGH" "HIGH" \
                "Container runs in privileged mode" \
                "engine=$engine; container=$name; image=$image; privileged=true; pid_mode=${pid_mode:-default}; network_mode=${network_mode:-default}." \
                "$engine inspect -f '{{.HostConfig.Privileged}} {{.HostConfig.PidMode}} {{.HostConfig.NetworkMode}}' $(shell_quote "$id")" \
                "Remove privileged mode and grant only the exact devices or capabilities required."
        fi
        if grep -Eqi '"ALL"|SYS_ADMIN|SYS_MODULE|SYS_PTRACE|DAC_READ_SEARCH|NET_ADMIN' <<< "$caps"; then
            dangerous_caps=$((dangerous_caps + 1))
            if grep -Eqi '"ALL"' <<< "$caps"; then
                add_result "$prefix-CAPS-$suffix" "containers" "FAIL" "HIGH" "HIGH" \
                    "Container adds all Linux capabilities" \
                    "engine=$engine; container=$name; cap_add=$caps." \
                    "$engine inspect -f '{{json .HostConfig.CapAdd}}' $(shell_quote "$id")" \
                    "Remove CAP_ALL and grant only narrowly required capabilities."
            else
                add_result "$prefix-CAPS-$suffix" "containers" "WARN" "HIGH" "HIGH" \
                    "Container adds high-risk Linux capabilities" \
                    "engine=$engine; container=$name; cap_add=$caps." \
                    "$engine inspect -f '{{json .HostConfig.CapAdd}}' $(shell_quote "$id")" \
                    "Confirm every added capability is required and cannot be replaced with a narrower design."
            fi
        fi
        while IFS='|' read -r type source destination rw; do
            [[ -n "$source$destination" ]] || continue
            if [[ "$destination" == "/var/run/docker.sock" || "$destination" == "/run/docker.sock" || "$source" == */docker.sock ]]; then
                socket_mounts=$((socket_mounts + 1))
                if [[ "$rw" == "true" ]]; then
                    add_result "$prefix-SOCKET-$suffix" "containers" "FAIL" "CRITICAL" "HIGH" \
                        "Container has read-write access to the Docker socket" \
                        "engine=$engine; container=$name; mount=$source->$destination; read_write=$rw." \
                        "$engine inspect -f '{{json .Mounts}}' $(shell_quote "$id")" \
                        "Remove the socket mount or use a narrowly authorized proxy; write access is effectively host-root control."
                else
                    add_result "$prefix-SOCKET-$suffix" "containers" "WARN" "HIGH" "HIGH" \
                        "Container can access the Docker socket" \
                        "engine=$engine; container=$name; mount=$source->$destination; read_write=$rw." \
                        "$engine inspect -f '{{json .Mounts}}' $(shell_quote "$id")" \
                        "Remove the mount when possible; read-only filesystem mode does not guarantee read-only Docker API authorization."
                fi
                continue
            fi
            case "$source" in
                /|/etc|/etc/*|/root|/root/*|/proc|/proc/*|/sys|/sys/*|/dev|/dev/*|/var/lib/docker|/var/lib/docker/*|/var/run|/var/run/*|/run|/run/*)
                    if [[ "$rw" == "true" ]]; then
                        sensitive_mounts=$((sensitive_mounts + 1))
                        add_result "$prefix-MOUNT-$(stable_suffix "$engine|$id|$source|$destination")" "containers" "WARN" "HIGH" "HIGH" \
                            "Container has a writable sensitive host mount" \
                            "engine=$engine; container=$name; type=$type; source=$source; destination=$destination; read_write=$rw." \
                            "$engine inspect -f '{{json .Mounts}}' $(shell_quote "$id")" \
                            "Use a narrower read-only mount or remove host-path access."
                    fi
                    ;;
            esac
        done <<< "$mounts"
        if [[ -z "$user" || "$user" == "0" || "$user" == "root" || "$user" == "0:0" ]]; then
            root_count=$((root_count + 1))
            if [[ "$privileged" != "true" && -n "$published" ]]; then
                add_result "$prefix-ROOT-$suffix" "containers" "WARN" "LOW" "MEDIUM" \
                    "Network-published container uses the image default root user" \
                    "engine=$engine; container=$name; image=$image; configured_user=${user:-image default/root}; published=$(shorten "$published" 500)." \
                    "$engine inspect -f '{{.Config.User}} {{json .NetworkSettings.Ports}}' $(shell_quote "$id")" \
                    "Use a non-root application user where the image and workload support it."
            fi
        fi
        if [[ -n "$env_names" ]]; then
            add_result "$prefix-ENV-$suffix" "containers" "WARN" "LOW" "MEDIUM" \
                "Container environment includes secret-like variable names" \
                "engine=$engine; container=$name; variable_names=$env_names; values were not collected." \
                "$engine inspect -f '{{range .Config.Env}}{{println .}}{{end}}' $(shell_quote "$id") | sed 's/=.*//'" \
                "Prefer runtime secret files or the platform secret mechanism for high-value credentials."
        fi
        add_result "$prefix-MAP-$suffix" "containers" "INFO" "INFO" "HIGH" \
            "Container security map" \
            "engine=$engine; container=$name; image=$image; state=$state; health=$health; restarts=${restarts:-0}; user=${user:-image default/root}; privileged=${privileged:-unknown}; network_mode=${network_mode:-default}; pid_mode=${pid_mode:-default}; ipc_mode=${ipc_mode:-default}; readonly_rootfs=${readonly:-unknown}; restart_policy=${restart_policy:-none}; healthcheck=${healthcheck:-unknown}; security_options=${security:-none}; devices=${devices:-none}; published=${published:-none}." \
            "$engine inspect $(shell_quote "$id")" \
            "Use individual findings to prioritize changes; the map is neutral inventory."
    done <<< "$ids"
    add_result "$prefix-SUMMARY" "containers" "INFO" "INFO" "HIGH" \
        "${engine^} container security summary" \
        "total=$total; running=$running; unhealthy=$unhealthy; privileged=$privileged_count; root_user=$root_count; without_healthcheck=$no_health; without_restart_policy=$no_restart; secret_name_findings=$secret_env; dangerous_capability_sets=$dangerous_caps; socket_mounts=$socket_mounts; sensitive_writable_mounts=$sensitive_mounts." \
        "$engine ps -a; $engine info" \
        "Health checks and restart policies are contextual; privileged mode, dangerous capabilities and daemon-socket mounts require stronger justification."
}

check_databases_caches_containers() {
    check_mysql_mariadb
    check_postgresql
    check_redis
    check_mongodb_search_cache
    check_oci_engine docker
    check_oci_engine podman
}

check_certificates() {
    local count=0 warn=0 cert path enddate endepoch now days subject
    [[ -d /etc/letsencrypt/live ]] || {
        add_result "TLS-CERTBOT-001" "tls" "INFO" "INFO" "HIGH" \
            "No Certbot certificate directory was detected" "/etc/letsencrypt/live does not exist." \
            "ls -la /etc/letsencrypt/live" \
            "No action is required when TLS is managed another way."
        return
    }

    if ! have openssl; then
        add_result "TLS-CERTBOT-001" "tls" "SKIP" "INFO" "HIGH" \
            "Local certificates could not be parsed" "openssl is unavailable." \
            "command -v openssl" "Install or use another local certificate inspection tool."
        return
    fi

    now="$(date +%s)"
    while IFS= read -r cert; do
        [[ -r "$cert" ]] || continue
        path="$(readlink -f -- "$cert" 2>/dev/null || printf '%s' "$cert")"
        enddate="$(openssl x509 -in "$path" -noout -enddate 2>/dev/null | cut -d= -f2- || true)"
        subject="$(openssl x509 -in "$path" -noout -subject 2>/dev/null | sed 's/^subject=//' || true)"
        [[ -n "$enddate" ]] || continue
        endepoch="$(date -d "$enddate" +%s 2>/dev/null || true)"
        [[ "$endepoch" =~ ^[0-9]+$ ]] || continue
        days=$(( (endepoch - now) / 86400 ))
        if (( days < 0 )); then
            add_result "TLS-CERT-$(printf '%03d' "$count")" "tls" "FAIL" "CRITICAL" "HIGH" \
                "Local TLS certificate is expired" \
                "certificate=$cert; subject=$subject; expires=$enddate; days_remaining=$days." \
                "openssl x509 -in '$path' -noout -subject -issuer -dates" \
                "Renew and deploy the certificate immediately."
            warn=$((warn + 1))
        elif (( days < 7 )); then
            add_result "TLS-CERT-$(printf '%03d' "$count")" "tls" "FAIL" "HIGH" "HIGH" \
                "Local TLS certificate expires within 7 days" \
                "certificate=$cert; subject=$subject; expires=$enddate; days_remaining=$days." \
                "openssl x509 -in '$path' -noout -subject -issuer -dates" \
                "Test renewal and deployment before expiry."
            warn=$((warn + 1))
        elif (( days < 30 )); then
            add_result "TLS-CERT-$(printf '%03d' "$count")" "tls" "WARN" "MEDIUM" "HIGH" \
                "Local TLS certificate expires within 30 days" \
                "certificate=$cert; subject=$subject; expires=$enddate; days_remaining=$days." \
                "openssl x509 -in '$path' -noout -subject -issuer -dates" \
                "Confirm automatic renewal and service reload are functioning."
            warn=$((warn + 1))
        fi
        count=$((count + 1))
    done < <(find /etc/letsencrypt/live -mindepth 2 -maxdepth 2 -name fullchain.pem 2>/dev/null)

    if (( count == 0 )); then
        add_result "TLS-CERTBOT-001" "tls" "WARN" "LOW" "MEDIUM" \
            "Certbot directory exists but no readable fullchain was found" \
            "/etc/letsencrypt/live exists; readable fullchain.pem count=0." \
            "find /etc/letsencrypt/live -mindepth 2 -maxdepth 2 -name fullchain.pem -ls" \
            "Confirm permissions and whether Certbot still manages active certificates."
    elif (( warn == 0 )); then
        add_result "TLS-CERTBOT-001" "tls" "PASS" "INFO" "HIGH" \
            "Local Certbot certificates are not near expiry" \
            "$count readable certificates were checked; none expires within 30 days." \
            "find /etc/letsencrypt/live -name fullchain.pem -exec openssl x509 -in {} -noout -subject -enddate \;" \
            "No action required; renewal execution is checked separately through timers and logs in later versions."
    fi
}

check_backup_detection() {
    local evidence cron_evidence unit_evidence file
    unit_evidence="$({
        systemctl list-unit-files --no-legend --plain 2>/dev/null | grep -Ei 'backup|restic|borg|rsnapshot|duplicity|kopia|rclone' || true
        systemctl list-timers --all --no-legend --plain 2>/dev/null | grep -Ei 'backup|restic|borg|rsnapshot|duplicity|kopia|rclone' || true
    } | head -n 20)"

    cron_evidence="$({
        for file in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/*; do
            [[ -f "$file" && -r "$file" ]] || continue
            awk -v file="$file" '
                /^[[:space:]]*#/ || /^[[:space:]]*$/ {next}
                {
                    line=tolower($0)
                    if (line ~ /(backup|restic|borg|rsnapshot|duplicity|kopia|rclone|mysqldump|pg_dump)/) {
                        printf "%s:%d:%s\n", file, NR, $0
                    }
                }
            ' "$file"
        done
        find /etc/systemd/system -xdev -type f \( -name '*.service' -o -name '*.timer' \) -print0 2>/dev/null |
            while IFS= read -r -d '' file; do
                awk -v file="$file" '
                    /^[[:space:]]*[#;]/ || /^[[:space:]]*$/ {next}
                    {
                        line=tolower($0)
                        if (line ~ /(backup|restic|borg|rsnapshot|duplicity|kopia|rclone|mysqldump|pg_dump)/) {
                            printf "%s:%d:%s\n", file, NR, $0
                        }
                    }
                ' "$file"
            done
    } | head -n 20)"

    evidence="$(printf '%s\n%s\n' "$unit_evidence" "$cron_evidence" | sed '/^[[:space:]]*$/d' | head -n 30)"
    if [[ -n "$evidence" ]]; then
        add_result "BACKUP-DETECT-001" "backup" "INFO" "INFO" "MEDIUM" \
            "Potential backup jobs or tools were detected" "$evidence" \
            "systemctl list-timers --all; inspect uncommented cron and systemd job lines for backup tools" \
            "Verify the last successful backup, off-host copy, retention and a recent restore test. Detection does not prove recoverability."
    else
        add_result "BACKUP-DETECT-001" "backup" "INFO" "INFO" "LOW" \
            "No generic local backup job was detected" \
            "No active backup keyword was found in selected system units, timers or uncommented cron entries." \
            "systemctl list-timers --all; inspect uncommented cron and systemd job lines" \
            "Document provider snapshots, external orchestration or another backup mechanism; absence of a local match is not scored as a failure."
    fi
}


check_component_coverage_v08() {
    local unit_dump detected=() not_detected=() component present
    unit_dump="$(systemctl list-unit-files --no-legend --plain 2>/dev/null || true)"
    for component in nginx apache mariadb postgresql redis mongodb memcached elasticsearch docker podman certbot pm2 tor wireguard openvpn tailscale strongswan restic borg rsnapshot rclone duplicity fail2ban crowdsec auditd cloud-init qemu-guest-agent; do
        present=0
        case "$component" in
            nginx) { have nginx || grep -q '^nginx\.service' <<< "$unit_dump"; } && present=1 ;;
            apache) { have apache2ctl || have apachectl || grep -q '^apache2\.service' <<< "$unit_dump"; } && present=1 ;;
            mariadb) { have mariadbd || have mysqld || grep -Eq '^(mariadb|mysql)\.service' <<< "$unit_dump" || [[ -d "$MYSQL_CONFIG_ROOT" ]]; } && present=1 ;;
            postgresql) { have pg_lsclusters || have psql || grep -Eq '^postgresql(@|\.)' <<< "$unit_dump" || [[ -d "$POSTGRES_CONFIG_ROOT" ]]; } && present=1 ;;
            redis) { have redis-server || grep -Eq '^(redis|redis-server)\.service' <<< "$unit_dump" || [[ -d "$REDIS_CONFIG_ROOT" ]]; } && present=1 ;;
            mongodb) { have mongod || grep -Eq '^(mongod|mongodb)\.service' <<< "$unit_dump" || [[ -f "$MONGODB_CONFIG_FILE" ]]; } && present=1 ;;
            memcached) { have memcached || grep -q '^memcached\.service' <<< "$unit_dump"; } && present=1 ;;
            elasticsearch) { have elasticsearch || have opensearch || grep -Eq '^(elasticsearch|opensearch)\.service' <<< "$unit_dump"; } && present=1 ;;
            docker) { have docker || grep -q '^docker\.service' <<< "$unit_dump"; } && present=1 ;;
            podman) { have podman || grep -Eq '^podman' <<< "$unit_dump"; } && present=1 ;;
            certbot) { have certbot || grep -q '^certbot\.timer' <<< "$unit_dump" || [[ -d /etc/letsencrypt ]]; } && present=1 ;;
            pm2) { have pm2 || grep -Eq '^pm2-' <<< "$unit_dump"; } && present=1 ;;
            tor) { have tor || grep -Eq '^tor(@|\.)' <<< "$unit_dump"; } && present=1 ;;
            wireguard) { have wg || grep -Eq '^wg-quick@' <<< "$unit_dump"; } && present=1 ;;
            openvpn) { have openvpn || grep -Eq '^openvpn' <<< "$unit_dump"; } && present=1 ;;
            tailscale) { have tailscale || grep -q '^tailscaled\.service' <<< "$unit_dump"; } && present=1 ;;
            strongswan) { have ipsec || grep -Eq '^(strongswan|strongswan-starter|charon)' <<< "$unit_dump"; } && present=1 ;;
            restic|borg|rsnapshot|rclone|duplicity) have "$component" && present=1 ;;
            fail2ban) { have fail2ban-client || grep -q '^fail2ban\.service' <<< "$unit_dump"; } && present=1 ;;
            crowdsec) { have cscli || grep -q '^crowdsec\.service' <<< "$unit_dump"; } && present=1 ;;
            auditd) { have auditctl || grep -q '^auditd\.service' <<< "$unit_dump"; } && present=1 ;;
            cloud-init) { have cloud-init || grep -Eq '^cloud-(init|config|final|init-local)\.service' <<< "$unit_dump" || [[ -d /var/lib/cloud ]]; } && present=1 ;;
            qemu-guest-agent) { have qemu-ga || grep -q '^qemu-guest-agent\.service' <<< "$unit_dump"; } && present=1 ;;
        esac
        if (( present )); then detected+=("$component"); else not_detected+=("$component"); fi
    done
    add_result "APP-COVERAGE-001" "applications" "INFO" "INFO" "HIGH" \
        "Component audit coverage summary" \
        "detected=$(IFS=,; printf '%s' "${detected[*]:-none}"); not_detected=$(IFS=,; printf '%s' "${not_detected[*]:-none}"); a missing component is neutral and is not counted as PASS." \
        "systemctl list-unit-files; command -v nginx apache2ctl mariadbd psql redis-server mongod docker podman certbot pm2 tor wg openvpn tailscale ipsec restic borg rsnapshot rclone duplicity fail2ban-client cscli auditctl cloud-init qemu-ga" \
        "PASS means an applicable check completed successfully; INFO means neutral inventory or not detected; SKIP means applicable evidence could not be collected."
}

check_logs_deep_v06() {
    local journal_cfg effective storage max_use runtime_max keep_free runtime_keep retention file_sec
    local journal_dir=/var/log/journal journal_bytes=0 fs_kib=0 free_kib=0 pct=0 status severity
    local unit_counts deleted deleted_count=0 deleted_large=0 deleted_bytes=0 line size
    local rotate_configs patterns candidates covered_file uncovered_file candidate pattern match
    local candidate_count=0 uncovered_count=0 covered_count=0 recent_large recent_count=0

    if have journalctl; then
        journal_cfg="$(
            if have systemd-analyze; then systemd-analyze cat-config systemd/journald.conf 2>/dev/null || true; fi
            cat /etc/systemd/journald.conf 2>/dev/null || true
            for file in /etc/systemd/journald.conf.d/*.conf; do [[ -r "$file" ]] && cat "$file"; done
        )"
        effective="$(awk -F= '
            /^[[:space:]]*(Storage|SystemMaxUse|RuntimeMaxUse|SystemKeepFree|RuntimeKeepFree|MaxRetentionSec|MaxFileSec)[[:space:]]*=/ {
                key=$1; value=$2; gsub(/[[:space:]]/, "", key); sub(/^[[:space:]]*/, "", value); sub(/[[:space:]]*[#;].*$/, "", value); v[key]=value
            }
            END {for (k in v) printf "%s=%s\n", k, v[k]}
        ' <<< "$journal_cfg" | sort)"
        storage="$(awk -F= '$1=="Storage" {print $2}' <<< "$effective")"
        max_use="$(awk -F= '$1=="SystemMaxUse" {print $2}' <<< "$effective")"
        runtime_max="$(awk -F= '$1=="RuntimeMaxUse" {print $2}' <<< "$effective")"
        keep_free="$(awk -F= '$1=="SystemKeepFree" {print $2}' <<< "$effective")"
        runtime_keep="$(awk -F= '$1=="RuntimeKeepFree" {print $2}' <<< "$effective")"
        retention="$(awk -F= '$1=="MaxRetentionSec" {print $2}' <<< "$effective")"
        file_sec="$(awk -F= '$1=="MaxFileSec" {print $2}' <<< "$effective")"
        [[ -d "$journal_dir" ]] && journal_bytes="$(du -sb "$journal_dir" 2>/dev/null | awk '{print $1}' || printf 0)"
        read -r fs_kib free_kib < <(df -Pk "$journal_dir" 2>/dev/null | awk 'NR==2 {print $2, $4}' || printf '0 0\n')
        if [[ "$fs_kib" =~ ^[0-9]+$ && "$fs_kib" -gt 0 && "$journal_bytes" =~ ^[0-9]+$ ]]; then pct=$(( journal_bytes / 1024 * 100 / fs_kib )); fi
        status="INFO"; severity="INFO"
        if [[ -n "$max_use$runtime_max$keep_free$runtime_keep$retention" ]]; then status="PASS"
        elif (( journal_bytes > 1073741824 || pct >= 10 )); then status="WARN"; severity="MEDIUM"
        fi
        add_result "LOG-JOURNAL-LIMITS-001" "logs" "$status" "$severity" "MEDIUM" \
            "systemd journal retention and free-space protection" \
            "storage=${storage:-default}; system_max_use=${max_use:-default}; runtime_max_use=${runtime_max:-default}; system_keep_free=${keep_free:-default}; runtime_keep_free=${runtime_keep:-default}; max_retention=${retention:-default}; max_file_age=${file_sec:-default}; current_bytes=$journal_bytes; filesystem_percent=$pct." \
            "systemd-analyze cat-config systemd/journald.conf; journalctl --disk-usage; df -h /var/log/journal" \
            "Explicit limits are optional when defaults are acceptable; configure them when journal growth competes with application data."

        unit_counts="$(capture 20 journalctl --since '-24 hours' -n 5000 -o json --no-pager 2>/dev/null | sed -nE 's/.*"_SYSTEMD_UNIT":"([^"]+)".*/\1/p' | sort | uniq -c | sort -nr | head -n 12 || true)"
        add_result "LOG-JOURNAL-UNITS-001" "logs" "INFO" "INFO" "MEDIUM" \
            "Recent journal volume by systemd unit" \
            "sample_window=24h; maximum_entries=5000; top_units=${unit_counts:-no unit-tagged entries in the sample}." \
            "journalctl --since '-24 hours' -n 5000 -o json | extract _SYSTEMD_UNIT and count" \
            "Use this bounded sample to identify noisy units; it is not a byte-accurate accounting report."
    else
        add_result "LOG-JOURNAL-LIMITS-001" "logs" "SKIP" "INFO" "HIGH" \
            "Journal retention could not be inspected" "journalctl is unavailable." "command -v journalctl" \
            "Inspect the active logging subsystem manually."
    fi

    if have lsof; then
        deleted="$(capture 20 lsof -nP +L1 2>/dev/null | filter_deleted_open_lsof_v100 | head -n 30 || true)"
        if [[ -n "$deleted" ]]; then
            deleted_count="$(wc -l <<< "$deleted" | tr -d ' ')"
            while IFS= read -r line; do
                size="$(awk '{print $7}' <<< "$line")"
                [[ "$size" =~ ^[0-9]+$ ]] || continue
                deleted_bytes=$((deleted_bytes + size))
                (( size >= 52428800 )) && deleted_large=$((deleted_large + 1))
            done <<< "$deleted"
            if (( deleted_large > 0 )); then status="WARN"; severity="MEDIUM"; else status="INFO"; severity="INFO"; fi
            add_result "LOG-DELETED-OPEN-001" "logs" "$status" "$severity" "HIGH" \
                "Deleted files remain open by running processes" \
                "open_deleted_files=$deleted_count; estimated_bytes=$deleted_bytes; files_over_50MiB=$deleted_large; sample=$(shorten "$deleted" 1100)." \
                "lsof -nP +L1" \
                "Restart or reload the owning process after confirming service impact so the filesystem space can be released."
        else
            add_result "LOG-DELETED-OPEN-001" "logs" "PASS" "INFO" "HIGH" \
                "No deleted-but-open regular file was found" "lsof +L1 returned no deleted regular file." "lsof -nP +L1" "No action required."
        fi
    else
        add_result "LOG-DELETED-OPEN-001" "logs" "SKIP" "INFO" "HIGH" \
            "Deleted-but-open files were not inspected" "lsof is unavailable." "command -v lsof" \
            "Install lsof only when this local diagnostic is desired; VPScry does not install packages."
    fi

    rotate_configs="$(find /etc/logrotate.conf /etc/logrotate.d -maxdepth 2 -type f -readable 2>/dev/null | sort)"
    patterns="$(while IFS= read -r file; do
        awk '
            /^[[:space:]]*\// {
                line=$0; sub(/[[:space:]]*\{.*/, "", line); gsub(/[[:space:]]+/, "\n", line)
                n=split(line,a,"\n"); for(i=1;i<=n;i++) if(a[i] ~ /^\//) print a[i]
            }
        ' "$file"
    done <<< "$rotate_configs" | sort -u)"
    covered_file="$TMP_DIR/logrotate-covered"; uncovered_file="$TMP_DIR/logrotate-uncovered"
    : > "$covered_file"; : > "$uncovered_file"
    while IFS= read -r pattern; do
        [[ -n "$pattern" ]] || continue
        while IFS= read -r match; do [[ -f "$match" ]] && printf '%s\n' "$match"; done < <(compgen -G "$pattern" 2>/dev/null || true)
    done <<< "$patterns" | sort -u > "$covered_file"
    if have logrotate; then
        capture 20 logrotate -d /etc/logrotate.conf 2>/dev/null | sed -nE 's/^[[:space:]]*considering log[[:space:]]+([^[:space:]]+).*/\1/p' | sort -u >> "$covered_file" || true
        sort -u -o "$covered_file" "$covered_file"
    fi
    candidates="$(find /var/log -xdev -maxdepth 4 -type f -size +1M -mmin -10080 \
        ! -path '/var/log/journal/*' ! -path '/var/log/installer/*' \
        ! -name '*.gz' ! -name '*.xz' ! -name '*.zst' ! -name '*.dat' \
        ! -regex '.*\.[0-9]+$' ! -regex '.*-[0-9]\{8\}$' -print 2>/dev/null | sort | head -n 120)"
    while IFS= read -r candidate; do
        [[ -n "$candidate" ]] || continue
        candidate_count=$((candidate_count + 1))
        if grep -Fxq -- "$candidate" "$covered_file"; then covered_count=$((covered_count + 1)); else printf '%s\n' "$candidate" >> "$uncovered_file"; uncovered_count=$((uncovered_count + 1)); fi
    done <<< "$candidates"
    if (( candidate_count == 0 )); then
        add_result "LOG-ROTATE-COVERAGE-001" "logs" "INFO" "INFO" "MEDIUM" \
            "No active log file exceeded the coverage threshold" "candidate_threshold=1MiB; candidates=0." \
            "find /var/log -xdev -type f -size +1M" "No coverage conclusion was required."
    elif (( uncovered_count > 0 )); then
        add_result "LOG-ROTATE-COVERAGE-001" "logs" "WARN" "LOW" "MEDIUM" \
            "Some sizeable log files were not matched to a logrotate path" \
            "candidates=$candidate_count; covered=$covered_count; unmatched=$uncovered_count; sample=$(head -n 15 "$uncovered_file" | paste -sd, -)." \
            "logrotate -d /etc/logrotate.conf; inspect /etc/logrotate.d and application-native rotation" \
            "Confirm unmatched files are rotated by the application, journald or another mechanism before adding a rule."
    else
        add_result "LOG-ROTATE-COVERAGE-001" "logs" "PASS" "INFO" "MEDIUM" \
            "Sizeable active log files are matched by logrotate paths" \
            "candidates=$candidate_count; covered=$covered_count; unmatched=0; threshold=1MiB." \
            "logrotate -d /etc/logrotate.conf" "No action required after confirming application-native rotation is not double-configured."
    fi

    recent_large="$(find /var/log /root/.pm2/logs /home/*/.pm2/logs -xdev -type f -mmin -1440 -size +20M \
        ! -path '/var/log/journal/*' ! -path '/var/log/installer/*' \
        -printf '%s %TY-%Tm-%TdT%TH:%TM %p\n' 2>/dev/null | sort -nr | head -n 20 || true)"
    if [[ -n "$recent_large" ]]; then
        recent_count="$(wc -l <<< "$recent_large" | tr -d ' ')"
        add_result "LOG-APP-GROWTH-001" "logs" "WARN" "LOW" "MEDIUM" \
            "Large application logs changed within the last day" \
            "files=$recent_count; threshold=${LOG_GROWTH_MIB}MiB; sample=$(shorten "$recent_large" 1100)." \
            "find /var/log /root/.pm2/logs /home/*/.pm2/logs -type f -mmin -1440 -size +${LOG_GROWTH_MIB}M ! -path '/var/log/journal/*' -ls" \
            "Check whether the volume is expected and whether rotation and retention limits are effective."
    else
        add_result "LOG-APP-GROWTH-001" "logs" "PASS" "INFO" "MEDIUM" \
            "No rapidly changing large application log was identified" \
            "No selected log file both exceeded ${LOG_GROWTH_MIB}MiB and changed within the last 24 hours." \
            "find /var/log /root/.pm2/logs /home/*/.pm2/logs -type f -mmin -1440 -size +${LOG_GROWTH_MIB}M ! -path '/var/log/journal/*' -ls" \
            "No action required; this is a size-and-mtime proxy rather than historical growth measurement."
    fi
}

check_updates_deep_v06() {
    local apt_dump origins exclusions security_present=0 log="$UNATTENDED_LOG"
    local log_age=-1 log_tail failures notification_failures package_failures service_state timer_state reboot_setting reboot_time planned custom_reboots
    if ! have apt-config; then
        add_result "APT-POLICY-001" "updates" "SKIP" "INFO" "HIGH" \
            "Unattended-upgrades policy was not inspected" "apt-config is unavailable." "command -v apt-config" \
            "Inspect the package-management policy manually."
        return 0
    fi
    apt_dump="$(apt-config dump 2>/dev/null || true)"
    origins="$(grep -Ei '^Unattended-Upgrade::(Allowed-Origins|Origins-Pattern)' <<< "$apt_dump" | sed -E 's/[[:space:]]*;[[:space:]]*$//' | head -n 40 || true)"
    exclusions="$(grep -Ei '^Unattended-Upgrade::(Package-Blacklist|Package-Whitelist|MinimalSteps|Remove-Unused|AutoFixInterruptedDpkg)' <<< "$apt_dump" | sed -E 's/[[:space:]]*;[[:space:]]*$//' | head -n 40 || true)"
    grep -Eqi 'security' <<< "$origins" && security_present=1
    if (( security_present )); then
        add_result "APT-POLICY-001" "updates" "PASS" "INFO" "HIGH" \
            "Unattended-upgrades includes a security origin" \
            "origins=$(shorten "$origins" 1100); selected_policy=$(shorten "${exclusions:-none}" 700)." \
            "apt-config dump | grep -E 'Unattended-Upgrade::(Allowed-Origins|Origins-Pattern|Package-Blacklist)'" \
            "Review package exclusions so security fixes are not unintentionally held back."
    else
        add_result "APT-POLICY-001" "updates" "WARN" "MEDIUM" "MEDIUM" \
            "A security origin was not confirmed in unattended-upgrades policy" \
            "origins=${origins:-none}; selected_policy=$(shorten "${exclusions:-none}" 700)." \
            "apt-config dump | grep -E 'Unattended-Upgrade::(Allowed-Origins|Origins-Pattern)'" \
            "Confirm the Debian security suite is enabled; variables and included defaults may require manual interpretation."
    fi

    if [[ -r "$log" ]]; then
        log_age=$(( ( $(date +%s) - $(stat -Lc '%Y' "$log" 2>/dev/null || printf 0) ) / 86400 ))
        log_tail="$(tail -n 300 "$log" 2>/dev/null || true)"
        failures="$(grep -Ei '(^|[^a-z])(error|failed|failure|traceback|dpkg returned an error)' <<< "$log_tail" | tail -n 30 || true)"
        notification_failures="$(grep -Ei '(no /usr/bin/mail|no /usr/sbin/sendmail|can not send mail|cannot send mail|unable to send mail|mailx package)' <<< "$failures" | tail -n 20 || true)"
        package_failures="$(grep -Eiv '(no /usr/bin/mail|no /usr/sbin/sendmail|can not send mail|cannot send mail|unable to send mail|mailx package)' <<< "$failures" | tail -n 20 || true)"
    else
        log_tail=""; failures=""; notification_failures=""; package_failures=""
    fi
    service_state="$(systemctl show apt-daily-upgrade.service -p Result,ExecMainStatus,ActiveState,InactiveEnterTimestamp --value 2>/dev/null | paste -sd, - || true)"
    timer_state="$(systemctl show apt-daily-upgrade.timer -p ActiveState,UnitFileState,LastTriggerUSec --value 2>/dev/null | paste -sd, - || true)"
    if [[ -n "$package_failures" ]] || grep -Eqi 'failed|,[1-9][0-9]*,' <<< "$service_state"; then
        add_result "APT-RECENT-001" "updates" "WARN" "MEDIUM" "MEDIUM" \
            "Recent unattended-upgrades evidence includes package-management failure indicators" \
            "log_age_days=$log_age; service_state=${service_state:-unknown}; timer_state=${timer_state:-unknown}; indicators=$(shorten "$package_failures" 1000)." \
            "systemctl status apt-daily-upgrade.service apt-daily-upgrade.timer; tail -n 300 $log" \
            "Inspect the latest package-manager error and confirm the next scheduled run succeeds."
    elif (( log_age >= 0 && log_age <= 7 )); then
        add_result "APT-RECENT-001" "updates" "PASS" "INFO" "MEDIUM" \
            "Recent unattended-upgrades activity has no package-management failure indicator" \
            "log_age_days=$log_age; service_state=${service_state:-unknown}; timer_state=${timer_state:-unknown}." \
            "systemctl status apt-daily-upgrade.service apt-daily-upgrade.timer; tail -n 100 $log" \
            "No action required; package installation details remain available in the log."
    else
        add_result "APT-RECENT-001" "updates" "INFO" "INFO" "MEDIUM" \
            "Recent unattended-upgrades success could not be confirmed from its log" \
            "log_readable=$([[ -r "$log" ]] && printf yes || printf no); log_age_days=$log_age; service_state=${service_state:-unknown}; timer_state=${timer_state:-unknown}." \
            "systemctl status apt-daily-upgrade.service apt-daily-upgrade.timer; ls -l $log" \
            "Confirm the timer has triggered recently and review journal or package-manager logs."
    fi

    if [[ -n "$notification_failures" ]]; then
        add_result "APT-NOTIFY-001" "updates" "INFO" "INFO" "HIGH" \
            "Unattended-upgrades could not send configured mail notifications" \
            "package_upgrade_result=${service_state:-unknown}; notification_indicators=$(shorten "$notification_failures" 900)." \
            "apt-config dump | grep -E 'Unattended-Upgrade::Mail'; grep -Ei 'send mail|mailx|sendmail' $log | tail -n 20" \
            "Disable unused mail notifications or configure a supported notification path; this does not by itself mean package installation failed."
    fi

    reboot_setting="$(sed -nE 's/^Unattended-Upgrade::Automatic-Reboot[[:space:]]+"?([^";]+)"?;.*/\1/p' <<< "$apt_dump" | tail -n1)"
    reboot_time="$(sed -nE 's/^Unattended-Upgrade::Automatic-Reboot-Time[[:space:]]+"?([^";]+)"?;.*/\1/p' <<< "$apt_dump" | tail -n1)"
    custom_reboots="$({
        for file in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* /etc/systemd/system/*.service /etc/systemd/system/*.timer; do
            [[ -f "$file" && -r "$file" ]] || continue
            awk -v file="$file" '/^[[:space:]]*[#;]/ || /^[[:space:]]*$/ {next} tolower($0) ~ /(systemctl[[:space:]]+reboot|shutdown[[:space:]].*-r|(^|[[:space:]])reboot([[:space:]]|$))/ {printf "%s:%d:%s\n", file, NR, $0}' "$file"
        done
    } | head -n 20)"
    planned="automatic_reboot=${reboot_setting:-unset}; automatic_reboot_time=${reboot_time:-unset}; custom_entries=$(grep -c . <<< "$custom_reboots" || true)."
    [[ -n "$custom_reboots" ]] && planned+=" entries=$(shorten "$custom_reboots" 900)."
    add_result "APT-REBOOT-PLAN-001" "updates" "INFO" "INFO" "HIGH" \
        "Planned reboot inventory" "$planned" \
        "apt-config dump | grep 'Unattended-Upgrade::Automatic-Reboot'; inspect active cron and custom systemd units for reboot commands" \
        "Confirm reboot timing, workload startup order and external maintenance expectations."
}

check_backups_deep_v06() {
    local jobs_file="$TMP_DIR/backup-jobs" timers_file="$TMP_DIR/backup-timers" scripts_file="$TMP_DIR/backup-scripts" content_file="$TMP_DIR/backup-content"
    local file line timer service show result status exec_status last_trigger suffix job_count timer_count script_count
    local tools remote=0 retention=0 remote_tools="" retention_evidence="" timer_failures=0 timer_checked=0
    local candidate_dirs=() dir artifact_lines newest newest_epoch newest_size newest_path now age_days=-1
    local root_dev backup_dev storage_status storage_severity restore_paths restore_count=0
    : > "$jobs_file"; : > "$timers_file"; : > "$scripts_file"; : > "$content_file"
    for file in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/*; do
        [[ -f "$file" && -r "$file" ]] || continue
        awk -v file="$file" '
            /^[[:space:]]*#/ || /^[[:space:]]*$/ {next}
            {l=tolower($0); if(l ~ /(backup|restic|borg|rsnapshot|duplicity|kopia|rclone|mysqldump|mariadb-dump|pg_dump|pg_basebackup|tar[[:space:]].*\/backup)/) printf "%s:%d:%s\n", file, NR, $0}
        ' "$file" >> "$jobs_file"
    done
    systemctl list-timers --all --no-legend --plain 2>/dev/null | awk 'tolower($0) ~ /(backup|restic|borg|rsnapshot|duplicity|kopia|rclone|dump)/ && $(NF-1) ~ /\.timer$/ {print $(NF-1)}' | sort -u > "$timers_file"
    find /etc/systemd/system -xdev -type f \( -name '*.service' -o -name '*.timer' \) -readable -print0 2>/dev/null |
        while IFS= read -r -d '' file; do
            if grep -Eqi '(backup|restic|borg|rsnapshot|duplicity|kopia|rclone|mysqldump|mariadb-dump|pg_dump|pg_basebackup)' "$file"; then printf '%s\n' "$file"; fi
        done >> "$scripts_file"
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        printf '%s\n' "$line" | grep -Eo '/[^[:space:];|&]+\.(sh|bash|py|pl)' >> "$scripts_file" || true
    done < "$jobs_file"
    sort -u -o "$scripts_file" "$scripts_file"
    cat "$jobs_file" >> "$content_file"
    while IFS= read -r file; do
        [[ -f "$file" && -r "$file" ]] || continue
        grep -Eiv '^[[:space:]]*[#;]' "$file" 2>/dev/null | head -n 300 >> "$content_file" || true
    done < "$scripts_file"
    job_count="$(wc -l < "$jobs_file" | tr -d ' ')"; timer_count="$(wc -l < "$timers_file" | tr -d ' ')"; script_count="$(wc -l < "$scripts_file" | tr -d ' ')"
    tools="$({ cat "$content_file" 2>/dev/null; command -v restic borg rsnapshot rclone duplicity kopia 2>/dev/null || true; } | grep -Eio '(restic|borg|rsnapshot|rclone|duplicity|kopia|mysqldump|mariadb-dump|pg_dump|pg_basebackup)' | tr '[:upper:]' '[:lower:]' | sort -u | paste -sd, - || true)"
    if grep -Eqi '(rclone|restic|borg|duplicity|kopia|rsync|scp|sftp|s3:|b2:|azure:|swift:|remote:)' "$content_file" 2>/dev/null; then remote=1; remote_tools="$tools"; fi
    retention_evidence="$(grep -Eio -- '(--keep-[a-z-]+|forget|prune|retention|rotate|delete-older|expire|mtime[[:space:]]*\+[0-9]+)' "$content_file" 2>/dev/null | tr '[:upper:]' '[:lower:]' | sort -u | paste -sd, - || true)"
    [[ -n "$retention_evidence" ]] && retention=1
    local job_sources related_paths
    job_sources="$(cut -d: -f1 "$jobs_file" 2>/dev/null | sort -u | paste -sd, - || true)"
    related_paths="$(paste -sd, "$scripts_file" 2>/dev/null || true)"
    add_result "BACKUP-JOBS-001" "backup" "INFO" "INFO" "HIGH" \
        "Backup job and tool map" \
        "cron_or_command_jobs=$job_count; matching_timers=$timer_count; related_files=$script_count; tools=${tools:-custom-or-none}; remote_indicator=$remote; retention_indicator=$retention; job_sources=${job_sources:-none}; related_paths=$(shorten "${related_paths:-none}" 700); command contents were not retained in the report." \
        "systemctl list-timers --all; inspect uncommented cron entries and related unit files" \
        "Use this map to verify ownership, schedule, logging, destination and retention for every real backup job."

    while IFS= read -r timer; do
        [[ -n "$timer" ]] || continue
        timer_checked=$((timer_checked + 1)); service="${timer%.timer}.service"
        show="$(systemctl show "$service" -p Result,ExecMainStatus,ActiveState,InactiveEnterTimestamp --value 2>/dev/null | paste -sd, - || true)"
        result="$(systemctl show "$service" -p Result --value 2>/dev/null || true)"
        exec_status="$(systemctl show "$service" -p ExecMainStatus --value 2>/dev/null || true)"
        last_trigger="$(systemctl show "$timer" -p LastTriggerUSec --value 2>/dev/null || true)"
        suffix="$(stable_suffix "$timer|backup-result")"
        if [[ "$result" == "failed" || ( "$exec_status" =~ ^[0-9]+$ && "$exec_status" -ne 0 ) ]]; then
            timer_failures=$((timer_failures + 1))
            add_result "BACKUP-TIMER-$suffix" "backup" "FAIL" "HIGH" "HIGH" \
                "A backup-related systemd job last failed" \
                "timer=$timer; service=$service; last_trigger=${last_trigger:-unknown}; state=${show:-unknown}." \
                "systemctl status $(shell_quote "$timer") $(shell_quote "$service"); journalctl -u $(shell_quote "$service") -n 100" \
                "Correct the job failure and confirm a successful subsequent backup."
        else
            add_result "BACKUP-TIMER-$suffix" "backup" "INFO" "INFO" "MEDIUM" \
                "Backup-related systemd job state" \
                "timer=$timer; service=$service; last_trigger=${last_trigger:-unknown}; state=${show:-unknown}." \
                "systemctl status $(shell_quote "$timer") $(shell_quote "$service")" \
                "An inactive oneshot service is normal; confirm its last result and produced backup artifact."
        fi
    done < "$timers_file"

    for dir in /backup /backups /var/backups /srv/backup /srv/backups /mnt/backup /mnt/backups /opt/backup /opt/backups /home/*/backup /home/*/backups; do
        [[ -d "$dir" ]] && candidate_dirs+=("$dir")
    done
    while IFS= read -r dir; do
        [[ -d "$dir" ]] || continue
        case "$dir" in
            /tmp|/var/tmp|"$TMP_DIR"|"$TMP_DIR"/*|/tmp/vpscry.*|/tmp/vpscry.*/*|/var/tmp/vpscry.*|/var/tmp/vpscry.*/*) continue ;;
        esac
        candidate_dirs+=("$dir")
    done < <(grep -Eo '/[^[:space:]"'"'']*/(backup|backups)(/[^[:space:]"'"'']*)?' "$content_file" 2>/dev/null | while IFS= read -r file; do [[ -d "$file" ]] && printf '%s\n' "$file" || dirname "$file"; done | sort -u)
    mapfile -t candidate_dirs < <(printf '%s\n' "${candidate_dirs[@]:-}" | sed '/^$/d' | awk -v tmp="$TMP_DIR" '$0!="/tmp" && $0!="/var/tmp" && index($0,tmp)!=1 && $0 !~ /^\/tmp\/vpscry\./ && $0 !~ /^\/var\/tmp\/vpscry\./' | sort -u)
    artifact_lines="$({
        for dir in "${candidate_dirs[@]:-}"; do
            [[ -d "$dir" ]] || continue
            find "$dir" -xdev -maxdepth 4 -type f -size +0c \
                ! -path "$TMP_DIR/*" ! -path '/tmp/vpscry.*/*' ! -path '/var/tmp/vpscry.*/*' \
                ! -name 'dpkg.*' ! -name 'apt.*' ! -name 'alternatives.tar.*' \
                ! -iname '*restore*test*' ! -iname '*test*restore*' ! -iname '*recovery*test*' \
                -printf '%T@|%s|%p\n' 2>/dev/null
        done
    } | sort -t'|' -k1,1nr | head -n 50)"
    newest="$(head -n1 <<< "$artifact_lines")"
    if [[ -n "$newest" ]]; then
        IFS='|' read -r newest_epoch newest_size newest_path <<< "$newest"
        newest_epoch="${newest_epoch%%.*}"; now="$(date +%s)"
        if [[ "$newest_epoch" =~ ^[0-9]+$ ]]; then age_days=$(( (now - newest_epoch) / 86400 )); fi
        if (( age_days > BACKUP_MAX_AGE_DAYS )); then status="WARN"; storage_severity="MEDIUM"; else status="PASS"; storage_severity="INFO"; fi
        add_result "BACKUP-FRESHNESS-001" "backup" "$status" "$storage_severity" "MEDIUM" \
            "Newest local backup-like artifact age" \
            "newest_path=$newest_path; age_days=$age_days; size_bytes=$newest_size; candidate_directories=$(IFS=,; printf '%s' "${candidate_dirs[*]}"); inspected_files=$(wc -l <<< "$artifact_lines" | tr -d ' ')." \
            "find selected backup directories -type f -printf '%T@ %s %p\\n' | sort -nr" \
            "Freshness does not prove completeness or restorability; compare the age with the intended backup schedule."
        if have findmnt; then
            root_dev="$(findmnt -n -o SOURCE -T / 2>/dev/null | head -n1 || true)"
            backup_dev="$(findmnt -n -o SOURCE -T "$newest_path" 2>/dev/null | head -n1 || true)"
        else
            root_dev="$(df -P / 2>/dev/null | awk 'NR==2 {print $1}')"
            backup_dev="$(df -P "$newest_path" 2>/dev/null | awk 'NR==2 {print $1}')"
        fi
        storage_status="INFO"; storage_severity="INFO"
        if [[ -n "$root_dev$backup_dev" && "$root_dev" == "$backup_dev" && $remote -eq 0 ]]; then storage_status="WARN"; storage_severity="LOW"; fi
        add_result "BACKUP-STORAGE-001" "backup" "$storage_status" "$storage_severity" "MEDIUM" \
            "Backup storage-location context" \
            "root_device=${root_dev:-unknown}; newest_artifact_device=${backup_dev:-unknown}; same_device=$([[ -n "$root_dev" && "$root_dev" == "$backup_dev" ]] && printf yes || printf no); remote_indicator=$remote; remote_tools=${remote_tools:-none}." \
            "df -h / $(shell_quote "$newest_path"); inspect backup repository or remote configuration" \
            "Keep at least one independently protected copy; a same-disk artifact does not protect against disk or VPS loss."
    else
        add_result "BACKUP-FRESHNESS-001" "backup" "INFO" "INFO" "LOW" \
            "No local backup-like artifact was found in common directories" \
            "candidate_directories=$(IFS=,; printf '%s' "${candidate_dirs[*]:-none}"); remote_indicator=$remote; jobs=$job_count." \
            "Inspect provider snapshots, remote repositories and custom destinations" \
            "A remote-only design may be correct; document where freshness can be verified."
    fi

    if (( retention )); then
        add_result "BACKUP-RETENTION-001" "backup" "INFO" "INFO" "MEDIUM" \
            "Backup retention or pruning logic was detected" \
            "indicator_lines=$(shorten "$retention_evidence" 900); command presence does not prove successful enforcement." \
            "Inspect backup command, repository snapshots and prune logs" \
            "Confirm retention preserves required recovery points and that prune operations cannot delete the only good copy."
    else
        add_result "BACKUP-RETENTION-001" "backup" "INFO" "INFO" "LOW" \
            "Backup retention policy was not inferred" \
            "No keep, prune, forget, rotate or retention token was found in mapped local jobs and files." \
            "Inspect provider policy and backup-tool configuration" \
            "Document retention externally when it is not expressed in the local job."
    fi

    restore_paths="$({
        find /var/backups /backup /backups /srv/backup /srv/backups /etc/systemd/system -maxdepth 4 -type f \
            \( -iname '*restore*test*' -o -iname '*recovery*test*' -o -iname '*test*restore*' \) -print 2>/dev/null
        grep -RIlE 'restore[-_ ]?test|test[-_ ]?restore|recovery[-_ ]?test' /etc/systemd/system /etc/cron.d /etc/crontab 2>/dev/null || true
    } | sort -u | head -n 20)"
    [[ -n "$restore_paths" ]] && restore_count="$(wc -l <<< "$restore_paths" | tr -d ' ')"
    add_result "BACKUP-RESTORE-001" "backup" "INFO" "INFO" "$([[ -n "$restore_paths" ]] && printf MEDIUM || printf LOW)" \
        "Restore-test evidence inventory" \
        "evidence_files=$restore_count; paths=${restore_paths:-none found in selected local paths}; this does not prove that a restore succeeded." \
        "Review restore runbooks, logs, checksums and recovered application validation" \
        "Record a dated restore test with the recovered scope, validation steps and result."
}


check_sysctl_extended_v07() {
    local entry key relation expected value id status severity context
    local checks=(
        "net.ipv4.conf.all.accept_redirects|eq|0"
        "net.ipv4.conf.default.accept_redirects|eq|0"
        "net.ipv4.conf.all.send_redirects|eq|0"
        "net.ipv4.conf.default.send_redirects|eq|0"
        "net.ipv4.icmp_echo_ignore_broadcasts|eq|1"
        "net.ipv4.icmp_ignore_bogus_error_responses|eq|1"
        "net.ipv4.tcp_syncookies|eq|1"
        "kernel.randomize_va_space|eq|2"
        "fs.suid_dumpable|eq|0"
        "fs.protected_fifos|ge|1"
        "fs.protected_regular|ge|1"
        "kernel.perf_event_paranoid|ge|2"
        "kernel.unprivileged_bpf_disabled|ge|1"
    )
    for entry in "${checks[@]}"; do
        IFS='|' read -r key relation expected <<< "$entry"
        value="$(sysctl -n "$key" 2>/dev/null || true)"
        id="KERN-EXT-$(stable_suffix "$key")"
        if [[ -z "$value" ]]; then
            add_result "$id" "kernel" "INFO" "INFO" "MEDIUM" \
                "Optional kernel hardening setting is unavailable" "$key is not exposed by this kernel or namespace." \
                "sysctl $(shell_quote "$key")" "No action is required when the setting is unsupported."
            continue
        fi
        status="PASS"; severity="INFO"
        if [[ ! "$value" =~ ^-?[0-9]+$ ]]; then status="INFO"
        elif [[ "$relation" == "eq" && "$value" -ne "$expected" ]]; then status="WARN"; severity="LOW"
        elif [[ "$relation" == "ge" && "$value" -lt "$expected" ]]; then status="WARN"; severity="LOW"
        fi
        context=""
        [[ "$key" == "kernel.unprivileged_bpf_disabled" ]] && context=" Values 1 or 2 restrict unprivileged BPF; 2 may be permanent until reboot depending on kernel."
        add_result "$id" "kernel" "$status" "$severity" "HIGH" \
            "Context-aware kernel hardening setting" "$key=$value; expected_${relation}=$expected.$context" \
            "sysctl $(shell_quote "$key"); grep -R -- $(shell_quote "$key") /etc/sysctl.conf /etc/sysctl.d" \
            "$([[ "$status" == "PASS" ]] && printf 'No action required.' || printf 'Confirm workload and networking compatibility before changing the setting.')"
    done

    value="$(sysctl -n net.ipv6.conf.all.accept_redirects 2>/dev/null || true)"
    if [[ -n "$value" ]]; then
        if (( NET_PUBLIC_V6_COUNT > 0 || NET_IPV6_DEFAULT_ROUTE > 0 )); then
            status="PASS"; severity="INFO"; [[ "$value" != "0" ]] && status="WARN" && severity="LOW"
        else
            status="INFO"; severity="INFO"
        fi
        add_result "KERN-EXT-IPV6-REDIRECT" "kernel" "$status" "$severity" "HIGH" \
            "IPv6 redirect acceptance context" \
            "net.ipv6.conf.all.accept_redirects=$value; public_ipv6=$NET_PUBLIC_V6_COUNT; default_route_v6=$NET_IPV6_DEFAULT_ROUTE." \
            "sysctl net.ipv6.conf.all.accept_redirects; ip -6 addr; ip -6 route" \
            "Disable redirect acceptance before enabling routed public IPv6 unless the network design explicitly requires it."
    fi
}

check_mount_hardening_v07() {
    local target options id missing status severity expected note
    local targets=(/tmp /var/tmp /dev/shm /boot /boot/efi /home /var/log /var/log/audit)
    if ! have findmnt; then
        add_result "MOUNT-HARDEN-001" "filesystem" "SKIP" "INFO" "HIGH" \
            "Mount hardening could not be inspected" "findmnt is unavailable." "command -v findmnt" \
            "Inspect mount options manually."
        return
    fi
    for target in "${targets[@]}"; do
        [[ -e "$target" ]] || continue
        options="$(findmnt -n -o OPTIONS -T "$target" 2>/dev/null | head -n1 || true)"
        [[ -n "$options" ]] || continue
        expected=""; note=""
        case "$target" in
            /tmp|/var/tmp|/dev/shm) expected="nodev,nosuid"; note="noexec is workload-dependent and is not required by VPScry." ;;
            /boot|/boot/efi) expected="nodev,nosuid,noexec" ;;
            /home) expected="nodev" ;;
            /var/log|/var/log/audit) expected="nodev,nosuid,noexec" ;;
        esac
        missing=""
        IFS=',' read -ra _opts <<< "$expected"
        for _opt in "${_opts[@]}"; do
            grep -Eq "(^|,)${_opt}(,|$)" <<< "$options" || missing+="${_opt},"
        done
        missing="${missing%,}"
        id="MOUNT-HARDEN-$(stable_suffix "$target")"
        if [[ -z "$missing" ]]; then status="PASS"; severity="INFO"
        elif [[ "$(findmnt -n -o TARGET -T "$target" 2>/dev/null | head -n1)" != "$target" ]]; then status="INFO"; severity="INFO"
        else status="WARN"; severity="LOW"
        fi
        add_result "$id" "filesystem" "$status" "$severity" "MEDIUM" \
            "Sensitive path mount-option context" \
            "path=$target; mount=$(findmnt -n -o TARGET -T "$target" 2>/dev/null | head -n1); options=$options; suggested=$expected; missing=${missing:-none}; $note" \
            "findmnt -T $(shell_quote "$target") -o TARGET,SOURCE,FSTYPE,OPTIONS" \
            "Separate mounts are optional; apply restrictive options only when compatible with the deployment."
    done

    local sticky_bad="" count=0 dir mode
    for dir in /tmp /var/tmp; do
        [[ -d "$dir" ]] || continue
        mode="$(stat -Lc '%a' "$dir" 2>/dev/null || true)"
        if [[ "$mode" =~ ^[0-7]{3,4}$ ]] && (( (8#$mode & 8#1000) == 0 )); then sticky_bad+="$dir(mode=$mode),"; count=$((count + 1)); fi
    done
    if (( count > 0 )); then
        add_result "MOUNT-STICKY-001" "filesystem" "FAIL" "HIGH" "HIGH" \
            "World-writable temporary directory lacks the sticky bit" "paths=${sticky_bad%,}." \
            "stat -c '%a %n' /tmp /var/tmp" "Restore the sticky bit after confirming the directory purpose."
    else
        add_result "MOUNT-STICKY-001" "filesystem" "PASS" "INFO" "HIGH" \
            "Temporary directories use sticky-bit protection" "Checked /tmp and /var/tmp where present." \
            "stat -c '%a %n' /tmp /var/tmp" "No action required."
    fi
}

dpkg_owner_for_path() {
    local path="$1" owner="" alt=""
    have dpkg-query || return 0
    owner="$(dpkg-query -S -- "$path" 2>/dev/null | head -n1 | cut -d: -f1 || true)"
    if [[ -z "$owner" ]]; then
        case "$path" in
            /usr/bin/*) alt="/bin/${path#/usr/bin/}" ;;
            /usr/sbin/*) alt="/sbin/${path#/usr/sbin/}" ;;
            /usr/lib/*) alt="/lib/${path#/usr/lib/}" ;;
            /usr/lib64/*) alt="/lib64/${path#/usr/lib64/}" ;;
            /bin/*) alt="/usr/bin/${path#/bin/}" ;;
            /sbin/*) alt="/usr/sbin/${path#/sbin/}" ;;
            /lib/*) alt="/usr/lib/${path#/lib/}" ;;
            /lib64/*) alt="/usr/lib64/${path#/lib64/}" ;;
        esac
        [[ -n "$alt" ]] && owner="$(dpkg-query -S -- "$alt" 2>/dev/null | head -n1 | cut -d: -f1 || true)"
    fi
    if [[ -z "$owner" ]]; then
        alt="$(readlink -f -- "$path" 2>/dev/null || true)"
        [[ -n "$alt" && "$alt" != "$path" ]] && owner="$(dpkg-query -S -- "$alt" 2>/dev/null | head -n1 | cut -d: -f1 || true)"
    fi
    printf '%s' "$owner"
}

check_privileged_files_v07() {
    local list_file="$TMP_DIR/suid-sgid" path package desc local_count=0 packaged_count=0 total=0 skipped_nonexec=0 local_paths=""
    : > "$list_file"
    {
        capture 20 find /bin /sbin /usr/bin /usr/sbin /usr/libexec -xdev -type f \
            \( \( -perm -4000 -a -perm -0100 \) -o \( -perm -2000 -a -perm -0010 \) \) -print 2>/dev/null || true
        capture 20 find /usr/local /opt /home -xdev -maxdepth 6 \
            \( -type d \( -name node_modules -o -name .git -o -name vendor -o -name venv -o -name .venv -o -name pyvenv -o -name cache \) -prune \) -o \
            \( -type f \( \( -perm -4000 -a -perm -0100 \) -o \( -perm -2000 -a -perm -0010 \) \) -print \) 2>/dev/null | head -n 300 || true
    } | sort -u > "$list_file"
    while IFS= read -r path; do
        [[ -n "$path" ]] || continue
        if have file; then
            desc="$(file -Lb -- "$path" 2>/dev/null || true)"
            if ! grep -Eqi '(executable|script|shared object)' <<< "$desc"; then
                skipped_nonexec=$((skipped_nonexec + 1))
                continue
            fi
        fi
        total=$((total + 1)); package=""
        case "$path" in
            /usr/local/*|/opt/*|/home/*) ;;
            *) package="$(dpkg_owner_for_path "$path")" ;;
        esac
        if [[ -n "$package" ]]; then
            packaged_count=$((packaged_count + 1))
        else
            local_count=$((local_count + 1)); local_paths+="$path,"
        fi
    done < "$list_file"
    if (( local_count > 0 )); then
        add_result "FS-SUID-LOCAL-001" "filesystem" "WARN" "HIGH" "HIGH" \
            "Local or unowned privileged executables were found" \
            "executable_total=$total; package_owned=$packaged_count; local_or_unowned=$local_count; skipped_nonexecutable_setid=$skipped_nonexec; paths=$(shorten "${local_paths%,}" 1000)." \
            "find executable directories -type f with SUID/SGID; file PATH; dpkg-query -S PATH" \
            "Verify each local privileged executable, its provenance, owner, mode and continued necessity."
    else
        add_result "FS-SUID-LOCAL-001" "filesystem" "PASS" "INFO" "MEDIUM" \
            "Privileged executables are package-owned or absent" \
            "executable_total=$total; package_owned=$packaged_count; local=0; skipped_nonexecutable_setid=$skipped_nonexec." \
            "find executable directories -type f with SUID/SGID" \
            "Review package-owned privileged binaries after major package changes."
    fi
    add_result "FS-SUID-INVENTORY-001" "filesystem" "INFO" "INFO" "MEDIUM" \
        "SUID and SGID executable inventory summary" \
        "executable_total=$total; package_owned=$packaged_count; local_or_unowned=$local_count; nonexecutable_setid_ignored=$skipped_nonexec." \
        "inspect $list_file" "Only executable files are security-scored; set-ID bits on non-executable data files are ignored."
}

check_path_ownership_v07() {
    local scan_file="$TMP_DIR/path-risk-scan" ww_files ww_dirs orphan files_count dirs_count orphan_count
    : > "$scan_file"
    capture 35 find /etc /usr/local /opt /var/www /root /home -xdev -maxdepth 7 \
        \( -type d \( -name node_modules -o -name .git -o -name vendor -o -name venv -o -name .venv -o -name pyvenv -o -name cache -o -name caches \) -prune \) -o \
        \( -type f -perm -0002 -printf 'WWF|%p\n' \) -o \
        \( -type d -perm -0002 ! -perm -1000 -printf 'WWD|%p\n' \) -o \
        \( \( -nouser -o -nogroup \) -printf 'ORPHAN|%p\n' \) 2>/dev/null | head -n 300 > "$scan_file" || true
    ww_files="$(awk -F'|' '$1=="WWF" {print $2}' "$scan_file" | head -n 30)"
    ww_dirs="$(awk -F'|' '$1=="WWD" {print $2}' "$scan_file" | head -n 30)"
    orphan="$(awk -F'|' '$1=="ORPHAN" {print $2}' "$scan_file" | head -n 30)"
    files_count="$(grep -c '^WWF|' "$scan_file" || true)"; dirs_count="$(grep -c '^WWD|' "$scan_file" || true)"; orphan_count="$(grep -c '^ORPHAN|' "$scan_file" || true)"
    if [[ -n "$ww_files" ]]; then
        add_result "FS-WORLD-WRITABLE-FILE" "filesystem" "FAIL" "HIGH" "HIGH" \
            "World-writable regular files exist in selected sensitive paths" "count=$files_count; sample=$(shorten "$ww_files" 1000)." \
            "find selected sensitive paths -type f -perm -0002 -ls" \
            "Remove world-write permission and identify the process or user that required it."
    else
        add_result "FS-WORLD-WRITABLE-FILE" "filesystem" "PASS" "INFO" "MEDIUM" \
            "No world-writable regular file was found in the bounded sensitive-path scan" \
            "roots=/etc,/usr/local,/opt,/var/www,/root,/home; maxdepth=7; large dependency and cache trees were pruned." \
            "find selected sensitive paths -type f -perm -0002 -ls" "No action required."
    fi
    if [[ -n "$ww_dirs" ]]; then
        add_result "FS-WORLD-WRITABLE-DIR" "filesystem" "WARN" "MEDIUM" "HIGH" \
            "World-writable directories without sticky-bit protection exist" "count=$dirs_count; sample=$(shorten "$ww_dirs" 1000)." \
            "find selected sensitive paths -type d -perm -0002 ! -perm -1000 -ls" \
            "Restrict write access or add sticky-bit protection only when shared-write semantics are intended."
    else
        add_result "FS-WORLD-WRITABLE-DIR" "filesystem" "PASS" "INFO" "MEDIUM" \
            "No unsafe world-writable directory was found in the bounded sensitive-path scan" \
            "roots=/etc,/usr/local,/opt,/var/www,/root,/home; maxdepth=7; pruned dependency and cache trees." \
            "find selected sensitive paths -type d -perm -0002 ! -perm -1000 -ls" "No action required."
    fi
    if [[ -n "$orphan" ]]; then
        add_result "FS-ORPHAN-ID-001" "filesystem" "WARN" "MEDIUM" "HIGH" \
            "Files with orphaned user or group IDs were found" "count=$orphan_count; sample=$(shorten "$orphan" 1000)." \
            "find selected sensitive paths \\( -nouser -o -nogroup \\) -ls" \
            "Assign the intended owner or remove obsolete files after validating their purpose."
    else
        add_result "FS-ORPHAN-ID-001" "filesystem" "PASS" "INFO" "MEDIUM" \
            "No orphaned user or group ID was found in the bounded sensitive-path scan" \
            "roots=/etc,/usr/local,/opt,/var/www,/root,/home; maxdepth=7." \
            "find selected sensitive paths \\( -nouser -o -nogroup \\) -ls" "No action required."
    fi

    if have getfacl; then
        local acl_files="$TMP_DIR/acl-files" acl_findings="" acl_count=0 f acl
        : > "$acl_files"
        find /etc/sudoers.d /etc/systemd/system /etc/cron.d /root/.ssh /home/*/.ssh -maxdepth 2 -type f -readable -print 2>/dev/null | head -n 200 > "$acl_files"
        while IFS= read -r f; do
            acl="$(getfacl -cp -- "$f" 2>/dev/null || true)"
            if grep -Eq '^(user|group):[^:]+:.*w|^mask::.*w' <<< "$acl"; then acl_findings+="$f,"; acl_count=$((acl_count + 1)); fi
        done < "$acl_files"
        if (( acl_count > 0 )); then
            add_result "FS-ACL-SENSITIVE-001" "filesystem" "WARN" "MEDIUM" "MEDIUM" \
                "Sensitive files have additional writable ACL entries" "count=$acl_count; paths=$(shorten "${acl_findings%,}" 900)." \
                "getfacl -cp FILE" "Confirm every named ACL principal and remove unintended write access."
        else
            add_result "FS-ACL-SENSITIVE-001" "filesystem" "PASS" "INFO" "MEDIUM" \
                "No additional writable ACL was found on selected sensitive files" "files_checked=$(wc -l < "$acl_files" | tr -d ' ')." \
                "getfacl -cp FILE" "No action required."
        fi
    else
        add_result "FS-ACL-SENSITIVE-001" "filesystem" "SKIP" "INFO" "HIGH" \
            "Sensitive ACLs were not inspected" "getfacl is unavailable." "command -v getfacl" \
            "Install the acl tools only when this local diagnostic is desired."
    fi
}

admin_login_backend_v011() {
    if have lastlog2; then
        printf 'lastlog2'
    elif have lastlog; then
        printf 'lastlog'
    elif have lslogins; then
        printf 'lslogins'
    else
        printf 'unavailable'
    fi
}

admin_last_login_value_v011() {
    local user="$1" backend row date_text epoch
    backend="$(admin_login_backend_v011)"
    case "$backend" in
        lastlog2|lastlog)
            row="$("$backend" -u "$user" 2>/dev/null | tail -n1 || true)"
            if grep -Eqi 'Never logged( in)?' <<< "$row"; then
                printf 'never'
                return 0
            fi
            date_text="$(awk '{for(i=4;i<=NF;i++) printf "%s%s", $i, (i<NF?OFS:ORS)}' <<< "$row")"
            ;;
        lslogins)
            row="$(lslogins --logins "$user" --noheadings --notruncate --time-format iso --raw --output USER,LAST-LOGIN 2>/dev/null | head -n1 || true)"
            date_text="${row#"$user"}"
            date_text="$(trim "$date_text")"
            if [[ -z "$date_text" || "$date_text" == "$row" ]]; then
                printf 'never'
                return 0
            fi
            ;;
        *)
            printf 'unavailable'
            return 0
            ;;
    esac
    epoch="$(date -d "$date_text" +%s 2>/dev/null || true)"
    if [[ "$epoch" =~ ^[0-9]+$ ]]; then
        printf '%s' "$epoch"
    else
        printf 'unknown'
    fi
}

check_identity_policy_v07() {
    local login_defs max_days min_days warn_age interactive="" aging_weak="" service_shells="" admin_users="" user uid shell pass lastchg min max warn inactive expire
    max_days="$(awk '$1=="PASS_MAX_DAYS" {print $2}' /etc/login.defs 2>/dev/null | tail -n1)"
    min_days="$(awk '$1=="PASS_MIN_DAYS" {print $2}' /etc/login.defs 2>/dev/null | tail -n1)"
    warn_age="$(awk '$1=="PASS_WARN_AGE" {print $2}' /etc/login.defs 2>/dev/null | tail -n1)"
    add_result "AUTH-AGING-POLICY-001" "accounts" "INFO" "INFO" "HIGH" \
        "Default password-aging policy inventory" \
        "PASS_MAX_DAYS=${max_days:-unset}; PASS_MIN_DAYS=${min_days:-unset}; PASS_WARN_AGE=${warn_age:-unset}; existing accounts may override these defaults." \
        "grep -E '^[[:space:]]*PASS_(MAX|MIN|WARN)' /etc/login.defs; chage -l USER" \
        "Use password aging only where local passwords are part of the authentication model."

    while IFS=: read -r user pass lastchg min max warn inactive expire _; do
        uid="$(getent passwd "$user" 2>/dev/null | cut -d: -f3)"; shell="$(getent passwd "$user" 2>/dev/null | cut -d: -f7)"
        [[ "$uid" =~ ^[0-9]+$ ]] || continue
        if [[ "$shell" =~ /(nologin|false)$ ]]; then continue; fi
        if (( uid == 0 || uid >= 1000 )); then
            interactive+="$user(uid=$uid,shell=$shell,max=${max:-unset}),"
            if [[ "$pass" != '!'* && "$pass" != '*'* && ( -z "$max" || "$max" == "99999" ) ]]; then aging_weak+="$user,"; fi
        elif [[ "$pass" != '!'* && "$pass" != '*'* ]]; then
            service_shells+="$user(uid=$uid,shell=$shell),"
        fi
    done < /etc/shadow 2>/dev/null
    if [[ -n "$aging_weak" ]]; then
        add_result "AUTH-AGING-USERS-001" "accounts" "WARN" "LOW" "MEDIUM" \
            "Some interactive local-password accounts have no practical password expiry" \
            "accounts=${aging_weak%,}; interactive_inventory=$(shorten "${interactive%,}" 900)." \
            "chage -l USER; getent shadow USER" \
            "Use expiry only when required by policy; key-only and service identities may be handled differently."
    else
        add_result "AUTH-AGING-USERS-001" "accounts" "PASS" "INFO" "MEDIUM" \
            "No obviously unlimited interactive local-password account was identified" \
            "interactive_inventory=$(shorten "${interactive:-none}" 900)." \
            "chage -l USER; getent shadow USER" "No action required."
    fi
    if [[ -n "$service_shells" ]]; then
        add_result "AUTH-SERVICE-SHELL-001" "accounts" "WARN" "MEDIUM" "MEDIUM" \
            "Unlocked system accounts have interactive shells" "accounts=${service_shells%,}." \
            "awk -F: '\$3<1000 && \$7 !~ /(nologin|false)$/ {print}' /etc/passwd; passwd -S USER" \
            "Confirm each account requires interactive login; otherwise lock it and use nologin."
    else
        add_result "AUTH-SERVICE-SHELL-001" "accounts" "PASS" "INFO" "MEDIUM" \
            "No unlocked system account with an interactive shell was identified" "UID<1000 accounts were correlated with shadow lock state." \
            "awk -F: '\$3<1000 && \$7 !~ /(nologin|false)$/ {print}' /etc/passwd" "No action required."
    fi

    admin_users="$({ getent group sudo 2>/dev/null | cut -d: -f4 | tr ',' '\n'; getent group admin 2>/dev/null | cut -d: -f4 | tr ',' '\n'; } | sed '/^$/d' | sort -u | paste -sd, -)"
    add_result "AUTH-ADMIN-USERS-001" "accounts" "INFO" "INFO" "HIGH" \
        "Administrative group membership inventory" "sudo_or_admin_members=${admin_users:-none}; root is reported separately through UID 0 checks." \
        "getent group sudo; getent group admin" "Review administrative membership after role or personnel changes."

    local admin activity="" stale="" epoch_value age now shadow_field login_backend
    now="$(date +%s)"
    login_backend="$(admin_login_backend_v011)"
    IFS=',' read -ra _admins <<< "$admin_users"
    for admin in "${_admins[@]}"; do
        [[ -n "$admin" ]] || continue
        epoch_value="$(admin_last_login_value_v011 "$admin")"
        case "$epoch_value" in
            never) activity+="$admin=never," ;;
            unavailable) activity+="$admin=login-history-unavailable," ;;
            unknown) activity+="$admin=unknown," ;;
            *)
                if [[ "$epoch_value" =~ ^[0-9]+$ ]]; then
                    age=$(( (now - epoch_value) / 86400 )); activity+="$admin=${age}d,"
                    shadow_field="$(getent shadow "$admin" 2>/dev/null | cut -d: -f2)"
                    if (( age > 365 )) && [[ "$shadow_field" != '!'* && "$shadow_field" != '*'* ]]; then stale+="$admin(${age}d),"; fi
                else
                    activity+="$admin=unknown,"
                fi
                ;;
        esac
    done
    if [[ -n "$stale" ]]; then
        add_result "AUTH-ADMIN-ACTIVITY-001" "accounts" "WARN" "MEDIUM" "MEDIUM" \
            "Unlocked administrative accounts appear stale" "backend=$login_backend; accounts=${stale%,}; activity=${activity%,}." \
            "lastlog2 -u USER; lastlog -u USER; lslogins --logins USER --output USER,LAST-LOGIN; getent group sudo; passwd -S USER" \
            "Confirm ownership and current need before locking or removing an administrative account."
    else
        add_result "AUTH-ADMIN-ACTIVITY-001" "accounts" "INFO" "INFO" "MEDIUM" \
            "Administrative last-login context" "backend=$login_backend; activity=${activity:-no non-root administrative member detected}; stale_threshold_days=365." \
            "lastlog2 -u USER; lastlog -u USER; lslogins --logins USER --output USER,LAST-LOGIN; getent group sudo" \
            "A never-used account is not automatically stale; review it against its provisioning purpose."
    fi
}

check_sudo_context_v07() {
    local rules nopass_all command_nopass all_rules dangerous_count scoped_count total
    rules="$({ awk -v file=/etc/sudoers '/^[[:space:]]*(#|$)/ {next} {print file ":" NR ":" $0}' /etc/sudoers 2>/dev/null; for f in /etc/sudoers.d/*; do [[ -f "$f" ]] && awk -v file="$f" '/^[[:space:]]*(#|$)/ {next} {print file ":" NR ":" $0}' "$f"; done; } | head -n 200)"
    total="$(grep -c . <<< "$rules" || true)"
    nopass_all="$(grep -Ei 'NOPASSWD:[[:space:]]*(ALL|ALL[[:space:]]*$)' <<< "$rules" || true)"
    command_nopass="$(grep -Ei 'NOPASSWD:' <<< "$rules" | grep -Eiv 'NOPASSWD:[[:space:]]*(ALL|ALL[[:space:]]*$)' || true)"
    all_rules="$(grep -Ei 'ALL[[:space:]]*=\([^)]+\)[[:space:]]*(ALL:ALL[[:space:]]+)?ALL([[:space:]]|$)' <<< "$rules" || true)"
    dangerous_count="$(grep -c . <<< "$nopass_all" || true)"; scoped_count="$(grep -c . <<< "$command_nopass" || true)"
    if [[ -n "$nopass_all" ]]; then
        add_result "AUTH-SUDO-NOPASS-ALL" "accounts" "FAIL" "HIGH" "HIGH" \
            "Unrestricted passwordless sudo rule was found" "count=$dangerous_count; locations=$(shorten "$nopass_all" 1000)." \
            "visudo -c; grep -Rni 'NOPASSWD' /etc/sudoers /etc/sudoers.d" \
            "Replace unrestricted passwordless elevation with narrowly scoped commands or an approved automation identity."
    else
        add_result "AUTH-SUDO-NOPASS-ALL" "accounts" "PASS" "INFO" "HIGH" \
            "No unrestricted passwordless sudo rule was found" "active_rules=$total; scoped_nopasswd=$scoped_count." \
            "grep -Rni 'NOPASSWD' /etc/sudoers /etc/sudoers.d" "No action required."
    fi
    add_result "AUTH-SUDO-CONTEXT-001" "accounts" "INFO" "INFO" "MEDIUM" \
        "Command-level sudo policy inventory" \
        "active_rules=$total; full_admin_rules=$(grep -c . <<< "$all_rules" || true); scoped_nopasswd=$scoped_count; scoped_locations=$(shorten "${command_nopass:-none}" 900)." \
        "visudo -c; grep -RniEv '^[[:space:]]*(#|$)' /etc/sudoers /etc/sudoers.d" \
        "Review wildcard arguments, writable command paths and command-scoped NOPASSWD rules manually."
}

check_apparmor_coverage_v07() {
    local aa profiles enforcing complain unconfined exposed="" process pid binary covered=0 uncovered=0 item
    if ! have aa-status; then
        add_result "KERN-APPARMOR-COVERAGE" "kernel" "INFO" "INFO" "HIGH" \
            "AppArmor workload coverage was not inspected" "aa-status is unavailable." "command -v aa-status" \
            "AppArmor is optional but useful for exposed services."
        return
    fi
    aa="$(aa-status 2>/dev/null || true)"
    profiles="$(sed -nE 's/^[[:space:]]*([0-9]+) profiles are loaded.*/\1/p' <<< "$aa" | head -n1)"
    enforcing="$(sed -nE 's/^[[:space:]]*([0-9]+) profiles are in enforce mode.*/\1/p' <<< "$aa" | head -n1)"
    complain="$(sed -nE 's/^[[:space:]]*([0-9]+) profiles are in complain mode.*/\1/p' <<< "$aa" | head -n1)"
    if have ss; then
        while IFS= read -r item; do
            pid="$(sed -nE 's/.*pid=([0-9]+).*/\1/p' <<< "$item" | head -n1)"; [[ "$pid" =~ ^[0-9]+$ ]] || continue
            binary="$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)"; [[ -n "$binary" ]] || continue
            process="$(basename "$binary")"
            grep -Fq "$binary" <<< "$aa" && covered=$((covered + 1)) || uncovered=$((uncovered + 1))
            exposed+="$process:$binary," 
        done < <(ss -H -lntup 2>/dev/null | awk '$5 ~ /^(0\.0\.0\.0:|\[::\]:)/ {print}' | head -n 30)
    fi
    add_result "KERN-APPARMOR-COVERAGE" "kernel" "INFO" "INFO" "MEDIUM" \
        "AppArmor profile and exposed-process coverage context" \
        "profiles_loaded=${profiles:-unknown}; enforce=${enforcing:-unknown}; complain=${complain:-unknown}; exposed_process_instances=$((covered+uncovered)); apparent_profile_matches=$covered; unmatched=$uncovered; processes=$(shorten "${exposed:-none}" 900)." \
        "aa-status; ss -lntup; readlink -f /proc/PID/exe" \
        "Profile-name matching is approximate; confirm exposed service confinement with aa-status and service-specific tests."
}

check_security_controls_v07() {
    local unit active enabled status jail_status jails ssh_jail bouncers audit_state rules lost enabled_mode

    if have fail2ban-client || systemctl list-unit-files fail2ban.service --no-legend 2>/dev/null | grep -q fail2ban; then
        active="$(systemctl is-active fail2ban.service 2>/dev/null || true)"; enabled="$(systemctl is-enabled fail2ban.service 2>/dev/null || true)"
        jail_status="$(capture 15 fail2ban-client status 2>/dev/null || true)"; jails="$(sed -nE 's/.*Jail list:[[:space:]]*(.*)/\1/p' <<< "$jail_status" | tail -n1)"
        grep -Eqi '(^|,[[:space:]]*)sshd([[:space:]]*,|$)' <<< "$jails" && ssh_jail=1 || ssh_jail=0
        status="INFO"; [[ "$active" == "active" ]] && status="PASS"; [[ "$active" == "failed" ]] && status="WARN"
        add_result "CTRL-FAIL2BAN-001" "controls" "$status" "$([[ "$status" == WARN ]] && printf MEDIUM || printf INFO)" "HIGH" \
            "Fail2ban service and jail inventory" "active=${active:-unknown}; enabled=${enabled:-unknown}; jails=${jails:-none-or-unavailable}; sshd_jail=$ssh_jail." \
            "systemctl status fail2ban; fail2ban-client status" \
            "Use an SSH jail only when it complements the authentication and firewall design; absence is not an automatic failure."
    else
        add_result "CTRL-FAIL2BAN-001" "controls" "INFO" "INFO" "HIGH" \
            "Fail2ban was not detected" "No fail2ban binary or unit was found." "command -v fail2ban-client; systemctl status fail2ban" \
            "This is neutral; key-only SSH, rate limiting or another control may be used."
    fi

    if have cscli || systemctl list-unit-files crowdsec.service --no-legend 2>/dev/null | grep -q crowdsec; then
        active="$(systemctl is-active crowdsec.service 2>/dev/null || true)"; enabled="$(systemctl is-enabled crowdsec.service 2>/dev/null || true)"
        bouncers="$(capture 15 cscli bouncers list -o raw 2>/dev/null | awk 'NF {count++} END {print count+0}' || true)"
        status="INFO"; [[ "$active" == "active" ]] && status="PASS"; [[ "$active" == "failed" ]] && status="WARN"
        add_result "CTRL-CROWDSEC-001" "controls" "$status" "$([[ "$status" == WARN ]] && printf MEDIUM || printf INFO)" "MEDIUM" \
            "CrowdSec service and bouncer inventory" "active=${active:-unknown}; enabled=${enabled:-unknown}; bouncer_rows=${bouncers:-unknown}; no API keys were collected." \
            "systemctl status crowdsec; cscli bouncers list" \
            "Confirm at least one enforcement bouncer when CrowdSec decisions are expected to block traffic."
    else
        add_result "CTRL-CROWDSEC-001" "controls" "INFO" "INFO" "HIGH" \
            "CrowdSec was not detected" "No cscli binary or crowdsec unit was found." "command -v cscli; systemctl status crowdsec" \
            "This is neutral; another intrusion-prevention design may be used."
    fi

    if have auditctl || systemctl list-unit-files auditd.service --no-legend 2>/dev/null | grep -q auditd; then
        active="$(systemctl is-active auditd.service 2>/dev/null || true)"; enabled="$(systemctl is-enabled auditd.service 2>/dev/null || true)"
        audit_state="$(capture 15 auditctl -s 2>/dev/null || true)"; rules="$(capture 15 auditctl -l 2>/dev/null | grep -cv '^No rules' || true)"
        lost="$(awk '$1=="lost" {print $2}' <<< "$audit_state")"; enabled_mode="$(awk '$1=="enabled" {print $2}' <<< "$audit_state")"
        status="INFO"; [[ "$active" == "active" ]] && status="PASS"; [[ "$active" == "failed" || ( "$lost" =~ ^[0-9]+$ && "$lost" -gt 0 ) ]] && status="WARN"
        add_result "CTRL-AUDITD-001" "controls" "$status" "$([[ "$status" == WARN ]] && printf MEDIUM || printf INFO)" "MEDIUM" \
            "Linux audit subsystem inventory" "active=${active:-unknown}; enabled_at_boot=${enabled:-unknown}; kernel_enabled=${enabled_mode:-unknown}; loaded_rules=${rules:-unknown}; lost_records=${lost:-unknown}." \
            "systemctl status auditd; auditctl -s; auditctl -l" \
            "Auditd is optional for small VPS workloads; when used, review rule relevance, backlog loss and log rotation."
    else
        add_result "CTRL-AUDITD-001" "controls" "INFO" "INFO" "HIGH" \
            "auditd was not detected" "No auditctl binary or auditd unit was found." "command -v auditctl; systemctl status auditd" \
            "This is neutral unless audit logging is required by policy or regulation."
    fi
}

check_host_hardening_identity_v07() {
    check_sysctl_extended_v07
    check_mount_hardening_v07
    check_privileged_files_v07
    check_path_ownership_v07
    check_identity_policy_v07
    check_sudo_context_v07
    check_apparmor_coverage_v07
    check_security_controls_v07
}

mode_has_group_or_other_bits() {
    local mode="$1"
    [[ "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
    mode="${mode: -3}"
    (( 8#${mode:1:1} != 0 || 8#${mode:2:1} != 0 ))
}

collect_tor_units_v010() {
    local unit active sub enabled
    local -a candidates=()
    local -A seen=()
    while IFS= read -r unit; do
        [[ -n "$unit" && -z "${seen[$unit]+x}" ]] || continue
        seen["$unit"]=1; candidates+=("$unit")
    done < <(
        {
            systemctl list-units --type=service --all --no-legend --plain 2>/dev/null | awk '$1 ~ /^tor(@.*)?\.service$/ {print $1}'
            systemctl list-unit-files --type=service --no-legend --plain 2>/dev/null | awk '$1 ~ /^tor(@.*)?\.service$/ {print $1}'
        } | sort -u
    )
    for unit in "${candidates[@]}"; do
        active="$(systemctl show "$unit" -p ActiveState --value 2>/dev/null || true)"
        sub="$(systemctl show "$unit" -p SubState --value 2>/dev/null || true)"
        enabled="$(systemctl is-enabled "$unit" 2>/dev/null || true)"
        printf '%s=%s/%s/%s\n' "$unit" "${active:-unknown}" "${sub:-unknown}" "${enabled:-unknown}"
    done | paste -sd, -
}

check_tor_v08() {
    local unit_dump detected=0 configs=() file active_lines inventory="" units socks control control_socket cookie hashed
    local hidden_dirs=() hidden_ports=0 dir stat_out owner group mode bad_dirs="" bad_keys="" key verify_out verify_rc status severity
    unit_dump="$(systemctl list-unit-files --no-legend --plain 2>/dev/null || true)"
    if have tor || grep -Eq '^tor(@|\\.)' <<< "$unit_dump" || [[ -d $TOR_CONFIG_ROOT ]]; then detected=1; fi
    if (( ! detected )); then
        add_result "TOR-DETECT-001" "tor" "INFO" "INFO" "HIGH" \
            "Tor was not detected" "No tor binary, unit or $TOR_CONFIG_ROOT directory was found." \
            "command -v tor; systemctl list-unit-files 'tor*'; ls -ld $TOR_CONFIG_ROOT" \
            "This is neutral when the host is not intended to provide Tor services."
        return
    fi

    while IFS= read -r file; do [[ -f "$file" && -r "$file" ]] && configs+=("$file"); done < <(
        find $TOR_CONFIG_ROOT -maxdepth 4 -type f -name 'torrc*' -readable 2>/dev/null | sort -u
    )
    active_lines="$({ for file in "${configs[@]:-}"; do awk 'BEGIN{IGNORECASE=1} /^[[:space:]]*#/ || /^[[:space:]]*$/ {next} {print}' "$file"; done; } 2>/dev/null)"
    units="$(collect_tor_units_v010)"
    socks="$(awk 'tolower($1)=="socksport" {print $2}' <<< "$active_lines" | paste -sd, -)"
    control="$(awk 'tolower($1)=="controlport" {print $2}' <<< "$active_lines" | paste -sd, -)"
    control_socket="$(awk 'tolower($1)=="controlsocket" {print $2}' <<< "$active_lines" | paste -sd, -)"
    cookie="$(awk 'tolower($1)=="cookieauthentication" {print tolower($2)}' <<< "$active_lines" | tail -n1)"
    hashed="$(awk 'tolower($1)=="hashedcontrolpassword" {count++} END{print count+0}' <<< "$active_lines")"
    while IFS= read -r dir; do [[ -n "$dir" ]] && hidden_dirs+=("$dir"); done < <(awk 'tolower($1)=="hiddenservicedir" {print $2}' <<< "$active_lines" | sort -u)
    hidden_ports="$(awk 'tolower($1)=="hiddenserviceport" {count++} END{print count+0}' <<< "$active_lines")"
    inventory="configs=${#configs[@]}; units=${units:-none}; socks_ports=${socks:-default-or-none}; control_ports=${control:-none}; control_sockets=${control_socket:-none}; hidden_service_dirs=${#hidden_dirs[@]}; hidden_service_ports=$hidden_ports."
    add_result "TOR-INVENTORY-001" "tor" "INFO" "INFO" "HIGH" \
        "Tor instance and endpoint inventory" "$inventory" \
        "systemctl list-units 'tor*'; grep -RniE '^(SocksPort|ControlPort|ControlSocket|HiddenServiceDir|HiddenServicePort|CookieAuthentication|HashedControlPassword)' $TOR_CONFIG_ROOT" \
        "Confirm each Tor instance, endpoint and hidden service matches the intended deployment."

    if [[ -n "$control" && "$cookie" != "1" && "$cookie" != "true" && "$hashed" == "0" && -z "$control_socket" ]]; then
        add_result "TOR-CONTROL-AUTH-001" "tor" "FAIL" "HIGH" "HIGH" \
            "Tor control endpoint lacks an inferred authentication mechanism" \
            "control_ports=$control; CookieAuthentication=${cookie:-unset}; HashedControlPassword_count=$hashed; ControlSocket=${control_socket:-none}." \
            "grep -RniE '^(ControlPort|ControlSocket|CookieAuthentication|HashedControlPassword)' $TOR_CONFIG_ROOT" \
            "Require cookie or hashed-password authentication and keep control endpoints local."
    elif [[ -n "$control" || -n "$control_socket" ]]; then
        add_result "TOR-CONTROL-AUTH-001" "tor" "PASS" "INFO" "MEDIUM" \
            "Tor control authentication is configured" \
            "control_ports=${control:-none}; control_sockets=${control_socket:-none}; cookie_auth=${cookie:-unset}; hashed_password_entries=$hashed." \
            "grep -RniE '^(ControlPort|ControlSocket|CookieAuthentication|HashedControlPassword)' $TOR_CONFIG_ROOT" \
            "Keep the control interface local and restrict its cookie or socket permissions."
    else
        add_result "TOR-CONTROL-AUTH-001" "tor" "INFO" "INFO" "HIGH" \
            "No Tor control endpoint was configured" "No active ControlPort or ControlSocket directive was inferred." \
            "grep -RniE '^(ControlPort|ControlSocket)' $TOR_CONFIG_ROOT" "No action required."
    fi

    for dir in "${hidden_dirs[@]:-}"; do
        [[ -e "$dir" ]] || { bad_dirs+="$dir(missing),"; continue; }
        stat_out="$(stat -Lc '%U|%G|%a' -- "$dir" 2>/dev/null || true)"
        IFS='|' read -r owner group mode <<< "$stat_out"
        if [[ -z "$mode" ]] || mode_has_group_or_other_bits "$mode"; then bad_dirs+="$dir(owner=$owner,group=$group,mode=$mode),"; fi
        for key in "$dir"/private_key "$dir"/hs_ed25519_secret_key; do
            [[ -f "$key" ]] || continue
            stat_out="$(stat -Lc '%U|%G|%a' -- "$key" 2>/dev/null || true)"
            IFS='|' read -r owner group mode <<< "$stat_out"
            if [[ -z "$mode" ]] || mode_has_group_or_other_bits "$mode"; then bad_keys+="$key(owner=$owner,group=$group,mode=$mode),"; fi
        done
    done
    if [[ -n "$bad_dirs$bad_keys" ]]; then
        add_result "TOR-HS-PERM-001" "tor" "FAIL" "HIGH" "HIGH" \
            "Tor hidden-service material has unsafe or missing permissions" \
            "directories=${bad_dirs%,}; secret_keys=${bad_keys%,}." \
            "find /var/lib/tor /var/lib/tor-instances -maxdepth 4 -type d -o -name private_key -o -name hs_ed25519_secret_key | xargs stat" \
            "Restrict hidden-service directories and secret keys to the Tor service identity."
    elif (( ${#hidden_dirs[@]} > 0 )); then
        add_result "TOR-HS-PERM-001" "tor" "PASS" "INFO" "HIGH" \
            "Tor hidden-service directories and secret keys are restricted" \
            "hidden_service_dirs=${#hidden_dirs[@]}; no group or other permission bit was found on selected sensitive paths." \
            "find selected HiddenServiceDir paths -maxdepth 1 -exec stat -c '%U %G %a %n' {} +" \
            "No action required."
    fi

    if have tor && (( ${#configs[@]} > 0 )); then
        local tor_user="" current_user
        current_user="$(id -un 2>/dev/null || printf unknown)"
        if (( ${#hidden_dirs[@]} > 0 )) && [[ -e "${hidden_dirs[0]}" ]]; then tor_user="$(stat -Lc '%U' -- "${hidden_dirs[0]}" 2>/dev/null || true)"; fi
        [[ -n "$tor_user" ]] || { getent passwd debian-tor >/dev/null 2>&1 && tor_user="debian-tor"; }
        if (( RUN_AS_ROOT )) && [[ -n "$tor_user" && "$tor_user" != "root" ]]; then
            verify_out="$(capture_potentially_networked 20 runuser -u "$tor_user" -- tor --verify-config -f "${configs[0]}" 2>&1)"; verify_rc=$?
        elif [[ -n "$tor_user" && "$tor_user" != "$current_user" ]]; then
            verify_out="Validation requires the Tor service user $tor_user, but root privileges are unavailable."; verify_rc=126
        else
            verify_out="$(capture_potentially_networked 20 tor --verify-config -f "${configs[0]}" 2>&1)"; verify_rc=$?
        fi
        if (( verify_rc == 0 )); then status="PASS"; severity="INFO"
        elif (( verify_rc == 125 || verify_rc == 126 )); then status="SKIP"; severity="INFO"
        else status="FAIL"; severity="HIGH"; fi
        add_result "TOR-CONFIG-001" "tor" "$status" "$severity" "HIGH" \
            "Tor configuration validation" \
            "$([[ $verify_rc -eq 125 ]] && printf 'Offline network isolation was unavailable, so tor --verify-config was not run.' || shorten "$verify_out" 1200); validation_user=${tor_user:-$current_user}." \
            "$([[ -n "$tor_user" && "$tor_user" != "root" ]] && printf 'sudo -u %q -- tor --verify-config -f %q' "$tor_user" "${configs[0]}" || printf 'tor --verify-config -f %q' "${configs[0]}")" \
            "$([[ "$status" == FAIL ]] && printf 'Correct the configuration before restarting Tor.' || printf 'No action required.')"
    fi
}

check_wireguard_v08() {
    local unit_dump configs=() file stat_out owner group mode bad="" interfaces config_count active_count=0 listen_ports="" inline_keys=0 saveconfig=0
    unit_dump="$(systemctl list-unit-files --no-legend --plain 2>/dev/null || true)"
    if ! have wg && ! grep -q '^wg-quick@' <<< "$unit_dump" && [[ ! -d /etc/wireguard ]]; then return; fi
    while IFS= read -r file; do [[ -f "$file" ]] && configs+=("$file"); done < <(find /etc/wireguard -maxdepth 2 -type f -name '*.conf' 2>/dev/null | sort)
    for file in "${configs[@]:-}"; do
        stat_out="$(stat -Lc '%U|%G|%a' -- "$file" 2>/dev/null || true)"; IFS='|' read -r owner group mode <<< "$stat_out"
        if [[ -z "$mode" ]] || mode_has_group_or_other_bits "$mode"; then bad+="$file(owner=$owner,group=$group,mode=$mode),"; fi
        grep -Eqi '^[[:space:]]*PrivateKey[[:space:]]*=' "$file" && inline_keys=$((inline_keys + 1))
        grep -Eqi '^[[:space:]]*SaveConfig[[:space:]]*=[[:space:]]*true' "$file" && saveconfig=$((saveconfig + 1))
    done
    interfaces="$(capture 10 wg show interfaces 2>/dev/null || true)"
    [[ -n "$interfaces" ]] && active_count="$(wc -w <<< "$interfaces" | tr -d ' ')"
    if have wg; then
        local iface
        for iface in $interfaces; do listen_ports+="$iface:$(wg show "$iface" listen-port 2>/dev/null || printf unknown),"; done
    fi
    add_result "VPN-WG-INVENTORY-001" "vpn" "INFO" "INFO" "HIGH" \
        "WireGuard configuration and interface inventory" \
        "config_files=${#configs[@]}; active_interfaces=$active_count; interfaces=${interfaces:-none}; listen_ports=${listen_ports%,}; inline_private_keys=$inline_keys; saveconfig_enabled=$saveconfig." \
        "wg show; systemctl status 'wg-quick@*'; find /etc/wireguard -type f -name '*.conf' -exec stat -c '%U %G %a %n' {} +" \
        "Confirm interface ownership, routes, peer scope and listener exposure."
    if [[ -n "$bad" ]]; then
        add_result "VPN-WG-PERM-001" "vpn" "FAIL" "HIGH" "HIGH" \
            "WireGuard configuration files expose sensitive material" "files=${bad%,}; inline_private_key_files=$inline_keys." \
            "find /etc/wireguard -type f -name '*.conf' -exec stat -c '%U %G %a %n' {} +" \
            "Restrict configuration files containing private keys to root or the required service identity."
    elif (( ${#configs[@]} > 0 )); then
        add_result "VPN-WG-PERM-001" "vpn" "PASS" "INFO" "HIGH" \
            "WireGuard configuration files are permission-restricted" "config_files=${#configs[@]}; no group or other permission bit was found." \
            "find /etc/wireguard -type f -name '*.conf' -exec stat -c '%U %G %a %n' {} +" "No action required."
    fi
}

check_openvpn_v08() {
    local unit_dump configs=() file active management_bad="" key_bad="" server_count=0 client_count=0 script_high=0 keypath stat_out owner group mode
    unit_dump="$(systemctl list-unit-files --no-legend --plain 2>/dev/null || true)"
    if ! have openvpn && ! grep -Eq '^openvpn' <<< "$unit_dump" && [[ ! -d /etc/openvpn ]]; then return; fi
    while IFS= read -r file; do [[ -f "$file" ]] && configs+=("$file"); done < <(find /etc/openvpn -maxdepth 4 -type f \( -name '*.conf' -o -name '*.ovpn' \) 2>/dev/null | sort)
    for file in "${configs[@]:-}"; do
        active="$(awk '!/^[[:space:]]*[#;]/ && NF {print}' "$file" 2>/dev/null)"
        grep -Eqi '^[[:space:]]*server[[:space:]]' <<< "$active" && server_count=$((server_count + 1))
        grep -Eqi '^[[:space:]]*client([[:space:]]|$)' <<< "$active" && client_count=$((client_count + 1))
        while read -r _ host port password_file; do
            [[ -n "$host" ]] || continue
            case "$host" in 127.0.0.1|localhost|::1|unix) ;; *) management_bad+="$file:$host:$port," ;; esac
            [[ -n "$password_file" && "$password_file" != "stdin" && -f "$password_file" ]] || management_bad+="$file:management-without-password-file,"
        done < <(awk 'tolower($1)=="management" {print $0}' <<< "$active")
        awk 'tolower($1)=="script-security" && $2+0 >= 3 {found=1} END{exit !found}' <<< "$active" && script_high=$((script_high + 1)) || true
        while IFS= read -r keypath; do
            [[ "$keypath" == /* && -f "$keypath" ]] || continue
            stat_out="$(stat -Lc '%U|%G|%a' -- "$keypath" 2>/dev/null || true)"; IFS='|' read -r owner group mode <<< "$stat_out"
            if [[ -z "$mode" ]] || mode_has_group_or_other_bits "$mode"; then key_bad+="$keypath(owner=$owner,group=$group,mode=$mode),"; fi
        done < <(awk 'tolower($1) ~ /^(key|tls-auth|tls-crypt|secret)$/ {print $2}' <<< "$active")
    done
    add_result "VPN-OPENVPN-INVENTORY-001" "vpn" "INFO" "INFO" "HIGH" \
        "OpenVPN configuration inventory" \
        "config_files=${#configs[@]}; server_profiles=$server_count; client_profiles=$client_count; high_script_security_profiles=$script_high; units=$(systemctl list-units --type=service --all --no-legend 2>/dev/null | awk '$1 ~ /^openvpn/ {print $1"="$3"/"$4}' | paste -sd, -)." \
        "systemctl list-units 'openvpn*'; find /etc/openvpn -type f; grep active OpenVPN directives" \
        "Review management endpoints, script execution, key permissions and route ownership."
    if [[ -n "$management_bad" ]]; then
        add_result "VPN-OPENVPN-MGMT-001" "vpn" "FAIL" "HIGH" "HIGH" \
            "OpenVPN management interface may be remotely exposed or unauthenticated" "entries=${management_bad%,}." \
            "grep -RniE '^[[:space:]]*management[[:space:]]' /etc/openvpn" \
            "Bind management interfaces to loopback or a Unix socket and require a protected password file."
    fi
    if [[ -n "$key_bad" ]]; then
        add_result "VPN-OPENVPN-KEYS-001" "vpn" "FAIL" "HIGH" "HIGH" \
            "OpenVPN private key material has broad permissions" "files=${key_bad%,}." \
            "stat -c '%U %G %a %n' KEY_FILE" "Restrict private key material to the OpenVPN service identity and administrators."
    fi
}

check_tailscale_strongswan_v08() {
    local unit_dump active enabled status_json backend iface_count routes secrets_bad="" file stat_out owner group mode
    unit_dump="$(systemctl list-unit-files --no-legend --plain 2>/dev/null || true)"
    if have tailscale || grep -q '^tailscaled\\.service' <<< "$unit_dump"; then
        active="$(systemctl is-active tailscaled.service 2>/dev/null || true)"; enabled="$(systemctl is-enabled tailscaled.service 2>/dev/null || true)"
        status_json="$(capture 10 tailscale status --json 2>/dev/null || true)"
        backend="$(sed -nE 's/.*"BackendState"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p' <<< "$status_json" | head -n1)"
        iface_count="$(ip -o link show 2>/dev/null | grep -c 'tailscale0' || true)"
        add_result "VPN-TAILSCALE-001" "vpn" "$([[ "$active" == active ]] && printf PASS || printf WARN)" "$([[ "$active" == active ]] && printf INFO || printf MEDIUM)" "MEDIUM" \
            "Tailscale service and local-state inventory" \
            "active=${active:-unknown}; enabled=${enabled:-unknown}; backend_state=${backend:-unknown}; tailscale_interfaces=$iface_count; peer names and addresses were not retained." \
            "systemctl status tailscaled; tailscale status --json; ip addr show tailscale0" \
            "Confirm advertised routes, exit-node use and ACL policy in the Tailscale control plane."
    fi
    if have ipsec || grep -Eq '^(strongswan|strongswan-starter|charon)' <<< "$unit_dump" || [[ -d /etc/swanctl || -f /etc/ipsec.conf ]]; then
        active="$(systemctl is-active strongswan.service strongswan-starter.service 2>/dev/null | paste -sd, - || true)"
        for file in /etc/ipsec.secrets /etc/swanctl/conf.d/*.conf /etc/swanctl/private/*; do
            [[ -f "$file" ]] || continue
            case "$file" in /etc/swanctl/conf.d/*.conf) continue ;; esac
            stat_out="$(stat -Lc '%U|%G|%a' -- "$file" 2>/dev/null || true)"; IFS='|' read -r owner group mode <<< "$stat_out"
            if [[ -z "$mode" ]] || mode_has_group_or_other_bits "$mode"; then secrets_bad+="$file(owner=$owner,group=$group,mode=$mode),"; fi
        done
        add_result "VPN-STRONGSWAN-001" "vpn" "INFO" "INFO" "MEDIUM" \
            "strongSwan configuration and service inventory" \
            "service_states=${active:-unknown}; ipsec_conf=$([[ -f /etc/ipsec.conf ]] && printf present || printf absent); swanctl_conf=$([[ -d /etc/swanctl ]] && printf present || printf absent)." \
            "systemctl status strongswan strongswan-starter; ipsec statusall; swanctl --list-sas" \
            "Review connection ownership, traffic selectors, forwarding and firewall rules."
        if [[ -n "$secrets_bad" ]]; then
            add_result "VPN-STRONGSWAN-SECRETS-001" "vpn" "FAIL" "HIGH" "HIGH" \
                "strongSwan secret material has broad permissions" "files=${secrets_bad%,}." \
                "stat -c '%U %G %a %n' /etc/ipsec.secrets /etc/swanctl/private/*" \
                "Restrict PSKs and private keys to root or the strongSwan service identity."
        fi
    fi
    routes="$(ip route show table all 2>/dev/null | grep -E '(^|[[:space:]])(wg[0-9A-Za-z_.-]*|tun[0-9A-Za-z_.-]*|tap[0-9A-Za-z_.-]*|tailscale0)([[:space:]]|$)' | head -n 30 | paste -sd';' - || true)"
    add_result "VPN-ROUTE-001" "vpn" "INFO" "INFO" "MEDIUM" \
        "VPN interface, route and forwarding context" \
        "interfaces=$(ip -o link show 2>/dev/null | awk -F': ' '$2 ~ /^(wg|tun|tap|tailscale|ipsec|xfrm)/ {print $2}' | paste -sd, -); routes=${routes:-none}; ipv4_forward=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || printf unknown); ipv6_forward=$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null || printf unknown); firewall_v4=$NET_FW_V4_POLICY; firewall_v6=$NET_FW_V6_POLICY." \
        "ip addr; ip route show table all; sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding; nft list ruleset" \
        "Confirm that VPN server routes have matching forwarding and source-restricted firewall/NAT rules."
}

check_cloud_vps_v08() {
    local cloud_detected=0 cloud_status datasource sensitive_bad="" file stat_out owner group mode metadata_route virt
    local stat1 stat2 total1 steal1 total2 steal2 delta_total delta_steal steal_pct="unknown" steal_status="INFO" steal_severity="INFO"
    local mem_total swap_total balloon="none" cpu_max memory_max qga_state
    if have cloud-init || [[ -d /var/lib/cloud ]] || systemctl list-unit-files --no-legend 2>/dev/null | grep -Eq '^cloud-(init|config|final|init-local)\\.service'; then cloud_detected=1; fi
    if (( cloud_detected )); then
        cloud_status="$(capture 15 cloud-init status --long 2>/dev/null | tr '\n' ';' || true)"
        datasource="$(grep -Eo '"ds"[[:space:]]*:[[:space:]]*"[^"]+"|"datasource"[[:space:]]*:[[:space:]]*"[^"]+"' /run/cloud-init/result.json /var/lib/cloud/instance/instance-data.json 2>/dev/null | head -n1 | sed -E 's/.*:[[:space:]]*"([^"]+)"/\1/' || true)"
        for file in /var/lib/cloud/instance/user-data.txt /var/lib/cloud/instance/user-data.txt.i /var/lib/cloud/instance/instance-data-sensitive.json; do
            [[ -f "$file" ]] || continue
            stat_out="$(stat -Lc '%U|%G|%a' -- "$file" 2>/dev/null || true)"; IFS='|' read -r owner group mode <<< "$stat_out"
            if [[ -z "$mode" ]] || mode_has_group_or_other_bits "$mode"; then sensitive_bad+="$file(owner=$owner,group=$group,mode=$mode),"; fi
        done
        add_result "CLOUD-INIT-001" "cloud" "INFO" "INFO" "MEDIUM" \
            "cloud-init state and datasource inventory" \
            "datasource=${datasource:-unknown}; status=$(shorten "${cloud_status:-unknown}" 900); user-data contents were not collected." \
            "cloud-init status --long; cat /run/cloud-init/result.json; stat /var/lib/cloud/instance/user-data.txt" \
            "Remove stale provisioning data only after confirming rebuild and recovery requirements."
        if [[ -n "$sensitive_bad" ]]; then
            add_result "CLOUD-DATA-PERM-001" "cloud" "FAIL" "HIGH" "HIGH" \
                "cloud-init sensitive instance data has broad permissions" "files=${sensitive_bad%,}." \
                "stat -c '%U %G %a %n' /var/lib/cloud/instance/user-data.txt /var/lib/cloud/instance/instance-data-sensitive.json" \
                "Restrict user-data and sensitive instance-data files to root."
        else
            add_result "CLOUD-DATA-PERM-001" "cloud" "PASS" "INFO" "MEDIUM" \
                "cloud-init sensitive local files are permission-restricted or absent" \
                "Selected user-data and sensitive instance-data paths had no group or other permission bit." \
                "stat -c '%U %G %a %n' /var/lib/cloud/instance/user-data.txt /var/lib/cloud/instance/instance-data-sensitive.json" "No action required."
        fi
    else
        add_result "CLOUD-INIT-001" "cloud" "INFO" "INFO" "HIGH" \
            "cloud-init was not detected" "No cloud-init binary, state directory or unit was found." \
            "command -v cloud-init; systemctl list-unit-files 'cloud-*'; ls -ld /var/lib/cloud" \
            "This is neutral for manually provisioned VPS hosts."
    fi
    metadata_route="$(ip route get 169.254.169.254 2>/dev/null | head -n1 || true)"
    add_result "CLOUD-METADATA-001" "cloud" "INFO" "INFO" "MEDIUM" \
        "Cloud metadata-service route context" \
        "ipv4_metadata_route=${metadata_route:-unreachable-or-unknown}; no HTTP request to the metadata service was made." \
        "ip route get 169.254.169.254; nft list ruleset" \
        "Restrict metadata access from untrusted workloads and containers when supported by the provider."

    virt="$(systemd-detect-virt 2>/dev/null || printf none)"
    stat1="$(awk '/^cpu / {total=0; for(i=2;i<=9;i++) total+=$i; print total, $9; exit}' /proc/stat 2>/dev/null)"
    sleep 1
    stat2="$(awk '/^cpu / {total=0; for(i=2;i<=9;i++) total+=$i; print total, $9; exit}' /proc/stat 2>/dev/null)"
    read -r total1 steal1 <<< "$stat1"; read -r total2 steal2 <<< "$stat2"
    if [[ "$total1" =~ ^[0-9]+$ && "$total2" =~ ^[0-9]+$ && "$steal1" =~ ^[0-9]+$ && "$steal2" =~ ^[0-9]+$ ]]; then
        delta_total=$((total2-total1)); delta_steal=$((steal2-steal1))
        if (( delta_total > 0 )); then steal_pct="$(awk -v s="$delta_steal" -v t="$delta_total" 'BEGIN{printf "%.2f", (s*100)/t}')"; fi
    fi
    if [[ "$steal_pct" != unknown ]] && awk -v v="$steal_pct" 'BEGIN{exit !(v>=10)}'; then steal_status="WARN"; steal_severity="MEDIUM"; fi
    if [[ "$steal_pct" != unknown ]] && awk -v v="$steal_pct" 'BEGIN{exit !(v>=25)}'; then steal_severity="HIGH"; fi
    add_result "VIRT-STEAL-001" "virtualization" "$steal_status" "$steal_severity" "LOW" \
        "Short CPU steal-time sample" \
        "virtualization=$virt; sample_seconds=1; steal_percent=$steal_pct; a short sample is directional, not a capacity benchmark." \
        "awk '/^cpu / {print}' /proc/stat; mpstat 1 5" \
        "Repeat during workload peaks before concluding that the VPS host is oversubscribed."
    balloon="$({ lsmod 2>/dev/null | awk '$1 ~ /(virtio_balloon|vmw_balloon|xen_balloon)/ {print $1}'; find /sys -maxdepth 6 -type d -iname '*balloon*' -printf '%p\n' 2>/dev/null | head -n5; } | paste -sd, -)"
    mem_total="$(awk '/MemTotal:/ {print int($2/1024)}' /proc/meminfo 2>/dev/null)"; swap_total="$(awk '/SwapTotal:/ {print int($2/1024)}' /proc/meminfo 2>/dev/null)"
    cpu_max="$(cat /sys/fs/cgroup/cpu.max 2>/dev/null || printf unknown)"; memory_max="$(cat /sys/fs/cgroup/memory.max 2>/dev/null || printf unknown)"
    qga_state="$(systemctl is-active qemu-guest-agent.service 2>/dev/null || true)"
    add_result "VIRT-CONTEXT-001" "virtualization" "INFO" "INFO" "MEDIUM" \
        "VPS virtualization and resource-limit context" \
        "virtualization=$virt; memory_mib=${mem_total:-unknown}; swap_mib=${swap_total:-unknown}; balloon_indicators=${balloon:-none}; cgroup_cpu_max=$cpu_max; cgroup_memory_max=$memory_max; qemu_guest_agent=${qga_state:-not-detected}." \
        "systemd-detect-virt; free -h; swapon --show; cat /sys/fs/cgroup/cpu.max /sys/fs/cgroup/memory.max; systemctl status qemu-guest-agent" \
        "Interpret ballooning, quotas and swap together with provider guarantees and observed pressure."
    if [[ "$swap_total" =~ ^[0-9]+$ && "$mem_total" =~ ^[0-9]+$ && "$swap_total" -eq 0 && "$mem_total" -lt 2048 ]]; then
        add_result "VIRT-SWAP-001" "virtualization" "WARN" "LOW" "MEDIUM" \
            "Small VPS has no swap or compressed-memory fallback" \
            "memory_mib=$mem_total; swap_mib=0; no universal swap requirement is enforced." \
            "free -h; swapon --show; systemctl status systemd-zram-setup@*" \
            "Consider a small encrypted swap or zram after evaluating latency, storage and OOM expectations."
    else
        add_result "VIRT-SWAP-001" "virtualization" "INFO" "INFO" "HIGH" \
            "VPS memory and swap context" "memory_mib=${mem_total:-unknown}; swap_mib=${swap_total:-unknown}." \
            "free -h; swapon --show" "No universal swap requirement is enforced."
    fi
}

check_tor_vpn_vps_v08() {
    local detected=""
    check_tor_v08
    check_wireguard_v08
    check_openvpn_v08
    check_tailscale_strongswan_v08
    check_cloud_vps_v08
    detected="$({ command -v wg openvpn tailscale ipsec tor 2>/dev/null || true; ip -o link show 2>/dev/null | awk -F': ' '$2 ~ /^(wg|tun|tap|tailscale|ipsec|xfrm)/ {print $2}'; } | sed '/^$/d' | paste -sd, -)"
    add_result "VPS-MODULE-SUMMARY-001" "virtualization" "INFO" "INFO" "HIGH" \
        "Tor, VPN and VPS-specific module summary" \
        "detected_commands_or_interfaces=${detected:-none}; offline_mode=$((1-ONLINE)); metadata_http_requests=0; secret_values_collected=0." \
        "Review TOR-*, VPN-*, CLOUD-* and VIRT-* findings in this report" \
        "Use the component findings to confirm routing, permissions and provider-specific assumptions."
}


policy_missing_status() {
    case "$SEVERITY_PROFILE" in
        strict) printf 'FAIL|HIGH' ;;
        relaxed) printf 'INFO|INFO' ;;
        *) printf 'WARN|MEDIUM' ;;
    esac
}

check_policy_config_security_v09() {
    local stat_out owner group mode status="PASS" severity="INFO" expired="" id data
    if [[ -n "$CONFIG_FILE" ]]; then
        stat_out="$(stat -Lc '%U|%G|%a' -- "$CONFIG_FILE" 2>/dev/null || true)"
        IFS='|' read -r owner group mode <<< "$stat_out"
        if [[ -z "$mode" ]] || is_group_or_world_writable "$mode"; then status="FAIL"; severity="HIGH"; fi
        add_result "POLICY-CONFIG-001" "policy" "$status" "$severity" "HIGH" \
            "Policy configuration file ownership and permissions" \
            "file=$CONFIG_FILE; owner=${owner:-unknown}; group=${group:-unknown}; mode=${mode:-unknown}; parser=data-only; shell_source=never." \
            "stat -Lc '%U %G %a %n' -- $(shell_quote "$CONFIG_FILE")" \
            "$([[ "$status" == FAIL ]] && printf 'Remove group/world write access before trusting suppressions or expectations.' || printf 'No action required.')"
    else
        add_result "POLICY-CONFIG-001" "policy" "INFO" "INFO" "HIGH" \
            "No external policy configuration file was supplied" \
            "Built-in balanced defaults and CLI arguments were used; no file was sourced." \
            "sudo ./vpscry.sh --config /etc/vpscry/vpscry.conf" \
            "Use a data-only config when repeatable host-specific expectations are required."
    fi
    for id in "${!EXPIRED_SUPPRESSIONS[@]}"; do
        data="${EXPIRED_SUPPRESSIONS[$id]}"
        expired+="$id(until=${data%%|*},reason=${data#*|}),"
    done
    if [[ -n "$expired" ]]; then
        add_result "POLICY-SUPPRESS-EXPIRED" "policy" "WARN" "MEDIUM" "HIGH" \
            "One or more finding suppressions have expired" "entries=${expired%,}." \
            "grep -n '^suppress=' $(shell_quote "${CONFIG_FILE:-/etc/vpscry/vpscry.conf}")" \
            "Remove, renew or remediate each expired exception with a fresh justification."
    fi
}

check_expected_assets_v09() {
    local status severity item active enabled found all_evidence
    local missing_services="" missing_sites="" missing_timers="" missing_backups=""
    local total_services=0 total_sites=0 total_timers=0 total_backups=0 _name
    IFS='|' read -r status severity <<< "$(policy_missing_status)"
    all_evidence="$(printf '%s\n' "${R_TITLE[@]}" "${R_EVIDENCE[@]}")"

    if [[ -n "$EXPECTED_SERVICES_RAW" ]]; then
        IFS=',' read -ra _items <<< "$EXPECTED_SERVICES_RAW"
        for item in "${_items[@]}"; do
            item="$(trim "$item")"; [[ -n "$item" ]] || continue
            total_services=$((total_services+1)); active="$(systemctl is-active "$item" 2>/dev/null || true)"
            [[ "$active" == active ]] || missing_services+="$item(state=${active:-not-found}),"
        done
        add_result "POLICY-SERVICES-001" "policy" "$([[ -z "$missing_services" ]] && printf PASS || printf %s "$status")" "$([[ -z "$missing_services" ]] && printf INFO || printf %s "$severity")" "HIGH" \
            "Expected systemd service baseline" "configured=$total_services; missing_or_inactive=${missing_services:-none}." \
            "systemctl is-active SERVICE; systemctl status SERVICE" \
            "$([[ -z "$missing_services" ]] && printf 'All expected services are active.' || printf 'Confirm whether missing or inactive services are intentional.')"
    fi

    if [[ -n "$EXPECTED_WEBSITES_RAW" ]]; then
        IFS=',' read -ra _items <<< "$EXPECTED_WEBSITES_RAW"
        for item in "${_items[@]}"; do
            item="$(trim "$item")"; [[ -n "$item" ]] || continue
            total_sites=$((total_sites+1)); found=0
            for _name in "${WEB_PUBLIC_NAMES[@]:-}"; do [[ "${_name,,}" == "${item,,}" ]] && found=1; done
            (( found )) || missing_sites+="$item,"
        done
        add_result "POLICY-WEBSITES-001" "policy" "$([[ -z "$missing_sites" ]] && printf PASS || printf %s "$status")" "$([[ -z "$missing_sites" ]] && printf INFO || printf %s "$severity")" "HIGH" \
            "Expected website configuration baseline" "configured=$total_sites; missing_from_local_web_config=${missing_sites:-none}." \
            "nginx -T; apache2ctl -S" "Confirm that every expected public name is configured on this host."
    fi

    if [[ -n "$EXPECTED_TIMERS_RAW" ]]; then
        IFS=',' read -ra _items <<< "$EXPECTED_TIMERS_RAW"
        for item in "${_items[@]}"; do
            item="$(trim "$item")"; [[ -n "$item" ]] || continue
            total_timers=$((total_timers+1)); enabled="$(systemctl is-enabled "$item" 2>/dev/null || true)"; active="$(systemctl is-active "$item" 2>/dev/null || true)"
            [[ "$enabled" == enabled && "$active" == active ]] || missing_timers+="$item(enabled=${enabled:-not-found},active=${active:-unknown}),"
        done
        add_result "POLICY-TIMERS-001" "policy" "$([[ -z "$missing_timers" ]] && printf PASS || printf %s "$status")" "$([[ -z "$missing_timers" ]] && printf INFO || printf %s "$severity")" "HIGH" \
            "Expected systemd timer baseline" "configured=$total_timers; missing_or_inactive=${missing_timers:-none}." \
            "systemctl is-enabled TIMER; systemctl is-active TIMER; systemctl list-timers --all" "Confirm every expected timer is installed, enabled and active."
    fi

    if [[ -n "$EXPECTED_BACKUPS_RAW" ]]; then
        IFS=',' read -ra _items <<< "$EXPECTED_BACKUPS_RAW"
        for item in "${_items[@]}"; do
            item="$(trim "$item")"; [[ -n "$item" ]] || continue
            total_backups=$((total_backups+1)); grep -Fqi -- "$item" <<< "$all_evidence" || missing_backups+="$item,"
        done
        add_result "POLICY-BACKUPS-001" "policy" "$([[ -z "$missing_backups" ]] && printf PASS || printf %s "$status")" "$([[ -z "$missing_backups" ]] && printf INFO || printf %s "$severity")" "MEDIUM" \
            "Expected backup evidence baseline" "configured=$total_backups; unmatched_tokens=${missing_backups:-none}; matching uses local job/tool/path evidence without secret values." \
            "Review BACKUP-* findings and expected_backups in the policy file" "Use stable tool, timer or path tokens that should appear on every healthy run."
    fi

    if [[ -z "$EXPECTED_SERVICES_RAW$EXPECTED_WEBSITES_RAW$EXPECTED_TIMERS_RAW$EXPECTED_BACKUPS_RAW" ]]; then
        add_result "POLICY-EXPECTATIONS-001" "policy" "INFO" "INFO" "HIGH" \
            "No explicit service, website, timer or backup expectations were configured" \
            "The audit remains inventory-driven; expected_ports may still be supplied independently." \
            "Review vpscry.conf.example" "Add only host-specific expectations that should remain stable between runs."
    fi
}

status_rank_v09() {
    case "$1" in PASS) printf 0;; INFO) printf 1;; SKIP) printf 2;; WARN) printf 3;; FAIL) printf 4;; *) printf 1;; esac
}

evidence_hash_v09() {
    local value="${1-}" first="" last=""
    [[ -n "$value" ]] && { first="${value:0:1}"; last="${value: -1}"; }
    printf 'len:%s:first:%q:last:%q' "${#value}" "$first" "$last"
}

check_baseline_diff_v09() {
    local id old_status old_severity old_hash old_rank new_rank i
    local new_count=0 resolved_count=0 worse_count=0 better_count=0 evidence_changed=0
    local new_sample="" resolved_sample="" worse_sample="" better_sample=""
    local new_display resolved_display worse_display better_display
    declare -A old_seen=() old_s=() old_sev=() old_h=() cur_s=() cur_h=()
    if [[ -z "$BASELINE_FILE" ]]; then
        add_result "BASELINE-DIFF-001" "baseline" "INFO" "INFO" "HIGH" \
            "No comparison baseline was supplied" "baseline_file=none." \
            "sudo ./vpscry.sh --write-baseline ./host.baseline" "Create a baseline after reviewing and accepting a healthy host state."
        return
    fi
    if [[ ! -r "$BASELINE_FILE" ]]; then
        add_result "BASELINE-DIFF-001" "baseline" "WARN" "MEDIUM" "HIGH" \
            "Configured baseline file could not be read" "baseline_file=$BASELINE_FILE." \
            "stat -- $(shell_quote "$BASELINE_FILE")" "Correct the path or permissions before relying on regression detection."
        return
    fi
    while IFS=$'\t' read -r id old_status old_severity old_hash; do
        [[ "$id" =~ ^# || -z "$id" ]] && continue
        old_seen["$id"]=1; old_s["$id"]="$old_status"; old_sev["$id"]="$old_severity"; old_h["$id"]="$old_hash"
    done < "$BASELINE_FILE"
    for ((i=0; i<${#R_ID[@]}; i++)); do
        [[ "${R_ID[$i]}" == BASELINE-* ]] && continue
        cur_s["${R_ID[$i]}"]="${R_STATUS[$i]}"; cur_h["${R_ID[$i]}"]="$(evidence_hash_v09 "${R_EVIDENCE[$i]}")"
    done
    for id in "${!cur_s[@]}"; do
        if [[ -z "${old_seen[$id]+x}" ]]; then
            new_count=$((new_count+1)); [[ $(tr -cd ',' <<< "$new_sample" | wc -c) -lt 7 ]] && new_sample+="$id,"
            continue
        fi
        old_rank="$(status_rank_v09 "${old_s[$id]}")"; new_rank="$(status_rank_v09 "${cur_s[$id]}")"
        if (( new_rank>old_rank )); then worse_count=$((worse_count+1)); worse_sample+="$id(${old_s[$id]}→${cur_s[$id]}),"
        elif (( new_rank<old_rank )); then better_count=$((better_count+1)); better_sample+="$id(${old_s[$id]}→${cur_s[$id]}),"
        elif [[ "${old_h[$id]}" != "${cur_h[$id]}" ]]; then evidence_changed=$((evidence_changed+1)); fi
    done
    for id in "${!old_seen[@]}"; do
        [[ -n "${cur_s[$id]+x}" ]] || { resolved_count=$((resolved_count+1)); resolved_sample+="$id,"; }
    done
    local bstatus="INFO" bseverity="INFO"
    (( worse_count>0 )) && { bstatus="WARN"; bseverity="MEDIUM"; }
    new_display="${new_sample%,}"; [[ -n "$new_display" ]] || new_display="none"
    resolved_display="${resolved_sample%,}"; [[ -n "$resolved_display" ]] || resolved_display="none"
    worse_display="${worse_sample%,}"; [[ -n "$worse_display" ]] || worse_display="none"
    better_display="${better_sample%,}"; [[ -n "$better_display" ]] || better_display="none"
    add_result "BASELINE-DIFF-001" "baseline" "$bstatus" "$bseverity" "HIGH" \
        "Baseline regression summary" \
        "baseline=$BASELINE_FILE; new=$new_count(sample=$new_display); resolved=$resolved_count(sample=$resolved_display); worse=$worse_count(sample=$worse_display); better=$better_count(sample=$better_display); evidence_changed=$evidence_changed." \
        "diff -u $(shell_quote "$BASELINE_FILE") CURRENT_BASELINE" \
        "$([[ "$bstatus" == WARN ]] && printf 'Review worsened statuses before accepting a new baseline.' || printf 'No worsened status was detected against the supplied baseline.')"
}

write_baseline_snapshot_v09() {
    local file="$WRITE_BASELINE_FILE" i tmp
    [[ -n "$file" ]] || return 0
    mkdir -p -- "$(dirname -- "$file")" 2>/dev/null || true
    tmp="$TMP_DIR/baseline.tsv"
    {
        printf '# VPScry baseline v1\n'
        printf '# tool_version=%s\thost=%s\tcreated=%s\n' "$VERSION" "$HOSTNAME_VALUE" "$START_ISO"
        for ((i=0; i<${#R_ID[@]}; i++)); do
            [[ "${R_ID[$i]}" == BASELINE-* ]] && continue
            printf '%s\t%s\t%s\t%s\n' "${R_ID[$i]}" "${R_STATUS[$i]}" "${R_SEVERITY[$i]}" "$(evidence_hash_v09 "${R_EVIDENCE[$i]}")"
        done | sort
    } > "$tmp"
    install -m 0600 "$tmp" "$file" || fatal "Cannot write baseline: $file"
    if (( RUN_AS_ROOT )) && [[ "$REPORT_OWNER_UID" =~ ^[0-9]+$ && "$REPORT_OWNER_GID" =~ ^[0-9]+$ ]] && (( REPORT_OWNER_UID>0 )); then chown "$REPORT_OWNER_UID:$REPORT_OWNER_GID" -- "$file" 2>/dev/null || true; fi
}

check_policy_baseline_v09() {
    check_policy_config_security_v09
    check_expected_assets_v09
    check_baseline_diff_v09
}

check_kernel_hardening() {
    local key value expected status severity title evidence
    local checks=(
        "kernel.dmesg_restrict|1"
        "kernel.kptr_restrict|1"
        "kernel.yama.ptrace_scope|1"
        "fs.protected_hardlinks|1"
        "fs.protected_symlinks|1"
    )
    local index=0
    for entry in "${checks[@]}"; do
        IFS='|' read -r key expected <<< "$entry"
        value="$(sysctl -n "$key" 2>/dev/null || true)"
        if [[ -z "$value" ]]; then
            add_result "KERN-SYSCTL-$(printf '%03d' "$index")" "kernel" "SKIP" "INFO" "MEDIUM" \
                "Kernel hardening setting is unavailable" "$key could not be read." \
                "sysctl '$key'" "The setting may be unavailable in this kernel or namespace."
        elif [[ "$value" =~ ^[0-9]+$ ]] && (( value >= expected )); then
            add_result "KERN-SYSCTL-$(printf '%03d' "$index")" "kernel" "PASS" "INFO" "HIGH" \
                "Kernel hardening setting is enabled" "$key=$value; expected minimum=$expected." \
                "sysctl '$key'" "No action required."
        else
            add_result "KERN-SYSCTL-$(printf '%03d' "$index")" "kernel" "WARN" "LOW" "HIGH" \
                "Kernel hardening setting is weaker than the baseline" "$key=$value; suggested minimum=$expected." \
                "sysctl '$key'; grep -R -- '$key' /etc/sysctl.conf /etc/sysctl.d" \
                "Confirm application compatibility before increasing the setting."
        fi
        index=$((index + 1))
    done

    if have aa-status; then
        local aa
        aa="$(aa-status 2>/dev/null | head -n 8 || true)"
        if grep -qi 'apparmor module is loaded' <<< "$aa"; then
            add_result "KERN-APPARMOR-001" "kernel" "PASS" "INFO" "MEDIUM" \
                "AppArmor is loaded" "$aa" "aa-status" \
                "Review whether exposed services have enforcing profiles; presence alone is not full confinement."
        else
            add_result "KERN-APPARMOR-001" "kernel" "WARN" "LOW" "MEDIUM" \
                "AppArmor is installed but not confirmed active" "$aa" "aa-status" \
                "Enable AppArmor if compatible with the VPS kernel and workload."
        fi
    else
        add_result "KERN-APPARMOR-001" "kernel" "INFO" "INFO" "HIGH" \
            "AppArmor status tool was not detected" "aa-status is unavailable." \
            "command -v aa-status; cat /sys/module/apparmor/parameters/enabled 2>/dev/null" \
            "AppArmor is recommended for additional service confinement but absence is not treated as an automatic failure."
    fi
}


ESCAPED_VALUE=""
json_escape_set() {
    ESCAPED_VALUE="${1-}"
    ESCAPED_VALUE=${ESCAPED_VALUE//\\/\\\\}
    ESCAPED_VALUE=${ESCAPED_VALUE//\"/\\\"}
    ESCAPED_VALUE=${ESCAPED_VALUE//$'\n'/\\n}
    ESCAPED_VALUE=${ESCAPED_VALUE//$'\r'/\\r}
    ESCAPED_VALUE=${ESCAPED_VALUE//$'\t'/\\t}
}

html_escape_set() {
    ESCAPED_VALUE="${1-}"
    ESCAPED_VALUE=${ESCAPED_VALUE//&/\\&amp;}
    ESCAPED_VALUE=${ESCAPED_VALUE//</\\&lt;}
    ESCAPED_VALUE=${ESCAPED_VALUE//>/\\&gt;}
    ESCAPED_VALUE=${ESCAPED_VALUE//\"/\\&quot;}
    ESCAPED_VALUE=${ESCAPED_VALUE//$'\''/\\&#39;}
}

md_escape_set() {
    ESCAPED_VALUE="$(trim "${1-}")"
    ESCAPED_VALUE=${ESCAPED_VALUE//\\/\\\\}
    ESCAPED_VALUE=${ESCAPED_VALUE//\|/\\|}
    ESCAPED_VALUE=${ESCAPED_VALUE//\`/\\\`}
}

write_text_report() {
    local file="$OUTPUT_DIR/report.txt" i
    {
        printf '%s\n' "$REPORT_TITLE"
        printf 'Version: %s\nAuthor: %s · %s\nTagline: %s\nHost: %s\nStarted: %s\nOnline permitted: %s\nRoot privileges: %s\nExpected ports: %s\n\n' \
            "$VERSION" "$AUTHOR" "$WEBSITE" "$TAGLINE" "$HOSTNAME_VALUE" "$START_ISO" "$ONLINE" "$RUN_AS_ROOT" "${EXPECTED_PORTS_RAW:-none}"
        printf 'Summary: FAIL=%s WARN=%s PASS=%s INFO=%s SKIP=%s\n\n' \
            "${COUNTS[FAIL]}" "${COUNTS[WARN]}" "${COUNTS[PASS]}" "${COUNTS[INFO]}" "${COUNTS[SKIP]}"
        for ((i=0; i<${#R_ID[@]}; i++)); do
            printf '[%s] %s | %s | severity=%s confidence=%s\n' \
                "${R_STATUS[$i]}" "${R_ID[$i]}" "${R_TITLE[$i]}" "${R_SEVERITY[$i]}" "${R_CONFIDENCE[$i]}"
            printf 'Category: %s\n' "${R_CATEGORY[$i]}"
            printf 'Evidence: %s\n' "${R_EVIDENCE[$i]}"
            printf 'Verify: %s\n' "${R_VERIFY[$i]}"
            printf 'Recommendation: %s\n\n' "${R_RECOMMENDATION[$i]}"
        done
    } > "$file"
}

write_markdown_report() {
    local file="$OUTPUT_DIR/report.md" i e_author e_website e_tagline e_host e_ports
    local e_title e_evidence e_verify e_recommendation
    md_escape_set "$AUTHOR"; e_author="$ESCAPED_VALUE"
    md_escape_set "$WEBSITE"; e_website="$ESCAPED_VALUE"
    md_escape_set "$TAGLINE"; e_tagline="$ESCAPED_VALUE"
    md_escape_set "$HOSTNAME_VALUE"; e_host="$ESCAPED_VALUE"
    md_escape_set "${EXPECTED_PORTS_RAW:-none}"; e_ports="$ESCAPED_VALUE"
    {
        printf '# %s\n\n' "$REPORT_TITLE"
        printf -- '- **Version:** `%s`\n- **Author:** %s · %s\n- **Tagline:** %s\n- **Host:** `%s`\n- **Started:** `%s`\n- **Online permitted:** `%s`\n- **Root privileges:** `%s`\n- **Expected ports:** `%s`\n\n' \
            "$VERSION" "$e_author" "$e_website" "$e_tagline" "$e_host" "$START_ISO" "$ONLINE" "$RUN_AS_ROOT" "$e_ports"
        printf '## Summary\n\n'
        printf '| FAIL | WARN | PASS | INFO | SKIP |\n|---:|---:|---:|---:|---:|\n'
        printf '| %s | %s | %s | %s | %s |\n\n' \
            "${COUNTS[FAIL]}" "${COUNTS[WARN]}" "${COUNTS[PASS]}" "${COUNTS[INFO]}" "${COUNTS[SKIP]}"
        printf '## Results\n\n'
        for ((i=0; i<${#R_ID[@]}; i++)); do
            md_escape_set "${R_TITLE[$i]}"; e_title="$ESCAPED_VALUE"
            md_escape_set "${R_EVIDENCE[$i]}"; e_evidence="$ESCAPED_VALUE"
            md_escape_set "${R_VERIFY[$i]}"; e_verify="$ESCAPED_VALUE"
            md_escape_set "${R_RECOMMENDATION[$i]}"; e_recommendation="$ESCAPED_VALUE"
            printf '### `%s` — %s\n\n' "${R_ID[$i]}" "$e_title"
            printf -- '- **Status:** `%s`\n- **Category:** `%s`\n- **Severity:** `%s`\n- **Confidence:** `%s`\n' \
                "${R_STATUS[$i]}" "${R_CATEGORY[$i]}" "${R_SEVERITY[$i]}" "${R_CONFIDENCE[$i]}"
            printf -- '- **Evidence:** %s\n' "$e_evidence"
            printf -- '- **Verification:** `%s`\n' "$e_verify"
            printf -- '- **Recommendation:** %s\n\n' "$e_recommendation"
        done
    } > "$file"
}
write_json_report() {
    local file="$OUTPUT_DIR/report.json" i comma
    local e_program e_version e_display e_author e_website e_tagline e_host e_ports
    local e_id e_category e_status e_severity e_confidence e_title e_evidence e_verify e_recommendation
    json_escape_set "$PROGRAM"; e_program="$ESCAPED_VALUE"
    json_escape_set "$VERSION"; e_version="$ESCAPED_VALUE"
    json_escape_set "$DISPLAY_NAME"; e_display="$ESCAPED_VALUE"
    json_escape_set "$AUTHOR"; e_author="$ESCAPED_VALUE"
    json_escape_set "$WEBSITE"; e_website="$ESCAPED_VALUE"
    json_escape_set "$TAGLINE"; e_tagline="$ESCAPED_VALUE"
    json_escape_set "$HOSTNAME_VALUE"; e_host="$ESCAPED_VALUE"
    json_escape_set "${EXPECTED_PORTS_RAW:-}"; e_ports="$ESCAPED_VALUE"
    {
        printf '{\n'
        printf '  "schema_version": "2.0.0",\n'
        printf '  "tool": "%s",\n' "$e_program"
        printf '  "tool_version": "%s",\n' "$e_version"
        printf '  "display_name": "%s",\n' "$e_display"
        printf '  "author": "%s",\n' "$e_author"
        printf '  "website": "%s",\n' "$e_website"
        printf '  "tagline": "%s",\n' "$e_tagline"
        printf '  "host": "%s",\n' "$e_host"
        printf '  "started_at": "%s",\n' "$START_ISO"
        printf '  "online_permitted": %s,\n' "$([[ $ONLINE -eq 1 ]] && printf true || printf false)"
        printf '  "root_privileges": %s,\n' "$([[ $RUN_AS_ROOT -eq 1 ]] && printf true || printf false)"
        printf '  "expected_ports": "%s",\n' "$e_ports"
        printf '  "terminal_mode": "%s",\n' "$TERMINAL_MODE"
        printf '  "severity_profile": "%s",\n' "$SEVERITY_PROFILE"
        printf '  "evidence_limit": %s,\n' "$EVIDENCE_LIMIT"
        printf '  "command_timeout_seconds": %s,\n' "$COMMAND_TIMEOUT_MAX"
        printf '  "summary": {"fail": %s, "warn": %s, "pass": %s, "info": %s, "skip": %s},\n' \
            "${COUNTS[FAIL]}" "${COUNTS[WARN]}" "${COUNTS[PASS]}" "${COUNTS[INFO]}" "${COUNTS[SKIP]}"
        printf '  "results": [\n'
        for ((i=0; i<${#R_ID[@]}; i++)); do
            comma=","; (( i == ${#R_ID[@]} - 1 )) && comma=""
            json_escape_set "${R_ID[$i]}"; e_id="$ESCAPED_VALUE"
            json_escape_set "${R_CATEGORY[$i]}"; e_category="$ESCAPED_VALUE"
            json_escape_set "${R_STATUS[$i]}"; e_status="$ESCAPED_VALUE"
            json_escape_set "${R_SEVERITY[$i]}"; e_severity="$ESCAPED_VALUE"
            json_escape_set "${R_CONFIDENCE[$i]}"; e_confidence="$ESCAPED_VALUE"
            json_escape_set "${R_TITLE[$i]}"; e_title="$ESCAPED_VALUE"
            json_escape_set "${R_EVIDENCE[$i]}"; e_evidence="$ESCAPED_VALUE"
            json_escape_set "${R_VERIFY[$i]}"; e_verify="$ESCAPED_VALUE"
            json_escape_set "${R_RECOMMENDATION[$i]}"; e_recommendation="$ESCAPED_VALUE"
            printf '    {"id":"%s","category":"%s","status":"%s","severity":"%s","confidence":"%s","title":"%s","evidence":"%s","verification_command":"%s","recommendation":"%s"}%s\n' \
                "$e_id" "$e_category" "$e_status" "$e_severity" "$e_confidence" "$e_title" "$e_evidence" "$e_verify" "$e_recommendation" "$comma"
        done
        printf '  ]\n}\n'
    } > "$file"
}
write_sarif_report() {
    local file="$OUTPUT_DIR/report.sarif" i first=1 level
    local e_id e_title e_category e_severity e_confidence e_evidence e_verify e_recommendation
    {
        printf '{"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs":[{'
        printf '"tool":{"driver":{"name":"VPScry","version":"%s","informationUri":"https://0ut3r.space","rules":[' "$VERSION"
        for ((i=0; i<${#R_ID[@]}; i++)); do
            [[ "${R_STATUS[$i]}" == FAIL || "${R_STATUS[$i]}" == WARN ]] || continue
            (( first )) || printf ','; first=0
            json_escape_set "${R_ID[$i]}"; e_id="$ESCAPED_VALUE"; json_escape_set "${R_TITLE[$i]}"; e_title="$ESCAPED_VALUE"
            printf '{"id":"%s","shortDescription":{"text":"%s"}}' "$e_id" "$e_title"
        done
        printf ']}},"results":['; first=1
        for ((i=0; i<${#R_ID[@]}; i++)); do
            case "${R_STATUS[$i]}" in FAIL) level=error;; WARN) level=warning;; *) continue;; esac
            (( first )) || printf ','; first=0
            json_escape_set "${R_ID[$i]}"; e_id="$ESCAPED_VALUE"
            json_escape_set "${R_TITLE[$i]}"; e_title="$ESCAPED_VALUE"
            json_escape_set "${R_CATEGORY[$i]}"; e_category="$ESCAPED_VALUE"
            json_escape_set "${R_SEVERITY[$i]}"; e_severity="$ESCAPED_VALUE"
            json_escape_set "${R_CONFIDENCE[$i]}"; e_confidence="$ESCAPED_VALUE"
            json_escape_set "${R_EVIDENCE[$i]}"; e_evidence="$ESCAPED_VALUE"
            json_escape_set "${R_VERIFY[$i]}"; e_verify="$ESCAPED_VALUE"
            json_escape_set "${R_RECOMMENDATION[$i]}"; e_recommendation="$ESCAPED_VALUE"
            printf '{"ruleId":"%s","level":"%s","message":{"text":"%s"},"properties":{"category":"%s","severity":"%s","confidence":"%s","evidence":"%s","verification_command":"%s","recommendation":"%s"}}' \
                "$e_id" "$level" "$e_title" "$e_category" "$e_severity" "$e_confidence" "$e_evidence" "$e_verify" "$e_recommendation"
        done
        printf ']}]}\n'
    } > "$file"
}

write_html_report() {
    local file="$OUTPUT_DIR/report.html" i status_class
    local e_title e_version e_author e_website e_tagline e_host e_ports
    local e_id e_item_title e_category e_severity e_confidence e_evidence e_verify e_recommendation
    html_escape_set "$REPORT_TITLE"; e_title="$ESCAPED_VALUE"
    html_escape_set "$VERSION"; e_version="$ESCAPED_VALUE"
    html_escape_set "$AUTHOR"; e_author="$ESCAPED_VALUE"
    html_escape_set "$WEBSITE"; e_website="$ESCAPED_VALUE"
    html_escape_set "$TAGLINE"; e_tagline="$ESCAPED_VALUE"
    html_escape_set "$HOSTNAME_VALUE"; e_host="$ESCAPED_VALUE"
    html_escape_set "${EXPECTED_PORTS_RAW:-none}"; e_ports="$ESCAPED_VALUE"
    {
        cat <<'HTML_HEAD'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VPScry Report</title>
<style>
:root{color-scheme:light dark;font-family:Inter,system-ui,sans-serif}body{max-width:1180px;margin:0 auto;padding:28px;line-height:1.5;background:#111827;color:#e5e7eb}h1,h2{color:#fff}.meta,.summary,.item{background:#1f2937;border:1px solid #374151;border-radius:10px;padding:16px;margin:14px 0}.summary{display:flex;gap:12px;flex-wrap:wrap}.badge{display:inline-block;border-radius:999px;padding:3px 9px;font-weight:700;font-size:.82rem}.PASS{background:#064e3b;color:#a7f3d0}.WARN{background:#713f12;color:#fde68a}.FAIL{background:#7f1d1d;color:#fecaca}.INFO{background:#1e3a8a;color:#bfdbfe}.SKIP{background:#374151;color:#d1d5db}.grid{display:grid;grid-template-columns:150px 1fr;gap:7px 12px}.label{font-weight:700;color:#9ca3af}code{white-space:pre-wrap;overflow-wrap:anywhere;background:#111827;padding:2px 5px;border-radius:4px}a{color:#93c5fd}@media(max-width:700px){body{padding:14px}.grid{grid-template-columns:1fr}.label{margin-top:7px}}
</style>
</head>
<body>
HTML_HEAD
        printf '<h1>%s</h1>\n' "$e_title"
        printf '<div class="meta"><div class="grid"><div class="label">Version</div><div>%s</div><div class="label">Author</div><div>%s · %s</div><div class="label">Tagline</div><div>%s</div><div class="label">Host</div><div>%s</div><div class="label">Started</div><div>%s</div><div class="label">Online permitted</div><div>%s</div><div class="label">Root privileges</div><div>%s</div><div class="label">Expected ports</div><div>%s</div></div></div>\n' \
            "$e_version" "$e_author" "$e_website" "$e_tagline" "$e_host" "$START_ISO" "$ONLINE" "$RUN_AS_ROOT" "$e_ports"
        printf '<h2>Summary</h2><div class="summary">'
        printf '<span class="badge FAIL">FAIL %s</span>' "${COUNTS[FAIL]}"
        printf '<span class="badge WARN">WARN %s</span>' "${COUNTS[WARN]}"
        printf '<span class="badge PASS">PASS %s</span>' "${COUNTS[PASS]}"
        printf '<span class="badge INFO">INFO %s</span>' "${COUNTS[INFO]}"
        printf '<span class="badge SKIP">SKIP %s</span></div>\n' "${COUNTS[SKIP]}"
        printf '<h2>Results</h2>\n'
        for ((i=0; i<${#R_ID[@]}; i++)); do
            status_class="${R_STATUS[$i]}"
            html_escape_set "${R_ID[$i]}"; e_id="$ESCAPED_VALUE"
            html_escape_set "${R_TITLE[$i]}"; e_item_title="$ESCAPED_VALUE"
            html_escape_set "${R_CATEGORY[$i]}"; e_category="$ESCAPED_VALUE"
            html_escape_set "${R_SEVERITY[$i]}"; e_severity="$ESCAPED_VALUE"
            html_escape_set "${R_CONFIDENCE[$i]}"; e_confidence="$ESCAPED_VALUE"
            html_escape_set "${R_EVIDENCE[$i]}"; e_evidence="$ESCAPED_VALUE"
            html_escape_set "${R_VERIFY[$i]}"; e_verify="$ESCAPED_VALUE"
            html_escape_set "${R_RECOMMENDATION[$i]}"; e_recommendation="$ESCAPED_VALUE"
            printf '<section class="item"><h3><span class="badge %s">%s</span> <code>%s</code> — %s</h3><div class="grid">' \
                "$status_class" "$status_class" "$e_id" "$e_item_title"
            printf '<div class="label">Category</div><div>%s</div>' "$e_category"
            printf '<div class="label">Severity</div><div>%s</div>' "$e_severity"
            printf '<div class="label">Confidence</div><div>%s</div>' "$e_confidence"
            printf '<div class="label">Evidence</div><div>%s</div>' "$e_evidence"
            printf '<div class="label">Verification</div><div><code>%s</code></div>' "$e_verify"
            printf '<div class="label">Recommendation</div><div>%s</div></div></section>\n' "$e_recommendation"
        done
        printf '</body></html>\n'
    } > "$file"
}
write_actions_report() {
    local file="$OUTPUT_DIR/report-actions.txt" i found=0 status
    {
        printf 'VPScry Action Summary\n'
        printf 'Version: %s\nHost: %s\nStarted: %s\n\n' "$VERSION" "$HOSTNAME_VALUE" "$START_ISO"
        printf 'FAIL=%s WARN=%s\n\n' "${COUNTS[FAIL]}" "${COUNTS[WARN]}"
        for status in FAIL WARN; do
            for ((i=0; i<${#R_ID[@]}; i++)); do
                [[ "${R_STATUS[$i]}" == "$status" ]] || continue
                found=1
                printf '[%s] %s | severity=%s confidence=%s\n' "$status" "${R_ID[$i]} — ${R_TITLE[$i]}" "${R_SEVERITY[$i]}" "${R_CONFIDENCE[$i]}"
                printf 'Evidence: %s\n' "${R_EVIDENCE[$i]}"
                printf 'Verify: %s\n' "${R_VERIFY[$i]}"
                printf 'Recommendation: %s\n\n' "${R_RECOMMENDATION[$i]}"
            done
        done
        if (( ! found )); then
            printf 'No FAIL or WARN finding was recorded.\n'
        fi
    } > "$file"
}

format_requested() {
    local needle="$1"
    [[ ",$FORMATS," == *",all,"* || ",$FORMATS," == *",$needle,"* ]]
}

write_reports() {
    local created=0 report_file
    [[ -e "$OUTPUT_DIR" ]] || created=1
    mkdir -p -- "$OUTPUT_DIR" || fatal "Cannot create report directory: $OUTPUT_DIR"
    format_requested text && write_text_report
    format_requested markdown && write_markdown_report
    format_requested json && write_json_report
    format_requested html && write_html_report
    format_requested actions && write_actions_report
    format_requested sarif && write_sarif_report
    write_baseline_snapshot_v09
    chmod 0700 "$OUTPUT_DIR" 2>/dev/null || true
    chmod u-s,g-s "$OUTPUT_DIR" 2>/dev/null || true
    find "$OUTPUT_DIR" -maxdepth 1 -type f -exec chmod 0600 {} + 2>/dev/null || true

    if (( RUN_AS_ROOT )) && [[ "$REPORT_OWNER_UID" =~ ^[0-9]+$ && "$REPORT_OWNER_GID" =~ ^[0-9]+$ ]] && (( REPORT_OWNER_UID > 0 )); then
        for report_file in "$OUTPUT_DIR"/report.txt "$OUTPUT_DIR"/report.md "$OUTPUT_DIR"/report.json "$OUTPUT_DIR"/report.html "$OUTPUT_DIR"/report-actions.txt "$OUTPUT_DIR"/report.sarif; do
            [[ -f "$report_file" ]] && chown "$REPORT_OWNER_UID:$REPORT_OWNER_GID" -- "$report_file" 2>/dev/null || true
        done
        if (( created )); then
            chown "$REPORT_OWNER_UID:$REPORT_OWNER_GID" -- "$OUTPUT_DIR" 2>/dev/null || true
        fi
    fi
}

run_stage() {
    local title="$1" details="$2" before_fail before_warn before_pass before_info before_skip
    local d_fail d_warn d_pass d_info d_skip result_color result_label fn
    shift 2
    STAGE_CURRENT=$((STAGE_CURRENT + 1))
    before_fail=${COUNTS[FAIL]}
    before_warn=${COUNTS[WARN]}
    before_pass=${COUNTS[PASS]}
    before_info=${COUNTS[INFO]}
    before_skip=${COUNTS[SKIP]}

    if [[ "$TERMINAL_MODE" == "progress" ]]; then
        printf '%s[%02d/%02d]%s %s%s%s\n' \
            "$C_GRAY" "$STAGE_CURRENT" "$STAGE_TOTAL" "$C_RESET" "$C_BOLD" "$title" "$C_RESET"
        printf '         %s\n' "$details"
    elif [[ "$TERMINAL_MODE" == "verbose" ]]; then
        printf '\n%s== %s ==%s\n' "$C_BOLD" "$title" "$C_RESET"
    fi

    for fn in "$@"; do
        "$fn"
    done

    d_fail=$((COUNTS[FAIL] - before_fail))
    d_warn=$((COUNTS[WARN] - before_warn))
    d_pass=$((COUNTS[PASS] - before_pass))
    d_info=$((COUNTS[INFO] - before_info))
    d_skip=$((COUNTS[SKIP] - before_skip))

    if [[ "$TERMINAL_MODE" == "progress" ]]; then
        if (( d_fail > 0 )); then
            result_color="$C_RED"
            result_label="issues"
        elif (( d_warn > 0 )); then
            result_color="$C_YELLOW"
            result_label="review"
        elif (( d_skip > 0 && d_pass == 0 )); then
            result_color="$C_GRAY"
            result_label="partial"
        else
            result_color="$C_GREEN"
            result_label="done"
        fi
        printf '         %s%s%s — FAIL %d · WARN %d · PASS %d · INFO %d · SKIP %d\n' \
            "$result_color" "$result_label" "$C_RESET" "$d_fail" "$d_warn" "$d_pass" "$d_info" "$d_skip"
    fi
}

print_summary() {
    local end_epoch duration overall
    end_epoch="$(date +%s)"
    duration=$((end_epoch - START_EPOCH))
    if (( COUNTS[FAIL] > 0 )); then
        overall="ACTION REQUIRED"
    elif (( COUNTS[WARN] > 0 )); then
        overall="REVIEW RECOMMENDED"
    else
        overall="HEALTHY"
    fi
    printf '\n%s%s%s\n' "$C_BOLD" "$REPORT_TITLE" "$C_RESET"
    printf 'Overall: %s\n' "$overall"
    printf '%sFAIL=%s%s  %sWARN=%s%s  %sPASS=%s%s  %sINFO=%s%s  %sSKIP=%s%s\n' \
        "$C_RED" "${COUNTS[FAIL]}" "$C_RESET" "$C_YELLOW" "${COUNTS[WARN]}" "$C_RESET" \
        "$C_GREEN" "${COUNTS[PASS]}" "$C_RESET" "$C_BLUE" "${COUNTS[INFO]}" "$C_RESET" \
        "$C_GRAY" "${COUNTS[SKIP]}" "$C_RESET"
    printf 'Duration: %ss\nReports: %s\n' "$duration" "$OUTPUT_DIR"
}

parse_args() {
    local argv=("$@") i
    for ((i=0; i<${#argv[@]}; i++)); do
        if [[ "${argv[$i]}" == --config ]]; then
            (( i+1<${#argv[@]} )) || fatal "--config requires a value"
            CONFIG_FILE="${argv[$((i+1))]}"
        fi
    done
    [[ -n "$CONFIG_FILE" ]] && load_config_file "$CONFIG_FILE"
    while (( $# )); do
        case "$1" in
            --output-dir) shift; (( $# )) || fatal "--output-dir requires a value"; OUTPUT_DIR="$1" ;;
            --formats) shift; (( $# )) || fatal "--formats requires a value"; FORMATS="$1" ;;
            --online) ONLINE=1 ;;
            --fail-on) shift; (( $# )) || fatal "--fail-on requires a value"; FAIL_ON="${1,,}" ;;
            --config) shift; (( $# )) || fatal "--config requires a value"; CONFIG_FILE="$1" ;;
            --expected-ports) shift; (( $# )) || fatal "--expected-ports requires a value"; EXPECTED_PORTS_RAW="$1" ;;
            --baseline) shift; (( $# )) || fatal "--baseline requires a value"; BASELINE_FILE="$1" ;;
            --write-baseline) shift; (( $# )) || fatal "--write-baseline requires a value"; WRITE_BASELINE_FILE="$1" ;;
            --severity-profile) shift; (( $# )) || fatal "--severity-profile requires a value"; SEVERITY_PROFILE="$1" ;;
            --evidence-limit) shift; (( $# )) || fatal "--evidence-limit requires a value"; EVIDENCE_LIMIT="$1" ;;
            --timeout) shift; (( $# )) || fatal "--timeout requires a value"; COMMAND_TIMEOUT_MAX="$1" ;;
            --sarif) [[ ",$FORMATS," == *,sarif,* ]] || FORMATS="$FORMATS,sarif" ;;
            --no-color) COLOR_MODE=never ;;
            --verbose) TERMINAL_MODE=verbose ;;
            --quiet) TERMINAL_MODE=quiet ;;
            --version) printf '%s %s\n' "$DISPLAY_NAME" "$VERSION"; exit 0 ;;
            -h|--help) usage; exit 0 ;;
            *) fatal "Unknown argument: $1" ;;
        esac
        shift
    done
    FORMATS="${FORMATS// /}"
    validate_policy_settings
    net_parse_expected_ports
    [[ "$FORMATS" =~ ^(all|text|markdown|json|html|actions|sarif)(,(text|markdown|json|html|actions|sarif))*$ ]] || fatal "Invalid --formats value: $FORMATS"
    if [[ -z "$OUTPUT_DIR" ]]; then
        local safe_host timestamp
        safe_host="${HOSTNAME_VALUE//[^A-Za-z0-9._-]/_}"; timestamp="$(date +%Y%m%d-%H%M%S)"
        OUTPUT_DIR="./vpscry-${safe_host}-${timestamp}"
    fi
}

main() {
    parse_args "$@"
    init_colors
    init_network_guard
    TMP_DIR="$(mktemp -d -t vpscry.XXXXXX)" || fatal "Cannot create temporary directory"
    umask 077

    if [[ "$TERMINAL_MODE" != "quiet" ]]; then
        print_banner
        printf '%s──────────────────────────────────────────%s\n' "$C_GRAY" "$C_RESET"
        printf 'Mode:        read-only / %s\n' "$([[ $ONLINE -eq 1 ]] && printf online-enabled || printf offline)"
        printf 'Host:        %s\n' "$HOSTNAME_VALUE"
        printf 'Privileges:  %s\n' "$([[ $RUN_AS_ROOT -eq 1 ]] && printf root || printf limited)"
        printf 'Started:     %s\n' "$START_ISO"
        printf 'Port model:  %s\n' "${EXPECTED_PORTS_RAW:-inventory-only}"
        printf 'Terminal:    %s\n' "$TERMINAL_MODE"
        printf 'Policy:      %s%s\n' "$SEVERITY_PROFILE" "$([[ -n "$CONFIG_FILE" ]] && printf ' · config=%s' "$CONFIG_FILE" || true)"
        printf 'Exit policy: %s\n' "$FAIL_ON"
        printf '%s──────────────────────────────────────────%s\n\n' "$C_GRAY" "$C_RESET"
    fi

    run_stage "System health" \
        "OS, storage, memory, clock and reboot state" \
        check_system_identity check_storage check_memory check_time_and_reboot
    run_stage "systemd services" \
        "service states, oneshot context, custom units and execution mapping" \
        check_systemd check_systemd_service_mapping
    run_stage "Network exposure" \
        "interfaces, listeners, firewall policy, expected ports and DNS" \
        check_network
    run_stage "SSH and accounts" \
        "effective SSH policy, keys, local accounts and sudo syntax" \
        check_ssh check_accounts_and_sudo
    run_stage "Updates" \
        "APT metadata, unattended-upgrades, origins, results and reboot plans" \
        check_updates check_updates_deep_v06
    run_stage "Logs" \
        "journald, logrotate, growth and deleted-open files" \
        check_logs check_logs_deep_v06
    run_stage "Scheduled execution" \
        "cron, timers and root-executed paths" \
        check_cron_and_scheduled_execution
    run_stage "Web and TLS" \
        "Nginx, Apache, PHP-FPM, Certbot, PM2 and local certificates" \
        check_service_configuration check_web_tls_process_managers check_certificates
    run_stage "Data services" \
        "databases, caches, search services and containers" \
        check_databases_caches_containers
    run_stage "Backups" \
        "jobs, timers, freshness, storage, retention and restore evidence" \
        check_backup_detection check_backups_deep_v06
    run_stage "Host hardening" \
        "kernel, mounts, privileged files, permissions, identity and controls" \
        check_kernel_hardening check_host_hardening_identity_v07
    run_stage "Tor, VPN and VPS" \
        "Tor, WireGuard, OpenVPN, Tailscale, strongSwan, cloud-init and virtualization" \
        check_tor_vpn_vps_v08
    run_stage "Policy, coverage and baseline" \
        "component coverage, safe config, expectations, suppressions and regression comparison" \
        check_component_coverage_v08 check_policy_baseline_v09
    run_stage "Reports" \
        "TXT, Markdown, JSON, HTML, action summary and optional SARIF output" \
        write_reports

    print_summary
    case "$FAIL_ON" in
        fail) (( COUNTS[FAIL] > 0 )) && return 2 ;;
        warn) (( COUNTS[FAIL] > 0 || COUNTS[WARN] > 0 )) && return 2 ;;
    esac
    return 0
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
