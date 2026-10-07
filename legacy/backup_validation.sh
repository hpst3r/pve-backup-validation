#!/bin/bash
# ==============================================================================
# Proxmox Backup Validation
#
# Performs automated test restores of PBS backups into isolated VMs, validates
# boot, systemd services, TCP ports and HTTP endpoints, then destroys them.
#
# Port/HTTP checks run INSIDE the guest (via qemu-guest-agent), not from the
# host — so they work even on an isolated bridge with no route.
#
# Location: PVE node (NOT on the PBS host)
# Host requires: qm, qmrestore, pvesh, python3, flock, curl (Telegram)
# Guest requires: qemu-guest-agent running (+ curl/wget for HTTP checks)
# Config/secrets: /root/backup_validation.env  (override: BACKUP_VALIDATION_ENV)
#
# Author:  Tobias Pandolfo (Tobidp) — https://www.linkedin.com/in/tobiaspandolfo/
# Repo:    https://github.com/Tobidp/pve-backup-validation
# License: MIT (c) 2026 Tobias Pandolfo — see LICENSE
# ==============================================================================

set -uo pipefail

# ══════════════════════════════════════════════════════════════════════════════
# GLOBAL CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════

# ── PBS / PVE ─────────────────────────────────────────────────────────────────
PBS_STORAGE="pbs"                    # PBS storage name in PVE
RESTORE_STORAGE="local-lvm"          # Destination storage for the temporary restore
ISOLATED_BRIDGE="vmbr99"             # Bridge with no route to production
TEMP_VMID_PREFIX="9"                 # Temp VMID = prefix + original VMID (e.g. 675 -> 9675)

# ── Timeouts (seconds) ────────────────────────────────────────────────────────
BOOT_TIMEOUT=180                     # Wait for boot + guest-agent
SERVICE_TIMEOUT=60                   # Wait for TCP/HTTP service to respond
RESTORE_TIMEOUT=3600                 # Maximum restore timeout (1h)
GUEST_EXEC_TIMEOUT=120               # Max time for a command via guest-agent

# ── Files ─────────────────────────────────────────────────────────────────────
CONFIG_FILE="/root/backup_validation.conf"
LOG_BASE="/var/log/backup_validation"   # Logs root
RUN_DIR=""                           # Set in main(): $LOG_BASE/MM-DD-YY_HHhMM
CYCLE_LOG=""                         # Cycle-level log (pre-checks, summary)
LOG_FILE=""                          # Current log; switched per-VM in process_vm()
NODE=$(hostname)

# ── Telegram ──────────────────────────────────────────────────────────────────
TELEGRAM_TOKEN=""                    # SET in backup_validation.env
TELEGRAM_CHAT_ID=""                  # SET in backup_validation.env (the group/chat id)
TELEGRAM_THREAD_ID=""                # Optional: topic id in a forum supergroup (message_thread_id)
TELEGRAM_SILENT_ON_SUCCESS=true      # true = success messages without sound

# ── Execution ─────────────────────────────────────────────────────────────────
LOCKFILE="/var/lock/backup_validation.lock"   # Ensures a single run (flock)
TEMP_VM_TAG="backup-validation-temp"          # Tag applied to the throwaway test VM

# ══════════════════════════════════════════════════════════════════════════════
# ENVIRONMENT FILE LOADING (secrets + overrides)
#
# Everything above are DEFAULTS. The file pointed to by BACKUP_VALIDATION_ENV
# (default: /root/backup_validation.env) is loaded here and OVERRIDES any
# variable — it holds the Telegram token and per-node tweaks. CRLF is tolerated.
# ══════════════════════════════════════════════════════════════════════════════

ENV_FILE="${BACKUP_VALIDATION_ENV:-/root/backup_validation.env}"
if [[ -f "$ENV_FILE" ]]; then
    # shellcheck disable=SC1090
    source <(tr -d '\r' < "$ENV_FILE")
fi

# ══════════════════════════════════════════════════════════════════════════════
# SERVICE SIGNATURE LIBRARY (Auto-Discovery)
#
# Format: SYSTEMD_NAME:PORT:PROTOCOL:HTTP_ENDPOINT
# - SYSTEMD_NAME: unit name (supports multiple alternatives separated by |)
# - PORT: default TCP port (0 = no port validation)
# - PROTOCOL: tcp | http | https | none
# - HTTP_ENDPOINT: HTTP path to validate (empty = "/")
# ══════════════════════════════════════════════════════════════════════════════

declare -A SERVICE_SIGNATURES=(
    ["apache2|httpd"]="80:http:/"
    ["nginx"]="80:http:/"
    ["postgresql|postgresql@*"]="5432:tcp:"
    ["mariadb|mysql|mysqld"]="3306:tcp:"
    ["redis-server|redis"]="6379:tcp:"
    ["mongod|mongodb"]="27017:tcp:"
    ["clickhouse-server"]="9000:tcp:"
    ["docker"]="0:none:"
    ["elasticsearch"]="9200:http:/"
    ["rabbitmq-server"]="5672:tcp:"
    ["cloudflared"]="0:custom_cloudflared:"
)

# ══════════════════════════════════════════════════════════════════════════════
# GLOBAL STATE VARIABLES
# ══════════════════════════════════════════════════════════════════════════════

CYCLE_START=""
CYCLE_START_TS=0
TOTAL_OK=0
TOTAL_FAIL=0
TOTAL_VMS=0
FAILURES_LIST=""
CURRENT_TEMP_VMID=""                 # Temp VM being processed (cleanup on interruption)
LAST_HTTP_CODE=""                    # Set by check_http_guest (surfaced in the alert)
LAST_SYSTEMD_DETAIL=""              # Set by check_systemd (compact reason for the alert)

# ══════════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

# Quote-safe trim: drops CR (Windows line endings) and leading/trailing whitespace.
# Pure bash — unlike xargs, it never chokes on unbalanced quotes.
trim() {
    local s="${1//$'\r'/}"
    s="${s#"${s%%[![:space:]]*}"}"   # remove leading whitespace
    s="${s%"${s##*[![:space:]]}"}"   # remove trailing whitespace
    printf '%s' "$s"
}

format_duration() {
    local seconds=$1
    local h=$(( seconds / 3600 ))
    local m=$(( (seconds % 3600) / 60 ))
    local s=$(( seconds % 60 ))
    if (( h > 0 )); then
        printf "%dh %dm %ds" "$h" "$m" "$s"
    elif (( m > 0 )); then
        printf "%dm %ds" "$m" "$s"
    else
        printf "%ds" "$s"
    fi
}

format_size() {
    local bytes=$1
    if (( bytes >= 1073741824 )); then
        echo "$(awk "BEGIN {printf \"%.1f\", $bytes/1073741824}") GB"
    elif (( bytes >= 1048576 )); then
        echo "$(awk "BEGIN {printf \"%.1f\", $bytes/1048576}") MB"
    else
        echo "$(awk "BEGIN {printf \"%.1f\", $bytes/1024}") KB"
    fi
}

format_age() {
    local ctime=$1
    local now=$(date +%s)
    local diff=$(( now - ctime ))
    format_duration "$diff"
}

# ══════════════════════════════════════════════════════════════════════════════
# TELEGRAM
# ══════════════════════════════════════════════════════════════════════════════

send_telegram() {
    local message="$1"
    local type="${2:-INFO}"          # OK | FAIL | SUMMARY | INFO
    local silent="false"

    [[ -z "$TELEGRAM_TOKEN" || -z "$TELEGRAM_CHAT_ID" ]] && return 0

    if [[ "$type" == "OK" && "$TELEGRAM_SILENT_ON_SUCCESS" == "true" ]]; then
        silent="true"
    fi

    # Route to a forum-supergroup topic if a thread id is configured
    local thread_arg=()
    [[ -n "$TELEGRAM_THREAD_ID" ]] && thread_arg=(--data-urlencode "message_thread_id=${TELEGRAM_THREAD_ID}")

    local response
    response=$(curl -s -X POST \
        "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage" \
        --data-urlencode "chat_id=${TELEGRAM_CHAT_ID}" \
        "${thread_arg[@]}" \
        --data-urlencode "text=${message}" \
        --data-urlencode "parse_mode=Markdown" \
        --data-urlencode "disable_notification=${silent}" 2>&1)

    if ! echo "$response" | grep -q '"ok":true'; then
        log "TELEGRAM_FAIL | Response: $response"
    fi
}

# Sends an image (e.g. a console screenshot) with a short caption
send_telegram_photo() {
    local photo="$1"
    local caption="$2"

    [[ -z "$TELEGRAM_TOKEN" || -z "$TELEGRAM_CHAT_ID" ]] && return 0
    [[ -s "$photo" ]] || return 0

    local thread_arg=()
    [[ -n "$TELEGRAM_THREAD_ID" ]] && thread_arg=(-F "message_thread_id=${TELEGRAM_THREAD_ID}")

    local response
    response=$(curl -s -X POST \
        "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendPhoto" \
        -F "chat_id=${TELEGRAM_CHAT_ID}" \
        "${thread_arg[@]}" \
        -F "photo=@${photo}" \
        -F "caption=${caption}" 2>&1)

    if ! echo "$response" | grep -q '"ok":true'; then
        log "TELEGRAM_PHOTO_FAIL | Response: $response"
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# SNAPSHOT METADATA COLLECTION (PBS)
# ══════════════════════════════════════════════════════════════════════════════

get_snapshot_metadata() {
    local vmid=$1
    # Returns: volid|ctime|size (separated by |)
    pvesh get "/nodes/$NODE/storage/$PBS_STORAGE/content" \
        --output-format json 2>/dev/null \
        | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    # vmid may come back as int or str depending on PVE version — compare as str
    snaps = [x for x in data if str(x.get('vmid', '')) == '$vmid' and x.get('content') == 'backup']
    snaps.sort(key=lambda x: x.get('ctime', 0), reverse=True)
    if snaps:
        s = snaps[0]
        print(f\"{s['volid']}|{s.get('ctime', 0)}|{s.get('size', 0)}\")
except Exception as e:
    print('', file=sys.stderr)
" 2>/dev/null
}

# ══════════════════════════════════════════════════════════════════════════════
# GET SOURCE VM NAME
# ══════════════════════════════════════════════════════════════════════════════

get_vm_name() {
    local vmid=$1
    local name
    # Cluster-aware query: sees VMs on any node (local storage, no shared VM FS)
    name=$(pvesh get /cluster/resources --type vm --output-format json 2>/dev/null \
        | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for vm in data:
        if vm.get('vmid') == $vmid:
            print(vm.get('name', ''))
            break
except Exception:
    pass
" 2>/dev/null)
    # Fallback: local config (if the VM lives on this node) and finally vm-<id>
    [[ -z "$name" ]] && name=$(qm config "$vmid" 2>/dev/null | grep -E "^name:" | awk '{print $2}')
    echo "${name:-vm-${vmid}}"
}

# ══════════════════════════════════════════════════════════════════════════════
# QEMU GUEST AGENT — GUEST INTERACTION
# ══════════════════════════════════════════════════════════════════════════════

wait_for_boot() {
    local vmid=$1
    local elapsed=0
    log "BOOT_WAIT | VMID=$vmid | TIMEOUT=${BOOT_TIMEOUT}s"
    while (( elapsed < BOOT_TIMEOUT )); do
        if qm agent "$vmid" ping &>/dev/null; then
            log "BOOT_OK | VMID=$vmid | ELAPSED=${elapsed}s"
            echo "$elapsed"
            return 0
        fi
        sleep 5
        (( elapsed += 5 ))
    done
    log "BOOT_FAIL | VMID=$vmid | TIMEOUT_EXCEEDED"
    return 1
}

get_guest_ip() {
    local vmid=$1
    qm agent "$vmid" network-get-interfaces 2>/dev/null \
        | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for iface in data:
        if iface.get('name', '').startswith('lo'):
            continue
        for addr in iface.get('ip-addresses', []):
            if addr.get('ip-address-type') == 'ipv4':
                ip = addr.get('ip-address', '')
                if ip and not ip.startswith('127.'):
                    print(ip)
                    sys.exit()
except Exception:
    pass
" 2>/dev/null
}

# Runs a command in the guest via guest-agent and returns stdout
guest_exec() {
    local vmid=$1
    shift
    local cmd_json
    cmd_json=$(qm agent "$vmid" exec -- "$@" 2>/dev/null)

    [[ -z "$cmd_json" ]] && return 1

    local pid
    pid=$(echo "$cmd_json" | python3 -c "
import sys, json
try:
    print(json.load(sys.stdin).get('pid', ''))
except Exception:
    pass
" 2>/dev/null)

    [[ -z "$pid" ]] && return 1

    # Wait for completion
    local attempts=0
    while (( attempts < GUEST_EXEC_TIMEOUT )); do
        local status_json
        status_json=$(qm agent "$vmid" exec-status "$pid" 2>/dev/null)
        local exited
        exited=$(echo "$status_json" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print('1' if d.get('exited') else '0')
except Exception:
    print('0')
" 2>/dev/null)

        if [[ "$exited" == "1" ]]; then
            echo "$status_json" | python3 -c "
import sys, json, base64
try:
    d = json.load(sys.stdin)
    out = d.get('out-data', '')
    if out:
        try:
            print(base64.b64decode(out).decode('utf-8', errors='replace'), end='')
        except Exception:
            print(out, end='')
except Exception:
    pass
" 2>/dev/null
            return 0
        fi
        sleep 1
        (( attempts++ ))
    done
    return 1
}

# ══════════════════════════════════════════════════════════════════════════════
# SERVICE AUTO-DISCOVERY
# ══════════════════════════════════════════════════════════════════════════════

# List enabled systemd services in the guest
list_guest_services() {
    local vmid=$1
    guest_exec "$vmid" /bin/bash -c \
        "systemctl list-unit-files --type=service --state=enabled --no-legend --no-pager 2>/dev/null | awk '{print \$1}' | sed 's/\.service\$//'"
}

# For each known signature, check whether the service is present in the guest
discover_services_to_validate() {
    local vmid=$1
    local guest_services
    guest_services=$(list_guest_services "$vmid")

    local discovered=""

    for signature in "${!SERVICE_SIGNATURES[@]}"; do
        local meta="${SERVICE_SIGNATURES[$signature]}"
        # a signature may have alternatives separated by |
        IFS='|' read -ra alternatives <<< "$signature"
        for alt in "${alternatives[@]}"; do
            # Supports basic wildcards
            if echo "$guest_services" | grep -qE "^${alt//\*/.*}$"; then
                # Find the real service name in the guest
                local real_service
                real_service=$(echo "$guest_services" | grep -E "^${alt//\*/.*}$" | head -1)
                discovered="${discovered}${real_service}:${meta}|"
                break
            fi
        done
    done

    echo "$discovered"
}

# ══════════════════════════════════════════════════════════════════════════════
# VALIDATIONS
# ══════════════════════════════════════════════════════════════════════════════

check_systemd() {
    local vmid=$1
    local service=$2
    local result
    result=$(guest_exec "$vmid" /bin/bash -c "systemctl is-active $service 2>/dev/null")
    result=$(echo "$result" | tr -d '[:space:]')

    if [[ "$result" == "active" ]]; then
        log "SYSTEMD_OK | VMID=$vmid | SERVICE=$service"
        LAST_SYSTEMD_DETAIL=""
        return 0
    fi

    # Not active — capture WHY: a compact reason for the alert, full diag for the log
    local props
    props=$(guest_exec "$vmid" /bin/bash -c \
        "systemctl show '$service' -p ActiveState,SubState,Result 2>/dev/null | tr '\n' ' '")
    props=$(trim "$props")
    LAST_SYSTEMD_DETAIL="${result}${props:+ — $props}"

    log "SYSTEMD_FAIL | VMID=$vmid | SERVICE=$service | STATUS=$result | $props"

    local diag
    diag=$(guest_exec "$vmid" /bin/bash -c \
        "systemctl status '$service' --no-pager -l 2>&1 | head -n 25; echo '----- journal (last 15) -----'; journalctl -u '$service' -n 15 --no-pager 2>&1")
    [[ -n "$diag" ]] && log "SYSTEMD_DIAG | VMID=$vmid | SERVICE=$service
$diag"

    return 1
}

# Checks, INSIDE the guest, whether there is a TCP socket in LISTEN on the port (ss or netstat)
check_tcp_guest() {
    local vmid=$1
    local port=$2
    local elapsed=0
    while (( elapsed < SERVICE_TIMEOUT )); do
        local r
        r=$(guest_exec "$vmid" /bin/bash -c \
            "{ ss -ltn 2>/dev/null || netstat -ltn 2>/dev/null; } | grep -qE '[:.]${port}([[:space:]]|\$)' && echo OK")
        if [[ "$(echo "$r" | tr -d '[:space:]')" == "OK" ]]; then
            log "TCP_OK | VMID=$vmid | PORT=$port (LISTEN internal)"
            return 0
        fi
        sleep 3
        (( elapsed += 3 ))
    done
    log "TCP_FAIL | VMID=$vmid | PORT=$port | No socket in LISTEN state (internal)"
    return 1
}

check_cloudflared() {
    local vmid=$1
    log "CLOUDFLARED_CHECK | VMID=$vmid | Waiting 30s for log analysis"
    sleep 30

    local errors
    errors=$(guest_exec "$vmid" /bin/bash -c \
        "journalctl -u cloudflared --since '1 minute ago' --no-pager 2>/dev/null | grep -iE 'error|fatal|failed' | grep -vE 'network is unreachable|no such host|dial tcp|context deadline' | wc -l")

    errors=$(echo "$errors" | tr -d '[:space:]')

    if [[ "$errors" == "0" || -z "$errors" ]]; then
        log "CLOUDFLARED_OK | VMID=$vmid | No critical errors in log"
        return 0
    fi

    log "CLOUDFLARED_FAIL | VMID=$vmid | $errors non-network-related errors"
    return 1
}

# Makes an HTTP(S) request INSIDE the guest against localhost (curl or wget).
# Returns: 0 = OK | 1 = no valid response | 2 = no HTTP client in guest
check_http_guest() {
    local vmid=$1
    local port=$2
    local endpoint="${3:-/}"
    local proto="${4:-http}"
    local elapsed=0
    local code=""
    while (( elapsed < SERVICE_TIMEOUT )); do
        code=$(guest_exec "$vmid" /bin/bash -c "
if command -v curl >/dev/null 2>&1; then
    curl -sk -o /dev/null -w '%{http_code}' --max-time 5 '${proto}://127.0.0.1:${port}${endpoint}' 2>/dev/null
elif command -v wget >/dev/null 2>&1; then
    c=\$(wget -qS -O /dev/null --no-check-certificate --timeout=5 '${proto}://127.0.0.1:${port}${endpoint}' 2>&1 | grep -oE 'HTTP/[0-9.]+ [0-9]{3}' | tail -1 | grep -oE '[0-9]{3}')
    echo \"\${c:-000}\"
else
    echo NOCLIENT
fi
")
        code=$(echo "$code" | tr -d '[:space:]')
        if [[ "$code" == "NOCLIENT" ]]; then
            log "HTTP_NOCLIENT | VMID=$vmid | PORT=$port | No curl/wget in guest"
            LAST_HTTP_CODE="NOCLIENT"
            return 2
        fi
        # Accept 2xx, 3xx, 401, 403 (service responding, even if it denies access)
        if [[ "$code" =~ ^(2|3)[0-9]{2}$ ]] || [[ "$code" == "401" ]] || [[ "$code" == "403" ]]; then
            log "HTTP_OK | VMID=$vmid | PORT=$port | CODE=$code (internal)"
            LAST_HTTP_CODE="$code"
            return 0
        fi
        sleep 3
        (( elapsed += 3 ))
    done
    LAST_HTTP_CODE="${code:-timeout}"
    log "HTTP_FAIL | VMID=$vmid | PORT=$port | LAST_CODE=$LAST_HTTP_CODE (internal)"
    return 1
}

# ══════════════════════════════════════════════════════════════════════════════
# CONSOLE CAPTURE
# ══════════════════════════════════════════════════════════════════════════════

# Captures the VM's VGA console to a PNG (shows GRUB / kernel panic / fsck /
# emergency shell — things the guest agent can't see). Echoes the PNG path on
# success, nothing on failure. $2 = output path WITHOUT extension.
capture_console() {
    local vmid=$1
    local out_base=$2
    local ppm="${out_base}.ppm"
    local png="${out_base}.png"

    # Try native PNG first (QEMU 8+); the monitor reads the command from stdin
    qm monitor "$vmid" <<< "screendump ${png} -f png" &>/dev/null
    if [[ -s "$png" ]]; then
        echo "$png"; return 0
    fi

    # Fallback: dump PPM and convert with netpbm or ImageMagick
    qm monitor "$vmid" <<< "screendump ${ppm}" &>/dev/null
    [[ -s "$ppm" ]] || return 1

    if command -v pnmtopng &>/dev/null; then
        pnmtopng "$ppm" > "$png" 2>/dev/null
    elif command -v convert &>/dev/null; then
        convert "$ppm" "$png" 2>/dev/null
    fi

    if [[ -s "$png" ]]; then
        rm -f "$ppm"
        echo "$png"; return 0
    fi
    return 1   # no converter available — PPM kept on disk, but not sendable
}

# ══════════════════════════════════════════════════════════════════════════════
# CLEANUP
# ══════════════════════════════════════════════════════════════════════════════

cleanup_vm() {
    local vmid=$1
    # Safety guard: only destroy IDs that match the temp scheme — the prefix
    # followed by a real VMID (>= 100, i.e. at least 3 digits after the prefix).
    local min_len=$(( ${#TEMP_VMID_PREFIX} + 3 ))
    if [[ ! "$vmid" =~ ^[0-9]+$ ]] || [[ "$vmid" != "${TEMP_VMID_PREFIX}"* ]] || (( ${#vmid} < min_len )); then
        log "CLEANUP_REFUSED | VMID='$vmid' does not match the temp scheme (${TEMP_VMID_PREFIX}<vmid>) — refusing to destroy"
        CURRENT_TEMP_VMID=""
        return 0
    fi
    if qm status "$vmid" &>/dev/null; then
        log "DESTROY | VMID=$vmid"
        qm stop "$vmid" --skiplock 1 &>/dev/null || true
        sleep 5
        qm destroy "$vmid" --purge 1 --destroy-unreferenced-disks 1 &>/dev/null || true
    fi
    CURRENT_TEMP_VMID=""
}

# Global trap: cleans up the in-flight temporary VM if the script is interrupted
cleanup_global() {
    trap '' INT TERM
    log "INTERRUPTED | Signal received — cleaning up temporary VM and aborting"
    [[ -n "$CURRENT_TEMP_VMID" ]] && cleanup_vm "$CURRENT_TEMP_VMID"
    exit 130
}

# ══════════════════════════════════════════════════════════════════════════════
# PER-VM PROCESSING
# ══════════════════════════════════════════════════════════════════════════════

process_vm() {
    local orig_vmid=$1
    local mode=$2
    local overrides=$3
    local temp_vmid=$4

    local vm_start_ts=$(date +%s)
    local vm_name
    vm_name=$(get_vm_name "$orig_vmid")

    # Dedicated log for this VM: $RUN_DIR/<vmid>/<vmid>.log
    local vm_log_dir="$RUN_DIR/$orig_vmid"
    mkdir -p "$vm_log_dir"
    LOG_FILE="$vm_log_dir/${orig_vmid}.log"

    log "══ START | VM=$vm_name | ORIG_VMID=$orig_vmid | TEMP_VMID=$temp_vmid | MODE=$mode"

    trap "cleanup_vm $temp_vmid" RETURN
    CURRENT_TEMP_VMID=$temp_vmid

    # ── 1. Locate snapshot ────────────────────────────────────────────────────
    local snap_meta
    snap_meta=$(get_snapshot_metadata "$orig_vmid")

    if [[ -z "$snap_meta" ]]; then
        log "SNAPSHOT_FAIL | VMID=$orig_vmid | No snapshot found"
        local vm_duration
        vm_duration=$(format_duration $(( $(date +%s) - vm_start_ts )))
        notify_failure "$vm_name" "$orig_vmid" "$temp_vmid" "-" "-" "-" \
            "$vm_duration" "" "NO_SNAPSHOT"
        register_failure "$orig_vmid" "$vm_name" "NO_SNAPSHOT"
        return 1
    fi

    local volid ctime size_bytes
    IFS='|' read -r volid ctime size_bytes <<< "$snap_meta"

    local snap_date
    snap_date=$(date -d "@$ctime" '+%Y-%m-%d %H:%M:%S')
    local snap_age
    snap_age=$(format_age "$ctime")
    local snap_size
    snap_size=$(format_size "$size_bytes")

    log "SNAPSHOT_OK | VOLID=$volid | DATE=$snap_date | AGE=$snap_age | SIZE=$snap_size"

    # ── 2. Restore ────────────────────────────────────────────────────────────
    log "RESTORE_START | TEMP_VMID=$temp_vmid"
    if ! timeout "$RESTORE_TIMEOUT" qmrestore "$volid" "$temp_vmid" \
        --storage "$RESTORE_STORAGE" \
        --unique 1 &>>"$LOG_FILE"; then
        log "RESTORE_FAIL | TEMP_VMID=$temp_vmid"
        local vm_duration
        vm_duration=$(format_duration $(( $(date +%s) - vm_start_ts )))
        notify_failure "$vm_name" "$orig_vmid" "$temp_vmid" "$snap_date" \
            "$snap_age" "$snap_size" "$vm_duration" "" "RESTORE_FAIL"
        register_failure "$orig_vmid" "$vm_name" "RESTORE_FAIL"
        return 1
    fi
    log "RESTORE_OK | TEMP_VMID=$temp_vmid"

    # Mark the temporary VM as a disposable test artifact (visual safety cue)
    qm set "$temp_vmid" \
        --tags "$TEMP_VM_TAG" \
        --description "TEMP RESTORE TEST — safe to delete. Created by backup_validation.sh from VMID $orig_vmid ($vm_name) at $(date '+%Y-%m-%d %H:%M:%S')." \
        &>>"$LOG_FILE" || true

    # ── 3. Network isolation ──────────────────────────────────────────────────
    local net_config
    net_config=$(qm config "$temp_vmid" 2>/dev/null | grep -E "^net[0-9]+:")

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        local netid
        netid=$(echo "$line" | grep -oE "^net[0-9]+")
        [[ -z "$netid" ]] && continue
        # Preserve model/MAC/VLAN/queues — only swap the bridge and disable firewall
        local value
        value=$(echo "$line" | sed -E 's/^net[0-9]+:[[:space:]]*//')
        if echo "$value" | grep -q 'bridge='; then
            value=$(echo "$value" | sed -E "s/bridge=[^,]*/bridge=${ISOLATED_BRIDGE}/")
        else
            value="${value},bridge=${ISOLATED_BRIDGE}"
        fi
        if echo "$value" | grep -q 'firewall='; then
            value=$(echo "$value" | sed -E "s/firewall=[^,]*/firewall=0/")
        else
            value="${value},firewall=0"
        fi
        qm set "$temp_vmid" --"$netid" "$value" &>>"$LOG_FILE"
    done <<< "$net_config"

    log "NETWORK_ISOLATED | TEMP_VMID=$temp_vmid | BRIDGE=$ISOLATED_BRIDGE"

    # ── 4. Boot ───────────────────────────────────────────────────────────────
    qm start "$temp_vmid" &>>"$LOG_FILE"
    local boot_time
    boot_time=$(wait_for_boot "$temp_vmid")

    if [[ -z "$boot_time" ]]; then
        register_failure "$orig_vmid" "$vm_name" "BOOT_TIMEOUT"
        local vm_duration
        vm_duration=$(format_duration $(( $(date +%s) - vm_start_ts )))

        # The guest agent never came up — capture the console screen, which still
        # shows whatever stalled the boot (GRUB, kernel panic, fsck, emergency).
        local console_png
        console_png=$(capture_console "$temp_vmid" "$vm_log_dir/boot_console_${temp_vmid}")
        if [[ -n "$console_png" ]]; then
            log "CONSOLE_CAPTURED | VMID=$temp_vmid | $console_png"
        else
            log "CONSOLE_CAPTURE_FAIL | VMID=$temp_vmid | no PNG produced (missing pnmtopng/convert?)"
        fi

        notify_failure "$vm_name" "$orig_vmid" "$temp_vmid" "$snap_date" \
            "$snap_age" "$snap_size" "$vm_duration" "" "BOOT_TIMEOUT"

        [[ -n "$console_png" ]] && send_telegram_photo "$console_png" \
            "🖥️ ${vm_name} (temp ${temp_vmid}) — console at BOOT_TIMEOUT (GRUB / panic / fsck / emergency?)"

        return 1
    fi

    # ── 5. Get guest IP ───────────────────────────────────────────────────────
    sleep 5  # margin for the network to settle
    local guest_ip
    guest_ip=$(get_guest_ip "$temp_vmid")

    if [[ -z "$guest_ip" ]]; then
        log "IP_WARN | VMID=$temp_vmid | IP not detected (checks run inside the guest anyway)"
        guest_ip="N/A"
    else
        log "IP_OK | VMID=$temp_vmid | IP=$guest_ip"
    fi

    # ── 6. Auto-discovery + overrides ─────────────────────────────────────────
    local services_to_validate=""

    if [[ "$mode" == "auto" || "$mode" == "hybrid" ]]; then
        services_to_validate=$(discover_services_to_validate "$temp_vmid")
        log "AUTO_DISCOVERY | VMID=$temp_vmid | SERVICES=${services_to_validate:-none}"
    fi

    # Add overrides (format: service:port,service:port)
    if [[ "$mode" == "hybrid" || "$mode" == "manual" ]]; then
        if [[ -n "$overrides" ]]; then
            IFS=',' read -ra override_list <<< "$overrides"
            for override in "${override_list[@]}"; do
                local ov_service ov_port
                ov_service=$(echo "$override" | cut -d':' -f1)
                ov_port=$(echo "$override" | cut -d':' -f2)
                local proto="tcp"
                [[ "$ov_port" == "80" || "$ov_port" == "8080" ]] && proto="http"
                [[ "$ov_port" == "443" || "$ov_port" == "8443" ]] && proto="https"
                services_to_validate="${services_to_validate}${ov_service}:${ov_port}:${proto}:/|"
            done
            log "OVERRIDES_APPLIED | VMID=$temp_vmid | $overrides"
        fi
    fi

    # ── 7. Run validations ────────────────────────────────────────────────────
    local checks=""
    local final_result="OK"
    local failure_reason=""

    # Boot check (always)
    checks="${checks}  ✓ Boot (${boot_time}s)\n"

    if [[ -z "$services_to_validate" ]]; then
        checks="${checks}  ⚠ No service identified to validate\n"
    else
        IFS='|' read -ra service_list <<< "$services_to_validate"
        for item in "${service_list[@]}"; do
            [[ -z "$item" ]] && continue

            local svc port proto endpoint
            IFS=':' read -r svc port proto endpoint <<< "$item"
            endpoint="${endpoint:-/}"

            # 7.1 systemd check
            local svc_ok=true
            if ! check_systemd "$temp_vmid" "$svc"; then
                checks="${checks}  ✗ systemd: ${svc} [${LAST_SYSTEMD_DETAIL:-inactive}]\n"
                final_result="FAIL"
                failure_reason="SYSTEMD_FAIL_${svc}"
                svc_ok=false
            else
                checks="${checks}  ✓ systemd: ${svc}\n"
            fi

            # 7.2 Custom validations (run regardless of IP/port)
            if $svc_ok; then
                case "$proto" in
                    custom_cloudflared)
                        if check_cloudflared "$temp_vmid"; then
                            checks="${checks}  ✓ Log clean (${svc})\n"
                        else
                            checks="${checks}  ✗ Log has errors (${svc})\n"
                            final_result="FAIL"
                            failure_reason="LOG_FAIL_${svc}"
                        fi
                        ;;
                esac
            fi

            # 7.3 Port/HTTP check — executed INSIDE the guest (network-independent)
            if $svc_ok && [[ "$port" != "0" ]]; then
                case "$proto" in
                    http|https)
                        local http_rc
                        check_http_guest "$temp_vmid" "$port" "$endpoint" "$proto"
                        http_rc=$?
                        if (( http_rc == 0 )); then
                            checks="${checks}  ✓ ${proto^^} ${port} (${svc}) [${LAST_HTTP_CODE}]\n"
                        elif (( http_rc == 2 )); then
                            # No HTTP client in guest → at least validate the port is LISTEN
                            if check_tcp_guest "$temp_vmid" "$port"; then
                                checks="${checks}  ✓ Port ${port} LISTEN (${svc}) [no HTTP client in guest]\n"
                            else
                                checks="${checks}  ✗ Port ${port} (${svc}) [not listening]\n"
                                final_result="FAIL"
                                failure_reason="PORT_FAIL_${svc}_${port}"
                            fi
                        else
                            checks="${checks}  ✗ ${proto^^} ${port} (${svc}) [${LAST_HTTP_CODE}]\n"
                            final_result="FAIL"
                            failure_reason="${proto^^}_FAIL_${svc}_${port}_${LAST_HTTP_CODE}"
                        fi
                        ;;
                    tcp)
                        if check_tcp_guest "$temp_vmid" "$port"; then
                            checks="${checks}  ✓ TCP ${port} (${svc})\n"
                        else
                            checks="${checks}  ✗ TCP ${port} (${svc}) [not listening]\n"
                            final_result="FAIL"
                            failure_reason="TCP_FAIL_${svc}_${port}"
                        fi
                        ;;
                esac
            fi
        done
    fi

    # ── 8. Notification and accounting ────────────────────────────────────────
    local vm_duration
    vm_duration=$(format_duration $(( $(date +%s) - vm_start_ts )))

    log "RESULT=$final_result | VM=$vm_name | VMID=$orig_vmid | DURATION=$vm_duration"

    if [[ "$final_result" == "OK" ]]; then
        notify_success "$vm_name" "$orig_vmid" "$temp_vmid" "$guest_ip" \
            "$snap_date" "$snap_age" "$snap_size" "$vm_duration" "$checks"
        (( TOTAL_OK++ ))
    else
        notify_failure "$vm_name" "$orig_vmid" "$temp_vmid" "$snap_date" \
            "$snap_age" "$snap_size" "$vm_duration" "$checks" "$failure_reason"
        register_failure "$orig_vmid" "$vm_name" "$failure_reason"
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# TELEGRAM MESSAGES
# ══════════════════════════════════════════════════════════════════════════════

notify_success() {
    local name=$1 orig_vmid=$2 temp_vmid=$3 ip=$4 snap_date=$5 \
          snap_age=$6 snap_size=$7 duration=$8 checks=$9

    local msg="✅ *BACKUP\_VALIDATION* | OK

*VM:* \`${name}\`
*VMID:* ${orig_vmid} → ${temp_vmid}
*Node:* ${NODE}
*Test IP:* \`${ip}\`
*Snapshot:* ${snap_date} (age: ${snap_age})
*Size:* ${snap_size}
*Duration:* ${duration}

*Checks:*
\`\`\`
$(echo -e "$checks")
\`\`\`"

    send_telegram "$msg" "OK"
}

notify_failure() {
    local name=$1 orig_vmid=$2 temp_vmid=$3 snap_date=$4 \
          snap_age=$5 snap_size=$6 duration=$7 checks=$8 reason=$9

    local msg="❌ *BACKUP\_VALIDATION* | FAIL

*VM:* \`${name}\`
*VMID:* ${orig_vmid} → ${temp_vmid}
*Node:* ${NODE}
*Snapshot:* ${snap_date} (age: ${snap_age})
*Size:* ${snap_size}
*Duration:* ${duration}

*Checks:*
\`\`\`
$(echo -e "$checks")
\`\`\`
*Reason:* \`${reason}\`
*Log:* \`${LOG_FILE}\`"

    send_telegram "$msg" "FAIL"
}

# Records the failure in the summary list AND counts it (single source of TOTAL_FAIL).
# Called on ALL failure paths — including snapshot/restore.
register_failure() {
    local vmid=$1 name=$2 reason=$3
    FAILURES_LIST="${FAILURES_LIST}  • VMID ${vmid} (${name}): ${reason}\n"
    (( TOTAL_FAIL++ )) || true
}

send_summary() {
    local end_ts=$(date +%s)
    local end_date
    end_date=$(date '+%Y-%m-%d %H:%M:%S')
    local total_duration
    total_duration=$(format_duration $(( end_ts - CYCLE_START_TS )))

    local msg="📊 *BACKUP\_VALIDATION* | SUMMARY

*Node:* ${NODE}
*Start:* ${CYCLE_START}
*End:* ${end_date}
*Total duration:* ${total_duration}

*VMs tested:* ${TOTAL_VMS}
  ✅ OK:   ${TOTAL_OK}
  ❌ FAIL: ${TOTAL_FAIL}"

    if (( TOTAL_FAIL > 0 )); then
        msg="${msg}

*Failures:*
\`\`\`
$(echo -e "$FAILURES_LIST")
\`\`\`"
        send_telegram "$msg" "FAIL"
    else
        send_telegram "$msg" "OK"
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

parse_args() {
    TEST_MODE=""
    TEST_VMID=""
    TEST_VM_MODE="auto"
    TEST_OVERRIDES=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --vmid)
                TEST_MODE="single"
                TEST_VMID="$2"
                shift 2
                ;;
            --mode)
                TEST_VM_MODE="$2"
                shift 2
                ;;
            --overrides)
                TEST_OVERRIDES="$2"
                shift 2
                ;;
            --help|-h)
                cat <<EOF
Usage:
  $0 # Run full cycle from CONFIG_FILE
  $0 --vmid VMID [--mode MODE] [--overrides OV] # One-off test of a single VM

Options:
  --vmid VMID            Original VMID of the VM to test
  --mode MODE            auto | hybrid | manual (default: auto)
  --overrides STRING     "service:port,service:port" (for hybrid/manual)

Examples:
  $0 --vmid 105 # Auto-discovery test on VM 105
  $0 --vmid 105 --mode hybrid --overrides "cloudflared:0"
  $0 --vmid 105 --mode manual --overrides "myapp:8080"
EOF
                exit 0
                ;;
            *)
                echo "Unknown argument: $1"
                exit 1
                ;;
        esac
    done
}

main() {
    parse_args "$@"

    # ── Single run (flock) ────────────────────────────────────────────────────
    if command -v flock &>/dev/null; then
        mkdir -p "$(dirname "$LOCKFILE")" 2>/dev/null || true
        exec 200>"$LOCKFILE" || true
        if ! flock -n 200; then
            echo "[$(date '+%F %T')] FATAL | Another run in progress (lock: $LOCKFILE). Aborting." >&2
            exit 1
        fi
    else
        echo "[$(date '+%F %T')] WARN | flock unavailable — no single-run protection" >&2
    fi

    CYCLE_START=$(date '+%Y-%m-%d %H:%M:%S')
    CYCLE_START_TS=$(date +%s)

    # This run's directory: /var/log/backup_validation/MM-DD-YY_HHhMM
    RUN_DIR="$LOG_BASE/$(date '+%m-%d-%y_%Hh%M')"
    mkdir -p "$RUN_DIR"
    CYCLE_LOG="$RUN_DIR/_cycle.log"
    LOG_FILE="$CYCLE_LOG"

    # Clean up the temporary VM if the script is interrupted
    trap cleanup_global INT TERM

    if [[ "$TEST_MODE" == "single" ]]; then
        log "════════════════ SINGLE TEST MODE ════════════════"
        log "VMID=$TEST_VMID | MODE=$TEST_VM_MODE | OVERRIDES=$TEST_OVERRIDES"
    else
        log "════════════════ CYCLE START ════════════════"
        log "NODE=$NODE | CONFIG=$CONFIG_FILE"
    fi

    if [[ -f "$ENV_FILE" ]]; then
        log "ENV | Loaded: $ENV_FILE"
    else
        log "ENV | Not found ($ENV_FILE) — using defaults; Telegram may be inactive"
    fi

    # Validate prerequisites
    if ! command -v qmrestore &>/dev/null; then
        log "FATAL | qmrestore not available — this script must run on a PVE node"
        exit 1
    fi

    if ! ip link show "$ISOLATED_BRIDGE" &>/dev/null; then
        log "FATAL | Isolated bridge $ISOLATED_BRIDGE does not exist"
        exit 1
    fi

    # The prefix must be a positive integer (no leading zero) so the temp VMID is
    # always strictly larger than the source and well-formed (e.g. 9 + 675 = 9675).
    if [[ ! "$TEMP_VMID_PREFIX" =~ ^[1-9][0-9]*$ ]]; then
        log "FATAL | TEMP_VMID_PREFIX must be a positive integer (got '$TEMP_VMID_PREFIX')"
        exit 1
    fi

    # ── SINGLE TEST MODE ──────────────────────────────────────────────────────
    if [[ "$TEST_MODE" == "single" ]]; then
        local temp_vmid="${TEMP_VMID_PREFIX}${TEST_VMID}"

        if qm status "$temp_vmid" &>/dev/null; then
            log "FATAL | Temporary VMID $temp_vmid already in use"
            exit 1
        fi

        (( TOTAL_VMS++ ))
        process_vm "$TEST_VMID" "$TEST_VM_MODE" "$TEST_OVERRIDES" "$temp_vmid" || true
        LOG_FILE="$CYCLE_LOG"

        log "════════════════ TEST END | OK=$TOTAL_OK | FAIL=$TOTAL_FAIL ════════════════"
        send_summary
        return
    fi

    # ── FULL CYCLE MODE ───────────────────────────────────────────────────────
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log "FATAL | Configuration file not found: $CONFIG_FILE"
        exit 1
    fi

    while IFS=';' read -r orig_vmid mode overrides || [[ -n "$orig_vmid" ]]; do
        # Tolerate CRLF and surrounding spaces; skip comments/blanks early
        orig_vmid=$(trim "$orig_vmid")
        [[ "$orig_vmid" =~ ^# ]] && continue
        [[ -z "$orig_vmid" ]] && continue

        mode=$(trim "${mode:-auto}")
        [[ -z "$mode" ]] && mode="auto"
        overrides=$(trim "${overrides:-}")

        local temp_vmid="${TEMP_VMID_PREFIX}${orig_vmid}"
        (( TOTAL_VMS++ ))

        if qm status "$temp_vmid" &>/dev/null; then
            log "FATAL | Temporary VMID $temp_vmid already in use. Clean up before proceeding."
            register_failure "$orig_vmid" "$(get_vm_name "$orig_vmid")" "TEMP_VMID_BUSY"
            continue
        fi

        process_vm "$orig_vmid" "$mode" "$overrides" "$temp_vmid" || true
        LOG_FILE="$CYCLE_LOG"

    done < "$CONFIG_FILE"

    log "════════════════ CYCLE END | OK=$TOTAL_OK | FAIL=$TOTAL_FAIL ════════════════"
    send_summary
}

main "$@"
