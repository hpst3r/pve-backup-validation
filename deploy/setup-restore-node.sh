#!/bin/bash
# Prepare a STANDALONE Proxmox VE restore node for pbv. Run as root ON the restore node.
# Review before running. Idempotent where pveum allows it.
#
#   ./setup-restore-node.sh <backup_storage_id> <target_storage_id> [bridge=vmbr-pbv]
#
# Creates:
#   - an isolated bridge (no ports, no IP) if missing
#   - user pbv@pve + API token pbv@pve!validation (privilege-separated)
#   - role PBVRestore with the privileges pbv needs, granted on the minimum paths
#
# The PBS storage itself (pointing at the PRODUCTION datastore, ideally with a PBS
# user that only has DatastoreReader on it, plus the encryption key if backups are
# encrypted) must be added beforehand: Datacenter -> Storage -> Add -> Proxmox Backup Server.
set -euo pipefail

BACKUP_STORAGE="${1:?backup storage id (type pbs)}"
TARGET_STORAGE="${2:?target storage id for temp disks}"
BRIDGE="${3:-vmbr-pbv}"
USER="pbv@pve"
TOKEN="validation"
ROLE="PBVRestore"

command -v pveum >/dev/null || { echo "run this on a Proxmox VE node" >&2; exit 1; }

if [ -f /etc/pve/corosync.conf ]; then
    echo "WARNING: this node is part of a cluster. pbv refuses clustered nodes by default" >&2
    echo "         (target.require_standalone). Use a dedicated standalone node." >&2
fi

pvever="$(pveversion | sed -E 's#pve-manager/([0-9]+).*#\1#')"

# ── isolated bridge ──────────────────────────────────────────────────────────
if ! ip link show "$BRIDGE" >/dev/null 2>&1; then
    echo "creating isolated bridge $BRIDGE"
    cat >> /etc/network/interfaces <<EOF

auto $BRIDGE
iface $BRIDGE inet manual
    bridge-ports none
    bridge-stp off
    bridge-fd 0
#pbv isolated test network: no ports, no IP, no gateway
EOF
    ifreload -a
fi

# ── role ─────────────────────────────────────────────────────────────────────
PRIVS="VM.Allocate VM.Audit VM.Backup VM.PowerMgmt VM.Config.Disk VM.Config.CDROM VM.Config.CPU \
VM.Config.Memory VM.Config.Network VM.Config.HWType VM.Config.Options VM.Config.Cloudinit \
Datastore.AllocateSpace Datastore.Audit SDN.Use Sys.Audit Pool.Audit"
if [ "$pvever" -ge 9 ]; then
    # PVE 9 split VM.Monitor; guest-agent exec + file-write need these.
    PRIVS="$PRIVS VM.GuestAgent.Audit VM.GuestAgent.Unrestricted VM.GuestAgent.FileWrite VM.GuestAgent.FileRead"
else
    PRIVS="$PRIVS VM.Monitor"
fi
if pveum role list --output-format json | grep -q "\"roleid\":\"$ROLE\""; then
    pveum role modify "$ROLE" --privs "${PRIVS// /,}"
else
    pveum role add "$ROLE" --privs "${PRIVS// /,}"
fi

# ── user + token ─────────────────────────────────────────────────────────────
pveum user list --output-format json | grep -q "\"userid\":\"$USER\"" || \
    pveum user add "$USER" --comment "pbv backup validation (restore node only)"

if ! pveum user token list "$USER" --output-format json | grep -q "\"tokenid\":\"$TOKEN\""; then
    echo "creating API token $USER!$TOKEN — the secret is shown ONCE below:"
    pveum user token add "$USER" "$TOKEN" --privsep 1 --comment pbv
fi

# Temp VMs live at /vms/<900000+vmid>; restore also checks VM.Backup on the SOURCE vmid
# path (/vms/<vmid>) for backup-volume access, so grant on /vms. A privilege-separated
# token gets the intersection of user and token ACLs, so grant both.
for path in /vms "/storage/$BACKUP_STORAGE" "/storage/$TARGET_STORAGE" \
            /sdn/zones/localnetwork "/nodes/$(hostname)"; do
    pveum acl modify "$path" --users "$USER" --roles "$ROLE" --propagate 1
    pveum acl modify "$path" --tokens "$USER!$TOKEN" --roles "$ROLE" --propagate 1
done

mkdir -p /var/lib/pbv/screendump && chmod 700 /var/lib/pbv/screendump

cat <<EOF

Done. Next:
  1. Put the token secret in /etc/pbv/secrets/pve-token (chmod 600).
  2. Root-only operations (removing non-mapped PCI/USB passthrough, screendump) need
     [node_shell]: run pbv on this node as root (mode = "local"), or allow an SSH key
     for root from the runner (mode = "ssh", pin the host key in known_hosts).
  3. pbv -c /etc/pbv/config.toml preflight
EOF
