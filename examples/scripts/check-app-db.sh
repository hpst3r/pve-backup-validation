#!/bin/sh
# Runs INSIDE the restored guest via the QEMU guest agent.
# Exit 0 = pass, anything else = fail (see expect_exit / warn_exit).
# pbv provides PBV_RUN_ID, PBV_VMID, PBV_TEMP_VMID, PBV_VM_NAME, PBV_OS,
# PBV_GUEST_IP(S), PBV_TARGET_NODE, PBV_CHECK_NAME plus the check's env table.
set -eu
echo "pbv check on ${PBV_VM_NAME:-?} (${PBV_TEMP_VMID:-?})"
if command -v psql >/dev/null 2>&1; then
    su - postgres -c "psql -tAc 'select count(*) from pg_database'" || exit 1
fi
test -s /etc/hostname
