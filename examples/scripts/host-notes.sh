#!/bin/sh
# Runs on the pbv RUNNER (not in the guest). Use for probes from outside,
# e.g. via a jump interface on the isolated bridge. Write artifacts to
# $PBV_WORK_DIR.
set -eu
echo "host check for ${PBV_VM_NAME} temp=${PBV_TEMP_VMID} ips=${PBV_GUEST_IPS}" | tee "${PBV_WORK_DIR}/host-notes.txt"
