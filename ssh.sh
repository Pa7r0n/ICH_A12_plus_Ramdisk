#!/usr/bin/env bash
# SSH into the running SSH ramdisk (password: alpine).
# Tunnel: iproxy 2222 → device port 22 (dropbear from ssh.tar.gz).
#
# Interactive sessions:
#   1) run mount_filesystems (System / Preboot / xART)
#   2) print iOS version from Preboot SystemVersion.plist
#   3) open a shell

set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=env.sh
source "$ROOT/env.sh"

nr_banner "ssh $NR_VERSION"

IPROXY="$NR_TOOLS/iproxy"
SSHPASS="$NR_TOOLS/sshpass"

[[ -x "$IPROXY" && -x "$SSHPASS" ]] || {
    echo "missing iproxy/sshpass under $NR_TOOLS" >&2
    exit 1
}

# Kill stale tunnels on our port, then start fresh.
pkill -f 'iproxy 2222 22' 2>/dev/null || true
"$IPROXY" 2222 22 >/dev/null 2>&1 &
sleep 1

SSH_OPTS=(
    -o HostKeyAlgorithms=+ssh-rsa
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -p 2222
)

# Remote bootstrap: mount volumes, show which iOS the device NAND is on.
REMOTE_BOOTSTRAP=$(cat <<'EOS'
#!/bin/sh
set -u

echo "=== mounting filesystems ==="
if command -v mount_filesystems >/dev/null 2>&1; then
    mount_filesystems || true
elif [ -x /usr/bin/mount_filesystems ]; then
    /usr/bin/mount_filesystems || true
else
    echo "mount_filesystems not found on ramdisk"
fi

SV=""
for candidate in \
    /mnt6/cryptex1/current/SystemVersion.plist \
    /mnt1/System/Library/CoreServices/SystemVersion.plist
do
    if [ -f "$candidate" ]; then
        SV="$candidate"
        break
    fi
done

echo
echo "=== device iOS (from NAND) ==="
if [ -n "$SV" ]; then
    echo "path: $SV"
    # Prefer readable keys when present
    ver=$(sed -n '/ProductVersion/{n;s/.*<string>\([^<]*\)<\/string>.*/\1/p;}' "$SV" | head -1)
    build=$(sed -n '/ProductBuildVersion/{n;s/.*<string>\([^<]*\)<\/string>.*/\1/p;}' "$SV" | head -1)
    name=$(sed -n '/ProductName/{n;s/.*<string>\([^<]*\)<\/string>.*/\1/p;}' "$SV" | head -1)
    if [ -n "$ver" ] || [ -n "$build" ]; then
        echo "ProductName:          ${name:-unknown}"
        echo "ProductVersion:       ${ver:-unknown}"
        echo "ProductBuildVersion:  ${build:-unknown}"
        echo
    fi
    cat "$SV"
else
    echo "(SystemVersion.plist not found — is Preboot/System mounted?)"
    echo "tried: /mnt6/cryptex1/current/SystemVersion.plist"
    echo "       /mnt1/System/Library/CoreServices/SystemVersion.plist"
fi

echo
echo "=== shell (new_ramdisk) ==="
if [ -x /bin/bash ]; then
    exec /bin/bash -l
fi
exec /bin/sh -l
EOS
)

if (($#)); then
    exec "$SSHPASS" -p 'alpine' ssh "${SSH_OPTS[@]}" root@localhost "$@"
else
    exec "$SSHPASS" -p 'alpine' ssh -t "${SSH_OPTS[@]}" root@localhost "$REMOTE_BOOTSTRAP"
fi
