#!/usr/bin/env bash
# SSH into the running SSH ramdisk (password: alpine).
# Tunnel: iproxy 2222 → device port 22 (dropbear from ssh.tar.gz).

set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=env.sh
source "$ROOT/env.sh"

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

if (($#)); then
    exec "$SSHPASS" -p 'alpine' ssh "${SSH_OPTS[@]}" root@localhost "$@"
else
    exec "$SSHPASS" -p 'alpine' ssh -t "${SSH_OPTS[@]}" root@localhost
fi
