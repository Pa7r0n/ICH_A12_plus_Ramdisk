#!/usr/bin/env bash
# Show connected device + last built bootchain status.

set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=env.sh
source "$ROOT/env.sh"
# shellcheck source=scripts/devices.sh
source "$ROOT/scripts/devices.sh"

IRECOVERY="$NR_TOOLS/irecovery"

nr_banner "status $NR_VERSION"

echo "=== USB / irecovery ==="
if DEVICE_INFO="$("$IRECOVERY" -q 2>/dev/null)"; then
    echo "$DEVICE_INFO" | sed 's/^/  /'
    CPID="$(awk -F': ' '$1 == "CPID" { print $2; exit }' <<<"$DEVICE_INFO")"
    if [[ -n "$CPID" ]]; then
        echo "  chip: $(nr_chip_for_cpid "$CPID")"
        if nr_is_supported_cpid "$CPID"; then
            echo "  support: A12/A13 toolkit OK"
        else
            echo "  support: unsupported CPID"
        fi
    fi
else
    echo "  (no device / irecovery failed)"
fi

echo
echo "=== last bootchain ==="
if [[ -n "${BOOTCHAIN_NAME:-}" && -d "${BOOTCHAIN:-}" ]]; then
    echo "  name: $BOOTCHAIN_NAME"
    echo "  path: $BOOTCHAIN"
    if [[ -f "$BOOTCHAIN/chain.info" ]]; then
        sed 's/^/  /' "$BOOTCHAIN/chain.info"
    fi
    for f in iBoot.patched.bin devicetree.img4 trustcache.img4 ramdisk.img4 kernelcache.img4; do
        if [[ -f "$BOOTCHAIN/$f" ]]; then
            printf '  OK  %s\n' "$f"
        else
            printf '  MISS %s\n' "$f"
        fi
    done
    for f in sptm.img4 txm.img4 iBSS.patched.bin with-fw.enabled; do
        [[ -f "$BOOTCHAIN/$f" ]] && printf '  OK  %s (optional)\n' "$f"
    done
else
    echo "  (none — run ./build.sh)"
fi
