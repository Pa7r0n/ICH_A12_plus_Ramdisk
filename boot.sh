#!/usr/bin/env bash
# Boot the SSH ramdisk for A12/A13 after usbliter8 pwned DFU.
#
#   usbliter8 (RP2350) → PWND DFU → [optional iBSS] → iBEC →
#   [SPTM] [TXM] → DeviceTree → trustcache → ramdisk → [AOP…] → kernel/bootx
#
# Usage:
#   ./boot.sh                 # auto --with-fw if staged
#   ./boot.sh --no-fw         # skip AOP/ANE/…
#   ./boot.sh --with-fw       # force firmware suite
#   ./boot.sh --sep           # upload staged RestoreSEP
#   BOOTCHAIN_NAME=... ./boot.sh

set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=env.sh
source "$ROOT/env.sh"

IRECOVERY="$NR_TOOLS/irecovery"
USBLITER8_BOOT="$NR_TOOLS/usbliter8_boot"

WITH_FW=-1
SEP=0
while (($#)); do
    case "$1" in
        --no-fw) WITH_FW=0; shift ;;
        --with-fw) WITH_FW=1; shift ;;
        --sep) SEP=1; shift ;;
        -h|--help)
            sed -n '2,16p' "$0"
            exit 0
            ;;
        *)
            echo "unknown option: $1" >&2
            exit 64
            ;;
    esac
done

[[ -n "${BOOTCHAIN_NAME:-}" && -d "${BOOTCHAIN:-}" ]] || {
    echo "missing bootchain. Run ./build.sh first, or set BOOTCHAIN_NAME=..." >&2
    exit 1
}

[[ -x "$IRECOVERY" && -x "$USBLITER8_BOOT" ]] || {
    echo "missing tools under $NR_TOOLS" >&2
    exit 1
}

if ((WITH_FW < 0)); then
    if [[ -f "$BOOTCHAIN/with-fw.enabled" ]]; then
        WITH_FW=1
    else
        WITH_FW=0
    fi
fi

DEVICE_INFO="$("$IRECOVERY" -q 2>/dev/null || true)"
PWND="$(awk -F': ' '$1 == "PWND" { print $2; exit }' <<<"$DEVICE_INFO")"
MODE="$(awk -F': ' '$1 == "MODE" { print $2; exit }' <<<"$DEVICE_INFO")"
[[ "$MODE" == "DFU" && "$PWND" == "usbliter8" ]] || {
    echo "need pwned DFU (PWND: usbliter8); MODE=${MODE:-?} PWND=${PWND:-?}" >&2
    exit 1
}

wait_recovery() {
    local i
    for i in $(seq 1 45); do
        if "$IRECOVERY" -q 2>/dev/null | grep -q 'MODE: Recovery'; then
            return 0
        fi
        sleep 1
    done
    echo "warning: timed out waiting for Recovery after iBoot" >&2
    return 0
}

echo "Booting: $BOOTCHAIN_NAME"
if [[ -f "$BOOTCHAIN/chain.info" ]]; then
    sed 's/^/  /' "$BOOTCHAIN/chain.info"
fi

sleep 2

if [[ -f "$BOOTCHAIN/iBSS.patched.bin" && -f "$BOOTCHAIN/use-ibss" ]]; then
    echo "Loading iBSS..."
    "$USBLITER8_BOOT" "$BOOTCHAIN/iBSS.patched.bin"
    sleep 4
    echo "Loading iBEC..."
    "$IRECOVERY" -f "$BOOTCHAIN/iBoot.patched.bin"
    "$IRECOVERY" -c go
    sleep 2
    wait_recovery
else
    echo "Loading iBEC (direct, no iBSS)..."
    "$USBLITER8_BOOT" "$BOOTCHAIN/iBoot.patched.bin"
    sleep 4
    wait_recovery
fi

if [[ -f "$BOOTCHAIN/sptm.img4" ]]; then
    echo "Loading patched SPTM..."
    "$IRECOVERY" -f "$BOOTCHAIN/sptm.img4"
    "$IRECOVERY" -c firmware
fi
if [[ -f "$BOOTCHAIN/txm.img4" ]]; then
    echo "Loading patched TXM..."
    "$IRECOVERY" -f "$BOOTCHAIN/txm.img4"
    "$IRECOVERY" -c firmware
fi

if ((SEP)); then
    [[ -f "$BOOTCHAIN/sep-firmware.img4" ]] || {
        echo "missing sep-firmware.img4 (rebuild with ./build.sh --live-data)" >&2
        exit 1
    }
    echo "Loading RestoreSEP..."
    "$IRECOVERY" -f "$BOOTCHAIN/sep-firmware.img4"
    "$IRECOVERY" -c sepfirmware
fi

echo "Loading DeviceTree..."
"$IRECOVERY" -f "$BOOTCHAIN/devicetree.img4"
"$IRECOVERY" -c devicetree

echo "Loading trustcache..."
"$IRECOVERY" -f "$BOOTCHAIN/trustcache.img4"
"$IRECOVERY" -c firmware

echo "Loading ramdisk..."
"$IRECOVERY" -f "$BOOTCHAIN/ramdisk.img4"
sleep 2
"$IRECOVERY" -c ramdisk

if ((WITH_FW)); then
    for fw in AOP ANE AVE ISP GFX SIO; do
        if [[ -f "$BOOTCHAIN/$fw.img4" ]]; then
            echo "Loading $fw..."
            "$IRECOVERY" -f "$BOOTCHAIN/$fw.img4"
            "$IRECOVERY" -c firmware
        fi
    done
fi

echo "Loading kernel / bootx..."
"$IRECOVERY" -f "$BOOTCHAIN/kernelcache.img4"
"$IRECOVERY" -c bootx

echo
echo "If the logo / verbose boot looks healthy, SSH in a few seconds:"
echo "  ./ssh.sh"
echo "password: alpine"
