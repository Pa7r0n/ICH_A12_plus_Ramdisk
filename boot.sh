#!/usr/bin/env bash
# Boot the SSH ramdisk for A12/A13 after usbliter8 pwned DFU.
#
# Matches the proven XR flow (usbliter8-xr-ramdisk):
#   iBEC → Recovery → bgcolor → [signed logo] → firmwares → DT →
#   trustcache → ramdisk → kernel → setenvnp boot-args → bootx
#
# Usage:
#   ./boot.sh                 # verbose boot-args + optional signed ICH logo
#   ./boot.sh --no-fw
#   ./boot.sh --with-fw
#   ./boot.sh --no-logo       # bgcolor only (safest if screen went blank)
#   ./boot.sh --logo          # force signed logo.img4 setpicture
#   ./boot.sh --sep
#   BOOTCHAIN_NAME=... ./boot.sh

set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=env.sh
source "$ROOT/env.sh"
# shellcheck source=scripts/devices.sh
source "$ROOT/scripts/devices.sh"

IRECOVERY="$NR_TOOLS/irecovery"
USBLITER8_BOOT="$NR_TOOLS/usbliter8_boot"
LOGO_IMG4="${LOGO_IMG4:-$NR_RESOURCES/logo.img4}"
LOGO_HOLD_SECS="${LOGO_HOLD_SECS:-3}"

# Full verbose args (set via setenvnp immediately before bootx).
# Same family as usbliter8-xr-ramdisk/exploit.sh — required for on-screen -v.
BOOTARGS="${BOOTARGS:-rd=md0 -v debug=0x2014e serial=3 wdt=-1}"

WITH_FW=-1
SEP=0
# Default: try signed logo. Use --no-logo if the panel went blank before.
USE_LOGO=1
while (($#)); do
    case "$1" in
        --no-fw) WITH_FW=0; shift ;;
        --with-fw) WITH_FW=1; shift ;;
        --no-logo) USE_LOGO=0; shift ;;
        --logo) USE_LOGO=1; shift ;;
        --sep) SEP=1; shift ;;
        -h|--help)
            sed -n '2,20p' "$0"
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
    local i mode
    for i in $(seq 1 45); do
        mode="$("$IRECOVERY" -q 2>/dev/null | awk -F': ' '$1 == "MODE" { print $2; exit }')"
        if [[ "$mode" == "Recovery" ]]; then
            echo "  iBoot Recovery ready"
            return 0
        fi
        sleep 1
    done
    echo "warning: timed out waiting for Recovery after iBoot (MODE=${mode:-?})" >&2
    return 1
}

# Build a fullscreen black + centered ICH mark for THIS device's panel, then setpicture.
show_ich_logo_signed() {
    local mode board cpid w h
    mode="$("$IRECOVERY" -q 2>/dev/null | awk -F': ' '$1 == "MODE" { print $2; exit }')"
    [[ "$mode" == "Recovery" ]] || {
        echo "warning: not Recovery — skip logo" >&2
        return 1
    }

    board="$("$IRECOVERY" -q 2>/dev/null | awk -F': ' '$1 == "MODEL" { print $2; exit }')"
    cpid="$("$IRECOVERY" -q 2>/dev/null | awk -F': ' '$1 == "CPID" { print $2; exit }')"
    board="${board:-unknown}"
    cpid="${cpid:-0x8020}"
    read -r w h <<<"$(nr_panel_for_board "$board")"
    if nr_panel_for_board "$board" >/dev/null 2>&1; then
        echo "Logo: $board → panel ${w}x${h} (centered for this device)"
    else
        echo "warning: unknown board $board — fallback ${w}x${h} (still centered)" >&2
    fi

    if ! NR_CPID="$cpid" "$ROOT/scripts/make_logo.sh" "$board"; then
        echo "error: could not build logo for $board (${w}x${h})" >&2
        return 1
    fi
    [[ -s "$LOGO_IMG4" ]] || {
        echo "warning: missing $LOGO_IMG4 after make_logo" >&2
        return 1
    }

    echo "Setting ICH logo (signed IMG4 + setpicture)..."
    echo "  file: $LOGO_IMG4 ($(wc -c <"$LOGO_IMG4") bytes)"
    if ! "$IRECOVERY" -f "$LOGO_IMG4"; then
        echo "error: irecovery -f logo.img4 failed" >&2
        return 1
    fi
    if "$IRECOVERY" -c "setpicture 1" \
        || "$IRECOVERY" -c "setpicture" \
        || "$IRECOVERY" -c "setpicture 0"; then
        echo "  setpicture OK — hold ${LOGO_HOLD_SECS}s (watch LCD)"
        sleep "$LOGO_HOLD_SECS"
        return 0
    fi
    echo "error: setpicture failed after signed upload" >&2
    return 1
}

nr_banner "boot $NR_VERSION"
echo "Booting: $BOOTCHAIN_NAME"
echo "  new_ramdisk $NR_VERSION by $NR_AUTHOR"
echo "  Telegram: $NR_TELEGRAM"
echo "  boot-args (setenvnp): $BOOTARGS"
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
    wait_recovery || true
else
    echo "Loading iBEC (direct, no iBSS)..."
    "$USBLITER8_BOOT" "$BOOTCHAIN/iBoot.patched.bin"
    sleep 4
    wait_recovery || true
fi

# Black bgcolor matches the fullscreen logo canvas (no white corners).
echo "Display: bgcolor black, then centered ICH logo"
"$IRECOVERY" -c "bgcolor 0 0 0" || echo "warning: bgcolor failed" >&2
sleep 1

if ((USE_LOGO)); then
    show_ich_logo_signed || {
        echo "warning: signed logo failed — continuing (use --no-logo next time if screen blanks)" >&2
        "$IRECOVERY" -c "bgcolor 0 0 0" || true
    }
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

# Load coprocessor firmwares before DT (matches working XR exploit.sh order).
if ((WITH_FW)); then
    for fw in AOP ANE AVE ISP GFX SIO; do
        if [[ -f "$BOOTCHAIN/$fw.img4" ]]; then
            echo "Loading $fw..."
            "$IRECOVERY" -f "$BOOTCHAIN/$fw.img4"
            "$IRECOVERY" -c firmware
        fi
    done
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

echo "Loading kernel..."
"$IRECOVERY" -f "$BOOTCHAIN/kernelcache.img4"

# Critical for on-screen verbose: setenvnp immediately before bootx
# (baked-in iBEC args alone were not enough on this path).
echo "Setting boot-args via setenvnp: $BOOTARGS"
"$IRECOVERY" -c "setenvnp boot-args $BOOTARGS" \
    || "$IRECOVERY" -c "setenv boot-args $BOOTARGS" \
    || echo "warning: setenvnp/setenv failed — verbose may not appear" >&2

echo "bootx..."
"$IRECOVERY" -c bootx

echo
echo "Expect: teal (and ICH logo if setpicture worked), then verbose text on LCD + DCSD."
echo "If the screen stayed blank last time, try:  ./boot.sh --no-logo"
echo "SSH when up:  ./ssh.sh   (password: alpine)"
nr_footer
