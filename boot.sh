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
# Normal USB often needs longer than DCSD for DFU→Recovery reenumeration.
RECOVERY_WAIT_SECS="${RECOVERY_WAIT_SECS:-120}"
IRECV_CMD_TIMEOUT_SECS="${IRECV_CMD_TIMEOUT_SECS:-30}"
IRECV_UPLOAD_TIMEOUT_SECS="${IRECV_UPLOAD_TIMEOUT_SECS:-300}"

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

# Run a command with an alarm so a missing/half-enumerated USB device cannot
# hang the script forever (common after iBoot on normal Lightning cables).
with_timeout() {
    local secs="$1"
    shift
    perl -e '
        use strict;
        use warnings;
        my $t = shift @ARGV;
        $SIG{ALRM} = sub {
            print STDERR "error: timed out after ${t}s: @ARGV\n";
            exit 124;
        };
        alarm $t;
        exec @ARGV or die "exec failed: $!\n";
    ' "$secs" "$@"
}

# Query a single irecovery -q field (empty if no device / timeout).
irecv_field() {
    local key="$1"
    local out
    out="$(with_timeout 5 "$IRECOVERY" -q 2>/dev/null || true)"
    awk -F': ' -v key="$key" '$1 == key { print $2; exit }' <<<"$out"
}

irecv_mode() {
    irecv_field MODE
}

# irecovery upload/command with timeout (prevents infinite "stuck after iBoot").
# Uploads (-f) get a longer budget — ramdisk/kernel can be large over USB.
irecv() {
    local secs="$IRECV_CMD_TIMEOUT_SECS"
    if [[ "${1:-}" == "-f" ]]; then
        secs="$IRECV_UPLOAD_TIMEOUT_SECS"
    fi
    with_timeout "$secs" "$IRECOVERY" "$@"
}

# After usbliter8_boot, iBoot must leave DFU and reappear as Recovery over USB.
# DCSD/serial often still shows iBoot even when host USB Recovery never returns;
# on a normal cable that looks like "stuck after iBoot sent".
wait_recovery() {
    local i mode last="" prompt_at=25
    echo "Waiting for USB Recovery after iBoot (up to ${RECOVERY_WAIT_SECS}s)..."
    echo "  tip: use a USB-A → Lightning cable; unplug/replug once if this stalls"

    # Phase 1: DFU should drop after Boot triggered.
    for i in $(seq 1 20); do
        mode="$(irecv_mode)"
        if [[ -z "$mode" || "$mode" != "DFU" ]]; then
            break
        fi
        if ((i == 1 || i % 5 == 0)); then
            echo "  still DFU — waiting for iBoot USB reenumeration… (${i}s)"
        fi
        sleep 1
    done

    # Phase 2: Recovery must appear (AppleUSBDevice / irecovery MODE: Recovery).
    for i in $(seq 1 "$RECOVERY_WAIT_SECS"); do
        mode="$(irecv_mode)"
        if [[ "$mode" != "$last" ]]; then
            echo "  USB MODE: ${mode:-none}"
            last="$mode"
        fi
        if [[ "$mode" == "Recovery" ]]; then
            # Confirm the Recovery interface accepts a command (not a ghost enum).
            if with_timeout 8 "$IRECOVERY" -c "getenv build-version" >/dev/null 2>&1 \
                || with_timeout 8 "$IRECOVERY" -q >/dev/null 2>&1; then
                echo "  iBoot Recovery ready (USB)"
                return 0
            fi
            echo "  Recovery seen but not responding yet — retrying…"
        fi
        if ((i == prompt_at)); then
            echo
            echo "  *** USB Recovery not up yet ***"
            echo "  Unplug the Lightning cable, wait 2s, plug back into the same port."
            echo "  Keep the device as-is (do not force-restart). Waiting continues…"
            echo
            prompt_at=$((prompt_at + 30))
        fi
        sleep 1
    done

    mode="$(irecv_mode)"
    echo "error: timed out waiting for Recovery after iBoot (MODE=${mode:-none})" >&2
    echo "hint: rebuild with ./build.sh --with-fw (USB firmwares), retry on USB-A cable," >&2
    echo "      or re-pwn DFU and run ./boot.sh again" >&2
    return 1
}

# Build a fullscreen black + centered ICH mark for THIS device's panel, then setpicture.
show_ich_logo_signed() {
    local mode board cpid w h
    mode="$(irecv_mode)"
    [[ "$mode" == "Recovery" ]] || {
        echo "warning: not Recovery — skip logo" >&2
        return 1
    }

    board="$(irecv_field MODEL)"
    cpid="$(irecv_field CPID)"
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
    if ! irecv -f "$LOGO_IMG4"; then
        echo "error: irecovery -f logo.img4 failed" >&2
        return 1
    fi
    if irecv -c "setpicture 1" \
        || irecv -c "setpicture" \
        || irecv -c "setpicture 0"; then
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
echo "  USB firmwares: $([[ $WITH_FW -eq 1 ]] && echo enabled || echo disabled)"
if [[ -f "$BOOTCHAIN/chain.info" ]]; then
    sed 's/^/  /' "$BOOTCHAIN/chain.info"
fi
if ((WITH_FW == 0)); then
    echo "warning: bootchain has no with-fw — normal USB may fail after iBoot;" >&2
    echo "         rebuild: ./build.sh --with-fw   then retry ./boot.sh" >&2
fi

DEVICE_INFO="$(with_timeout 8 "$IRECOVERY" -q 2>/dev/null || true)"
PWND="$(awk -F': ' '$1 == "PWND" { print $2; exit }' <<<"$DEVICE_INFO")"
MODE="$(awk -F': ' '$1 == "MODE" { print $2; exit }' <<<"$DEVICE_INFO")"
[[ "$MODE" == "DFU" && "$PWND" == "usbliter8" ]] || {
    echo "need pwned DFU (PWND: usbliter8); MODE=${MODE:-?} PWND=${PWND:-?}" >&2
    exit 1
}

sleep 2

if [[ -f "$BOOTCHAIN/iBSS.patched.bin" && -f "$BOOTCHAIN/use-ibss" ]]; then
    echo "Loading iBSS..."
    "$USBLITER8_BOOT" "$BOOTCHAIN/iBSS.patched.bin"
    sleep 5
    echo "Loading iBEC..."
    # iBSS path: device should already be Recovery-capable; use timed irecovery.
    irecv -f "$BOOTCHAIN/iBoot.patched.bin"
    irecv -c go
    sleep 3
    wait_recovery
else
    echo "Loading iBEC (direct, no iBSS)..."
    "$USBLITER8_BOOT" "$BOOTCHAIN/iBoot.patched.bin"
    echo "  Boot triggered — waiting for normal USB Recovery (not just DCSD serial)…"
    sleep 5
    wait_recovery
fi

# Black bgcolor matches the fullscreen logo canvas (no white corners).
echo "Display: bgcolor black, then centered ICH logo"
irecv -c "bgcolor 0 0 0" || echo "warning: bgcolor failed" >&2
sleep 1

if ((USE_LOGO)); then
    show_ich_logo_signed || {
        echo "warning: signed logo failed — continuing (use --no-logo next time if screen blanks)" >&2
        irecv -c "bgcolor 0 0 0" || true
    }
fi

if [[ -f "$BOOTCHAIN/sptm.img4" ]]; then
    echo "Loading patched SPTM..."
    irecv -f "$BOOTCHAIN/sptm.img4"
    irecv -c firmware
fi
if [[ -f "$BOOTCHAIN/txm.img4" ]]; then
    echo "Loading patched TXM..."
    irecv -f "$BOOTCHAIN/txm.img4"
    irecv -c firmware
fi

if ((SEP)); then
    [[ -f "$BOOTCHAIN/sep-firmware.img4" ]] || {
        echo "missing sep-firmware.img4 (rebuild with ./build.sh --live-data)" >&2
        exit 1
    }
    echo "Loading RestoreSEP..."
    irecv -f "$BOOTCHAIN/sep-firmware.img4"
    irecv -c sepfirmware
fi

# Load coprocessor firmwares before DT (needed on many boards for host USB / SSH).
if ((WITH_FW)); then
    for fw in AOP ANE AVE ISP GFX SIO; do
        if [[ -f "$BOOTCHAIN/$fw.img4" ]]; then
            echo "Loading $fw..."
            irecv -f "$BOOTCHAIN/$fw.img4"
            irecv -c firmware
        fi
    done
fi

echo "Loading DeviceTree..."
irecv -f "$BOOTCHAIN/devicetree.img4"
irecv -c devicetree

echo "Loading trustcache..."
irecv -f "$BOOTCHAIN/trustcache.img4"
irecv -c firmware

echo "Loading ramdisk..."
irecv -f "$BOOTCHAIN/ramdisk.img4"
sleep 2
irecv -c ramdisk

echo "Loading kernel..."
irecv -f "$BOOTCHAIN/kernelcache.img4"

# Critical for on-screen verbose: setenvnp immediately before bootx
# (baked-in iBEC args alone were not enough on this path).
echo "Setting boot-args via setenvnp: $BOOTARGS"
irecv -c "setenvnp boot-args $BOOTARGS" \
    || irecv -c "setenv boot-args $BOOTARGS" \
    || echo "warning: setenvnp/setenv failed — verbose may not appear" >&2

echo "bootx..."
irecv -c bootx

echo
echo "Expect: teal (and ICH logo if setpicture worked), then verbose text on LCD."
echo "DCSD serial is optional (serial=3); normal USB is enough for SSH."
echo "If the screen stayed blank last time, try:  ./boot.sh --no-logo"
echo "SSH when up:  ./ssh.sh   (password: alpine)"
nr_footer
