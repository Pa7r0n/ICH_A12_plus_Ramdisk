#!/usr/bin/env bash
# A12/A13 usbliter8 targets + native LCD sizes for centered boot logos.

nr_chip_for_cpid() {
    case "$1" in
        0x8020) echo "A12" ;;
        0x8030) echo "A13" ;;
        0x8027) echo "A12X" ;;
        *) echo "unknown" ;;
    esac
}

nr_is_supported_cpid() {
    case "$1" in
        0x8020|0x8030|0x8027) return 0 ;;
        *) return 1 ;;
    esac
}

# Native panel WxH for iBoot setpicture fullscreen canvas.
# Unknown boards fall back to 1170x2532 (common modern phone) — still centered.
nr_panel_for_board() {
    case "$1" in
        # iPhone A12
        n841ap) echo "828 1792" ;;          # XR
        d321ap) echo "1125 2436" ;;         # XS
        d331ap|d331pap) echo "1242 2688" ;; # XS Max
        # iPhone A13
        n104ap) echo "828 1792" ;;          # 11
        d421ap) echo "1125 2436" ;;         # 11 Pro
        d431ap) echo "1242 2688" ;;         # 11 Pro Max
        d79ap)  echo "750 1334" ;;          # SE 2nd gen
        # iPad A12 / A12X / A13
        j210ap|j210aap) echo "1536 2048" ;; # iPad mini 5
        j217ap|j218ap) echo "1668 2224" ;;  # iPad Air 3
        j320ap|j321ap) echo "1668 2388" ;;  # iPad Pro 11" 2018
        j417ap|j418ap) echo "2048 2732" ;;  # iPad Pro 12.9" 3rd gen
        j307ap|j308ap) echo "1620 2160" ;;  # iPad 9th gen (A13)
        *)
            echo "1170 2532" # safe centered fallback
            return 1
            ;;
    esac
    return 0
}

# Mark size ~35% of the shorter edge (looks balanced on phones + iPads).
nr_logo_mark_for_panel() {
    local w="$1" h="$2"
    local short="$w"
    ((h < w)) && short="$h"
    local mark=$((short * 35 / 100))
    ((mark < 240)) && mark=240
    ((mark > 720)) && mark=720
    # even
    mark=$((mark - mark % 2))
    echo "$mark"
}
