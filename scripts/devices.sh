#!/usr/bin/env bash
# A12/A13 usbliter8 target CPIDs (from usbliter8ra1n device table).

# CPID → chip family
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
        0x8020|0x8030) return 0 ;;
        0x8027) return 0 ;; # usbliter8: exploit yes, offsets TBD
        *) return 1 ;;
    esac
}
