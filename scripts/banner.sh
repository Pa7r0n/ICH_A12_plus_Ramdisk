#!/usr/bin/env bash
# Shared branding for build / boot / status output.

NR_VERSION="${NR_VERSION:-v1.Zero}"
NR_AUTHOR="${NR_AUTHOR:-@Official_I_C_H}"
NR_TELEGRAM="${NR_TELEGRAM:-https://t.me/Official_I_C_H}"

nr_banner() {
    local stage="${1:-new_ramdisk}"
    cat <<EOF

╔══════════════════════════════════════════════════════╗
║  new_ramdisk  ${NR_VERSION}
║  A12 / A13 SSH ramdisk
║  by ${NR_AUTHOR}
║  Telegram: ${NR_TELEGRAM}
║  stage: ${stage}
╚══════════════════════════════════════════════════════╝

EOF
}

nr_footer() {
    echo
    echo "────────────────────────────────────────"
    echo "  new_ramdisk ${NR_VERSION} · made by ${NR_AUTHOR}"
    echo "  Telegram: ${NR_TELEGRAM}"
    echo "────────────────────────────────────────"
}
