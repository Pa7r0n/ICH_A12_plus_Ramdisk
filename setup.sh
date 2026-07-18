#!/usr/bin/env bash
# Install host dependencies for ICH_A12+ Ramdisk (v1.1) on a fresh macOS.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=env.sh
source "$ROOT/env.sh"

nr_banner "setup $NR_VERSION"

FAIL=0
ok()   { echo "  OK   $*"; }
warn() { echo "  WARN $*"; }
bad()  { echo "  MISS $*"; FAIL=1; }

echo "=== platform ==="
[[ "$(uname)" == "Darwin" ]] || {
    echo "This toolkit requires macOS." >&2
    exit 1
}
ok "macOS $(sw_vers -productVersion)"

echo
echo "=== Homebrew ==="
if ! command -v brew >/dev/null 2>&1; then
    echo "Homebrew not found. Installing..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    if [[ -x /opt/homebrew/bin/brew ]]; then
        eval "$(/opt/homebrew/bin/brew shellenv)"
    elif [[ -x /usr/local/bin/brew ]]; then
        eval "$(/usr/local/bin/brew shellenv)"
    fi
fi
command -v brew >/dev/null && ok "brew $(brew --version | head -1)" || bad "brew"

echo
echo "=== brew packages ==="
BREW_PKGS=(python@3 curl)
# ipsw is often a cask/formula from blacktop; try formula then alternate.
for pkg in "${BREW_PKGS[@]}"; do
    if brew list --formula "$pkg" >/dev/null 2>&1 || brew list --cask "$pkg" >/dev/null 2>&1; then
        ok "$pkg (already installed)"
    else
        echo "  installing $pkg..."
        brew install "$pkg" || warn "could not brew install $pkg"
    fi
done

if command -v ipsw >/dev/null 2>&1; then
    ok "ipsw $(ipsw version 2>/dev/null | head -1 || echo present)"
else
    echo "  installing ipsw..."
    if brew install blacktop/tap/ipsw 2>/dev/null || brew install ipsw 2>/dev/null; then
        ok "ipsw installed"
    else
        bad "ipsw — install from https://github.com/blacktop/ipsw (brew install blacktop/tap/ipsw)"
    fi
fi

# Optional host iproxy if vendored one fails on newer macOS
if ! [[ -x "$NR_TOOLS/iproxy" ]]; then
    brew install libimobiledevice 2>/dev/null || true
fi

echo
echo "=== Python packages ==="
PYTHON=python3
command -v "$PYTHON" >/dev/null || bad "python3"
if command -v "$PYTHON" >/dev/null; then
    ok "$PYTHON $($PYTHON --version 2>&1)"
    "$PYTHON" -m pip install --upgrade pip >/dev/null 2>&1 || true
    "$PYTHON" -m pip install -r "$ROOT/requirements.txt"
    if "$PYTHON" -c "import pyimg4, capstone" 2>/dev/null; then
        ok "pyimg4 + capstone"
    else
        bad "pyimg4/capstone import failed"
    fi
fi

echo
echo "=== vendored tools (tools/darwin) ==="
for t in irecovery pzb img4 gtar trustcache jq usbliter8_boot iproxy sshpass libusb-1.0.0.dylib; do
    if [[ -e "$NR_TOOLS/$t" ]]; then
        ok "$t"
    else
        bad "$t"
    fi
done

echo
echo "=== resources ==="
for t in ssh.tar.gz sshtarlist.txt IM4M_0x8020 IM4M_0x8030 mount_filesystems.safe; do
    if [[ -e "$NR_RESOURCES/$t" ]]; then
        ok "$t"
    else
        bad "$t"
    fi
done

echo
if ((FAIL)); then
    echo "Setup incomplete — fix MISS items above, then re-run ./setup.sh"
    nr_footer
    exit 1
fi
echo "Setup complete. Next:"
echo "  1) Pwn DFU with RP2350 + usbliter8"
echo "  2) ./build.sh --with-fw"
echo "  3) ./boot.sh && ./ssh.sh"
nr_footer
