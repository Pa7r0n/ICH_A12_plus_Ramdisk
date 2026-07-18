#!/usr/bin/env bash
# Build a centered ICH boot logo on a pure-black fullscreen canvas.
#
# Usage:
#   ./scripts/make_logo.sh                         # uses BOARD from env or XR default
#   ./scripts/make_logo.sh n841ap                  # boardconfig → panel lookup
#   ./scripts/make_logo.sh icon.png 828 1792       # explicit panel
#   ./scripts/make_logo.sh icon.png 828 1792 420 0x8020
#
# boot.sh calls this automatically for the connected device so the mark
# is always centered on that panel (universal A12/A13).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../env.sh
source "$ROOT/env.sh"
# shellcheck source=devices.sh
source "$ROOT/scripts/devices.sh"

PNG="$NR_RESOURCES/ich_logo.png"
BOARD=""
WIDTH=""
HEIGHT=""
MARK=""
CPID="0x8020"

# Parse args flexibly: board name OR png + dimensions
if (($# >= 1)) && [[ "$1" == *.png || "$1" == *.PNG || "$1" == /* || "$1" == ./* ]]; then
    PNG="$1"
    shift
    if (($# >= 2)) && [[ "$1" =~ ^[0-9]+$ && "$2" =~ ^[0-9]+$ ]]; then
        WIDTH="$1"
        HEIGHT="$2"
        shift 2
        (($#)) && [[ "$1" =~ ^[0-9]+$ ]] && { MARK="$1"; shift; }
        (($#)) && CPID="$1"
    fi
elif (($# >= 1)); then
    BOARD="$1"
    shift
    (($#)) && [[ -f "$1" || "$1" == *.png ]] && { PNG="$1"; shift; }
fi

if [[ -z "$WIDTH" || -z "$HEIGHT" ]]; then
    BOARD="${BOARD:-${NR_BOARD:-n841ap}}"
    panel="$(nr_panel_for_board "$BOARD")" && known=1 || known=0
    read -r WIDTH HEIGHT <<<"$panel"
    if ((known == 0)); then
        echo "warning: unknown board '$BOARD' — using fallback panel ${WIDTH}x${HEIGHT}" >&2
    fi
fi

MARK="${MARK:-$(nr_logo_mark_for_panel "$WIDTH" "$HEIGHT")}"
CPID="${NR_CPID:-$CPID}"

IBOOTIM="$NR_TOOLS/ibootim"
IMG4="$NR_TOOLS/img4"
IM4M="$NR_RESOURCES/IM4M_$CPID"
[[ -f "$IM4M" ]] || IM4M="$NR_RESOURCES/IM4M_0x8020"

CACHE="$NR_RESOURCES/logo_cache"
mkdir -p "$CACHE"
TAG="${BOARD:-${WIDTH}x${HEIGHT}}"
TAG="${TAG//\//_}"
FULL="$CACHE/${TAG}_${WIDTH}x${HEIGHT}.png"
RAW="$CACHE/${TAG}_${WIDTH}x${HEIGHT}.raw"
OUT="$CACHE/${TAG}_${WIDTH}x${HEIGHT}.img4"

# Also publish as the default paths boot.sh uses
PUB_RAW="$NR_RESOURCES/ich_logo.raw"
PUB_OUT="$NR_RESOURCES/logo.img4"

[[ -f "$PNG" ]] || { echo "missing PNG: $PNG" >&2; exit 1; }
[[ -x "$IBOOTIM" && -x "$IMG4" ]] || { echo "missing ibootim/img4" >&2; exit 1; }
[[ -f "$IM4M" ]] || { echo "missing IM4M" >&2; exit 1; }

echo "logo: board=${BOARD:-custom} panel=${WIDTH}x${HEIGHT} mark=${MARK} cpid=${CPID}"

python3 - "$PNG" "$FULL" "$WIDTH" "$HEIGHT" "$MARK" <<'PY'
from pathlib import Path
import sys

try:
    from PIL import Image
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pillow", "-q"])
    from PIL import Image

src, out, W, H, LOGO = sys.argv[1], Path(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5])
im = Image.open(src).convert("RGBA")
# Composite onto white first so transparent areas become background
base = Image.new("RGBA", im.size, (255, 255, 255, 255))
base.paste(im, mask=im.split()[-1])
gray = base.convert("L")
# Silhouette for boot splash:
#   dark ink (ICH letters)  → white
#   light paper background  → black
# Threshold mid-gray so anti-aliased edges stay readable.
bw = gray.point(lambda p: 255 if p < 140 else 0, mode="L").convert("RGB")

mark = bw.resize((LOGO, LOGO), Image.Resampling.NEAREST)
# Light cleanup: ensure pure B/W after scale
px = mark.load()
for y in range(LOGO):
    for x in range(LOGO):
        r, g, b = px[x, y]
        px[x, y] = (255, 255, 255) if (r + g + b) > 300 else (0, 0, 0)

canvas = Image.new("RGB", (W, H), (0, 0, 0))
x = (W - LOGO) // 2
y = (H - LOGO) // 2
canvas.paste(mark, (x, y))
out.parent.mkdir(parents=True, exist_ok=True)
canvas.save(out)
# sanity: must have some white pixels (the letters)
white = sum(1 for p in canvas.getdata() if p[0] > 200)
print(f"fullscreen {W}x{H} mark={LOGO} at ({x},{y}) white_pixels={white}")
if white < 100:
    raise SystemExit("logo mark has no visible white pixels — abort")
PY

"$IBOOTIM" "$FULL" "$RAW"
"$IMG4" -i "$RAW" -o "$OUT" -A -T logo -M "$IM4M"
cp -f "$RAW" "$PUB_RAW"
cp -f "$RAW" "$NR_RESOURCES/ich_logo_plain.raw"
cp -f "$OUT" "$PUB_OUT"

echo "wrote $OUT"
echo "published $PUB_OUT (centered for ${WIDTH}x${HEIGHT})"
