#!/usr/bin/env python3
"""Replace SSHRD_Script branding in restored_external with ICH — keep USB entitlements."""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

# Exact same-length replacements.
STRING_REPLACEMENTS: list[tuple[bytes, bytes]] = [
    (
        b"SSHRD_Script Sep 22 2022 18:56:50",
        b"ICH_A12+ Ramdisk v1.1            ",
    ),
    (
        b"SSHRD_Script by Nathan (verygenericname)",
        b"ICH_A12+ Ramdisk by @Official_I_C_H     ",
    ),
    (
        b"Compiled Sep 22 2022 18:56:50",
        b"Compiled ICH_A12+ Ramdisk    ",
    ),
    (
        b"Starting ramdisk tool",
        b"Starting ICH ramdisk ",
    ),
    (
        b"TrollStore by opa334",
        b"ICH_A12+ Ramdisk    ",
    ),
]


def ich_line(width: int, text: str = "") -> bytes:
    if not text:
        return b" " * width
    t = text.encode("ascii")[:width]
    pad = width - len(t)
    left = pad // 2
    return b" " * left + t + b" " * (pad - left)


def _is_art_line(s: bytes) -> bool:
    """True for SSHRD ASCII-art lines (not normal log messages)."""
    if len(s) < 20:
        return False
    # Functional strings we must never touch
    banned = (
        b"Running",
        b"waiting",
        b"USB",
        b"Compiled",
        b"SSHRD",
        b"ICH_",
        b"Troll",
        b"Starting",
        b"Unable",
        b"dropbear",
        b"reboot",
        b"server",
        b"seconds",
        b"FAIL",
        b"done",
    )
    for b in banned:
        if b in s:
            return False
    # Art is dense with Q / l / ; / W / @ / etc.
    fancy = sum(1 for c in s if c in b"Ql;W@#$mwg*")
    return fancy >= max(8, len(s) // 4)


def rebrand_ascii_art(data: bytearray) -> int:
    """Replace SSHRD ASCII-art cstrings with a compact ICH banner (no huge blank gap)."""
    # Only scan the known art window (before credit string).
    credit = data.find(b"SSHRD_Script by Nathan")
    if credit < 0:
        credit = data.find(b"ICH_A12+ Ramdisk by @Official_I_C_H")
    start = data.find(b"lllll")
    if start < 0:
        start = data.find(b"QQQQQQ")
    if start < 0 or credit < 0 or credit <= start:
        print("note: ASCII art window not found")
        return 0

    spans: list[tuple[int, int]] = []
    i = start
    while i < credit:
        if 32 <= data[i] < 127:
            j = i
            while j < credit and 32 <= data[j] < 127:
                j += 1
            if j < len(data) and data[j] == 0 and j > i:
                spans.append((i, j))
            i = j + 1
        else:
            i += 1

    art = [(a, b) for a, b in spans if _is_art_line(bytes(data[a:b]))]
    if not art:
        print("note: no art-like cstrings matched")
        return 0

    # Prefer wide lines for a readable banner; blank leftover art (no giant empty block).
    banner = [
        "########################################",
        "#                                      #",
        "#         ICH_A12+  Ramdisk            #",
        "#       by  @Official_I_C_H            #",
        "#                                      #",
        "########################################",
    ]
    wide = [(a, b) for a, b in art if (b - a) >= 40] or art

    for idx, (a, b) in enumerate(wide):
        width = b - a
        if idx < len(banner):
            data[a:b] = ich_line(width, banner[idx])
        else:
            data[a:b] = b" " * width

    # Blank non-wide art lines so old SSHRD glyphs disappear
    wide_set = set(wide)
    for a, b in art:
        if (a, b) not in wide_set:
            data[a:b] = b" " * (b - a)

    print(f"rebranded {len(art)} art cstrings → compact ICH banner on {min(len(banner), len(wide))} lines")
    return len(art)


def apply_string_replacements(data: bytearray) -> int:
    n = 0
    for old, new in STRING_REPLACEMENTS:
        if len(old) != len(new):
            raise SystemExit(f"length mismatch {len(old)}!={len(new)}: {old!r}")
        count = data.count(old)
        if count == 0:
            if data.count(new) == 0:
                print(f"warning: missing {old!r}")
            continue
        idx = 0
        while True:
            i = data.find(old, idx)
            if i < 0:
                break
            data[i : i + len(old)] = new
            n += 1
            idx = i + len(old)
        print(f"replaced → {new!r}")
    return n


def extract_ents(stock: Path, ldid: str, out: Path) -> Path:
    r = subprocess.run([ldid, "-e", str(stock)], check=True, capture_output=True)
    if not r.stdout.strip():
        raise SystemExit(f"no entitlements on {stock} — refuse to resign without ents")
    out.write_bytes(r.stdout)
    print(f"wrote entitlements {out} ({len(r.stdout)} bytes)")
    return out


def resign(path: Path, ldid: str, ents: Path) -> None:
    subprocess.run([ldid, f"-S{ents}", str(path)], check=True)
    # verify
    r = subprocess.run([ldid, "-e", str(path)], check=True, capture_output=True)
    if b"usbdevice" not in r.stdout and b"platform-application" not in r.stdout:
        raise SystemExit("resign lost USB/platform entitlements — abort")
    print(f"resigned with entitlements ({len(r.stdout)} bytes ents)")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("input", type=Path, help="stock restored_external")
    ap.add_argument("-o", "--output", type=Path, required=True)
    ap.add_argument("--ldid", default="ldid")
    ap.add_argument(
        "--entitlements",
        type=Path,
        help="ents plist (default: extract from input)",
    )
    ap.add_argument("--no-ldid", action="store_true")
    args = ap.parse_args()

    data = bytearray(args.input.read_bytes())
    apply_string_replacements(data)
    rebrand_ascii_art(data)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(data)

    if not args.no_ldid:
        ents = args.entitlements
        if ents is None:
            ents = args.output.with_suffix(args.output.suffix + ".ents.xml")
            extract_ents(args.input, args.ldid, ents)
        resign(args.output, args.ldid, ents)

    print(f"wrote {args.output} ({args.output.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
