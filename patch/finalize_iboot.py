#!/usr/bin/env python3
"""Finalize Leeksov-patched iBEC: rd=md0 boot-args + optional n841 safe wrapper."""

from __future__ import annotations

import argparse
from pathlib import Path

# Verified n841 / iBoot-11881 remote-boot wrapper (XR 18.7.9).
FALSE_POSITIVE_OFFSET = 0xE10
FALSE_POSITIVE_LENGTH = 8
IMAGE4_CANARY_BRANCH = 0x2C194
IMAGE4_CALLBACK_RESULT = 0x2C198
UPDATE_DEVICE_TREE_TRAMPOLINE = 0x2C8DC

NOP = bytes.fromhex("1f2003d5")
MOV_X0_ZERO = bytes.fromhex("000080d2")

# Leeksov iboot_patchfinder writes this slot (29 bytes incl. NUL).
# Keep debug=0x2014e for verbose; rd=md0 for ramdisk. Runtime setenvnp
# in boot.sh still overrides/extends before bootx.
LEEKSOV_BOOT_ARGS = b"serial=3 -v debug=0x2014e %s\x00"
RAMDISK_BOOT_ARGS = b"rd=md0 -v debug=0x2014e\x00\x00\x00\x00\x00\x00"


def apply_boot_args(data: bytearray) -> None:
    if data.count(RAMDISK_BOOT_ARGS) == 1:
        print("boot-args already set to ramdisk form")
        return
    if len(LEEKSOV_BOOT_ARGS) != len(RAMDISK_BOOT_ARGS):
        raise SystemExit("internal boot-args length mismatch")
    if data.count(LEEKSOV_BOOT_ARGS) != 1:
        raise SystemExit(
            "expected exactly one Leeksov boot-args slot "
            f"({LEEKSOV_BOOT_ARGS!r}); found {data.count(LEEKSOV_BOOT_ARGS)}"
        )
    idx = data.index(LEEKSOV_BOOT_ARGS)
    data[idx : idx + len(LEEKSOV_BOOT_ARGS)] = RAMDISK_BOOT_ARGS
    print(f"boot-args → rd=md0 @ 0x{idx:X}")


def apply_n841_wrapper(stock: bytes, patched: bytearray) -> None:
    if len(stock) != len(patched):
        raise SystemExit("stock and patched iBoot sizes differ")
    patched[FALSE_POSITIVE_OFFSET : FALSE_POSITIVE_OFFSET + FALSE_POSITIVE_LENGTH] = (
        stock[FALSE_POSITIVE_OFFSET : FALSE_POSITIVE_OFFSET + FALSE_POSITIVE_LENGTH]
    )
    patched[IMAGE4_CANARY_BRANCH : IMAGE4_CANARY_BRANCH + 4] = NOP
    patched[IMAGE4_CALLBACK_RESULT : IMAGE4_CALLBACK_RESULT + 4] = MOV_X0_ZERO
    patched[
        UPDATE_DEVICE_TREE_TRAMPOLINE : UPDATE_DEVICE_TREE_TRAMPOLINE + 4
    ] = stock[UPDATE_DEVICE_TREE_TRAMPOLINE : UPDATE_DEVICE_TREE_TRAMPOLINE + 4]
    print("applied n841ap safe IMG4 / UpdateDeviceTree wrapper")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stock", required=True, type=Path)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--board", required=True, help="DeviceClass / boardconfig")
    args = parser.parse_args()

    stock = args.stock.read_bytes()
    patched = bytearray(args.input.read_bytes())
    apply_boot_args(patched)
    if args.board == "n841ap":
        apply_n841_wrapper(stock, patched)
    else:
        print(
            f"board {args.board}: skipping n841-only wrapper "
            "(Leeksov iBoot patches only — verify on device)"
        )
    args.output.write_bytes(patched)
    print(f"wrote {args.output}")


if __name__ == "__main__":
    main()
