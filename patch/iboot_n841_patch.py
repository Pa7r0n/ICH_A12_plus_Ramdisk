#!/usr/bin/env python3
"""Apply the verified n841 / iBoot-11881 remote-boot wrapper patch."""

from __future__ import annotations

import argparse
from pathlib import Path


FALSE_POSITIVE_OFFSET = 0xE10
FALSE_POSITIVE_LENGTH = 8
IMAGE4_CANARY_BRANCH = 0x2C194
IMAGE4_CALLBACK_RESULT = 0x2C198
UPDATE_DEVICE_TREE_TRAMPOLINE = 0x2C8DC

NOP = bytes.fromhex("1f2003d5")
MOV_X0_ZERO = bytes.fromhex("000080d2")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stock", required=True, type=Path)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    stock = args.stock.read_bytes()
    patched = bytearray(args.input.read_bytes())
    if len(stock) != len(patched):
        raise SystemExit("stock and patched iBoot sizes differ")

    # The generic Leeksov matcher selects this unrelated early epilogue on
    # iBoot-11881. Restore it from the IPSW baseline.
    patched[
        FALSE_POSITIVE_OFFSET : FALSE_POSITIVE_OFFSET + FALSE_POSITIVE_LENGTH
    ] = stock[
        FALSE_POSITIVE_OFFSET : FALSE_POSITIVE_OFFSET + FALSE_POSITIVE_LENGTH
    ]

    # image4_validate_property_callback: ignore its failure return.
    patched[IMAGE4_CANARY_BRANCH : IMAGE4_CANARY_BRANCH + 4] = NOP
    patched[IMAGE4_CALLBACK_RESULT : IMAGE4_CALLBACK_RESULT + 4] = MOV_X0_ZERO

    # iBoot64Patcher_cryptic replaces this argument-reload trampoline with a
    # MOV instruction on iBoot-11881, which produces firebloom ptr_oob.
    patched[
        UPDATE_DEVICE_TREE_TRAMPOLINE : UPDATE_DEVICE_TREE_TRAMPOLINE + 4
    ] = stock[
        UPDATE_DEVICE_TREE_TRAMPOLINE : UPDATE_DEVICE_TREE_TRAMPOLINE + 4
    ]

    args.output.write_bytes(patched)
    print(f"wrote {args.output}")


if __name__ == "__main__":
    main()
