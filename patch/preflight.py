#!/usr/bin/env python3
"""Validate SSHRD bootchain artifacts before DFU upload."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from pyimg4 import IMG4, IM4P

EXPECTED_IMAGES = {
    "devicetree.img4": "rdtr",
    "ramdisk.img4": "rdsk",
    "trustcache.img4": "rtsc",
    "kernelcache.img4": "rkrn",
}

# n841 / iBoot-11881 remote-boot wrapper layout (XR 18.7.9 only).
FALSE_POSITIVE_OFFSET = 0xE10
IMAGE4_CANARY_BRANCH = 0x2C194
IMAGE4_CALLBACK_RESULT = 0x2C198
UPDATE_DEVICE_TREE_TRAMPOLINE = 0x2C8DC
NOP = bytes.fromhex("1f2003d5")
MOV_X0_ZERO = bytes.fromhex("000080d2")
MAX_REMOTE_RAMDISK_CONTAINER_BYTES = 210 * 1024 * 1024 + 16 * 1024


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_im4p(path: Path) -> tuple[IM4P, bool]:
    data = path.read_bytes()
    try:
        image = IMG4(data)
        return image.im4p, image.im4m is not None
    except Exception:
        return IM4P(data), False


def validate_img4s(bootchain: Path, *, allow_im4p_only: bool) -> None:
    for name, expected_type in EXPECTED_IMAGES.items():
        path = bootchain / name
        if not path.is_file():
            fail(f"missing {path}")
        payload, has_im4m = load_im4p(path)
        if payload.fourcc != expected_type:
            fail(f"{name} has type {payload.fourcc!r}, expected {expected_type!r}")
        if not allow_im4p_only and not has_im4m:
            fail(f"{name} has no IM4M ticket (pass --allow-im4p-only for plan-only)")
        if name == "ramdisk.img4" and path.stat().st_size > MAX_REMOTE_RAMDISK_CONTAINER_BYTES:
            fail(
                f"{name} is {path.stat().st_size} bytes; "
                f"limit is {MAX_REMOTE_RAMDISK_CONTAINER_BYTES}"
            )
        ticket = "IM4M=yes" if has_im4m else "IM4P-only"
        print(f"OK: {name}: type={expected_type}, {ticket}")


def validate_n841_iboot(iboot_path: Path, stock_path: Path) -> None:
    iboot = iboot_path.read_bytes()
    stock = stock_path.read_bytes()
    if len(iboot) != len(stock):
        fail(f"iBoot size differs from stock ({len(iboot)} != {len(stock)})")
    if iboot[IMAGE4_CANARY_BRANCH : IMAGE4_CANARY_BRANCH + 4] != NOP:
        fail("iBoot does not NOP the n841 IMG4 callback canary branch")
    if iboot[IMAGE4_CALLBACK_RESULT : IMAGE4_CALLBACK_RESULT + 4] != MOV_X0_ZERO:
        fail("iBoot does not force n841 IMG4 callback success")
    if (
        iboot[UPDATE_DEVICE_TREE_TRAMPOLINE : UPDATE_DEVICE_TREE_TRAMPOLINE + 4]
        != stock[UPDATE_DEVICE_TREE_TRAMPOLINE : UPDATE_DEVICE_TREE_TRAMPOLINE + 4]
    ):
        fail("iBoot modifies the n841 UpdateDeviceTree argument-reload trampoline")
    if b"rd=md0" not in iboot:
        fail("iBoot missing rd=md0 boot-args")
    print("OK: n841ap iBoot wrapper + rd=md0")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bootchain", required=True, type=Path)
    parser.add_argument("--stock-iboot", required=True, type=Path)
    parser.add_argument("--expected-board", required=True)
    parser.add_argument("--expected-build", required=True)
    parser.add_argument("--kernel-mode", default="stock")
    parser.add_argument("--stock-kernel", type=Path)
    parser.add_argument("--allow-patched-kernel", action="store_true")
    parser.add_argument("--allow-im4p-only", action="store_true")
    args = parser.parse_args()

    bootchain = args.bootchain
    if not bootchain.is_dir():
        fail(f"missing bootchain {bootchain}")

    info = bootchain / "chain.info"
    if info.is_file():
        text = info.read_text()
        if f"model={args.expected_board}" not in text:
            fail(f"chain.info board mismatch (want {args.expected_board})")
        if f"build={args.expected_build}" not in text:
            fail(f"chain.info build mismatch (want {args.expected_build})")
        print(f"OK: chain.info matches {args.expected_board} / {args.expected_build}")

    validate_img4s(bootchain, allow_im4p_only=args.allow_im4p_only)

    iboot = bootchain / "iBoot.patched.bin"
    if not iboot.is_file():
        fail(f"missing {iboot}")
    if b"rd=md0" not in iboot.read_bytes():
        fail("iBoot.patched.bin missing rd=md0")
    print("OK: iBoot has rd=md0")

    if args.expected_board == "n841ap":
        validate_n841_iboot(iboot, args.stock_iboot)
    else:
        print(f"OK: skipped n841-only iBoot checks for {args.expected_board}")

    if (bootchain / "sptm.img4").is_file():
        print("OK: SPTM staged")
    if (bootchain / "txm.img4").is_file():
        print("OK: TXM staged")

    mode = (bootchain / "kernel.mode").read_text().strip() if (bootchain / "kernel.mode").is_file() else args.kernel_mode
    if mode != args.kernel_mode:
        fail(f"kernel.mode={mode!r} != --kernel-mode {args.kernel_mode!r}")
    if mode == "patched" and not args.allow_patched_kernel:
        fail("patched kernel requires --allow-patched-kernel")
    print(f"OK: kernel mode {mode}")
    print("preflight passed")


if __name__ == "__main__":
    main()
