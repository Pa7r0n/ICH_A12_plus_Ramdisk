#!/usr/bin/env python3
"""Apply Leeksov kernel-patchfinder subsets (usbliter8ra1n matrix)."""

from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
KPF_PATH = ROOT / "kernel_patchfinder.py"

# Named sets → result keys from KernelPatchfinder.find_all()
SETS = {
    "debugger": ("PE_i_can_has_debugger",),
    "amfi": ("AMFIIsCDHashInTrustCache",),
    "launch": ("launch_constraints_func",),
}

# usbliter8ra1n README: iOS 15–18/26 → AMFI; iOS 27 → AMFI + TXM-era extras
PROFILES = {
    "ios15": ("debugger", "amfi"),
    "ios16": ("debugger", "amfi"),
    "ios17": ("debugger", "amfi"),
    "ios18": ("debugger", "amfi"),
    "ios26": ("debugger", "amfi"),
    "ios27": ("debugger", "amfi", "launch"),
    "amfi": ("amfi",),
    "amfi+debugger": ("debugger", "amfi"),
}

ALL_KEYS = (
    "PE_i_can_has_debugger",
    "AMFIIsCDHashInTrustCache",
    "launch_constraints_func",
)

# Always required for SSH binaries to execute
REQUIRED_ALWAYS = {"AMFIIsCDHashInTrustCache"}


def load_kpf():
    spec = importlib.util.spec_from_file_location("kernel_patchfinder", KPF_PATH)
    if spec is None or spec.loader is None:
        raise SystemExit(f"unable to load {KPF_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules["kernel_patchfinder"] = module
    spec.loader.exec_module(module)
    return module


def parse_kpf_set(value: str) -> set[str]:
    value = value.strip().lower()
    if value in ("all", "*"):
        return set(ALL_KEYS)
    if value in PROFILES:
        keys: set[str] = set()
        for name in PROFILES[value]:
            keys.update(SETS[name])
        return keys
    keys = set()
    for part in value.replace(",", "+").split("+"):
        part = part.strip()
        if not part:
            continue
        if part in PROFILES:
            for name in PROFILES[part]:
                keys.update(SETS[name])
            continue
        if part not in SETS:
            raise SystemExit(
                f"unknown kpf set {part!r}; expected all|ios15|ios16|ios17|ios18|ios26|ios27|"
                + "|".join(SETS)
                + "|debugger+amfi|..."
            )
        keys.update(SETS[part])
    if not keys:
        raise SystemExit("empty --kpf-set")
    return keys


def apply_subset(pf, results: dict, wanted: set[str]) -> int:
    kpf = sys.modules["kernel_patchfinder"]
    n = 0
    if "PE_i_can_has_debugger" in wanted and "PE_i_can_has_debugger" in results:
        off = results["PE_i_can_has_debugger"]
        pf.emit(off, kpf.p32(kpf.MOV_W0_1_U32), "PE_i_can_has_debugger → MOV W0, #1")
        pf.emit(off + 4, kpf.p32(kpf.RETAB_U32), "PE_i_can_has_debugger → RETAB")
        n += 2
    if "AMFIIsCDHashInTrustCache" in wanted and "AMFIIsCDHashInTrustCache" in results:
        off = results["AMFIIsCDHashInTrustCache"]
        pf.emit(off, kpf.p32(kpf.MOV_X0_1_U32), "AMFI trustcache → MOV X0, #1")
        pf.emit(off + 4, kpf.p32(kpf.CBZ_X2_8_U32), "AMFI trustcache → CBZ X2, +8")
        pf.emit(off + 8, kpf.p32(kpf.STR_X0_X2_U32), "AMFI trustcache → STR X0, [X2]")
        pf.emit(off + 12, kpf.p32(kpf.RET_U32), "AMFI trustcache → RET")
        n += 4
    if "launch_constraints_func" in wanted and "launch_constraints_func" in results:
        off = results["launch_constraints_func"]
        pf.emit(off, kpf.p32(kpf.MOV_W0_0_U32), "launch_constraints → MOV W0, #0")
        pf.emit(off + 4, kpf.p32(kpf.RETAB_U32), "launch_constraints → RETAB")
        n += 2
    return n


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="stock kernelcache.raw")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--kpf-set",
        default="ios18",
        help="ios17|ios18|ios26|ios27|all|debugger|amfi|launch|debugger+amfi|...",
    )
    parser.add_argument(
        "--allow-missing",
        action="store_true",
        help="skip optional targets not found (AMFI is still required)",
    )
    parser.add_argument("-q", "--quiet", action="store_true")
    args = parser.parse_args()

    wanted = parse_kpf_set(args.kpf_set)
    kpf = load_kpf()
    pf = kpf.KernelPatchfinder(args.input.read_bytes(), verbose=not args.quiet)
    results = pf.find_all()

    missing = sorted(key for key in wanted if key not in results)
    hard_missing = [k for k in missing if k in REQUIRED_ALWAYS or not args.allow_missing]
    soft_missing = [k for k in missing if k not in hard_missing]
    if hard_missing:
        raise SystemExit(f"kernel patchfinder did not locate: {', '.join(hard_missing)}")
    if soft_missing:
        print(f"note: skipping missing optional targets: {', '.join(soft_missing)}")
        wanted -= set(soft_missing)

    if "AMFIIsCDHashInTrustCache" not in results:
        raise SystemExit("AMFIIsCDHashInTrustCache not found — cannot patch for SSH")

    # Always ensure AMFI is applied when present
    wanted.add("AMFIIsCDHashInTrustCache")

    count = apply_subset(pf, results, wanted)
    args.output.write_bytes(bytes(pf.data))
    print(f"applied {count} instructions for set {{{', '.join(sorted(wanted))}}}")
    print(f"wrote {args.output}")


if __name__ == "__main__":
    main()
