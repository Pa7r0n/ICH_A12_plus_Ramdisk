#!/usr/bin/env python3
"""
sptm_patchfinder.py — SPTM (Secure Page Table Monitor) patchfinder for iOS 26-27.

SPTM controls CTRR lockdown, page table protection, and system register locking.
On iOS 27, SPTM is present on A13+ and will re-lock CTRR even if iBoot skips it.
This patchfinder finds and patches SPTM to prevent CTRR lockdown.

Patches:
  1. ctrr_lock_boot — force early return (CTRR stays unlocked)
  2. cpu_lock_system_registers — NOP system register lockdown
  3. sptm_determine_kernel_ctrr — prevent CTRR range setup

Usage:
    sptm_patchfinder.py <sptm.raw> [output.raw]
"""

import argparse
import struct
import sys
from pathlib import Path
from collections import defaultdict

PACIBSP_U32 = 0xD503237F
BTI_C_U32   = 0xD503245F
NOP_U32     = 0xD503201F
RET_U32     = 0xD65F03C0
MOV_W0_1    = 0x52800020

FUNC_STARTS = {PACIBSP_U32, BTI_C_U32}

def p32(v): return struct.pack('<I', v)
def rd32(d, o): return struct.unpack_from('<I', d, o)[0]
def rd64(d, o): return struct.unpack_from('<Q', d, o)[0]

def decode_adrp_imm(w):
    immhi = (w >> 5) & 0x7FFFF
    immlo = (w >> 29) & 0x3
    imm = (immhi << 2) | immlo
    if imm & (1 << 20): imm -= (1 << 21)
    return imm


class SPTMPatchfinder:
    def __init__(self, data, verbose=True):
        self.data = bytearray(data)
        self.size = len(data)
        self.verbose = verbose
        self.patches = []
        self.results = {}
        self.segments = []
        self.adrp_index = defaultdict(list)

        self._parse_macho()
        self._build_adrp_index()

    def log(self, msg):
        if self.verbose: print(msg)

    def emit(self, off, patch_bytes, desc):
        self.data[off:off + len(patch_bytes)] = patch_bytes
        self.patches.append((off, desc))
        va = self.foff_to_va(off)
        self.log(f"  0x{off:05X} (0x{va:X}): {desc}" if va else f"  0x{off:05X}: {desc}")

    def _parse_macho(self):
        ncmds = rd32(self.data, 16)
        off = 32
        for _ in range(ncmds):
            cmd, cs = rd32(self.data, off), rd32(self.data, off + 4)
            if cmd == 0x19:
                name = self.data[off+8:off+24].split(b'\x00')[0].decode()
                self.segments.append({
                    'name': name, 'vmaddr': rd64(self.data, off+24),
                    'vmsize': rd64(self.data, off+32), 'fileoff': rd64(self.data, off+40),
                    'filesize': rd64(self.data, off+48),
                })
            off += cs

    def va_to_foff(self, va):
        for s in self.segments:
            if s['vmaddr'] <= va < s['vmaddr'] + s['vmsize']:
                return int(va - s['vmaddr'] + s['fileoff'])
        return None

    def foff_to_va(self, foff):
        for s in self.segments:
            so, se = int(s['fileoff']), int(s['fileoff'] + s['filesize'])
            if so <= foff < se:
                return s['vmaddr'] + (foff - so)
        return None

    def text_exec_range(self):
        for s in self.segments:
            if s['name'] == '__TEXT_EXEC':
                return int(s['fileoff']), int(s['fileoff'] + s['filesize'])
        return 0, self.size

    def _build_adrp_index(self):
        te_start, te_end = self.text_exec_range()
        for foff in range(te_start, te_end, 4):
            w = rd32(self.data, foff)
            if (w & 0x9F000000) != 0x90000000: continue
            imm = decode_adrp_imm(w)
            va = self.foff_to_va(foff)
            if va:
                page = ((va & ~0xFFF) + (imm << 12)) & 0xFFFFFFFFFFFFFFFF
                self.adrp_index[page].append(foff)

    def find_string(self, needle):
        if isinstance(needle, str): needle = needle.encode()
        idx = self.data.find(needle)
        return idx if idx >= 0 else None

    def find_string_refs(self, str_foff):
        va = self.foff_to_va(str_foff)
        if va is None: return []
        page, page_off = va & ~0xFFF, va & 0xFFF
        refs = []
        for adrp_foff in self.adrp_index.get(page, []):
            for d in range(4, 20, 4):
                noff = adrp_foff + d
                if noff + 4 > self.size: break
                w = rd32(self.data, noff)
                if (w & 0xFF800000) == 0x91000000 and ((w >> 10) & 0xFFF) == page_off:
                    refs.append(adrp_foff)
                    break
        return refs

    def find_func_by_string(self, needle, label=None):
        soff = self.find_string(needle)
        if soff is None: return None
        refs = self.find_string_refs(soff)
        if not refs: return None
        func = self.find_func_start(refs[0])
        if func is not None and label:
            self.log(f"  {label}: func @ 0x{func:X}")
            self.results[label] = func
        return func

    def find_func_start(self, off):
        for i in range(off & ~3, max(0, off - 0x4000), -4):
            if rd32(self.data, i) in FUNC_STARTS: return i
        return None

    def find_func_end(self, off):
        for i in range(off, min(off + 0x4000, self.size - 4), 4):
            if rd32(self.data, i) in (RET_U32, 0xD65F0FFF): return i + 4
        return None

    # ─────────────────────────────────────────
    # 1. ctrr_lock_boot — force early return
    # ─────────────────────────────────────────

    def patch_ctrr_lock_boot(self):
        self.log("\n[1] ctrr_lock_boot")
        func = self.find_func_by_string("ctrr_lock_boot", "ctrr_lock_boot")
        if func is None:
            func = self.find_func_by_string("CTRR-A already enabled", "ctrr_lock_boot(alt)")
        if func is None:
            self.log("  [-] Not found")
            return False

        # The function starts with:
        #   PACIBSP / BTI c
        #   ... (maybe STP)
        #   ADRP + LDRB → check byte (already_locked flag)
        #   TBNZ/CBNZ → early return
        # We want to force the early return path.
        # Simplest: replace first instruction after prologue with MOV W0, #1; RET
        # Or: find the TBNZ/CBZ check and make it unconditional

        # Scan first 20 instructions for TBNZ/CBZ on bit 0 (the already_locked check)
        for off in range(func, min(func + 80, self.size - 4), 4):
            w = rd32(self.data, off)
            # TBNZ Wn, #0, target  = 0x37000000 | ...
            if (w & 0xFFF8001F) == 0x37000000:
                # Change TBNZ to unconditional B (always take early return)
                imm14 = (w >> 5) & 0x3FFF
                if imm14 & (1 << 13): imm14 -= (1 << 14)
                target = off + imm14 * 4
                delta = (target - off) >> 2
                b_insn = 0x14000000 | (delta & 0x3FFFFFF)
                self.emit(off, p32(b_insn), "TBNZ → B (always skip CTRR lock)")
                return True

            # CBZ/CBNZ pattern
            if (w & 0x7F000000) == 0x35000000:  # CBNZ
                imm19 = (w >> 5) & 0x7FFFF
                if imm19 & (1 << 18): imm19 -= (1 << 19)
                target = off + imm19 * 4
                delta = (target - off) >> 2
                b_insn = 0x14000000 | (delta & 0x3FFFFFF)
                self.emit(off, p32(b_insn), "CBNZ → B (always skip CTRR lock)")
                return True

        # Fallback: just MOV W0, #1; RET at function start + 4 (after PACIBSP)
        self.emit(func + 4, p32(MOV_W0_1), "ctrr_lock_boot: MOV W0, #1 (force return)")
        self.emit(func + 8, p32(RET_U32), "ctrr_lock_boot: RET")
        return True

    # ─────────────────────────────────────────
    # 2. cpu_lock_system_registers
    # ─────────────────────────────────────────

    def patch_cpu_lock_system_registers(self):
        self.log("\n[2] cpu_lock_system_registers")
        func = self.find_func_by_string("cpu_lock_system_registers", "cpu_lock_system_regs")
        if func is None:
            self.log("  [-] Not found")
            return False

        # Stub entire function: MOV W0, #0; RET (after PACIBSP)
        self.emit(func + 4, p32(0x52800000), "cpu_lock_system_regs: MOV W0, #0")
        self.emit(func + 8, p32(RET_U32), "cpu_lock_system_regs: RET")
        return True

    # ─────────────────────────────────────────
    # 3. sptm_determine_kernel_ctrr
    # ─────────────────────────────────────────

    def patch_sptm_determine_kernel_ctrr(self):
        self.log("\n[3] sptm_determine_kernel_ctrr")
        func = self.find_func_by_string("sptm_determine_kernel_ctrr", "sptm_determine_ctrr")
        if func is None:
            func = self.find_func_by_string("kernel-ctrr-to-be-enabled", "sptm_determine_ctrr(alt)")
        if func is None:
            self.log("  [-] Not found")
            return False

        # Stub: MOV W0, #0; RET (return "no CTRR needed")
        self.emit(func + 4, p32(0x52800000), "sptm_determine_ctrr: MOV W0, #0")
        self.emit(func + 8, p32(RET_U32), "sptm_determine_ctrr: RET")
        return True

    # ─────────────────────────────────────────
    # 4. Additional: find all CTRR MSR instructions
    # ─────────────────────────────────────────

    def find_ctrr_msr(self):
        self.log("\n[4] CTRR MSR instructions in SPTM")
        te_start, te_end = self.text_exec_range()
        count = 0
        for off in range(te_start, te_end, 4):
            w = rd32(self.data, off)
            if (w & 0xFFF00000) != 0xD5100000: continue
            op0 = 2 + ((w >> 19) & 1)
            op1 = (w >> 16) & 0x7
            crn = (w >> 12) & 0xF
            crm = (w >> 8) & 0xF
            op2 = (w >> 5) & 0x7

            if op0 == 3 and op1 == 4 and crn == 15 and crm == 2 and op2 in (2, 3, 4, 5):
                names = {2: "CTRR_LOCK", 3: "CTRR_A_LWR", 4: "CTRR_A_UPR", 5: "CTRR_CTL"}
                va = self.foff_to_va(off)
                self.log(f"  MSR {names.get(op2, '?')}_EL2 @ 0x{off:X} (0x{va:X})")
                self.results[f'msr_ctrr_{off:X}'] = off
                count += 1
        self.log(f"  {count} CTRR MSR instructions found")
        return count

    # ─────────────────────────────────────────
    # 5. Find key functions for reference
    # ─────────────────────────────────────────

    def find_key_functions(self):
        self.log("\n[5] Key function discovery")
        for needle, label in [
            ("xnu_ro_pagetables_begin", "xnu_ro_pagetables"),
            ("protected_write", "protected_write"),
            ("PPL_MAGIC_VALUE", "ppl_magic"),
            ("page_tables.c", "page_tables"),
            ("sptm_init", "sptm_init"),
            ("assert_amcc_cache_disabled", "amcc_cache_check"),
            ("/chosen/lock-regs", "lock_regs_dt"),
            ("bootstrap_unmap_io_region", "bootstrap_unmap"),
        ]:
            self.find_func_by_string(needle, label)

    # ─────────────────────────────────────────
    # Run all
    # ─────────────────────────────────────────

    def find_all(self):
        ident = self.find_string("SecurePageTableMonitor")
        if ident:
            end = self.data.find(b'\x00', ident)
            self.log(f"=== SPTM Patchfinder: {self.data[ident:end].decode(errors='replace')} ===")
        else:
            self.log(f"=== SPTM Patchfinder ({self.size/1024:.0f} KB) ===")

        # Count functions
        te_s, te_e = self.text_exec_range()
        funcs = sum(1 for i in range(te_s, te_e, 4) if rd32(self.data, i) in FUNC_STARTS)
        self.log(f"  {funcs} functions, {self.size/1024:.0f} KB\n")

        self.patch_ctrr_lock_boot()
        self.patch_cpu_lock_system_registers()
        self.patch_sptm_determine_kernel_ctrr()
        self.find_ctrr_msr()
        self.find_key_functions()

        self.log(f"\n  {len(self.patches)} patches, {len(self.results)} functions found")
        return self.data


def main():
    ap = argparse.ArgumentParser(description="SPTM patchfinder for iOS 26-27")
    ap.add_argument("input", type=Path)
    ap.add_argument("output", type=Path, nargs='?')
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args()

    data = args.input.read_bytes()
    pf = SPTMPatchfinder(data, verbose=not args.quiet)
    patched = pf.find_all()

    if args.output:
        args.output.write_bytes(bytes(patched))
        print(f"\nSaved to {args.output}")


if __name__ == "__main__":
    main()
