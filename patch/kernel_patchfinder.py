#!/usr/bin/env python3
"""
kernel_patchfinder.py — arm64e kernelcache patchfinder for A12/A13 jailbreak.

Ported from vphone-cli KernelPatcherBase.swift with additions.
Builds ADRP index (VA-aware) + BL index for O(1) lookups.
Finds all patch targets automatically via string xrefs, BL histogram,
and raw instruction pattern matching.

Tested: iOS 17.0 (18 targets), iOS 27.0 beta (18 targets), ~5s each.

Usage:
    kernel_patchfinder.py <kernelcache.raw> [--apply <output.raw>] [-q]
"""

import argparse
import struct
import sys
import time
from pathlib import Path
from collections import defaultdict

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

# ═══════════════════════════════════════════════════════════
# ARM64 instruction constants
# ═══════════════════════════════════════════════════════════

NOP_U32       = 0xD503201F
RET_U32       = 0xD65F03C0
RETAB_U32     = 0xD65F0FFF
PACIBSP_U32   = 0xD503237F
BTI_C_U32     = 0xD503245F
MOV_X0_0_U32  = 0xD2800000
MOV_X0_1_U32  = 0xD2800020
MOV_W0_0_U32  = 0x52800000
MOV_W0_1_U32  = 0x52800020
CBZ_X2_8_U32  = 0xB4000042
STR_X0_X2_U32 = 0xF9000040

FUNC_BOUNDARIES = {RET_U32, RETAB_U32, PACIBSP_U32, BTI_C_U32, NOP_U32}
FUNC_STARTS     = {PACIBSP_U32, BTI_C_U32}

def p32(v):
    return struct.pack('<I', v)

def rd32(d, o):
    return struct.unpack_from('<I', d, o)[0]

def rd64(d, o):
    return struct.unpack_from('<Q', d, o)[0]

def decode_adrp_imm(insn_word):
    immhi = (insn_word >> 5) & 0x7FFFF
    immlo = (insn_word >> 29) & 0x3
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= (1 << 21)
    return imm

def is_adrp(w):
    return (w & 0x9F000000) == 0x90000000

def is_bl(w):
    return (w >> 26) == 0b100101

def bl_target(off, w):
    imm26 = w & 0x3FFFFFF
    if imm26 & (1 << 25):
        imm26 -= (1 << 26)
    return off + imm26 * 4

def is_add_imm(w):
    return (w & 0xFF800000) == 0x91000000

def add_imm12(w):
    return (w >> 10) & 0xFFF


# ═══════════════════════════════════════════════════════════
# KernelPatchfinder
# ═══════════════════════════════════════════════════════════

class KernelPatchfinder:
    def __init__(self, data, verbose=True):
        self.data = bytearray(data)
        self.size = len(data)
        self.verbose = verbose
        self.patches = []

        self.base_va = 0
        self.segments = []
        self.code_ranges = []
        self.adrp_index = defaultdict(list)
        self.bl_index = defaultdict(list)
        self.panic_offset = None

    def log(self, msg):
        if self.verbose:
            print(msg)

    def emit(self, off, patch_bytes, desc):
        self.data[off:off + len(patch_bytes)] = patch_bytes
        self.patches.append((off, desc))
        self.log(f"  0x{off:08X}: {desc}")

    # ───────────────────────────────────────────────
    # Mach-O parsing
    # ───────────────────────────────────────────────

    def parse_macho(self):
        if rd32(self.data, 0) != 0xFEEDFACF:
            raise ValueError("Not Mach-O 64")

        ncmds = rd32(self.data, 16)
        off = 32
        for _ in range(ncmds):
            cmd, cmdsize = rd32(self.data, off), rd32(self.data, off + 4)

            if cmd == 0x19:  # LC_SEGMENT_64
                name = self.data[off+8:off+24].split(b'\x00')[0].decode()
                seg = {
                    'name': name,
                    'vmaddr':   rd64(self.data, off + 24),
                    'vmsize':   rd64(self.data, off + 32),
                    'fileoff':  rd64(self.data, off + 40),
                    'filesize': rd64(self.data, off + 48),
                }
                self.segments.append(seg)
                if name == '__TEXT':
                    self.base_va = seg['vmaddr']
                if name == '__TEXT_EXEC':
                    self.code_ranges.append((int(seg['fileoff']), int(seg['fileoff'] + seg['filesize'])))
                if name == '__PRELINK_TEXT' and seg['filesize'] > 0x1000:
                    self.code_ranges.append((int(seg['fileoff']), int(seg['fileoff'] + seg['filesize'])))

            off += cmdsize

        self.log(f"  Base VA: 0x{self.base_va:X}, Segments: {len(self.segments)}")
        for s, e in self.code_ranges:
            self.log(f"  Code range: 0x{s:X}-0x{e:X} ({(e-s)/1024/1024:.1f} MB)")

    # ───────────────────────────────────────────────
    # VA ↔ file offset conversion
    # ───────────────────────────────────────────────

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

    def main_code_range(self):
        return max(self.code_ranges, key=lambda r: r[1] - r[0])

    # ───────────────────────────────────────────────
    # Index building
    # ───────────────────────────────────────────────

    def build_adrp_index(self):
        t0 = time.time()
        self.adrp_index.clear()
        count = 0
        for start, end in self.code_ranges:
            for off in range(start, end, 4):
                w = rd32(self.data, off)
                if not is_adrp(w):
                    continue
                imm = decode_adrp_imm(w)
                va = self.foff_to_va(off)
                base = va if va else off
                page = ((base & ~0xFFF) + (imm << 12)) & 0xFFFFFFFFFFFFFFFF
                self.adrp_index[page].append(off)
                count += 1
        self.log(f"  ADRP index: {count} entries, {len(self.adrp_index)} pages ({time.time()-t0:.1f}s)")

    def build_bl_index(self):
        t0 = time.time()
        self.bl_index.clear()
        count = 0
        for start, end in self.code_ranges:
            for off in range(start, end, 4):
                w = rd32(self.data, off)
                if not is_bl(w):
                    continue
                self.bl_index[bl_target(off, w)].append(off)
                count += 1
        self.log(f"  BL index: {count} entries, {len(self.bl_index)} targets ({time.time()-t0:.1f}s)")

    # ───────────────────────────────────────────────
    # String and function helpers
    # ───────────────────────────────────────────────

    def find_string(self, needle):
        if isinstance(needle, str):
            needle = needle.encode()
        idx = self.data.find(needle)
        return idx if idx >= 0 else None

    def find_string_refs(self, string_foff):
        va = self.foff_to_va(string_foff)
        if va is None:
            return []
        page = va & ~0xFFF
        page_off = va & 0xFFF
        refs = []
        for adrp_off in self.adrp_index.get(page, []):
            for delta in range(4, 36, 4):
                add_off = adrp_off + delta
                if add_off + 4 > self.size:
                    break
                w = rd32(self.data, add_off)
                if is_add_imm(w) and add_imm12(w) == page_off:
                    adrp_rd = rd32(self.data, adrp_off) & 0x1F
                    add_rn = (w >> 5) & 0x1F
                    if adrp_rd == add_rn:
                        refs.append((adrp_off, add_off))
                        break
        return refs

    def find_func_by_string(self, needle, label=None):
        soff = self.find_string(needle)
        if soff is None:
            self.log(f"  {label or needle}: string NOT FOUND")
            return None
        refs = self.find_string_refs(soff)
        if not refs:
            self.log(f"  {label or needle}: str@0x{soff:X} no xrefs")
            return None
        func = self.find_func_start(refs[0][0])
        if func is not None:
            self.log(f"  {label or needle}: func=0x{func:X}")
        return func

    def find_func_start(self, off, max_back=0x4000):
        for i in range(off & ~3, max(0, off - max_back), -4):
            w = rd32(self.data, i)
            if w in FUNC_STARTS:
                return i
            if (w & 0x7FC07FFF) == 0x29007BFD:
                return i
        return None

    def find_func_end(self, off, max_fwd=0x4000):
        for i in range(off, min(off + max_fwd, self.size - 4), 4):
            w = rd32(self.data, i)
            if w in (RET_U32, RETAB_U32):
                return i + 4
        return None

    # ───────────────────────────────────────────────
    # _panic finder
    # ───────────────────────────────────────────────

    def find_panic(self):
        for target, callers in sorted(self.bl_index.items(), key=lambda x: -len(x[1]))[:15]:
            if len(callers) < 2000:
                break
            confirmed = 0
            for c in callers[:30]:
                for back in range(c - 4, max(c - 32, 0), -4):
                    w = rd32(self.data, back)
                    if (w & 0xFFC003E0) != 0x91000000:
                        continue
                    add_imm = (w >> 10) & 0xFFF
                    if back < 4:
                        break
                    aw = rd32(self.data, back - 4)
                    if (aw & 0x9F00001F) != 0x90000000:
                        break
                    imm = decode_adrp_imm(aw)
                    foff = ((back - 4) & ~0xFFF) + (imm << 12) + add_imm
                    if 0 <= foff < self.size - 60:
                        if b"%s:%d" in self.data[foff:foff+60]:
                            confirmed += 1
                    break
                if confirmed >= 3:
                    break
            if confirmed >= 3:
                self.panic_offset = target
                self.log(f"  _panic @ 0x{target:X} ({len(callers)} callers)")
                return
        top = sorted(self.bl_index.items(), key=lambda x: -len(x[1]))
        if len(top) > 2:
            self.panic_offset = top[2][0]
            self.log(f"  _panic (fallback) @ 0x{self.panic_offset:X}")

    # ───────────────────────────────────────────────
    # PE_i_can_has_debugger — global variable tracing
    # ───────────────────────────────────────────────

    def find_pe_debugger_via_global(self):
        init = self.find_func_by_string("debug-enabled\x00", "PE_init(debug-enabled)")
        if init is None:
            return None
        end = self.find_func_end(init) or init + 0x1000
        globals_written = set()
        for off in range(init, end, 4):
            w = rd32(self.data, off)
            if not is_adrp(w) or off + 4 >= end:
                continue
            nxt = rd32(self.data, off + 4)
            if (nxt & 0xFFC00000) in (0xB9000000, 0xF9000000):
                imm = decode_adrp_imm(w)
                page = (off & ~0xFFF) + (imm << 12)
                scale = 4 if (nxt & 0xFFC00000) == 0xB9000000 else 8
                str_imm = ((nxt >> 10) & 0xFFF) * scale
                globals_written.add((page + str_imm) & 0xFFFFFFFFFFFFFFFF)

        best = None
        for g in globals_written:
            for adrp_off in self.adrp_index.get(g & ~0xFFF, []):
                func = self.find_func_start(adrp_off)
                if func is None:
                    continue
                fend = self.find_func_end(func)
                if fend is None or fend - func > 48:
                    continue
                callers = len(self.bl_index.get(func, []))
                if callers > 100 and (best is None or callers > best[1]):
                    best = (func, callers)
        if best:
            self.log(f"  PE_i_can_has_debugger (global): func=0x{best[0]:X} callers={best[1]}")
        return best[0] if best else None

    # ───────────────────────────────────────────────
    # PE_i_can_has_debugger — BL histogram + ADRP x8 heuristic
    # ───────────────────────────────────────────────

    def find_pe_debugger_via_histogram(self):
        best_off, best_n = None, 0
        for target, callers in self.bl_index.items():
            n = len(callers)
            if not (50 <= n <= 300) or target + 16 > self.size or target & 3:
                continue
            first = rd32(self.data, target)
            adrp_at = None
            if (first & 0x9F00001F) == 0x90000008:
                adrp_at = target
            elif first == BTI_C_U32 and (rd32(self.data, target + 4) & 0x9F00001F) == 0x90000008:
                adrp_at = target + 4
            if adrp_at is None:
                continue
            if target >= 4 and rd32(self.data, target - 4) not in FUNC_BOUNDARIES:
                continue
            if not any((rd32(self.data, adrp_at + k*4) & 0xFFC00000) == 0xB9400000
                       and ((rd32(self.data, adrp_at + k*4) >> 5) & 0x1F) == 8
                       for k in range(1, 9) if adrp_at + k*4 + 4 <= self.size):
                continue
            if n > best_n:
                best_n = n
                best_off = target
        if best_off is not None:
            self.log(f"  PE_i_can_has_debugger (histogram): func=0x{best_off:X} callers={best_n}")
        return best_off

    # ───────────────────────────────────────────────
    # AMFIIsCDHashInTrustCache — instruction pattern
    # ───────────────────────────────────────────────

    def find_amfi_trustcache(self):
        code_start, code_end = self.main_code_range()
        self.log(f"  AMFI scan range: 0x{code_start:X}-0x{code_end:X}")

        MOV_X19_X2 = 0xAA0203F3
        MOV_X2_SP  = 0x910003E2
        STP_MASK, STP_VAL = 0xFFC07FFF, 0xA9007FFF
        BL_MASK,  BL_VAL  = 0xFC000000, 0x94000000
        MOV_X20_X0 = 0xAA0003F4
        CBNZ_W0_M, CBNZ_W0_V = 0x7F00001F, 0x35000000
        CBZ_X19_M, CBZ_X19_V = 0xFF00001F, 0xB4000013

        hits = []
        off = code_start
        while off < code_end - 4:
            w = rd32(self.data, off)
            if w not in FUNC_STARTS:
                off += 4
                continue
            fs = off
            fe = min(fs + 0x200, code_end)
            p = fs + 4
            while p < fe:
                if rd32(self.data, p) in FUNC_STARTS:
                    fe = p
                    break
                p += 4

            insns = [rd32(self.data, i) for i in range(fs, fe, 4)]

            # Strict pattern: MOV X19,X2 → STP XZR → MOV X2,SP → BL → MOV X20,X0 → CBNZ W0 → CBZ X19
            try:
                i1 = next(i for i, w in enumerate(insns) if w == MOV_X19_X2)
                i2 = next(i for i in range(i1+1, len(insns)) if (insns[i] & STP_MASK) == STP_VAL)
                i3 = next(i for i in range(i2+1, len(insns)) if insns[i] == MOV_X2_SP)
                i4 = next(i for i in range(i3+1, len(insns)) if (insns[i] & BL_MASK) == BL_VAL)
                i5 = next(i for i in range(i4+1, len(insns)) if insns[i] == MOV_X20_X0)
                next(i for i in range(i5+1, len(insns)) if (insns[i] & CBNZ_W0_M) == CBNZ_W0_V)
                next(i for i in range(i5+1, len(insns)) if (insns[i] & CBZ_X19_M) == CBZ_X19_V)
                hits.append(('strict', fs))
            except StopIteration:
                pass

            # Relaxed: STP XZR → MOV X2,SP → BL → CBNZ W0 (small function)
            if not any(h[1] == fs for h in hits):
                try:
                    i3 = next(i for i, w in enumerate(insns) if w == MOV_X2_SP)
                    next(i for i in range(max(0, i3-6), i3) if (insns[i] & STP_MASK) == STP_VAL)
                    i4 = next(i for i in range(i3+1, min(i3+4, len(insns))) if (insns[i] & BL_MASK) == BL_VAL)
                    next(i for i in range(i4+1, min(i4+3, len(insns))) if (insns[i] & CBNZ_W0_M) == CBNZ_W0_V)
                    if len(insns) <= 64:
                        hits.append(('relaxed', fs))
                except StopIteration:
                    pass

            off = fe

        if not hits:
            self.log(f"  AMFIIsCDHashInTrustCache: 0 hits")
            return None

        strict = [h[1] for h in hits if h[0] == 'strict']
        result = strict[0] if strict else hits[0][1]
        self.log(f"  AMFIIsCDHashInTrustCache: {len(hits)} hits ({len(strict)} strict), using 0x{result:X}")
        return result

    # ───────────────────────────────────────────────
    # vm_fault_enter — LDR [X,#offset] + TBZ #3 pattern
    # ───────────────────────────────────────────────

    def find_vm_fault_enter_pattern(self):
        self.log("  vm_fault_enter (instruction pattern)...")
        code_start, code_end = self.main_code_range()
        for off in range(code_start, min(code_end, self.size - 16), 4):
            w = rd32(self.data, off)
            if (w & 0xFFC00000) != 0xB9400000:
                continue
            ldr_imm = (w >> 10) & 0xFFF
            if ldr_imm not in (0x8, 0xA):  # #0x20 or #0x28
                continue
            rt = w & 0x1F
            for fwd in range(off + 4, min(off + 160, code_end), 4):
                tw = rd32(self.data, fwd)
                if (tw & 0x7F000000) != 0x36000000:
                    continue
                if (tw & 0x1F) != rt:
                    continue
                bit = ((tw >> 31) << 5) | ((tw >> 19) & 0x1F)
                if bit != 3:
                    continue
                mw = rd32(self.data, fwd + 4)
                if (mw & 0xFFFFFFE0) != 0x52800000:
                    break
                bw = rd32(self.data, fwd + 8)
                if (bw & 0xFC000000) != 0x14000000:
                    break
                func = self.find_func_start(off)
                if func:
                    self.log(f"  vm_fault_enter: func=0x{func:X} tbz@0x{fwd:X}")
                    return func
                break
        return None

    # ───────────────────────────────────────────────
    # mac_policy — BL frequency + page string check
    # ───────────────────────────────────────────────

    def find_mac_policy_register(self):
        for needle in ["mac_policy_register\x00", "mac_policy_register failed"]:
            func = self.find_func_by_string(needle, f"mac_policy({needle[:25]})")
            if func:
                return func

        self.log("  mac_policy: BL frequency heuristic...")
        code_start, code_end = self.main_code_range()
        for target, callers in sorted(self.bl_index.items(), key=lambda x: len(x[1])):
            n = len(callers)
            if not (3 <= n <= 10) or target < code_start or target >= code_end:
                continue
            fe = self.find_func_end(target)
            if fe is None:
                continue
            fsize = fe - target
            if not (100 <= fsize <= 800):
                continue
            for off in range(target, min(target + fsize, self.size - 4), 4):
                w = rd32(self.data, off)
                if not is_adrp(w):
                    continue
                va = self.foff_to_va(off)
                if va is None:
                    continue
                imm = decode_adrp_imm(w)
                page = (va & ~0xFFF) + (imm << 12)
                pfoff = self.va_to_foff(page)
                if pfoff and 0 <= pfoff < self.size - 20:
                    if b'mac_policy' in self.data[pfoff:pfoff+0x1000]:
                        caller_func = self.find_func_start(callers[0]) if callers else None
                        result = caller_func or target
                        self.log(f"  mac_policy (BL heuristic): func=0x{result:X}")
                        return result
        return None

    # ───────────────────────────────────────────────
    # find_all — orchestrate everything
    # ───────────────────────────────────────────────

    def find_all(self):
        self.log(f"=== Kernel Patchfinder ({self.size/1024/1024:.1f} MB) ===")

        t0 = time.time()
        self.log("\n[1] Parsing Mach-O...")
        self.parse_macho()
        self.log("[2] Building ADRP index...")
        self.build_adrp_index()
        self.log("[3] Building BL index...")
        self.build_bl_index()
        self.log("[4] Finding _panic...")
        self.find_panic()
        self.log(f"    Index build: {time.time()-t0:.1f}s\n")

        results = {}

        # ── Phase 1: string-anchored targets ──
        self.log("[5] String-anchored targets:")
        for needle, label in [
            ("rootvp not authenticated",    "bsd_init"),
            ("SecureRootName\x00",          "SecureRootName"),
            ("/usr/lib/dyld\x00",           "load_dylinker"),
            ("imageboot_needed",            "imageboot"),
            ("debug-enabled\x00",           "debug_enabled_init"),
            ("get-task-allow\x00",          "get_task_allow"),
            ("developer-mode\x00",          "developer_mode"),
            ("cs_enforcement_disable",      "cs_enforcement"),
            ("apfs_vfsop_mount\x00",        "apfs_mount"),
            ("apfs_graft\x00",             "apfs_graft"),
            ("proc_ro_ref_task\x00",        "task_for_pid"),
            ("vm_map_protect(",             "vm_map_protect_func"),
            ("vm_fault_enter_prepare",      "vm_fault_enter"),
            ("vm_fault_enter(",             "vm_fault_enter"),
            ("nvram-proxy-data\x00",        "nvram_verify"),
        ]:
            func = self.find_func_by_string(needle, label)
            if func is not None:
                results[label] = func

        # ── Phase 2: pattern-matched targets ──
        self.log("\n[6] Pattern-matched targets:")

        func = self.find_pe_debugger_via_global()
        if func:
            results['PE_i_can_has_debugger'] = func
        if 'PE_i_can_has_debugger' not in results:
            func = self.find_pe_debugger_via_histogram()
            if func:
                results['PE_i_can_has_debugger'] = func

        func = self.find_amfi_trustcache()
        if func:
            results['AMFIIsCDHashInTrustCache'] = func

        # ── Phase 3: capstone/instruction finders for remaining ──
        self.log("\n[7] Instruction-pattern finders:")

        if 'vm_fault_enter' not in results:
            func = self.find_vm_fault_enter_pattern()
            if func:
                results['vm_fault_enter'] = func

        if 'mac_policy' not in results:
            func = self.find_mac_policy_register()
            if func:
                results['mac_policy'] = func

        # Fallback string finders for remaining targets
        fallbacks = [
            ("dounmount",              ["MNT_ROOTFS", "vfs_iterate\x00", "coveredvp\x00"]),
            ("thid_should_crash",      ["thid_should_crash"]),
            ("launch_constraints_func", ["amfi_check_launch_constraint", "AMFI: launch constraint",
                                       "constraint_category", "launch constraint violated",
                                       "com.apple.private.amfi.can-execute-cdhash"]),
            ("seal_broken",            ["seal_is_broken"]),
        ]
        for label, needles in fallbacks:
            if label in results:
                continue
            for needle in needles:
                func = self.find_func_by_string(needle, f"{label}({needle[:20]})")
                if func:
                    results[label] = func
                    break

        # Heuristic fallback for dounmount
        if 'dounmount' not in results:
            for target, callers in self.bl_index.items():
                n = len(callers)
                if not (5 <= n <= 20):
                    continue
                fe = self.find_func_end(target)
                if fe and 400 <= fe - target <= 1500:
                    results['dounmount'] = target
                    self.log(f"  dounmount (heuristic): func=0x{target:X} callers={n}")
                    break

        # ── Summary ──
        if self.panic_offset:
            results['_panic'] = self.panic_offset

        self.log(f"\n{'='*60}")
        self.log(f"  FOUND: {len(results)} targets")
        self.log(f"{'='*60}")
        for label, foff in sorted(results.items()):
            va = self.foff_to_va(foff)
            va_s = f"VA=0x{va:X}" if va else ""
            self.log(f"  {label:<35s} foff=0x{foff:08X}  {va_s}")

        return results

    # ───────────────────────────────────────────────
    # Patch application
    # ───────────────────────────────────────────────

    def patch_all(self, results):
        n = 0
        if 'PE_i_can_has_debugger' in results:
            off = results['PE_i_can_has_debugger']
            self.emit(off, p32(MOV_W0_1_U32), "PE_i_can_has_debugger → MOV W0, #1")
            self.emit(off + 4, p32(RETAB_U32), "PE_i_can_has_debugger → RETAB")
            n += 2
        if 'AMFIIsCDHashInTrustCache' in results:
            off = results['AMFIIsCDHashInTrustCache']
            self.emit(off,      p32(MOV_X0_1_U32),  "AMFI trustcache → MOV X0, #1")
            self.emit(off + 4,  p32(CBZ_X2_8_U32),  "AMFI trustcache → CBZ X2, +8")
            self.emit(off + 8,  p32(STR_X0_X2_U32), "AMFI trustcache → STR X0, [X2]")
            self.emit(off + 12, p32(RET_U32),        "AMFI trustcache → RET")
            n += 4
        if 'launch_constraints_func' in results:
            off = results['launch_constraints_func']
            self.emit(off, p32(MOV_W0_0_U32), "launch_constraints → MOV W0, #0")
            self.emit(off + 4, p32(RETAB_U32), "launch_constraints → RETAB")
            n += 2
        self.log(f"\n  [{n} patches applied]")
        return n


def main():
    ap = argparse.ArgumentParser(description="arm64e kernelcache patchfinder")
    ap.add_argument("input", type=Path)
    ap.add_argument("--apply", type=Path, help="write patched output")
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args()

    data = args.input.read_bytes()
    pf = KernelPatchfinder(data, verbose=not args.quiet)
    results = pf.find_all()

    if args.apply:
        pf.patch_all(results)
        args.apply.write_bytes(bytes(pf.data))
        print(f"\nSaved to {args.apply}")


if __name__ == "__main__":
    main()
