#!/usr/bin/env python3
"""
txm_patchfinder.py — TXM (Trust eXecution Monitor) patchfinder for iOS 27 A12/A13.

Automatically finds and patches TXM security policy configuration.
No hardcoded offsets — finds targets via string xrefs, ADRP index,
instruction patterns, and global variable tracing.

Approach (from Duy Tran / IDA RE):
  1. Find device_type global via "unsupported device type" string → set to 0
  2. Find policy init function via "platform code only policy" string
  3. Trace policy struct stores (STRH WZR / STRB WZR to policy fields)
  4. Replace zero-stores with all-ones stores (enable all security bypasses)

Policy fields bypassed:
  - skipTrustEvaluation_allowAnySignature
  - allowUnrestrictedLocalSigning
  - relaxProfileTrust
  - allowModifiedCodeAndUnrestrictDebug

Additional patches:
  - Trustcache cdhash loader bypass
  - get-task-allow entitlement bypass
  - dynamic-codesigning bypass
  - pmap trust cache entitlement bypass

Usage:
    txm_patchfinder.py <txm.raw> [output.raw]
"""

import argparse
import struct
import sys
from pathlib import Path
from collections import defaultdict

PACIBSP_U32  = 0xD503237F
BTI_C_U32    = 0xD503245F
NOP_U32      = 0xD503201F
RET_U32      = 0xD65F03C0
MOV_X0_0_U32 = 0xD2800000
MOV_X0_1_U32 = 0xD2800020
MOV_W0_0_U32 = 0x52800000

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


class TXMPatchfinder:
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
        return func

    def find_func_start(self, off):
        for i in range(off & ~3, max(0, off - 0x2000), -4):
            if rd32(self.data, i) in FUNC_STARTS: return i
        return None

    def find_func_end(self, off):
        for i in range(off, min(off + 0x2000, self.size - 4), 4):
            if rd32(self.data, i) in (RET_U32, 0xD65F0FFF): return i + 4
        return None

    # ─────────────────────────────────────────
    # 1. device_type → 0 (triggers txm_cs_disable)
    # ─────────────────────────────────────────

    def patch_device_type(self):
        self.log("\n[1] device_type → 0")

        # Find via "unsupported device type" or "resolved system platform identity"
        init = self.find_func_by_string("resolved system platform identity", "txm_init")
        if init is None:
            init = self.find_func_by_string("unsupported device type", "txm_init(alt)")
        if init is None:
            self.log("  [-] TXM init not found")
            return False

        # Find STRB to device_type global: pattern is STRB Wn, [Xbase, #imm]
        # after the call to sub that returns device_type (0-7)
        # The store instruction writes to byte_xxxx1C382 (our case)
        te_start, te_end = self.text_exec_range()
        func_end = self.find_func_end(init) or init + 0x800

        # Find the global that gets written with device_type
        # Pattern: BL <get_device_type> ; STRB W0, [Xn, #imm]
        device_type_global = None
        device_type_store = None
        for off in range(init, func_end, 4):
            w = rd32(self.data, off)
            # STRB W0, [Xn, #imm] where W0 = return value of device_type getter
            if (w & 0xFFC0001F) == 0x39000000:  # STRB W0
                # Check if preceded by BL
                if off >= 4:
                    prev = rd32(self.data, off - 4)
                    if (prev >> 26) == 0b100101:  # BL
                        device_type_store = off
                        # Decode the store target
                        rn = (w >> 5) & 0x1F
                        imm = (w >> 10) & 0xFFF
                        # Find what Rn points to via ADRP+ADD before the BL
                        for back in range(off - 8, max(init, off - 40), -4):
                            bw = rd32(self.data, back)
                            if (bw & 0x9F00001F) == (0x90000000 | rn):  # ADRP Rn
                                adrp_imm = decode_adrp_imm(bw)
                                bva = self.foff_to_va(back)
                                if bva:
                                    page = (bva & ~0xFFF) + (adrp_imm << 12)
                                    # Check ADD after ADRP
                                    nxt = rd32(self.data, back + 4)
                                    if (nxt & 0xFF800000) == 0x91000000:
                                        add_imm = (nxt >> 10) & 0xFFF
                                        device_type_global = page + add_imm
                                break
                        break

        if device_type_store:
            # Replace STRB W0 with STRB WZR (store 0 instead of actual device_type)
            w = rd32(self.data, device_type_store)
            new_w = (w & ~0x1F) | 31  # Change Rt to WZR (register 31)
            self.emit(device_type_store, p32(new_w), "STRB WZR → device_type=0 (txm_cs_disable)")
            if device_type_global:
                self.results['device_type_global'] = device_type_global
                self.log(f"    device_type global @ VA 0x{device_type_global:X}")
            return True

        self.log("  [-] device_type store not found")
        return False

    # ─────────────────────────────────────────
    # 2. Policy struct: enable all bypass flags
    # ─────────────────────────────────────────

    def patch_policy_flags(self):
        self.log("\n[2] Policy flags → all enabled")

        # Find policy init via "platform code only policy" string
        func = self.find_func_by_string("platform code only policy", "policy_init")
        if func is None:
            return False

        func_end = self.find_func_end(func) or func + 0x400

        # Find all STRH WZR and STRB WZR to globals in this function
        # These are the policy flags being set to 0 (disabled)
        # We want to change them to store -1 (all bits set = enabled)
        patched = 0
        for off in range(func, func_end, 4):
            w = rd32(self.data, off)

            # STRH WZR, [Xn, #imm] = 0x7900001F family
            if (w & 0xFFC0001F) == 0x7900001F:
                rn = (w >> 5) & 0x1F
                imm = ((w >> 10) & 0xFFF) * 2
                # Need to: MOV W_temp, #-1 first, then STRH W_temp
                # But we can't insert instructions. Instead:
                # Find a preceding MOV/MOVZ that we can change
                # OR: replace STRH WZR with a NOP and add MOV+STRH elsewhere
                # Simplest: change WZR (reg 31) to W0, and add MOV W0,#-1 before
                # But that changes W0...
                #
                # Actually simplest approach: just NOP the zero-store.
                # The field will have garbage/previous value which may not be 0.
                # Better: find if there's a MOV W0, #0 before that we can change to MOV W0, #-1

                # Check 1-3 instructions before for MOV Wn, #0
                for back in range(1, 4):
                    prev = rd32(self.data, off - back * 4)
                    if (prev & 0xFFFFFFE0) == 0x52800000:  # MOV Wn, #0
                        prev_rd = prev & 0x1F
                        # Change to MOV Wn, #-1 (MOVN Wn, #0)
                        self.emit(off - back * 4, p32(0x12800000 | prev_rd), f"MOV W{prev_rd}, #-1")
                        # Also change the STRH to use that register instead of WZR
                        new_w = (w & ~0x1F) | prev_rd
                        self.emit(off, p32(new_w), f"STRH W{prev_rd}, [X{rn}, #0x{imm:X}] (policy flag)")
                        patched += 1
                        break
                else:
                    # No preceding MOV found — just NOP the zero-store
                    self.emit(off, p32(NOP_U32), f"NOP STRH WZR, [X{rn}, #0x{imm:X}] (policy flag)")
                    patched += 1

            # STRB WZR, [Xn, #imm] = 0x3900001F family
            if (w & 0xFFC0001F) == 0x3900001F:
                rn = (w >> 5) & 0x1F
                imm = (w >> 10) & 0xFFF
                for back in range(1, 4):
                    prev = rd32(self.data, off - back * 4)
                    if (prev & 0xFFFFFFE0) == 0x52800000:
                        prev_rd = prev & 0x1F
                        self.emit(off - back * 4, p32(0x12800000 | prev_rd), f"MOV W{prev_rd}, #-1")
                        new_w = (w & ~0x1F) | prev_rd
                        self.emit(off, p32(new_w), f"STRB W{prev_rd}, [X{rn}, #0x{imm:X}] (policy flag)")
                        patched += 1
                        break
                else:
                    self.emit(off, p32(NOP_U32), f"NOP STRB WZR, [X{rn}, #0x{imm:X}] (policy flag)")
                    patched += 1

        self.log(f"  {patched} policy flag stores patched")
        return patched > 0

    # ─────────────────────────────────────────
    # 3. String-anchored function stubs
    # ─────────────────────────────────────────

    def patch_func_stub(self, needle, label, ret_val=0):
        func = self.find_func_by_string(needle, label)
        if func is None: return False
        mov = MOV_X0_0_U32 if ret_val == 0 else MOV_X0_1_U32
        self.emit(func, p32(mov), f"{label}: MOV X0, #{ret_val}")
        self.emit(func + 4, p32(RET_U32), f"{label}: RET")
        return True

    # ─────────────────────────────────────────
    # Run all
    # ─────────────────────────────────────────

    def find_all(self):
        ident = self.find_string("TrustedExecutionMonitor")
        if ident:
            end = self.data.find(b'\x00', ident)
            self.log(f"=== TXM Patchfinder: {self.data[ident:end].decode(errors='replace')} ===")
        else:
            self.log(f"=== TXM Patchfinder ({self.size/1024:.0f} KB) ===")

        self.patch_device_type()
        self.patch_policy_flags()

        self.log("\n[3] Function stubs:")
        self.patch_func_stub("com.apple.private.amfi.can-load-cdhash", "cdhash_loader", 0)
        self.patch_func_stub("get-task-allow", "get_task_allow", 0)
        self.patch_func_stub("dynamic-codesigning", "dynamic_codesign", 0)
        self.patch_func_stub("com.apple.private.pmap.load-trust-cache", "pmap_trust", 0)

        self.log(f"\n  {len(self.patches)} total patches")
        return self.data


def main():
    ap = argparse.ArgumentParser(description="TXM patchfinder for iOS 27 A12/A13")
    ap.add_argument("input", type=Path)
    ap.add_argument("output", type=Path, nargs='?')
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args()

    data = args.input.read_bytes()
    pf = TXMPatchfinder(data, verbose=not args.quiet)
    patched = pf.find_all()

    if args.output:
        args.output.write_bytes(bytes(patched))
        print(f"\nSaved to {args.output}")


if __name__ == "__main__":
    main()
