#!/usr/bin/env python3
"""
iboot_patchfinder.py — Universal iBoot/iBSS/iBEC patchfinder for A12/A13.

Finds and patches all security-relevant targets in decrypted iBoot images.
Works across all A12/A13 devices (iPhone, iPad) and iOS 17-27.

Targets:
  1. image4_validate_property_callback — signature verification bypass
  2. CTRR lockdown — keep kernel text writable
  3. Boot-args — inject custom boot arguments
  4. Boot-args (alternative) — for iPads with different string layout
  5. Ticket verification anchors (for reference)

Usage:
    iboot_patchfinder.py <input.raw> [output.raw] [--mode ibss|ibec|llb] [--base 0x870000000]
"""

import argparse
import struct
import sys
from pathlib import Path
from collections import defaultdict

NOP_U32      = 0xD503201F
RET_U32      = 0xD65F03C0
RETAB_U32    = 0xD65F0FFF
PACIBSP_U32  = 0xD503237F
BTI_C_U32    = 0xD503245F
MOV_X0_0_U32 = 0xD2800000

def p32(v): return struct.pack('<I', v)
def rd32(d, o): return struct.unpack_from('<I', d, o)[0]

def decode_adrp_imm(w):
    immhi = (w >> 5) & 0x7FFFF
    immlo = (w >> 29) & 0x3
    imm = (immhi << 2) | immlo
    if imm & (1 << 20): imm -= (1 << 21)
    return imm

def encode_adrp(rd, pc, target_page):
    delta = (target_page - (pc & ~0xFFF)) >> 12
    immlo = delta & 0x3
    immhi = (delta >> 2) & 0x7FFFF
    return 0x90000000 | (immlo << 29) | (immhi << 5) | rd

def encode_add_imm(rd, rn, imm12):
    return 0x91000000 | (imm12 << 10) | (rn << 5) | rd


class IBootPatchfinder:
    def __init__(self, data, base=0x870000000, mode='ibec', verbose=True):
        self.data = bytearray(data)
        self.size = len(data)
        self.base = base
        self.mode = mode
        self.verbose = verbose
        self.patches = []
        self.results = {}

        # Detect code/data boundary
        self.code_end = self.size
        for i in range(self.size - 4, 0, -4):
            if rd32(self.data, i) == PACIBSP_U32 or rd32(self.data, i) == BTI_C_U32:
                self.code_end = i + 0x1000
                break

        # Build ADRP index
        self.adrp_index = defaultdict(list)
        for off in range(0, min(self.code_end, self.size - 4), 4):
            w = rd32(self.data, off)
            if (w & 0x9F000000) != 0x90000000:
                continue
            imm = decode_adrp_imm(w)
            page = ((self.base + off) & ~0xFFF) + (imm << 12)
            self.adrp_index[page & 0xFFFFFFFFFFFFFFFF].append(off)

    def log(self, msg):
        if self.verbose:
            print(msg)

    def emit(self, off, patch_bytes, desc):
        orig = bytes(self.data[off:off + len(patch_bytes)])
        self.data[off:off + len(patch_bytes)] = patch_bytes
        self.patches.append((off, self.base + off, orig, patch_bytes, desc))
        self.log(f"  0x{off:06X} (VA 0x{self.base+off:X}): {desc}")

    def find_string(self, needle):
        if isinstance(needle, str):
            needle = needle.encode()
        idx = self.data.find(needle)
        return idx if idx >= 0 else None

    def find_adrp_add_refs(self, target_off):
        target_va = self.base + target_off
        target_page = target_va & ~0xFFF
        page_off = target_va & 0xFFF
        refs = []
        for adrp_off in self.adrp_index.get(target_page, []):
            for d in range(4, 20, 4):
                add_off = adrp_off + d
                if add_off + 4 > self.size:
                    break
                w = rd32(self.data, add_off)
                if (w & 0xFF800000) == 0x91000000:
                    imm12 = (w >> 10) & 0xFFF
                    adrp_rd = rd32(self.data, adrp_off) & 0x1F
                    add_rn = (w >> 5) & 0x1F
                    if adrp_rd == add_rn and imm12 == page_off:
                        refs.append((adrp_off, add_off))
                        break
        return refs

    def find_func_start(self, off):
        for i in range(off & ~3, max(0, off - 0x2000), -4):
            w = rd32(self.data, i)
            if w in (PACIBSP_U32, BTI_C_U32):
                return i
        return None

    # ─────────────────────────────────────────────
    # 1. image4_validate_property_callback bypass
    # ─────────────────────────────────────────────

    def find_image4_callback(self):
        self.log("\n[1] image4_validate_property_callback")

        CHUNK = 0x2000
        for start in range(0, min(self.size, self.code_end), CHUNK - 0x100):
            end = min(start + CHUNK, self.size)
            for off in range(start, end - 8, 4):
                w = rd32(self.data, off)
                # Look for B.NE followed by MOV X0, Xn
                if (w & 0xFF00001F) != 0x54000001:  # B.NE
                    continue
                nxt = rd32(self.data, off + 4)
                if (nxt & 0xFFE0FFE0) != 0xAA0003E0:  # MOV X0, Xreg
                    continue
                src_reg = (nxt >> 16) & 0x1F

                # Verify CMP within 8 insns before
                has_cmp = any(
                    (rd32(self.data, off - k*4) & 0xFFE0FC1F) == 0xEB00001F
                    or (rd32(self.data, off - k*4) & 0x7F20001F) == 0x6B00001F
                    for k in range(1, 9) if off - k*4 >= 0
                )
                if not has_cmp:
                    continue

                # Verify MOVN Wreg, #0 (sets -1) within 64 insns before
                w_reg = src_reg  # Wreg version
                has_movn = False
                for k in range(1, 65):
                    if off - k*4 < 0:
                        break
                    prev = rd32(self.data, off - k*4)
                    # MOVN Wn, #0
                    if (prev & 0xFFE0001F) == (0x12800000 | w_reg):
                        has_movn = True
                        break
                    # MOV Wn, #-1 (alias for MOVN Wn, #0)
                    if (prev & 0xFFFFFFFF) == (0x12800000 | w_reg):
                        has_movn = True
                        break

                if not has_movn:
                    continue

                self.results['image4_callback_bne'] = off
                self.results['image4_callback_mov'] = off + 4
                self.emit(off, p32(NOP_U32), "NOP b.ne (image4 canary check)")
                self.emit(off + 4, p32(MOV_X0_0_U32), "MOV X0, #0 (force image4 success)")
                return True

        self.log("  [-] Not found")
        return False

    # ─────────────────────────────────────────────
    # 2. CTRR lockdown NOP
    # ─────────────────────────────────────────────

    def find_ctrr_lockdown(self):
        self.log("\n[2] CTRR lockdown")
        count = 0
        for off in range(0, min(self.code_end, self.size - 4), 4):
            w = rd32(self.data, off)
            if (w & 0xFFF00000) != 0xD5100000:
                continue
            op0 = 2 + ((w >> 19) & 1)
            op1 = (w >> 16) & 0x7
            crn = (w >> 12) & 0xF
            crm = (w >> 8) & 0xF
            op2 = (w >> 5) & 0x7

            if op0 == 3 and op1 == 4 and crn == 15 and crm == 2 and op2 in (2, 5):
                name = "CTRR_LOCK_EL2" if op2 == 2 else "CTRR_CTL_EL2"
                self.results[f'ctrr_{off:X}'] = off
                self.emit(off, p32(NOP_U32), f"NOP MSR {name}")
                count += 1

        if count == 0:
            self.log("  [-] No CTRR MSR found")
        return count > 0

    # ─────────────────────────────────────────────
    # 3. Boot-args injection
    # ─────────────────────────────────────────────

    def find_boot_args(self):
        if self.mode == 'ibss':
            return False

        self.log("\n[3] Boot-args")

        new_args = b"serial=3 -v debug=0x2014e %s\x00"

        # Strategy 1: "%s" near "rd=md0" (iPhone pattern)
        rd_md0 = self.find_string("rd=md0")
        if rd_md0 is not None:
            fmt_s = None
            for off in range(max(0, rd_md0 - 0x100), min(rd_md0 + 0x100, self.size)):
                if self.data[off:off+3] == b'%s\x00':
                    fmt_s = off
                    break

            if fmt_s is not None:
                refs = self.find_adrp_add_refs(fmt_s)
                if refs:
                    return self._inject_boot_args(refs, new_args, "Strategy 1: %%s near rd=md0")

        # Strategy 2: find boot-args string directly
        ba_off = self.find_string(b"boot-args\x00")
        if ba_off is not None:
            refs = self.find_adrp_add_refs(ba_off)
            if refs:
                self.log(f"  boot-args string @ 0x{ba_off:X} with {len(refs)} xrefs (reference only)")

        # Strategy 3: find "rd=md0" xref → containing function → find the format string
        if rd_md0 is not None:
            refs = self.find_adrp_add_refs(rd_md0)
            if refs:
                func = self.find_func_start(refs[0][0])
                if func is not None:
                    self.log(f"  rd=md0 xref in func @ 0x{func:X}")
                    # Scan function for any "%s" ADRP+ADD ref
                    for off in range(func, min(func + 0x400, self.code_end), 4):
                        w = rd32(self.data, off)
                        if (w & 0x9F000000) != 0x90000000:
                            continue
                        imm = decode_adrp_imm(w)
                        page = ((self.base + off) & ~0xFFF) + (imm << 12)
                        if off + 4 >= self.size:
                            continue
                        nxt = rd32(self.data, off + 4)
                        if (nxt & 0xFF800000) != 0x91000000:
                            continue
                        add_imm = (nxt >> 10) & 0xFFF
                        target_foff = (page - self.base) + add_imm
                        if 0 <= target_foff < self.size - 3:
                            if self.data[target_foff:target_foff+3] == b'%s\x00':
                                return self._inject_boot_args([(off, off+4)], new_args, "Strategy 3: %%s in rd=md0 function")

        # Strategy 4: search ALL "%s\0" strings and find one with ADRP xref near boot-args code
        self.log("  Strategy 4: scanning all %%s strings...")
        pos = 0
        while True:
            idx = self.data.find(b'%s\x00', pos)
            if idx < 0 or idx >= self.size:
                break
            refs = self.find_adrp_add_refs(idx)
            if refs:
                # Check if any ref is near "boot-args" or "rd=md0" string references
                for adrp_off, add_off in refs:
                    # Check if within 0x200 bytes of a function that also references boot-args or rd=md0
                    for check_str in [b"boot-args", b"rd=md0", b"debug-uarts"]:
                        check_off = self.find_string(check_str)
                        if check_off is None:
                            continue
                        check_refs = self.find_adrp_add_refs(check_off)
                        for cr_adrp, _ in check_refs:
                            if abs(cr_adrp - adrp_off) < 0x400:
                                return self._inject_boot_args([(adrp_off, add_off)], new_args, f"Strategy 4: %%s near {check_str.decode()}")
            pos = idx + 1

        self.log("  [-] Boot-args pattern not found")
        return False

    def _inject_boot_args(self, refs, new_args, strategy):
        # Find NUL slot for new string
        slot = None
        for off in range(0x14000, self.size - 64):
            if self.data[off:off+64] == b'\x00' * 64 and off % 16 == 0:
                slot = off
                break
        if slot is None:
            self.log("  [-] No NUL slot found")
            return False

        self.log(f"  {strategy}")
        self.emit(slot, new_args, f"Write boot-args @ 0x{slot:X}")
        self.results['boot_args_string'] = slot

        slot_va = self.base + slot
        slot_page = slot_va & ~0xFFF
        slot_pageoff = slot_va & 0xFFF

        for adrp_off, add_off in refs:
            adrp_w = rd32(self.data, adrp_off)
            rd = adrp_w & 0x1F
            pc = self.base + adrp_off
            new_adrp = encode_adrp(rd, pc, slot_page)
            self.emit(adrp_off, p32(new_adrp), "ADRP redirect to boot-args")

            add_w = rd32(self.data, add_off)
            add_rd = add_w & 0x1F
            add_rn = (add_w >> 5) & 0x1F
            new_add = encode_add_imm(add_rd, add_rn, slot_pageoff)
            self.emit(add_off, p32(new_add), "ADD redirect to boot-args offset")

        return True

    # ─────────────────────────────────────────────
    # 4. Additional: find key functions (patchfinder mode)
    # ─────────────────────────────────────────────

    def find_key_functions(self):
        self.log("\n[4] Key function discovery")

        string_names = {
            "double panic in": "_panic",
            "debug-uarts": "_main_task",
            "CPID:": "_platform_get_usb_serial_number_string",
            "image4_register_property_capture_callbacks": "_image4_register_callbacks",
            "Unknown ASN1 type": "_image4_validate_property_callback",
            "fuse-revision": "_UpdateDeviceTree",
            "aborting autoboot": "_check_autoboot",
            "chosen/memory-map": "_record_memory_range",
            "Ramdisk image not valid": "_do_ramdisk",
            "Device Tree image not valid": "_do_devicetree",
            "boot-command": "_sys_setup_default_environment",
            "backlight-level": "_platform_init_display",
            "boot-args": "_boot_args_handler",
            "gid-aes-key": "_aes_gid_key",
            "dart": "_dart_init",
            "ctrr": "_ctrr_handler",
            "ticket.der": "_ticket_verify",
        }

        for needle, name in string_names.items():
            str_off = self.find_string(needle)
            if str_off is None:
                continue
            refs = self.find_adrp_add_refs(str_off)
            if refs:
                func = self.find_func_start(refs[0][0])
                if func is not None:
                    self.results[name] = func
                    self.log(f"  {name:<45s} 0x{self.base+func:X}")
                else:
                    self.log(f"  {name:<45s} xref@0x{self.base+refs[0][0]:X} (no func)")
            else:
                self.log(f"  {name:<45s} str@0x{str_off:X} (no xref)")

    # ─────────────────────────────────────────────
    # Run all
    # ─────────────────────────────────────────────

    def find_all(self):
        self.log(f"=== iBoot Patchfinder (mode={self.mode}, base=0x{self.base:X}) ===")
        self.log(f"Size: {self.size} bytes ({self.size/1024:.0f} KB)")

        ver = self.find_string(b"iBoot for")
        if ver:
            end = self.data.find(b'\x00', ver)
            self.log(f"Banner: {self.data[ver:end].decode('ascii', errors='replace')}")

        self.find_image4_callback()
        self.find_ctrr_lockdown()
        self.find_boot_args()
        self.find_key_functions()

        self.log(f"\n  {len(self.patches)} patches, {len(self.results)} functions found")
        return self.data


def main():
    ap = argparse.ArgumentParser(description="Universal iBoot patchfinder for A12/A13")
    ap.add_argument("input", type=Path)
    ap.add_argument("output", type=Path, nargs='?')
    ap.add_argument("--base", default="0x870000000")
    ap.add_argument("--mode", choices=["ibss", "ibec", "llb"], default="ibec")
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args()

    data = args.input.read_bytes()
    pf = IBootPatchfinder(data, base=int(args.base, 0), mode=args.mode, verbose=not args.quiet)
    patched = pf.find_all()

    if args.output:
        args.output.write_bytes(bytes(patched))
        print(f"\nSaved to {args.output}")


if __name__ == "__main__":
    main()
