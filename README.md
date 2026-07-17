# new_ramdisk `v1.Zero`

**SSH ramdisk for A12 / A13** — build and boot a restore-style ramdisk for supported iOS versions after entering pwned DFU with [usbliter8](https://github.com/prdgmshift/usbliter8).

Made by **[@Official_I_C_H](https://t.me/Official_I_C_H)** · Telegram: [t.me/Official_I_C_H](https://t.me/Official_I_C_H)

Not a jailbreak. No PongoOS / jbinit. Research tooling for devices you own.

## Enter pwned DFU (required)

You need an **RP2350** board and the [usbliter8](https://github.com/prdgmshift/usbliter8) exploit:

1. Put the iPhone/iPad into normal **DFU** mode.
2. Run the usbliter8 exploit from the RP2350 (see that repo’s instructions).
3. Swap the cable to the Mac when the device shows pwned DFU.
4. Confirm:

```bash
./tools/darwin/irecovery -q
# expect: MODE: DFU  and  PWND: usbliter8
```

Until `PWND: usbliter8` appears, `./build.sh` / `./boot.sh` will refuse to run.

## What it does

1. Detects the connected pwned DFU device  
2. Lets you pick an **iOS version / build** (or pass `--version` / `--build`)  
3. Pulls firmware from the IPSW (`pzb` + BuildManifest)  
4. Patches **iBoot** (and **SPTM / TXM** when the Manifest has them)  
5. Builds an SSH ramdisk from the stock RestoreRamDisk + `ssh.tar.gz`  
6. Boots: iBEC → DeviceTree → trustcache → ramdisk → kernel → **SSH** (`alpine`)

```
[DFU]
    │  usbliter8 via RP2350  →  https://github.com/prdgmshift/usbliter8
[PWND DFU]  ← cable to Mac
    │  ./boot.sh
[patched iBEC]  boot-args: serial=3 -v rd=md0 wdt=-1
    │  [SPTM/TXM if present] → DT → trustcache → ramdisk → [AOP…] → bootx
[SSH]  ./ssh.sh   →  root@localhost:2222  password: alpine
```

## Mounting NAND volumes

After SSH:

```sh
mount_filesystems                 # System /mnt1, Preboot /mnt6, xART /mnt7
mount_filesystems --live-data     # Data /mnt2 (see notes below)
```

| iOS | System / Preboot / xART | Data (`/mnt2`) |
|-----|-------------------------|----------------|
| **≤ 15** | Works | **Works** in practice (user-tested) |
| **16** | Expected OK | **Not tested yet — please try and report** |
| **17+** | Works with safe helper | **Does not unlock** with known DFU-ramdisk methods so far |

### iOS 17+ Data (`/mnt2`)

No reliable Data unlock was found for DFU-boot ramdisks on iOS 17+:

- SEP is not bypassed; user Data stays SEP-gated.
- Stock `mount_filesystems` calling `seputil --load` can **SEP-panic** and kill SSH.
- This project ships a **safe** `mount_filesystems` that skips `seputil --load` and mounts System/Preboot/xART only.
- `--live-data` attempts a plain `mount_apfs` of Data; it typically hangs/fails without usable SEP keys.

If you find a working iOS 17+ Data mount path, open an issue/PR — it is not solved here yet.

## Patch matrix (A12/A13)

Applied only when components exist in BuildManifest ([usbliter8ra1n](https://github.com/Leeksov/usbliter8ra1n) table):

| iOS        | iBoot | SPTM | TXM | Kernel (default) |
|------------|-------|------|-----|------------------|
| 17.x       | yes   | —    | —   | stock            |
| 18.x       | yes   | —    | —   | stock            |
| 26.x       | yes   | —*   | —*  | stock            |
| 27.x beta  | yes   | yes  | yes | stock            |

\* A15+ can ship SPTM/TXM on 26.x; **A12/A13 typically do not**. The builder reads the Manifest.

## Supported chips

| CPID   | Chip | Example devices        | IM4M shipped            |
|--------|------|------------------------|-------------------------|
| 0x8020 | A12  | XR, XS, iPad Air 3…    | `resources/IM4M_0x8020` |
| 0x8030 | A13  | iPhone 11, SE 2…       | `resources/IM4M_0x8030` |
| 0x8027 | A12X | iPad Pro 2018          | provide `--im4m` (offsets TBD upstream) |

Proven end-to-end here: iPhone XR (`n841ap` / 0x8020) on **iOS 18.7.9 / 22H355** with `--with-fw` and stock kernel (SSH + System mounts). Other boards use the same flow; n841 gets an extra safe iBoot wrapper.

## Requirements (macOS)

- [usbliter8](https://github.com/prdgmshift/usbliter8) + **RP2350** for pwned DFU  
- `python3`, `ipsw` ([blacktop/ipsw](https://github.com/blacktop/ipsw)), `hdiutil` / `diskutil`  
- `pip3 install -r requirements.txt` (`pyimg4`)  
- Vendored tools under `tools/darwin/` (includes `libusb-1.0.0.dylib`)

## Quick start

```bash
cd new_ramdisk
pip3 install -r requirements.txt

# 1) Pwn DFU with RP2350 / usbliter8, then:
./status.sh

# 2) Build (interactive firmware picker, or pass --version / --build)
./build.sh --with-fw

# 3) Boot + SSH
./boot.sh
./ssh.sh
# password: alpine
```

Useful flags:

```bash
./build.sh --list                 # list firmwares for connected product
./build.sh --dry-run --version 18.7.9
./build.sh --use-ibss             # stage iBSS→iBEC (default: direct iBEC)
./build.sh --kernel patched       # experimental KPF (often breaks boot)
./build.sh --im4m /path/to/IM4M   # custom APTicket
./boot.sh --no-fw                 # skip AOP/ANE/… even if staged
```

## Layout

```
new_ramdisk/
  build.sh / boot.sh / ssh.sh / status.sh
  patch/          # patchfinders + finalize_iboot / preflight
  resources/      # ssh.tar.gz, IM4M_*, mount_filesystems.safe
  tools/darwin/   # host binaries + libusb
  bootchain/      # build output (gitignored)
  cache/          # IPSW download cache (gitignored)
  work/           # scratch — deleted automatically after a successful build
```

## Author

- Telegram: **[@Official_I_C_H](https://t.me/Official_I_C_H)**
- Version: **v1.Zero** (printed on build / boot / ssh / status banners)

## Credits

See [NOTICE](NOTICE).

- [usbliter8](https://github.com/prdgmshift/usbliter8) — Paradigm Shift (BootROM exploit / RP2350)
- [usbliter8ra1n](https://github.com/Leeksov/usbliter8ra1n) — Leeksov
- Patchfinders: [iboot](https://github.com/Leeksov/usbliter8-iboot-patchfinder) · [kernel](https://github.com/Leeksov/usbliter8-kernel-patchfinder) · [sptm](https://github.com/Leeksov/usbliter8-sptm-patchfinder) · [txm](https://github.com/Leeksov/usbliter8-txm-patchfinder)
- [palera1n](https://github.com/palera1n) / SSHRD ecosystem — ramdisk + trustcache tooling

## License

MIT. Upstream components retain their own licenses. **For research on devices you own.**
