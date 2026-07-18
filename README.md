# ICH_A12+ Ramdisk `v1.1`

**SSH ramdisk for A12 / A13** — build and boot a restore-style ramdisk for supported iOS versions after entering pwned DFU with [usbliter8](https://github.com/prdgmshift/usbliter8).

Made by **[@Official_I_C_H](https://t.me/Official_I_C_H)** · Telegram: [t.me/Official_I_C_H](https://t.me/Official_I_C_H)

Not a jailbreak. No PongoOS / jbinit. Research tooling for devices you own.

Guides followed: [usbliter8ra1n README](https://github.com/Leeksov/usbliter8ra1n/blob/main/README.md) · [RAMDISK_PLAN](https://github.com/Leeksov/usbliter8ra1n/blob/main/RAMDISK_PLAN.md)

## What’s new in v1.1

- **Default patched kernel** (Leeksov AMFI / debugger; iOS 27 adds launch constraints) — `--kernel stock` still available as fallback  
- **Safer ramdisk expand** (grow in place, then srcfolder copy fallback) — less breakage across IPSWs / macOS  
- **`./setup.sh`** installs host dependencies on a new Mac  
- SPTM / TXM still **Manifest-gated** (typical iOS 27-class on A12/A13)

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

## Setup (new Mac)

```bash
cd ICH_A12_plus_Ramdisk   # or new_ramdisk/
./setup.sh                # Homebrew + python deps + verify vendored tools
```

`setup.sh` installs / checks: Homebrew, `python3`, `ipsw`, `pyimg4`, `capstone`, and verifies `tools/darwin/*` + `resources/*`.

Manual fallback if you prefer:

```bash
brew install python@3 curl
brew install blacktop/tap/ipsw
pip3 install -r requirements.txt
```

## What it does

1. Detects the connected pwned DFU device  
2. Lets you pick an **iOS version / build**  
3. Pulls firmware from the IPSW (`pzb` + BuildManifest)  
4. Patches **iBoot** (and **SPTM / TXM** when present)  
5. Patches **kernel** (AMFI baseline; see matrix)  
6. Expands RestoreRamDisk, injects SSH, builds trustcache  
7. Boots: iBEC → DT → trustcache → ramdisk → kernel → **SSH** (`alpine`)

```
[DFU]
    │  usbliter8 via RP2350  →  https://github.com/prdgmshift/usbliter8
[PWND DFU]  ← cable to Mac
    │  ./boot.sh
[patched iBEC]  boot-args: serial=3 -v rd=md0 wdt=-1
    │  [SPTM/TXM if present] → DT → trustcache → ramdisk → [AOP…] → patched kernel/bootx
[SSH]  ./ssh.sh   →  root@localhost:2222  password: alpine
```

## Patch matrix (A12/A13)

| Layer | Tool | When |
|-------|------|------|
| iBoot | `iboot_patchfinder` + `rd=md0` (+ n841 safe wrapper) | always |
| SPTM | `sptm_patchfinder` | Manifest has SPTM |
| TXM | `txm_patchfinder` | Manifest has TXM (iOS 27) |
| Kernel | `kernel_patchfinder` via `apply_kernel_patches.py` | default **patched** |
| Ramdisk | expand + `ssh.tar.gz` | always |
| Trustcache | RestoreTrustCache + append SSH CDHashes | always |

Kernel `--kpf-set auto` mapping ([usbliter8ra1n](https://github.com/Leeksov/usbliter8ra1n)):

| iOS | Default patches |
|-----|-----------------|
| 17.x | debugger + AMFI |
| 18.x | debugger + AMFI |
| 26.x | debugger + AMFI |
| 27.x / TXM in IPSW | debugger + AMFI + launch constraints |

## Mounting NAND volumes

```sh
mount_filesystems                 # System /mnt1, Preboot /mnt6, xART /mnt7
mount_filesystems --live-data     # Data /mnt2 (see notes)
```

| iOS | System / Preboot / xART | Data (`/mnt2`) |
|-----|-------------------------|----------------|
| **≤ 15** | Works | **Works** in practice |
| **16** | Expected OK | **Not tested yet — please try and report** |
| **17+** | Works with safe helper | **Not unlocked** with known DFU-ramdisk methods yet |

On iOS 17+, stock `seputil --load` can SEP-panic; this project ships a safe `mount_filesystems`.

## Supported chips

| CPID   | Chip | Example devices        | IM4M shipped            |
|--------|------|------------------------|-------------------------|
| 0x8020 | A12  | XR, XS, iPad Air 3…    | `resources/IM4M_0x8020` |
| 0x8030 | A13  | iPhone 11, SE 2…       | `resources/IM4M_0x8030` |
| 0x8027 | A12X | iPad Pro 2018          | provide `--im4m` |

## Quick start

```bash
./setup.sh

# 1) Pwn DFU with RP2350 / usbliter8, then:
./status.sh

# 2) Build (patched kernel by default)
./build.sh --with-fw

# 3) Boot + SSH
./boot.sh
./ssh.sh
# password: alpine
```

Useful flags:

```bash
./build.sh --list
./build.sh --version 18.7.9 --with-fw
./build.sh --kernel stock              # fallback if patched kernel won't boot
./build.sh --kpf-set ios27             # force iOS 27 patch set
./build.sh --use-ibss
./boot.sh --no-fw
```

## Layout

```
  setup.sh / build.sh / boot.sh / ssh.sh / status.sh
  patch/          # Leeksov patchfinders + finalize_iboot / preflight
  resources/      # ssh.tar.gz, IM4M_*, mount_filesystems.safe
  tools/darwin/   # host binaries + libusb
  bootchain/      # build output (gitignored)
  cache/          # IPSW cache (gitignored)
  work/           # scratch — removed after successful build
```

## Author

- Telegram: **[@Official_I_C_H](https://t.me/Official_I_C_H)**
- Version: **v1.1**

## Credits

See [NOTICE](NOTICE).

- [usbliter8](https://github.com/prdgmshift/usbliter8) — Paradigm Shift  
- [usbliter8ra1n](https://github.com/Leeksov/usbliter8ra1n) — Leeksov  
- Patchfinders: [iboot](https://github.com/Leeksov/usbliter8-iboot-patchfinder) · [kernel](https://github.com/Leeksov/usbliter8-kernel-patchfinder) · [sptm](https://github.com/Leeksov/usbliter8-sptm-patchfinder) · [txm](https://github.com/Leeksov/usbliter8-txm-patchfinder)  
- [palera1n](https://github.com/palera1n) / SSHRD ecosystem  

## License

MIT. Upstream components retain their own licenses. **For research on devices you own.**
