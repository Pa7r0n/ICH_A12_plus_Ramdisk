# ICH_A12+ Ramdisk `v1.1`

SSH ramdisk for **A12 / A13** after pwned DFU with [usbliter8](https://github.com/prdgmshift/usbliter8).

Made by **[@Official_I_C_H](https://t.me/Official_I_C_H)** · [t.me/Official_I_C_H](https://t.me/Official_I_C_H)

Not a jailbreak. Research use on devices you own.

If this helps you, please ⭐ **star the repo** — thanks.
## ☕ Buy Me a Coffee

If this project helped you, please consider supporting its development.

### USDT (TRC20)

**Wallet Address**
`TV3W882uz6n219dDgAntedV9o518Sqk255`

**Network:** TRON (TRC20)

Every contribution helps maintain and improve this project. Thank you! ❤️

## Enter pwned DFU

1. DFU mode + **RP2350** + [usbliter8](https://github.com/prdgmshift/usbliter8)  
2. Cable to Mac  
3. Confirm:

```bash
./tools/darwin/irecovery -q
# MODE: DFU   PWND: usbliter8
```

## Setup

```bash
./setup.sh
# or: brew install python@3 curl blacktop/tap/ipsw && pip3 install -r requirements.txt
```

## Quick start

```bash
./status.sh
./build.sh --with-fw
./boot.sh
./ssh.sh
# password: alpine
```

`./ssh.sh` mounts System/Preboot/xART and prints the device iOS version from Preboot when available.

Useful flags:

```bash
./build.sh --list
./build.sh --version 18.7.9 --with-fw
./build.sh --kernel stock
./boot.sh --no-logo
./boot.sh --no-fw
```

## Boot

```
usbliter8 (RP2350) → PWND DFU
  → patched iBEC
  → ICH logo (centered for this device) + verbose boot-args
  → [SPTM/TXM if in IPSW] → firmwares → DT → trustcache → ramdisk → kernel/bootx
  → SSH  root@localhost:2222  alpine
```

Logo and verbose are handled in `./boot.sh` (panel size from board, `setenvnp` before `bootx`).

## Patches

| Layer | When |
|-------|------|
| iBoot | always (`rd=md0`, IMG4 path) |
| SPTM / TXM | only if BuildManifest has them |
| Kernel | patched by default (AMFI; more on iOS 27) — `--kernel stock` fallback |
| Ramdisk / trustcache | stock RestoreRamDisk + SSH inject |

## Mounts

```sh
mount_filesystems                 # /mnt1 System, /mnt6 Preboot, /mnt7 xART
mount_filesystems --live-data     # /mnt2 Data
```

| iOS | System / Preboot / xART | `/mnt2` Data |
|-----|-------------------------|--------------|
| ≤ 15 | OK | OK in practice |
| 16 | expected OK | not verified |
| 17+ | OK (safe helper, no `seputil --load`) | **still not working** |

Everything practical was tried for **`/mnt2` on iOS 17+**; Data stays SEP-gated and is **not solved** here. Contributions welcome if you find a reliable path.

## Devices

| CPID | Chip | Examples |
|------|------|----------|
| 0x8020 | A12 | XR, XS, iPad Air 3… |
| 0x8030 | A13 | iPhone 11, SE 2… |
| 0x8027 | A12X | iPad Pro 2018 (`--im4m`) |

## Credits

See [NOTICE](NOTICE).

- [usbliter8](https://github.com/prdgmshift/usbliter8) — Paradigm Shift  
- [usbliter8ra1n](https://github.com/Leeksov/usbliter8ra1n) — Leeksov  
- Patchfinders: [iboot](https://github.com/Leeksov/usbliter8-iboot-patchfinder) · [kernel](https://github.com/Leeksov/usbliter8-kernel-patchfinder) · [sptm](https://github.com/Leeksov/usbliter8-sptm-patchfinder) · [txm](https://github.com/Leeksov/usbliter8-txm-patchfinder)  
- [palera1n](https://github.com/palera1n) / SSHRD ecosystem  

## License

MIT. Upstream licenses apply. **For research on devices you own.**
