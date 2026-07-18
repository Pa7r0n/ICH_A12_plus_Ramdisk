#!/usr/bin/env bash
# Expand stock RestoreRamDisk and inject SSH payload.
# Method A: grow in place (truncate + apfs resizeContainer)
# Method B: mount stock, create new APFS raw image via srcfolder copy

nr_expand_inject_ramdisk() {
    local stock_dmg="$1"
    local ssh_tar="$2"
    local mounts_safe="${3:-}"
    local mount_pt="${4:-/tmp/NewRamdiskRD}"
    local gtar_bin="${5:-gtar}"

    [[ -s "$stock_dmg" ]] || {
        echo "ramdisk expand: missing $stock_dmg" >&2
        return 1
    }
    [[ -s "$ssh_tar" ]] || {
        echo "ramdisk expand: missing $ssh_tar" >&2
        return 1
    }

    local stock_bytes headroom max_bytes target_bytes size_m
    stock_bytes="$(stat -f%z "$stock_dmg")"
    headroom=$((80 * 1024 * 1024))
    max_bytes=$((280 * 1024 * 1024))
    target_bytes=$((stock_bytes + headroom))
    if ((target_bytes < 256 * 1024 * 1024)); then
        target_bytes=$((256 * 1024 * 1024))
    fi
    if ((target_bytes > max_bytes)); then
        target_bytes=$max_bytes
    fi
    if ((target_bytes <= stock_bytes)); then
        target_bytes=$((stock_bytes + 32 * 1024 * 1024))
        if ((target_bytes > max_bytes)); then
            echo "ramdisk expand: stock ${stock_bytes} already near max ${max_bytes}" >&2
            # still try inject if mountable without grow
            target_bytes=$stock_bytes
        fi
    fi
    size_m=$(( (target_bytes + 1024 * 1024 - 1) / (1024 * 1024) ))
    echo "ramdisk expand: stock=${stock_bytes} bytes → target≈${size_m}m"

    _nr_force_detach_mp() {
        hdiutil detach -force "$1" >/dev/null 2>&1 || true
    }

    _nr_inject_at() {
        local mp="$1"
        "$gtar_bin" -x --no-overwrite-dir -f "$ssh_tar" -C "$mp/"
        if [[ -n "$mounts_safe" && -f "$mounts_safe" ]]; then
            if [[ -f "$mp/usr/bin/mount_filesystems" ]]; then
                cp "$mp/usr/bin/mount_filesystems" \
                    "$mp/usr/bin/mount_filesystems.stock.panic" 2>/dev/null || true
            fi
            cp "$mounts_safe" "$mp/usr/bin/mount_filesystems"
            chmod 755 "$mp/usr/bin/mount_filesystems"
            echo "installed safe mount_filesystems (no seputil --load)"
        fi
    }

    _nr_find_apfs() {
        awk '
            /EF57347C-0000-11AA-AA11-0030654/ { print $1; exit }
            /Apple_APFS/ { print $1; exit }
        '
    }

    # ── Method A ──
    if ((target_bytes > stock_bytes)); then
        cp "$stock_dmg" "${stock_dmg}.bak"
        truncate -s "$target_bytes" "$stock_dmg"
    fi

    local attach_out apfs_disk
    if attach_out="$(hdiutil attach -nomount -owners off \
        -imagekey diskimage-class=CRawDiskImage "$stock_dmg" 2>/dev/null)"; then
        apfs_disk="$(_nr_find_apfs <<<"$attach_out")"
        if [[ -n "$apfs_disk" ]] && diskutil apfs resizeContainer "$apfs_disk" 0; then
            hdiutil detach -force "$apfs_disk" >/dev/null 2>&1 || true
            rm -f "${stock_dmg}.bak"
            echo "ramdisk expand: method A (resizeContainer) OK"
            _nr_force_detach_mp "$mount_pt"
            mkdir -p "$mount_pt"
            hdiutil attach -mountpoint "$mount_pt" -owners off \
                -imagekey diskimage-class=CRawDiskImage "$stock_dmg"
            _nr_inject_at "$mount_pt"
            _nr_force_detach_mp "$mount_pt"
            return 0
        fi
        # cleanup failed A
        local d
        d="$(awk '/^\/dev\//{print $1; exit}' <<<"$attach_out")"
        [[ -n "$d" ]] && hdiutil detach -force "$d" >/dev/null 2>&1 || true
        echo "ramdisk expand: method A failed — trying method B"
    else
        echo "ramdisk expand: method A attach failed — trying method B"
    fi

    # restore backup before B if we truncated
    if [[ -f "${stock_dmg}.bak" ]]; then
        mv -f "${stock_dmg}.bak" "$stock_dmg"
    fi

    # ── Method B: srcfolder copy into new raw APFS ──
    local stock_mp="/tmp/NewRamdiskStock$$"
    local out_base="/tmp/NewRamdiskOut$$"
    _nr_force_detach_mp "$stock_mp"
    rm -rf "$stock_mp"
    mkdir -p "$stock_mp"

    if ! hdiutil attach -mountpoint "$stock_mp" -owners off \
        -imagekey diskimage-class=CRawDiskImage "$stock_dmg" 2>/dev/null \
        && ! hdiutil attach -mountpoint "$stock_mp" -owners off "$stock_dmg" 2>/dev/null; then
        echo "ramdisk expand: cannot mount stock ramdisk" >&2
        rmdir "$stock_mp" 2>/dev/null || true
        return 1
    fi

    rm -f "${out_base}.dmg" "$out_base"
    if ! hdiutil create \
        -size "${size_m}m" \
        -imagekey diskimage-class=CRawDiskImage \
        -format UDRW \
        -fs APFS \
        -layout NONE \
        -srcfolder "$stock_mp" \
        -copyuid root \
        "$out_base"; then
        _nr_force_detach_mp "$stock_mp"
        rm -rf "$stock_mp"
        echo "ramdisk expand: method B hdiutil create failed" >&2
        return 1
    fi
    _nr_force_detach_mp "$stock_mp"
    rm -rf "$stock_mp"

    local created=""
    for cand in "${out_base}.dmg" "$out_base" "${out_base}.sparseimage"; do
        if [[ -f "$cand" ]]; then
            created="$cand"
            break
        fi
    done
    [[ -n "$created" ]] || {
        echo "ramdisk expand: method B produced no image" >&2
        return 1
    }

    # Normalize to a single raw-ish UDRW dmg path the rest of the pipeline expects
    local converted="/tmp/NewRamdiskConv$$"
    rm -f "${converted}.dmg" "$converted"
    if hdiutil convert "$created" -format UDRW -o "$converted" >/dev/null; then
        rm -f "$created"
        if [[ -f "${converted}.dmg" ]]; then
            mv -f "${converted}.dmg" "$stock_dmg"
        else
            mv -f "$converted" "$stock_dmg"
        fi
    else
        mv -f "$created" "$stock_dmg"
    fi

    echo "ramdisk expand: method B (srcfolder) OK (${size_m}m)"
    _nr_force_detach_mp "$mount_pt"
    mkdir -p "$mount_pt"
    if ! hdiutil attach -mountpoint "$mount_pt" -owners off \
        -imagekey diskimage-class=CRawDiskImage "$stock_dmg" 2>/dev/null \
        && ! hdiutil attach -mountpoint "$mount_pt" -owners off "$stock_dmg" 2>/dev/null; then
        echo "ramdisk expand: cannot mount expanded ramdisk for inject" >&2
        return 1
    fi
    _nr_inject_at "$mount_pt"
    _nr_force_detach_mp "$mount_pt"
    return 0
}
