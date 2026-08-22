#!/usr/bin/env sh
set -eu

if [ "$#" -ne 2 ] && [ "$#" -ne 3 ]; then
    echo "usage: $0 <validator-root> <regular-exfat-image> [payload-manifest.tsv]" >&2
    exit 2
fi

validator_root=$1
image=$2
manifest=${3-}

if [ ! -f "$image" ]; then
    echo "refusing non-regular image: $image" >&2
    exit 2
fi
if [ ! -x "$validator_root/sbin/mount.exfat-fuse" ]; then
    echo "mount.exfat-fuse is unavailable below: $validator_root" >&2
    exit 2
fi
if [ -n "$manifest" ] && [ ! -f "$manifest" ]; then
    echo "refusing non-regular payload manifest: $manifest" >&2
    exit 2
fi

mount_dir=$(mktemp -d /tmp/starconverter-exfat-mount.XXXXXX)
loop_device=
cleanup() {
    if mountpoint -q "$mount_dir"; then
        fusermount3 -u "$mount_dir" || umount "$mount_dir"
    fi
    if [ -n "$loop_device" ]; then
        losetup --detach "$loop_device"
    fi
    rmdir "$mount_dir"
}
trap cleanup EXIT INT TERM

export LD_LIBRARY_PATH="$validator_root/lib/x86_64-linux-gnu:$validator_root/usr/lib/x86_64-linux-gnu"
loop_device=$(losetup --read-only --find --show "$image")
test -b "$loop_device"
test "$(losetup --noheadings --output RO "$loop_device" | tr -d ' ')" = 1
loop_backing=$(losetup --noheadings --output BACK-FILE "$loop_device" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
test "$(readlink -f "$loop_backing")" = "$(readlink -f "$image")"
"$validator_root/sbin/mount.exfat-fuse" -o ro "$loop_device" "$mount_dir"
mountpoint -q "$mount_dir"

find "$mount_dir" -maxdepth 6 -printf '%y %P %s\n' | LC_ALL=C sort
if [ -n "$manifest" ]; then
    tab=$(printf '\t')
    checked=0
    while IFS="$tab" read -r relative expected_size expected_hash; do
        [ -n "$relative" ] || continue
        case "$relative" in
            /*) ;;
            *) echo "manifest path is not absolute within the mounted filesystem: $relative" >&2; exit 2 ;;
        esac
        case "/${relative#/}/" in
            *'/../'*|*'/./'*) echo "manifest path contains traversal: $relative" >&2; exit 2 ;;
        esac
        test "${#expected_hash}" -eq 64
        mounted_file="$mount_dir$relative"
        test -f "$mounted_file"
        test "$(stat -c %s "$mounted_file")" = "$expected_size"
        actual_hash=$(sha256sum "$mounted_file" | cut -d ' ' -f 1)
        test "$actual_hash" = "$expected_hash"
        checked=$((checked + 1))
    done < "$manifest"
    test "$checked" -gt 0
    printf '[PASS] read-only exFAT mount verified %s manifest payloads\n' "$checked"
else
    ls -lan "$mount_dir" "$mount_dir/alpha" "$mount_dir/alpha/Ωmega"
    test "$(cat "$mount_dir/readme.txt")" = '()*+,-./012345'
    test "$(stat -c %s "$mount_dir/alpha/Ωmega/fragmented.bin")" = 6000
    readme_hash=$(sha256sum "$mount_dir/readme.txt" | cut -d ' ' -f 1)
    fragmented_hash=$(sha256sum "$mount_dir/alpha/Ωmega/fragmented.bin" | cut -d ' ' -f 1)
    test "$readme_hash" = deee70659646c5b4f25155e113967db5aaee6f9616232a85dee3afb1159d6ffb
    test "$fragmented_hash" = 6f5b3bef759ffd6505beb8112b023a869b1b771946f88baec7f016ccfb1035d6
    printf '[PASS] read-only exFAT mount payload hashes %s %s\n' "$readme_hash" "$fragmented_hash"
fi
