#!/usr/bin/env sh
# Unpack Debian packages for the independent validators (NTFS-3G, exfatprogs) into an
# unprivileged validator root without installing them. Package extraction needs neither root
# nor network; download the .deb files beforehand, for example from packages.ubuntu.com.
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <deb-directory> <validator-root>" >&2
    exit 2
fi

deb_directory=$1
validator_root=$2

if [ ! -d "$deb_directory" ]; then
    echo "refusing missing package directory: $deb_directory" >&2
    exit 2
fi
case "$validator_root" in
    /tmp/*|"$HOME"/*) ;;
    *)
        echo "refusing validator root outside /tmp or \$HOME: $validator_root" >&2
        exit 2
        ;;
esac

found=0
for package in "$deb_directory"/*.deb; do
    [ -f "$package" ] || continue
    found=1
    mkdir -p "$validator_root"
    dpkg -x "$package" "$validator_root"
    echo "extracted $(basename "$package")"
done
if [ "$found" -eq 0 ]; then
    echo "no .deb packages below: $deb_directory" >&2
    exit 2
fi

# NTFS-3G packages install below bin/ and sbin/, exfatprogs below usr/sbin/.
export LD_LIBRARY_PATH="$validator_root/lib/x86_64-linux-gnu:$validator_root/usr/lib/x86_64-linux-gnu"
for tool in sbin/mkntfs sbin/ntfscp bin/ntfscat bin/ntfsinfo bin/ntfsfix bin/ntfsls usr/sbin/fsck.exfat; do
    if [ ! -x "$validator_root/$tool" ]; then
        echo "validator tool missing after extraction: $validator_root/$tool" >&2
        exit 1
    fi
    if ldd "$validator_root/$tool" | grep -q 'not found'; then
        echo "unresolved shared libraries for $tool:" >&2
        ldd "$validator_root/$tool" | grep 'not found' >&2
        exit 1
    fi
done

# fsck.exfat prints its version only while checking an image, so only NTFS-3G is echoed here.
"$validator_root/bin/ntfscat" -V 2>&1 | grep -m 1 'v20'
echo "validator root ready: $validator_root"
