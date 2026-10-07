#!/usr/bin/env sh
# Run the formatter-origin ADS and inline security descriptor probe with the independent
# NTFS-3G and exfatprogs tools taken from an unpacked validator root rather than from the
# system (see extract-validator-bundle.sh). Every other argument is forwarded unchanged to
# validate-formatter-ads.py; the report path must not already exist.
set -eu

if [ "$#" -lt 4 ]; then
    echo "usage: $0 <validator-root> <workspace> --cli <starconverter> --report <new-report.json>" >&2
    exit 2
fi

validator_root=$1
shift

for tool in sbin/mkntfs sbin/ntfscp bin/ntfscat bin/ntfsinfo bin/ntfsfix usr/sbin/fsck.exfat; do
    if [ ! -x "$validator_root/$tool" ]; then
        echo "validator tool unavailable below $validator_root: $tool" >&2
        exit 2
    fi
done

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

export LD_LIBRARY_PATH="$validator_root/lib/x86_64-linux-gnu:$validator_root/usr/lib/x86_64-linux-gnu"
export PATH="$validator_root/bin:$validator_root/sbin:$validator_root/usr/bin:$validator_root/usr/sbin:$PATH"

exec python3 "$script_dir/validate-formatter-ads.py" "$@"
