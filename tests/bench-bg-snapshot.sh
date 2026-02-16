#!/bin/bash
# Benchmark for QEMU background snapshot (UFFD-WP).
#
# Launches a QEMU VM, enables x-background-snapshot, migrates to
# /dev/null, and reports timing via QMP query-migrate.
#
# Usage: ./tests/bench-bg-snapshot.sh [ram_mb] [--dirty]
#   ram_mb:  VM RAM in MB (default: 1024)
#   --dirty: Boot a write-heavy guest that continuously dirties ~99MB of
#            pages (1MB-100MB range). This exercises the UFFD-WP fault
#            path where vCPUs get blocked on write-protected pages.

set -euo pipefail

RAM_MB="1024"
DIRTY_MODE=0
SETTLE_SECS=3

for arg in "$@"; do
    case "$arg" in
        --dirty) DIRTY_MODE=1 ;;
        [0-9]*) RAM_MB="$arg" ;;
    esac
done

QEMU="./build/qemu-system-x86_64"
QMP_SOCK="/tmp/qmp-snap-bench-$$.sock"
SERIAL_FILE="/tmp/snap-bench-serial-$$"
BOOTDISK="/tmp/snap-bench-boot-$$.raw"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ ! -x "$QEMU" ]; then
    echo "Error: $QEMU not found. Build QEMU first." >&2
    exit 1
fi

cleanup() {
    if [ -n "${QEMU_PID:-}" ]; then
        kill "$QEMU_PID" 2>/dev/null || true
        wait "$QEMU_PID" 2>/dev/null || true
    fi
    rm -f "$QMP_SOCK" "$SERIAL_FILE" "$BOOTDISK"
}
trap cleanup EXIT

echo "=== QEMU Background Snapshot Benchmark ==="
echo "RAM size: ${RAM_MB} MB"
if [ "$DIRTY_MODE" -eq 1 ]; then
    echo "Mode:     WRITE-HEAVY (guest continuously dirties 99MB)"
else
    echo "Mode:     IDLE (no guest activity)"
fi
echo "QEMU binary: $QEMU"
echo ""

EXTRA_ARGS=""
QMP_EXTRA=""

if [ "$DIRTY_MODE" -eq 1 ]; then
    # Extract the boot sector from the C header into a raw 512-byte file
    python3 -c "
import re, sys
with open('tests/qtest/migration/i386/a-b-bootblock.h') as f:
    text = f.read()
# Extract hex bytes from the array
hexvals = re.findall(r'0x([0-9a-fA-F]{2})', text)
data = bytes(int(h, 16) for h in hexvals)
with open('$BOOTDISK', 'wb') as f:
    f.write(data)
print(f'Extracted {len(data)} byte boot sector')
"
    EXTRA_ARGS="-drive if=none,id=d0,file=${BOOTDISK},format=raw -device ide-hd,drive=d0 -serial file:${SERIAL_FILE}"
    QMP_EXTRA="--serial-file ${SERIAL_FILE} --settle ${SETTLE_SECS}"

    # Ensure RAM >= 128MB for the write-heavy guest (writes to 1MB-100MB)
    if [ "$RAM_MB" -lt 128 ]; then
        echo "Warning: write-heavy guest needs >= 128MB RAM, adjusting to 128MB"
        RAM_MB=128
    fi
fi

# Start QEMU
"$QEMU" \
    -machine q35,accel=tcg \
    -m "$RAM_MB" \
    -nographic \
    -nodefaults \
    -qmp "unix:${QMP_SOCK},server=on,wait=off" \
    $EXTRA_ARGS \
    -S &
QEMU_PID=$!

# Wait for QMP socket
for i in $(seq 1 30); do
    if [ -S "$QMP_SOCK" ]; then
        break
    fi
    sleep 0.1
done

if [ ! -S "$QMP_SOCK" ]; then
    echo "Error: QMP socket did not appear" >&2
    exit 1
fi

# Run the benchmark
python3 "${SCRIPT_DIR}/bench-bg-snapshot-qmp.py" "$QMP_SOCK" $QMP_EXTRA
