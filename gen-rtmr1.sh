#!/bin/bash

# Try to reconstruct RTMR[1].

set -e

# Find the latest kernel and initrd in /boot
KERNEL=$(ls -1 /boot/vmlinuz-* 2>/dev/null | sort -V | tail -n 1)
INITRD=$(ls -1 /boot/initrd.img-* 2>/dev/null | grep "$(basename "$KERNEL" | cut -d'-' -f2-)" | sort -V | tail -n 1)
CMDLINE=/proc/cmdline

if [ ! -f "$KERNEL" ] || [ ! -f "$INITRD" ]; then
    echo "Kernel or initrd not found."
    exit 1
fi

echo "Using:"
echo "  Kernel: $KERNEL"
echo "  Initrd: $INITRD"
echo "  Cmdline: $CMDLINE"

sudo python3 - <<PYEOF
import hashlib

def sha384(data):
    return hashlib.sha384(data).digest()

def extend(rtmr, measurement):
    return hashlib.sha384(rtmr + measurement).digest()

with open("$KERNEL", "rb") as f:
    kernel = f.read()
with open("$INITRD", "rb") as f:
    initrd = f.read()
with open("$CMDLINE", "rb") as f:
    cmdline = f.read().rstrip(b'\n')

rtmr = bytes(48)
rtmr = extend(rtmr, sha384(kernel))
rtmr = extend(rtmr, sha384(initrd))
rtmr = extend(rtmr, sha384(cmdline))

print("RTMR[1] =", rtmr.hex())
PYEOF

