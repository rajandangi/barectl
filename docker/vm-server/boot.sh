#!/bin/sh
# Runs as the container's command with the cloud-init seed in /seed. QEMU restarts the
# guest's machine when its kernel reboots, as firmware would.
set -eu
cd /vm
[ -f disk.qcow2 ] || qemu-img create -q -f qcow2 -F qcow2 -b cloud.img disk.qcow2 12G
genisoimage -quiet -output seed.iso -volid cidata -joliet -rock /seed/user-data /seed/meta-data
network="user,id=net0,hostfwd=tcp::22-:22"
case $(dpkg --print-architecture) in
arm64)
    exec qemu-system-aarch64 -machine virt -cpu max,pauth-impdef=on \
        -accel tcg,thread=multi,tb-size=1024 -smp "${VM_CPUS:-4}" -m "${VM_MEMORY:-3072}" \
        -bios /usr/share/qemu-efi-aarch64/QEMU_EFI.fd \
        -drive if=virtio,format=qcow2,file=disk.qcow2 \
        -drive if=virtio,format=raw,file=seed.iso \
        -netdev "$network" -device virtio-net-pci,netdev=net0 \
        -nographic -serial mon:stdio
    ;;
amd64)
    accel=tcg,thread=multi,tb-size=1024
    [ -e /dev/kvm ] && accel=kvm
    exec qemu-system-x86_64 -machine q35 -cpu max -accel "$accel" \
        -smp "${VM_CPUS:-4}" -m "${VM_MEMORY:-3072}" \
        -drive if=virtio,format=qcow2,file=disk.qcow2 \
        -drive if=virtio,format=raw,file=seed.iso \
        -netdev "$network" -device virtio-net-pci,netdev=net0 \
        -nographic -serial mon:stdio
    ;;
esac
echo "Unsupported architecture." >&2
exit 1
