#!/usr/bin/env bash
# Real cloud images used for verification (downloaded once into ./images).
set -u
cd "$(dirname "$0")/../images"
get() { [ -s "$2" ] && { echo "have $2"; return; }; curl -sSfL --retry 3 -o "$2.part" "$1" && mv "$2.part" "$2" && echo "ok   $2 $(stat -c %s "$2")" || echo "FAIL $1"; }
A=https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/cloud
get $A/generic_alpine-3.24.1-x86_64-uefi-tiny-r0.qcow2 alpine-3.24-uefi-tiny.qcow2
get $A/generic_alpine-3.24.1-x86_64-bios-cloudinit-r0.qcow2 alpine-3.24-bios-cloudinit.qcow2
get https://cloud-images.ubuntu.com/releases/noble/release-20260926/ubuntu-24.04-server-cloudimg-amd64.img ubuntu-24.04.qcow2
get https://geo.mirror.pkgbuild.com/images/latest/Arch-Linux-x86_64-cloudimg.qcow2 arch-cloudimg.qcow2
get https://dl.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud-Base.latest.x86_64.qcow2 rocky-9.qcow2
get https://download.opensuse.org/distribution/leap/16.0/appliances/Leap-16.0-Minimal-VM.x86_64-Cloud.qcow2 opensuse-leap-16.qcow2
FCOS=$(curl -sSfL https://builds.coreos.fedoraproject.org/streams/stable.json | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["architectures"]["x86_64"]["artifacts"]["qemu"]["formats"]["qcow2.xz"]["disk"]["location"])')
if [ -n "$FCOS" ] && [ ! -s fcos.qcow2 ]; then get "$FCOS" fcos.qcow2.xz && xz -d fcos.qcow2.xz && echo "ok   fcos.qcow2"; fi
