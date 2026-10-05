#!/usr/bin/env python3
"""Build synthetic disk images from one known source tree, with the real mkfs tools.

Every variant holds the same tree, so tools/verify_fixtures.py can compare the
inspector's `export` of each image against the source, byte for byte. Run inside
tools/Containerfile (mkfs.ext4, mkfs.xfs, mkfs.btrfs, sfdisk, qemu-img).
"""
import json
import os
import random
import shutil
import subprocess
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else "fixtures/out/fs"
SRC = os.path.join(OUT, "src")
rng = random.Random(7)


def sh(*cmd, **kw):
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, **kw)


def write(rel, data):
    p = os.path.join(SRC, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "wb") as f:
        f.write(data)


def link(rel, target):
    p = os.path.join(SRC, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    os.symlink(target, p)


def build_source():
    shutil.rmtree(SRC, ignore_errors=True)
    os.makedirs(SRC)
    write("etc/os-release", b'NAME="Fixture Linux"\nID=fixture\nID_LIKE="debian"\nVERSION_ID="1.0"\nPRETTY_NAME="Fixture Linux 1.0 (\\"quoted\\")"\n')
    write("etc/shells", b"# /etc/shells\n/bin/sh\n/bin/bash\n")
    write("etc/default/useradd", b"GROUP=100\nSHELL=/bin/bash\n")
    write("etc/ssh/sshd_config", b"Include /etc/ssh/sshd_config.d/*.conf\n#UsePAM no\nUsePAM no\n")
    write("etc/ssh/sshd_config.d/10-pam.conf", b"UsePAM yes\n")
    os.makedirs(os.path.join(SRC, "etc/sudoers.d"))
    write("usr/bin/bash", b"\x7fELF fake bash\n")
    write("usr/bin/dash", b"\x7fELF fake dash\n")
    write("usr/bin/sudo", b"\x7fELF fake sudo\n")
    write("usr/bin/cloud-init", b"#!/usr/bin/python3\n")
    write("usr/sbin/sshd", b"\x7fELF fake sshd\n")
    write("usr/lib/systemd/systemd", b"\x7fELF fake systemd\n")
    write("usr/lib/python3/dist-packages/cloudinit/version.py", b'__VERSION__ = "99.1"\n')
    link("bin", "usr/bin")
    link("sbin", "usr/sbin")
    link("lib", "usr/lib")
    link("usr/bin/sh", "dash")
    link("usr/sbin/init", "../lib/systemd/systemd")
    write("var/lib/dpkg/status",
          b"Package: bash\nStatus: install ok installed\nVersion: 5.2-1\n\n"
          b"Package: gone\nStatus: deinstall ok config-files\nVersion: 1.0\n\n"
          b"Package: cloud-init\nStatus: install ok installed\nVersion: 99.1-1\n")
    # Edge cases for every reader.
    write("data/empty", b"")
    for n in (1, 7, 59, 60, 61, 100, 160, 3000):
        write(f"data/small-{n}", bytes(rng.randrange(256) for _ in range(n)))
    write("data/text.txt", ("the quick brown fox jumps over the lazy dog\n" * 4000).encode())
    write("data/random.bin", rng.randbytes(3 << 20))
    write("data/zeros.bin", bytes(2 << 20))
    with open(os.path.join(SRC, "data/sparse.bin"), "wb") as f:
        for off in (0, 1 << 20, 5 << 20, (16 << 20) - 10):
            f.seek(off)
            f.write(b"island at %d\n" % off)
    # Fragmented: many small appends interleaved with another growing file.
    a = open(os.path.join(SRC, "data/frag-a.bin"), "wb")
    b = open(os.path.join(SRC, "data/frag-b.bin"), "wb")
    for i in range(600):
        a.write(rng.randbytes(4096 + i))
        b.write(rng.randbytes(4096))
    a.close()
    b.close()
    for i in range(5000):
        write(f"bigdir/file-{i:05d}-{'x' * (i % 40)}", b"%d\n" % i)
    deep = "/".join(f"d{i}" for i in range(30))
    write(f"deep/{deep}/leaf", b"bottom\n")
    link("links/relative", "../data/text.txt")
    link("links/absolute", "/data/text.txt")
    link("links/chain1", "chain2")
    link("links/chain2", "relative")
    link("links/to-dir", "../bigdir")
    link("links/dangling", "/no/such/target")
    link("links/long-200", "/" + "a" * 199)
    link("links/long-1000", "/" + "b" * 999)
    write("names/unicode-ünïcødé-файл-📄", b"utf8 name\n")
    write("names/" + "n" * 255, b"max name length\n")


def size_of(path):
    total = 0
    for dp, dn, fn in os.walk(path):
        for f in fn:
            p = os.path.join(dp, f)
            if not os.path.islink(p):
                total += os.path.getsize(p)
    return total


def protofile(src, out):
    """mkfs.xfs prototype file describing `src` (xfsprogs 'proto' format)."""
    lines = ["fixture", "0 0", "d--755 0 0"]

    def walk(d, depth):
        for name in sorted(os.listdir(d)):
            p = os.path.join(d, name)
            ind = " " * (depth + 1)
            if os.path.islink(p):
                lines.append(f"{ind}{name} l--777 0 0 {os.readlink(p)}")
            elif os.path.isdir(p):
                lines.append(f"{ind}{name} d--755 0 0")
                walk(p, depth + 1)
                lines.append(f"{ind}$")
            else:
                lines.append(f"{ind}{name} ---644 0 0 {os.path.abspath(p)}")
    walk(src, 0)
    lines.append("$")
    with open(out, "w") as f:
        f.write("\n".join(lines) + "\n")


def mkfs(kind, opts, img):
    need = size_of(SRC)
    if os.path.exists(img):
        os.remove(img)
    if kind == "ext4":
        mb = need // (1 << 20) * 3 + 64
        if "65536" in opts:
            mb += 6000 * 64 // 1024 + 64
        sh("mkfs.ext4", "-q", "-F", "-d", SRC, *opts, img, f"{mb}M")
    elif kind == "xfs":
        proto = img + ".proto"
        protofile(SRC, proto)
        with open(img, "wb") as f:
            f.truncate(max(need * 3, 300 << 20))
        sh("mkfs.xfs", "-q", "-f", "-p", proto, *opts, img)
        os.remove(proto)
    elif kind == "btrfs":
        with open(img, "wb") as f:
            f.truncate(max(need * 3, 300 << 20))
        sh("mkfs.btrfs", "-q", "-f", "--rootdir", opts[0], *opts[1:], img)


def gpt_disk(fs_img, out, table="gpt"):
    """ESP + root partition. Layouts: gpt, gpt-4k (4096-byte sectors), dos, and
    dos-logical (root as logical partition 5 inside an extended partition). The
    filesystems are written at the offsets sfdisk reports."""
    esp = out + ".esp"
    with open(esp, "wb") as f:
        f.truncate(32 << 20)
    sh("mkfs.vfat", "-n", "EFI", esp)
    fs_size = os.path.getsize(fs_img)
    total = (4 << 20) + (32 << 20) + fs_size + (4 << 20)
    with open(out, "wb") as f:
        f.truncate(total)
    sector = 4096 if table == "gpt-4k" else 512
    esp_s, fs_s = (32 << 20) // sector, -(-fs_size // sector)
    if table in ("gpt", "gpt-4k"):
        first = 256 if sector == 4096 else 2048
        script = f"label: gpt\nstart={first}, size={esp_s}, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B\nsize={fs_s}, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4\n"
    elif table == "dos":
        script = f"label: dos\nstart=2048, size={esp_s}, type=ef\nsize={fs_s}, type=83\n"
    else:
        ext_start = 2048 + esp_s
        name = os.path.basename(out)
        script = (f"label: dos\nstart=2048, size={esp_s}, type=ef\n"
                  f"start={ext_start}, size={fs_s + 4096}, type=5\n"
                  f"{name}5 : start={ext_start + 2048}, size={fs_s}, type=83\n")
    # Run from the image's directory with its bare name: the logical partition line
    # names the device ("<name>5 : ...") exactly as sfdisk will.
    args = ["sfdisk", "-q"] + (["--sector-size", "4096"] if sector == 4096 else []) + [os.path.basename(out)]
    subprocess.run(args, input=script.encode(), check=True, stdout=subprocess.DEVNULL, cwd=os.path.dirname(os.path.abspath(out)))
    dump = json.loads(subprocess.run(["sfdisk", "-J"] + (["--sector-size", "4096"] if sector == 4096 else []) + [out],
                                     check=True, stdout=subprocess.PIPE).stdout)
    parts = dump["partitiontable"]["partitions"]
    esp_off = parts[0]["start"] * sector
    root = [p for p in parts if p["type"].lower() in ("83", "0fc63daf-8483-4772-8e79-3d69d8477de4")][0]
    for src, off in ((esp, esp_off), (fs_img, root["start"] * sector)):
        sh("dd", f"if={src}", f"of={out}", "bs=1M", f"seek={off}", "oflag=seek_bytes", "conv=notrunc,sparse", "status=none")
    os.remove(esp)


def qcow2(raw, out, *opts):
    sh("qemu-img", "convert", "-O", "qcow2", *opts, raw, out)


def main():
    os.makedirs(OUT, exist_ok=True)
    build_source()
    work = os.path.join(OUT, "work")
    os.makedirs(work, exist_ok=True)
    # btrfs with a default subvolume: the tree lives in subvolume "root".
    sv_src = os.path.join(work, "svsrc")
    shutil.rmtree(sv_src, ignore_errors=True)
    shutil.copytree(SRC, os.path.join(sv_src, "root"), symlinks=True)
    os.makedirs(os.path.join(sv_src, "home/user"))

    variants = {
        "ext4-default": ("ext4", []),
        "ext4-inline": ("ext4", ["-O", "inline_data"]),
        "ext2-blockmap": ("ext4", ["-t", "ext2"]),
        "ext3-1k": ("ext4", ["-t", "ext3", "-b", "1024"]),
        "ext4-nometa64": ("ext4", ["-O", "^64bit,meta_bg,^resize_inode"]),
        "ext4-64k": ("ext4", ["-b", "65536"]),
        "xfs-default": ("xfs", []),
        "xfs-v4": ("xfs", ["-m", "crc=0"]),
        "xfs-v4-noftype": ("xfs", ["-m", "crc=0", "-n", "ftype=0"]),
        "xfs-1k-dir8k": ("xfs", ["-b", "size=1024", "-n", "size=8192"]),
        "xfs-inode2k": ("xfs", ["-i", "size=2048"]),
        "btrfs-plain": ("btrfs", [SRC]),
        "btrfs-zstd": ("btrfs", [SRC, "--compress", "zstd"]),
        "btrfs-lzo": ("btrfs", [SRC, "--compress", "lzo"]),
        "btrfs-zlib": ("btrfs", [SRC, "--compress", "zlib"]),
        "btrfs-node4k-zstd15": ("btrfs", [SRC, "--nodesize", "4096", "--compress", "zstd:15"]),
        "btrfs-subvol": ("btrfs", [sv_src, "--subvol", "default:root", "--subvol", "rw:home"]),
        # Without no-holes, sparse files get explicit hole extents (disk_bytenr 0).
        "btrfs-holes": ("btrfs", [SRC, "-O", "^no-holes"]),
    }
    made = []
    for name, (kind, opts) in variants.items():
        fs_img = os.path.join(work, name + ".fs")
        try:
            mkfs(kind, opts, fs_img)
        except subprocess.CalledProcessError as e:
            print(f"skip {name}: {e.stderr.decode().strip()[:200]}")
            continue
        disk = os.path.join(work, name + ".disk")
        gpt_disk(fs_img, disk)
        qcow2(disk, os.path.join(OUT, f"{name}.qcow2"))
        made.append(name)
        if name == "ext4-default":
            # Container variants, all over the same disk.
            qcow2(disk, os.path.join(OUT, "c-deflate.qcow2"), "-c")
            qcow2(disk, os.path.join(OUT, "c-zstd.qcow2"), "-c", "-o", "compression_type=zstd")
            qcow2(disk, os.path.join(OUT, "c-v2-compat010.qcow2"), "-c", "-o", "compat=0.10")
            qcow2(disk, os.path.join(OUT, "c-cluster4k.qcow2"), "-o", "cluster_size=4096")
            qcow2(disk, os.path.join(OUT, "c-cluster2m.qcow2"), "-c", "-o", "cluster_size=2M")
            qcow2(disk, os.path.join(OUT, "c-extl2.qcow2"), "-o", "extended_l2=on,cluster_size=128k")
            # Metadata preallocation: every cluster allocated, zero runs flagged as zero.
            qcow2(disk, os.path.join(OUT, "c-prealloc-meta.qcow2"), "-o", "preallocation=metadata")
            # Zero-flag clusters (allocated and unallocated), written inside the ESP so
            # the root tree is untouched; the raw comparison reads them.
            z = os.path.join(OUT, "c-zeroflag.qcow2")
            qcow2(disk, z)
            sh("qemu-io", "-f", "qcow2", "-c", "write -z 4M 4M", "-c", "write -z -u 12M 2M", "-c", "write -P 0x5a 20M 64k", z)
            shutil.copy(disk, os.path.join(OUT, "c-raw-gpt.img"))
            for layout in ("dos", "dos-logical", "gpt-4k"):
                d2 = os.path.join(work, layout + ".disk")
                gpt_disk(fs_img, d2, table=layout)
                qcow2(d2, os.path.join(OUT, f"c-{layout}.qcow2"))
                os.remove(d2)
        if name in ("xfs-default", "btrfs-zstd"):
            qcow2(fs_img, os.path.join(OUT, f"c-notable-{name}.qcow2"))
        os.remove(disk)
        os.remove(fs_img)
    shutil.rmtree(work)
    print(f"built {len(made)} filesystem variants: {' '.join(made)}")


main()
