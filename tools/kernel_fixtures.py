#!/usr/bin/env python3
"""Fixtures written by a real kernel: libguestfs mounts copies of fixture images
read-write and creates the structures only a running filesystem driver produces
(holes, unwritten/prealloc extents, htree/node directories with deletions, long
symlinks, fragmented files, btrfs extents compressed at mount time). Then the
kernel's tar-out of each image is compared with the inspector's export.

Run inside tools/Containerfile.guestfs with the project at /work."""
import hashlib
import os
import shutil
import stat
import subprocess
import sys
import tarfile

TOOL = os.environ.get("CII_TOOL", "/work/target/release/cloud-image-inspector")
OUT = "/work/fixtures/out/kernel"
SRC = "/work/fixtures/out/fs"


def guestfish(image, script):
    r = subprocess.run(["guestfish", "-a", image], input="run\n" + script, text=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if r.returncode:
        raise SystemExit(f"guestfish failed on {image}: {r.stderr[-500:]}")
    return r.stdout


def common(mnt):
    s = f"mount {mnt} /\nmkdir-p /kernel/many\n"
    # Sparse: data islands with holes between them.
    s += "touch /kernel/sparse\ntruncate-size /kernel/sparse 33554432\n"
    for off in (0, 1 << 20, 9 << 20, (32 << 20) - 100):
        s += f"pwrite /kernel/sparse 'island-at-{off}' {off}\n"
    # Preallocated / unwritten extents.
    s += "fallocate64 /kernel/falloc 8388608\npwrite /kernel/falloc 'head' 0\n"
    # A large directory with deletions (ext4 htree, XFS leaf/node).
    s += "".join(f"touch /kernel/many/entry-{i:05d}-{'y' * (i % 30)}\n" for i in range(3000))
    s += "".join(f"rm /kernel/many/entry-{i:05d}-{'y' * (i % 30)}\n" for i in range(0, 3000, 7))
    s += "ln-s /" + "c" * 999 + " /kernel/long-link\n"
    # Fragmented: two files growing in alternation.
    for i in range(200):
        s += f"write-append /kernel/frag-a '{'A' * 3000}{i}'\nwrite-append /kernel/frag-b '{'B' * 5000}{i}'\n"
    return s


def build():
    os.makedirs(OUT, exist_ok=True)
    jobs = {
        "k-ext4.qcow2": ("ext4-default.qcow2", "/dev/sda2", ""),
        "k-xfs.qcow2": ("xfs-default.qcow2", "/dev/sda2", ""),
        "k-btrfs.qcow2": ("btrfs-holes.qcow2", "/dev/sda2", "btrfs"),
    }
    for out, (src, dev, kind) in jobs.items():
        img = os.path.join(OUT, out)
        shutil.copy(os.path.join(SRC, src), img)
        s = common(dev)
        if kind == "btrfs":
            # Files written under each compression mount option.
            for algo in ("zstd", "lzo", "zlib"):
                s += f"umount /\nmount-options compress-force={algo} {dev} /\n"
                s += "".join(f"write-append /kernel/compressed-{algo} '{'compressible text line ' * 40}{i}\\n'\n" for i in range(400))
        s += "umount /\n"
        guestfish(img, s)
        print(f"built {out}")


def tree(base):
    out = {}
    for dp, dn, fn in os.walk(base):
        for n in dn + fn:
            full = os.path.join(dp, n)
            rel = os.path.relpath(full, base)
            if rel.split("/")[0] == "lost+found":
                continue
            st = os.lstat(full)
            if stat.S_ISLNK(st.st_mode):
                out[rel] = ("link", os.readlink(full))
            elif stat.S_ISDIR(st.st_mode):
                out[rel] = ("dir", None)
            else:
                out[rel] = ("file", hashlib.sha256(open(full, "rb").read()).hexdigest())
    return out


def verify():
    bad = 0
    for img in sorted(f for f in os.listdir(OUT) if f.endswith(".qcow2")):
        p = os.path.join(OUT, img)
        w = f"/tmp/k-{img}"
        shutil.rmtree(w, ignore_errors=True)
        os.makedirs(w)
        subprocess.run(["guestfish", "--ro", "-a", p], input=f"run\nmount-ro /dev/sda2 /\ntar-out / {w}/k.tar\n",
                       text=True, check=True, stdout=subprocess.PIPE)
        with tarfile.open(f"{w}/k.tar") as t:
            t.extractall(f"{w}/kernel", members=[m for m in t.getmembers() if m.isreg() or m.isdir() or m.issym()], filter="fully_trusted")
        r = subprocess.run([TOOL, "export", "--partition", "2", p, "/", f"{w}/ours"], stderr=subprocess.PIPE,
                           env={**os.environ, "CII_STATS": "1"})
        stats = [kv for kv in r.stderr.decode().split() if "=" in kv and not kv.endswith("=0")]
        a, b = tree(f"{w}/kernel"), tree(f"{w}/ours")
        diffs = [k for k in sorted(set(a) | set(b)) if a.get(k) != b.get(k)]
        if diffs:
            bad += 1
            print(f"FAIL {img}: {len(diffs)} differences")
            for k in diffs[:8]:
                print(f"     {k}: kernel {a.get(k)} vs tool {b.get(k)}")
        else:
            print(f"ok   {img}: {len(a)} entries identical to the kernel's view")
        print("     paths: " + " ".join(s for s in stats if any(x in s for x in ("hole", "prealloc", "uninit", "unwritten", "htree", "leaf_node", "btree", "zstd", "lzo", "zlib", "remote", "block_symlink", "index_node"))))
        shutil.rmtree(w)
    return bad


if __name__ == "__main__":
    if "--verify-only" not in sys.argv:
        build()
    sys.exit(1 if verify() else 0)
