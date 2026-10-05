#!/usr/bin/env python3
"""Export every fixture image with the inspector and compare it with the source
tree it was built from: entry types, symlink targets, file contents. Also checks
the facts the fixture was built to show."""
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys

TOOL = "./target/release/cloud-image-inspector"
OUT = sys.argv[1] if len(sys.argv) > 1 else "fixtures/out/fs"
SRC = os.path.join(OUT, "src")


def tree(base):
    out = {}
    for dp, dn, fn in os.walk(base):
        for n in dn + fn:
            full = os.path.join(dp, n)
            rel = os.path.relpath(full, base)
            if rel == "lost+found" or rel.startswith("lost+found/"):
                continue
            st = os.lstat(full)
            if stat.S_ISLNK(st.st_mode):
                out[rel] = ("link", os.readlink(full))
            elif stat.S_ISDIR(st.st_mode):
                out[rel] = ("dir", None)
            else:
                out[rel] = ("file", hashlib.sha256(open(full, "rb").read()).hexdigest())
    return out


want = tree(SRC)
images = sorted(f for f in os.listdir(OUT) if f.endswith((".qcow2", ".img")))
failed = 0
for img in images:
    path = os.path.join(OUT, img)
    dest = os.path.join(OUT, "export-" + img)
    shutil.rmtree(dest, ignore_errors=True)
    r = subprocess.run([TOOL, "export", path, "/", dest], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if r.returncode != 0:
        print(f"FAIL {img}: export exited {r.returncode}: {r.stderr.decode().strip()[-300:]}")
        failed += 1
        continue
    got = tree(dest)
    if "subvol" in img:
        got.pop("home", None)
    # mkfs.xfs 6.13 writes a 1000-byte symlink into one 1 KiB v5 block (968 bytes of
    # room): the kernel's readlink says EFSCORRUPTED, and the tool must refuse it too.
    known_corrupt = {"links/long-1000"} if img.startswith("xfs-1k") else set()
    for k in known_corrupt:
        if k in got:
            print(f"     {img}: {k} was exported, but the kernel refuses it")
        want_k = want.pop(k, None)
    diffs = [k for k in sorted(set(want) | set(got)) if want.get(k) != got.get(k)]
    for k in known_corrupt:
        want[k] = want_k
    shutil.rmtree(dest)
    j = json.loads(subprocess.run([TOOL, "--json", path], stdout=subprocess.PIPE, check=True).stdout)
    f = j["facts"]
    checks = {
        "os id": f["os_release"]["id"] == "fixture",
        "pretty name unquoted": f["os_release"]["pretty_name"] == 'Fixture Linux 1.0 ("quoted")',
        "bash": f["shells"]["bash"] == "/bin/bash",
        "/bin/sh chain": f["shells"]["bin_sh"] == ["/bin/sh", "/usr/bin/dash"],
        "useradd": f["shells"]["useradd_default_shell"] == "/bin/bash",
        "sudo": f["privilege"]["sudo"] == "/usr/bin/sudo" and f["privilege"]["sudoers_d"],
        "init": f["init"]["system"] == "systemd" and f["init"]["sbin_init"] == ["/sbin/init", "/usr/lib/systemd/systemd"],
        "UsePAM from drop-in": f["sshd"]["use_pam"] == "yes" and f["sshd"]["includes_sshd_config_d"],
        "cloud-init version": f["first_boot"]["cloud_init_version"] == "99.1-1",
        "dpkg skips removed": f["packages"]["count"] == 2,
        "boot": j["boot"]["uefi"] or "notable" in img,
    }
    bad = [k for k, ok in checks.items() if not ok]
    root = j["root"]
    where = f"{root['filesystem']}" + (f" {root['subvolume']}" if root.get("subvolume") else "")
    files = sum(1 for v in want.values() if v[0] == "file")
    if diffs or bad:
        failed += 1
        print(f"FAIL {img} ({where}): {len(diffs)} tree differences, facts wrong: {bad}")
        for k in diffs[:8]:
            print(f"     {k}: source {want.get(k)} vs export {got.get(k)}")
    else:
        print(f"ok   {img:<32} {where:<28} {len(want)} entries ({files} files) identical, {len(checks)} facts ok")
# The container layer alone: the whole guest disk read through the tool must equal
# qemu-img's conversion of the same image.
raw_ok = 0
for img in images:
    path = os.path.join(OUT, img)
    a, b = "/tmp/cii-raw-tool", "/tmp/cii-raw-qemu"
    r = subprocess.run([TOOL, "raw", path, a], stderr=subprocess.PIPE, env={**os.environ, "CII_STATS": "1"})
    subprocess.run(["qemu-img", "convert", "-O", "raw", path, b], check=True)
    ha = hashlib.sha256(open(a, "rb").read()).hexdigest()
    hb = hashlib.sha256(open(b, "rb").read()).hexdigest()
    paths = {kv.split("=")[0]: int(kv.split("=")[1]) for kv in r.stderr.decode().split()[1:] if "=" in kv and kv.startswith("qcow2")}
    used = ",".join(k[6:] for k, v in paths.items() if v)
    if r.returncode == 0 and ha == hb:
        raw_ok += 1
        print(f"raw  {img:<32} identical to qemu-img ({os.path.getsize(b) >> 20} MiB; {used or 'raw file'})")
    else:
        failed += 1
        print(f"RAW FAIL {img}: tool {ha[:16]} vs qemu-img {hb[:16]} {r.stderr.decode()[-200:]}")
    os.remove(a)
    os.remove(b)
print(f"{len(images) - failed}/{len(images)} fixture images verified ({raw_ok} whole-disk raw comparisons identical)")
sys.exit(1 if failed else 0)
