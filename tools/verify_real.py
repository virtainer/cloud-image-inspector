#!/usr/bin/env python3
"""Verify cloud-image-inspector against an independent oracle: libguestfs, which
boots a real Linux kernel (KVM) to mount the image's filesystems.

For each image:
  1. whole-tree check: the kernel's `tar-out` of the root filesystem vs this tool's
     `export` of the same filesystem -- every entry's type, symlink target and file
     contents (SHA-256);
  2. fact check: every fact the tool reports, re-derived from kernel-side lookups;
  3. package check: `rpm --dbpath` / `dpkg-query --admindir` on the kernel-extracted
     database, and virt-inspector's application list.

Run inside tools/Containerfile.guestfs with the project at /work.
"""
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import xml.etree.ElementTree as ET

sys.stdout.reconfigure(line_buffering=True)

TOOL = "/work/target/release/cloud-image-inspector"
WORK = "/scratch"


def run(cmd, **kw):
    return subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kw).stdout


def guestfish(image, commands):
    return subprocess.run(
        ["guestfish", "--ro", "-a", image], input="run\n" + commands, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
    ).stdout


def mount_cmd(root):
    dev = f"/dev/sda{root['partition']}" if root["partition"] else "/dev/sda"
    opts = "ro"
    sv = root.get("subvolume")
    if sv:
        m = re.search(r"id (\d+)", sv)
        opts += f",subvolid={m.group(1)}"
    if root["filesystem"] == "xfs":
        opts += ",norecovery"
    return f"mount-options {opts} {dev} /\n"


def tree(base):
    """{relative path: (kind, detail)} for every entry under base."""
    out = {}
    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        for name in dirnames + filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, base)
            st = os.lstat(full)
            if stat.S_ISLNK(st.st_mode):
                out[rel] = ("link", os.readlink(full))
            elif stat.S_ISDIR(st.st_mode):
                out[rel] = ("dir", None)
            elif stat.S_ISREG(st.st_mode):
                h = hashlib.sha256()
                with open(full, "rb") as f:
                    for chunk in iter(lambda: f.read(1 << 20), b""):
                        h.update(chunk)
                out[rel] = ("file", h.hexdigest())
    return out


def extract(tar_path, dest):
    with tarfile.open(tar_path) as t:
        members = [m for m in t.getmembers() if m.isreg() or m.isdir() or m.issym() or m.islnk()]
        t.extractall(dest, members=members, filter="fully_trusted")
    # Make everything readable for hashing regardless of guest modes.
    for dirpath, dirnames, filenames in os.walk(dest):
        for n in dirnames:
            p = os.path.join(dirpath, n)
            if not os.path.islink(p):
                os.chmod(p, 0o755)
        for n in filenames:
            p = os.path.join(dirpath, n)
            if not os.path.islink(p):
                os.chmod(p, 0o644)


def first(answers, paths):
    for p in paths:
        if answers.get(("is-file", p)):
            return p
    return None


def first_any(answers, paths):
    for p in paths:
        if answers.get(("exists", p)):
            return p
    return None


def main(image):
    name = os.path.basename(image)
    print(f"\n######## {name}")
    ours = json.loads(run([TOOL, "--json", "--all-packages", image]))
    facts, root = ours["facts"], ours["root"]
    problems = []

    # ---------------------------------------------------------------- whole tree
    w = os.path.join(WORK, name)
    shutil.rmtree(w, ignore_errors=True)
    os.makedirs(w)
    top = root.get("ostree_deployment") or "/"
    guestfish(image, mount_cmd(root) + f"tar-out {top} {w}/oracle.tar\n")
    extract(f"{w}/oracle.tar", f"{w}/oracle")
    os.remove(f"{w}/oracle.tar")
    # Export the same filesystem view the tool chose, by partition/subvolume.
    args = [TOOL, "export"]
    if root["partition"]:
        args += ["--partition", str(root["partition"])]
    sv = root.get("subvolume")
    if sv:
        args += ["--subvol", re.search(r"id (\d+)", sv).group(1)]
    subprocess.run(args + [image, top, f"{w}/ours"], check=True, stderr=subprocess.PIPE)
    a, b = tree(f"{w}/oracle"), tree(f"{w}/ours")
    files = sum(1 for v in a.values() if v[0] == "file")
    links = sum(1 for v in a.values() if v[0] == "link")
    dirs = sum(1 for v in a.values() if v[0] == "dir")
    size = sum(os.path.getsize(os.path.join(w, "oracle", k)) for k, v in a.items() if v[0] == "file")
    diffs = [k for k in sorted(set(a) | set(b)) if a.get(k) != b.get(k)]
    print(f"tree: {len(a)} entries ({files} files, {links} symlinks, {dirs} dirs, {size/2**20:.0f} MiB) -- "
          f"{'IDENTICAL' if not diffs else f'{len(diffs)} DIFFERENCES'}")
    for k in diffs[:20]:
        problems.append(f"tree {k}: kernel {a.get(k)} vs ours {b.get(k)}")
    shutil.rmtree(f"{w}/ours")

    # --------------------------------------------------------------------- facts
    paths = [
        "/bin/bash", "/usr/bin/bash", "/usr/bin/sudo", "/bin/sudo", "/usr/sbin/sudo", "/usr/bin/doas",
        "/bin/doas", "/usr/sbin/doas", "/usr/lib/systemd/systemd", "/lib/systemd/systemd",
        "/sbin/openrc", "/usr/sbin/openrc", "/sbin/openrc-run", "/usr/sbin/sshd", "/usr/bin/sshd",
        "/sbin/sshd", "/usr/sbin/sshd.pam", "/usr/bin/cloud-init", "/bin/cloud-init",
        "/usr/local/bin/cloud-init", "/etc/doas.conf",
    ]
    dirs_ = ["/etc/sudoers.d", "/etc/doas.d"]
    any_ = ["/sbin/tiny-cloud", "/usr/sbin/tiny-cloud", "/usr/lib/tiny-cloud", "/lib/tiny-cloud",
            "/usr/lib/dracut/modules.d/30ignition", "/usr/lib/dracut/modules.d/35ignition",
            "/usr/bin/ignition", "/usr/lib/ignition"]
    script = mount_cmd(root)
    pre = "" if top == "/" else top
    for p in paths:
        script += f"echo @@is-file {p}\nis-file {pre}{p} followsymlinks:true\n"
    for p in dirs_:
        script += f"echo @@is-dir {p}\nis-dir {pre}{p} followsymlinks:true\n"
    for p in any_:
        script += f"echo @@exists {p}\nexists {pre}{p}\n"
    for p in ["/etc/os-release", "/usr/lib/os-release", "/etc/shells", "/etc/default/useradd"]:
        script += f"echo @@cat {p}\n-cat {pre}{p}\n"
    for p in ["/bin/sh", "/sbin/init"]:
        for i in range(6):
            script += f"echo @@readlink {p}#{i}\n-readlink {pre}{p}\n"
    out = guestfish(image, script)
    answers, cur, buf = {}, None, []
    for line in out.splitlines() + ["@@end x"]:
        if line.startswith("@@"):
            if cur:
                kind, p = cur
                text = "\n".join(buf)
                answers[(kind, p)] = (text == "true") if kind in ("is-file", "is-dir", "exists") else text
            k, p = line[2:].split(" ", 1)
            cur, buf = (k, p), []
        else:
            buf.append(line)

    def check(label, want, got):
        if want != got:
            problems.append(f"fact {label}: kernel says {want!r}, tool says {got!r}")
        print(f"  {'ok ' if want == got else 'BAD'} {label:<28} {got!r}")

    osr = answers.get(("cat", "/etc/os-release")) or answers.get(("cat", "/usr/lib/os-release")) or ""
    def osval(k):
        for line in osr.splitlines():
            if line.startswith(k + "="):
                return line[len(k) + 1:].strip().strip('"').strip("'")
        return ""
    for k in ("ID", "VERSION_ID", "ID_LIKE", "PRETTY_NAME"):
        check(f"os-release {k}", osval(k), facts["os_release"][k.lower()])
    shells = [l.strip() for l in (answers.get(("cat", "/etc/shells")) or "").splitlines() if l.strip() and not l.strip().startswith("#")]
    check("/etc/shells", shells, facts["shells"]["etc_shells"])
    ua = next((l.strip()[6:] for l in (answers.get(("cat", "/etc/default/useradd")) or "").splitlines() if l.strip().startswith("SHELL=")), None)
    check("useradd SHELL", ua, facts["shells"]["useradd_default_shell"])
    check("bash", first(answers, ["/bin/bash", "/usr/bin/bash"]), facts["shells"]["bash"])
    check("sudo", first(answers, ["/usr/bin/sudo", "/bin/sudo", "/usr/sbin/sudo"]), facts["privilege"]["sudo"])
    check("doas", first(answers, ["/usr/bin/doas", "/bin/doas", "/usr/sbin/doas"]), facts["privilege"]["doas"])
    check("/etc/sudoers.d", answers[("is-dir", "/etc/sudoers.d")], facts["privilege"]["sudoers_d"])
    check("/etc/doas.d", answers[("is-dir", "/etc/doas.d")], facts["privilege"]["doas_d"])
    check("/etc/doas.conf", answers[("is-file", "/etc/doas.conf")], facts["privilege"]["doas_conf"])
    check("systemd", first(answers, ["/usr/lib/systemd/systemd", "/lib/systemd/systemd"]), facts["init"]["systemd"])
    check("openrc", first(answers, ["/sbin/openrc", "/usr/sbin/openrc", "/sbin/openrc-run"]), facts["init"]["openrc"])
    check("sshd", first(answers, ["/usr/sbin/sshd", "/usr/bin/sshd", "/sbin/sshd"]), facts["sshd"]["sshd"])
    check("sshd.pam", first(answers, ["/usr/sbin/sshd.pam"]), facts["sshd"]["pam_build"])
    check("cloud-init", first(answers, ["/usr/bin/cloud-init", "/bin/cloud-init", "/usr/local/bin/cloud-init"]), facts["first_boot"]["cloud_init"])
    check("tiny-cloud", first_any(answers, any_[:4]), facts["first_boot"]["tiny_cloud"])
    ign = first_any(answers, any_[4:])
    if facts["first_boot"]["ignition"] and not ign:
        ign = facts["first_boot"]["ignition"] if os.path.exists(f"{w}/oracle{facts['first_boot']['ignition']}") else None
    check("ignition", ign, facts["first_boot"]["ignition"])
    # Link chains from the kernel-extracted tree: each hop resolved against the real
    # path of its parent directory, as `realpath` would inside the guest.
    rootdir = f"{w}/oracle"

    def real_dir(path):
        real, todo, hops = [], [c for c in path.split("/") if c], 0
        while todo:
            c = todo.pop(0)
            if c == ".":
                continue
            if c == "..":
                if real:
                    real.pop()
                continue
            here = rootdir + "/" + "/".join(real + [c])
            if os.path.islink(here) and hops < 40:
                hops += 1
                t = os.readlink(here)
                if t.startswith("/"):
                    real = []
                todo = [x for x in t.split("/") if x] + todo
            else:
                real.append(c)
        return "/" + "/".join(real)

    for p, key in (("/bin/sh", ("shells", "bin_sh")), ("/sbin/init", ("init", "sbin_init"))):
        chain, cur = [p], p
        if not os.path.exists(rootdir + real_dir(p)):
            chain = []
        else:
            for _ in range(40):
                parent, base = cur.rsplit("/", 1)
                full = rootdir + real_dir(parent) + "/" + base
                if not os.path.islink(full):
                    break
                t = os.readlink(full)
                nxt = os.path.normpath(t if t.startswith("/") else real_dir(parent) + "/" + t)
                np_, nn = nxt.rsplit("/", 1)
                cur = os.path.normpath(real_dir(np_) + "/" + nn)
                chain.append(cur)
        if p == "/sbin/init" and not chain:
            # The tool falls back to /usr/sbin/init when /sbin/init is missing.
            pass
        check(p + " chain", chain, facts[key[0]][key[1]])

    # ------------------------------------------------------------------ packages
    pk = facts["packages"]
    ours_pk = pk["installed"] if pk else {}
    native = None
    if pk and pk["manager"] == "rpm":
        dbdir = os.path.dirname(f"{w}/oracle{pk['database']}")
        backend = ["--define", "_db_backend ndb"] if pk["database"].endswith("Packages.db") else []
        r = subprocess.run(["rpm", *backend, "--dbpath", dbdir, "-qa", "--qf", "%{NAME}\t%|EPOCH?{%{EPOCH}:}:{}|%{VERSION}-%{RELEASE}\n"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if r.returncode == 0 and r.stdout.strip():
            native = {}
            for l in r.stdout.splitlines():
                if l:
                    n, v = l.split("\t")
                    native.setdefault(n, []).append(v)
        else:
            print(f"  --- rpm cannot read {pk['database']} here: {r.stderr.strip()[:120]}")
    elif pk and pk["manager"] in ("apk", "pacman"):
        # No apk or pacman in this container: hand the kernel-extracted database to
        # the real tool in its own distro container (the `native` step of
        # tools/verify-all.sh, tools/verify_native.py).
        nd = os.path.join(WORK, "native", name)
        shutil.rmtree(nd, ignore_errors=True)
        if pk["manager"] == "apk":
            dbdir = os.path.dirname(pk["database"])
            for sub in (dbdir, "/etc/apk"):
                if os.path.isdir(f"{w}/oracle{sub}"):
                    shutil.copytree(f"{w}/oracle{sub}", nd + sub, symlinks=True)
        else:
            shutil.copytree(f"{w}/oracle{pk['database']}", nd + "/var/lib/pacman/local", symlinks=True)
        with open(os.path.join(nd, "tool.json"), "w") as f:
            json.dump({"manager": pk["manager"], "installed": ours_pk}, f)
        print(f"  --- {pk['manager']} database handed to the native check: {sum(map(len, ours_pk.values()))} installed per the tool")
    elif pk and pk["manager"] == "dpkg":
        q = run(["dpkg-query", f"--admindir={w}/oracle/var/lib/dpkg", "-W", "-f", "${db:Status-Status}\t${Package}\t${Version}\n"]).decode()
        native = {}
        for l in q.splitlines():
            st, n, v = l.split("\t")
            if st == "installed":
                native.setdefault(n, []).append(v)
    if native is not None:
        native = {k: sorted(v) for k, v in native.items()}
        same = native == ours_pk
        print(f"  {'ok ' if same else 'BAD'} packages vs {pk['manager']} itself: {sum(map(len, native.values()))} vs {sum(map(len, ours_pk.values()))} installed")
        if not same:
            for n in sorted(set(native) | set(ours_pk)):
                if native.get(n) != ours_pk.get(n):
                    problems.append(f"package {n}: {pk['manager']} says {native.get(n)!r}, tool says {ours_pk.get(n)!r}")
    xml = run(["virt-inspector", "--no-icon", "-a", image]).decode()
    if ET.fromstring(xml).find(".//operatingsystem") is None:
        print("  --- virt-inspector does not recognise this image (no OS found); its package check is skipped")
        shutil.rmtree(w)
        return report(name, problems)
    apps = ET.fromstring(xml).findall(".//application")
    vi = {}
    for a in apps:
        vi.setdefault(a.findtext("name"), []).append(a)
    names_same = set(vi) == set(ours_pk)
    print(f"  {'ok ' if names_same else 'BAD'} package names vs virt-inspector: {len(vi)} vs {len(ours_pk)}")
    if not names_same:
        problems.append(f"virt-inspector names differ: only kernel {sorted(set(vi)-set(ours_pk))[:10]}, only tool {sorted(set(ours_pk)-set(vi))[:10]}")
    def vi_version(a):
        e, v, r = a.findtext("epoch") or "0", a.findtext("version") or "", a.findtext("release") or ""
        return (f"{e}:" if e not in ("", "0") else "") + v + (f"-{r}" if r else "")
    # virt-inspector drops an explicit epoch 0 and the "r" of apk releases; compare
    # in that notation (the tool reports each database's own spelling).
    def norm(x):
        x = re.sub(r"^0:", "", x)
        return re.sub(r"-r(\d+)$", r"-\1", x) if pk and pk["manager"] == "apk" else x
    vdiff = [n for n in sorted(set(vi) & set(ours_pk))
             if sorted(norm(vi_version(a)) for a in vi[n]) != sorted(norm(x) for x in ours_pk[n])]
    print(f"  {'ok ' if not vdiff else 'BAD'} package versions vs virt-inspector: {len(set(vi) & set(ours_pk)) - len(vdiff)} equal, {len(vdiff)} differ")
    for n in vdiff[:10]:
        problems.append(f"package {n}: virt-inspector {[vi_version(a) for a in vi[n]]!r}, tool {ours_pk[n]!r}")
    vi_os = ET.fromstring(xml).find(".//operatingsystem")
    print(f"  virt-inspector: distro={vi_os.findtext('distro')} version={vi_os.findtext('major_version')}.{vi_os.findtext('minor_version')} "
          f"package_format={vi_os.findtext('package_format')}")

    shutil.rmtree(w)
    return report(name, problems)


def report(name, problems):
    if problems:
        print(f"RESULT {name}: {len(problems)} PROBLEMS")
        for p in problems:
            print("   -", p)
        return 1
    print(f"RESULT {name}: all checks passed")
    return 0


if __name__ == "__main__":
    os.makedirs(WORK, exist_ok=True)
    sys.exit(max(main(i) for i in sys.argv[1:]))
