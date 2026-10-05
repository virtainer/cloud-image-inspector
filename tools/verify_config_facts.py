#!/usr/bin/env python3
"""Check the facts the inspector derives from configuration files against the
files as the guest kernel serves them (libguestfs): effective sshd UsePAM (first
value wins, Include expanded in place, /usr/etc vendor fallback), whether
sshd_config.d is included, cloud-init's datasource_list, /etc/shells and the
useradd default shell (both with the /usr/etc fallback)."""
import json
import re
import subprocess
import sys

TOOL = "/work/target/release/cloud-image-inspector"


def gf(image, mount, cmds):
    out = subprocess.run(["guestfish", "--ro", "-a", image], input="run\n" + mount + cmds, text=True,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
    res, cur, buf = {}, None, []
    for line in out.splitlines() + ["@@ end"]:
        if line.startswith("@@ "):
            if cur:
                res[cur] = "\n".join(buf)
            cur, buf = line[3:], []
        else:
            buf.append(line)
    return res


def main(image):
    d = json.loads(subprocess.run([TOOL, "--json", image], stdout=subprocess.PIPE, check=True).stdout)
    f, root = d["facts"], d["root"]
    dev = f"/dev/sda{root['partition']}" if root["partition"] else "/dev/sda"
    opts = "ro"
    if root.get("subvolume"):
        opts += ",subvolid=" + re.search(r"id (\d+)", root["subvolume"]).group(1)
    if root["filesystem"] == "xfs":
        opts += ",norecovery"
    mount = f"mount-options {opts} {dev} /\n"
    pre = root.get("ostree_deployment") or ""
    files = ["/etc/ssh/sshd_config", "/usr/etc/ssh/sshd_config", "/etc/cloud/cloud.cfg",
             "/etc/shells", "/usr/etc/shells", "/etc/default/useradd", "/usr/etc/default/useradd"]
    cmds = "".join(f"echo '@@ cat {p}'\n-cat {pre}{p}\n" for p in files)
    cmds += "".join(f"echo '@@ ls {p}'\n-ls {pre}{p}\n" for p in ["/etc/ssh/sshd_config.d", "/usr/etc/ssh/sshd_config.d", "/etc/cloud/cloud.cfg.d"])
    r = gf(image, mount, cmds)
    # Fetch every drop-in the directories list.
    more = ""
    for dirp in ["/etc/ssh/sshd_config.d", "/usr/etc/ssh/sshd_config.d", "/etc/cloud/cloud.cfg.d"]:
        for name in sorted(x for x in r.get(f"ls {dirp}", "").splitlines() if x.strip()):
            more += f"echo '@@ cat {dirp}/{name}'\n-cat {pre}{dirp}/{name}\n"
    if more:
        r.update(gf(image, mount, more))

    def text(p):
        t = r.get(f"cat {p}")
        return t if t else None

    # sshd: first UsePAM wins, Include "<dir>/*.conf" expanded in place.
    main_cfg = text("/etc/ssh/sshd_config") or text("/usr/etc/ssh/sshd_config")
    lines, includes = [], False
    for l in (main_cfg or "").splitlines():
        w = l.strip().split()
        if w and w[0].lower() == "include":
            for pat in w[1:]:
                if pat.endswith("/*.conf"):
                    includes = True
                    dirp = pat[: -len("/*.conf")]
                    dirp = dirp if dirp.startswith("/") else "/etc/ssh/" + dirp
                    for name in sorted(x for x in r.get(f"ls {dirp}", "").splitlines() if x.endswith(".conf")):
                        lines += (text(f"{dirp}/{name}") or "").splitlines()
        else:
            lines.append(l.strip())
    use_pam = None
    for l in lines:
        w = l.split()
        if w and not l.startswith("#") and w[0].lower() == "usepam" and len(w) > 1:
            use_pam = w[1].lower()
            break
    ds = None
    cfgs = ["/etc/cloud/cloud.cfg"] + [f"/etc/cloud/cloud.cfg.d/{n}" for n in sorted(x for x in r.get("ls /etc/cloud/cloud.cfg.d", "").splitlines() if x.endswith(".cfg"))]
    for p in cfgs:
        for l in (text(p) or "").splitlines():
            if l.strip().startswith("datasource_list:"):
                ds = l.strip()[len("datasource_list:"):].strip()
    shells_t = text("/etc/shells") or text("/usr/etc/shells") or ""
    shells = [l.strip() for l in shells_t.splitlines() if l.strip() and not l.strip().startswith("#")]
    ua_t = text("/etc/default/useradd") or text("/usr/etc/default/useradd") or ""
    ua = next((l.strip()[6:].strip() for l in ua_t.splitlines() if l.strip().startswith("SHELL=")), None)

    checks = [
        ("sshd UsePAM", use_pam, f["sshd"]["use_pam"]),
        ("sshd_config.d included", includes, f["sshd"]["includes_sshd_config_d"]),
        ("/etc/shells", shells, f["shells"]["etc_shells"]),
        ("useradd SHELL", ua, f["shells"]["useradd_default_shell"]),
    ]
    if f["first_boot"]["cloud_init"]:
        checks.append(("datasource_list", ds, f["first_boot"]["cloud_init_datasource_list"]))
    bad = [c for c in checks if c[1] != c[2]]
    name = image.split("/")[-1]
    print(f"{'ok ' if not bad else 'BAD'} {name:<52} " + "  ".join(f"{c[0]}={c[2]!r:.30}" for c in checks[:2]))
    for c in bad:
        print(f"     {c[0]}: kernel {c[1]!r} vs tool {c[2]!r}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(max(main(i) for i in sys.argv[1:]))
