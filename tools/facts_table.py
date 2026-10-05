#!/usr/bin/env python3
"""Markdown table of the facts the inspector reports, one row per image.
Usage: cloud-image-inspector --json IMAGE... | tools/facts_table.py"""
import json
import sys

docs = json.load(sys.stdin)
if isinstance(docs, dict):
    docs = [docs]
hdr = ("Image", "OS", "Boot", "Root", "bash", "/bin/sh", "useradd SHELL", "Privilege",
       "Init", "sshd.pam", "UsePAM", "First boot", "Packages")
print("| " + " | ".join(hdr) + " |")
print("|" + "---|" * len(hdr))
for d in docs:
    f, r, b, p = d["facts"], d["root"], d["boot"], d["facts"]["packages"]
    name = d["image"].split("/")[-1].removesuffix(".qcow2")
    boot = "UEFI+BIOS" if b["uefi"] and b["bios"] else "UEFI" if b["uefi"] else "BIOS" if b["bios"] else "-"
    root = f"p{r['partition']} {r['filesystem']}"
    sv = r.get("subvolume") or ""
    if sv and "id 5" not in sv:
        root += f" subvol `{sv.split(' ')[0]}`"
    if r.get("ostree_deployment"):
        root += " (OSTree)"
    sh = " → ".join(x.split("/")[-1] for x in f["shells"]["bin_sh"][1:]) or "-"
    priv = "doas" if f["privilege"]["doas"] else "sudo" if f["privilege"]["sudo"] else "-"
    fb = f["first_boot"]
    first = (f"cloud-init {fb['cloud_init_version'] or '?'}" if fb["cloud_init"]
             else "tiny-cloud" if fb["tiny_cloud"] else "Ignition" if fb["ignition"] else "-")
    row = (name, f"{f['os_release']['id']} {f['os_release']['version_id']}".strip(), boot, root,
           "yes" if f["shells"]["bash"] else "no", sh, f["shells"]["useradd_default_shell"] or "-", priv,
           f["init"]["system"], "yes" if f["sshd"]["pam_build"] else "no", f["sshd"]["use_pam"] or "(no)",
           first, f"{p['manager']} {p['count']}" if p else "-")
    print("| " + " | ".join(row) + " |")
