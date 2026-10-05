#!/usr/bin/env python3
"""Compare the tool's apk/pacman package lists with the real package managers.

tools/verify_real.py copies each apk or pacman database out of the kernel's
extraction into <dir>/<image>/ with the tool's list in tool.json; verify-all.sh
then runs `apk --root <image dir> info -v` (Alpine container) or
`pacman -Q --dbpath <image dir>/var/lib/pacman` (Arch container) into native.txt.
This script compares the two."""
import json
import os
import sys

base = sys.argv[1] if len(sys.argv) > 1 else "fixtures/out/scratch/native"
bad = checked = 0
for name in sorted(os.listdir(base)):
    d = os.path.join(base, name)
    tool = json.load(open(os.path.join(d, "tool.json")))
    native = {l.strip() for l in open(os.path.join(d, "native.txt")) if l.strip()}
    sep = "-" if tool["manager"] == "apk" else " "
    ours = {f"{n}{sep}{v}" for n, vs in tool["installed"].items() for v in vs}
    cmd = "apk info -v" if tool["manager"] == "apk" else "pacman -Q"
    ok = ours == native and native
    checked += 1
    bad += not ok
    print(f"{'ok ' if ok else 'BAD'} {name:<52} {cmd}: {len(native):>4}   tool: {len(ours):>4}")
    if not ok:
        print(f"     only {cmd}: {sorted(native - ours)[:5]}  only tool: {sorted(ours - native)[:5]}")
print(f"{checked - bad}/{checked} images: tool package lists identical to the native package manager")
sys.exit(1 if bad or not checked else 0)
