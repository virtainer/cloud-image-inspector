#!/usr/bin/env python3
"""Compression test vectors made by the reference implementations.

Writes <out>/<case>/plain and one file per codec. tests/compress.rs decodes each with
this crate's decoders and compares against `plain`.
"""
import os
import random
import subprocess
import sys
import zlib

import lzo

out = sys.argv[1] if len(sys.argv) > 1 else "fixtures/out/vectors"

rng = random.Random(1)
words = [
    "cloud", "image", "partition", "inode", "extent", "tree", "the", "of", "and", "kernel",
    "superblock", "allocation", "group", "directory", "symlink", "package", "version",
]


def text(n):
    parts, size = [], 0
    while size < n:
        w = rng.choice(words) + (" " if rng.random() < 0.9 else "\n")
        parts.append(w)
        size += len(w)
    return "".join(parts).encode()[:n]


def mixed(n):
    out = bytearray()
    while len(out) < n:
        kind = rng.randrange(3)
        k = rng.randrange(1, 40000)
        out += text(k) if kind == 0 else rng.randbytes(k) if kind == 1 else bytes(k)
    return bytes(out[:n])


cases = {
    "empty": b"",
    "one": b"a",
    "short": b"hello hello hello hello",
    "text": text(300_000),
    "random": rng.randbytes(200_000),
    "zeros": bytes(1 << 20),
    "mixed": mixed(500_000),
    "elf": open("/bin/ls", "rb").read(),
    "runs": b"".join(bytes([i % 7]) * (i % 300 + 1) for i in range(3000)),
}

for name, plain in cases.items():
    d = os.path.join(out, name)
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, "plain"), "wb").write(plain)
    for level in (0, 1, 6, 9):
        for wbits in (-12, -15):
            c = zlib.compressobj(level, zlib.DEFLATED, wbits)
            open(os.path.join(d, f"deflate-l{level}-w{-wbits}"), "wb").write(c.compress(plain) + c.flush())
        open(os.path.join(d, f"zlib-l{level}"), "wb").write(zlib.compress(plain, level))
    for level in ("1", "3", "7", "19", "22"):
        for check in ("--check", "--no-check"):
            args = ["zstd", "-q", "-c", f"-{level}", check]
            if level == "22":
                args.insert(1, "--ultra")
            z = subprocess.run(args, input=plain, stdout=subprocess.PIPE, check=True).stdout
            open(os.path.join(d, f"zstd-l{level}-{check.lstrip('-').replace('-', '')}"), "wb").write(z)
    one = subprocess.run(["zstd", "-q", "-c", "-3"], input=plain, stdout=subprocess.PIPE, check=True).stdout
    open(os.path.join(d, "zstd-twoframes"), "wb").write(one + one)
    open(os.path.join(d, "zstd-padded"), "wb").write(one + bytes(4096 - len(one) % 4096))
    if plain:  # python-lzo refuses nothing, but btrfs never stores empty segments
        open(os.path.join(d, "lzo1x-1"), "wb").write(lzo.compress(plain, 1, False))
        open(os.path.join(d, "lzo1x-999"), "wb").write(lzo.compress(plain, 9, False))

print(f"wrote {len(cases)} cases to {out}")

# ---------------------------------------------------------------- SQLite / rpmdb
import shutil
import sqlite3
import struct


def rpm_header(name, version, release, epoch=None, pad=0):
    entries, store = [], b""

    def add(tag, typ, data):
        nonlocal store
        entries.append((tag, typ, len(store), 1))
        store += data
    if epoch is not None:
        add(1003, 4, struct.pack(">I", epoch))  # INT32 first: 4-byte aligned
    add(1000, 6, name.encode() + b"\0")
    add(1001, 6, version.encode() + b"\0")
    add(1002, 6, release.encode() + b"\0")
    add(1004, 6, b"s" * pad + b"\0")  # a long SUMMARY: forces overflow pages
    return struct.pack(">II", len(entries), len(store)) + b"".join(struct.pack(">IIII", *e) for e in entries) + store


def packages(n, start=0):
    out = []
    for i in range(start, start + n):
        epoch = i % 3 if i % 5 == 0 else None
        out.append((f"pkg-{i:04d}", f"{i}.{i % 7}", f"{i % 11}.fc99", epoch, rng.randrange(0, 20000)))
    return out


def expected(pkgs):
    return "".join(f"{n}\t{'' if e is None else f'{e}:'}{v}-{r}\n" for n, v, r, e, _ in sorted(pkgs))


sq = os.path.join(out, "..", "sqlite")
shutil.rmtree(sq, ignore_errors=True)
os.makedirs(sq)
for ps in (512, 1024, 4096, 65536):
    db = os.path.join(sq, f"rpmdb-p{ps}.sqlite")
    c = sqlite3.connect(db)
    c.execute(f"PRAGMA page_size={ps}")
    c.execute("CREATE TABLE Packages (hnum INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL)")
    pk = packages(400)
    c.executemany("INSERT INTO Packages (blob) VALUES (?)", [(rpm_header(n, v, r, e, p),) for n, v, r, e, p in pk])
    c.commit()
    c.close()
    open(db + ".expected", "w").write(expected(pk))

# WAL: 150 rows checkpointed into the main file, 100 more committed only in the WAL,
# then a transaction whose spilled-but-uncommitted frames must be ignored.
db = os.path.join(sq, "wal-live.sqlite")
c = sqlite3.connect(db, isolation_level=None)
c.execute("PRAGMA page_size=1024")
c.execute("PRAGMA journal_mode=WAL")
c.execute("PRAGMA wal_autocheckpoint=0")
c.execute("CREATE TABLE Packages (hnum INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL)")
first, second, third = packages(150), packages(100, 150), packages(80, 250)
c.execute("BEGIN")
c.executemany("INSERT INTO Packages (blob) VALUES (?)", [(rpm_header(n, v, r, e, p),) for n, v, r, e, p in first])
c.execute("COMMIT")
c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
c.execute("BEGIN")
c.executemany("INSERT INTO Packages (blob) VALUES (?)", [(rpm_header(n, v, r, e, p),) for n, v, r, e, p in second])
c.execute("COMMIT")
c.execute("PRAGMA cache_size=1")
c.execute("BEGIN")
c.executemany("INSERT INTO Packages (blob) VALUES (?)", [(rpm_header(n, v, r, e, p),) for n, v, r, e, p in third])
snap = os.path.join(sq, "wal-snapshot.sqlite")
shutil.copy(db, snap)
shutil.copy(db + "-wal", snap + "-wal")
c.execute("ROLLBACK")
c.close()
open(snap + ".expected", "w").write(expected(first + second))
print(f"wrote sqlite fixtures to {sq}")
