# cloud-image-inspector

Read-only, userspace inspection of cloud disk images: what OS is inside, and the
facts that decide how a first-boot configuration has to be written for it. Nothing
is booted or mounted; the image is parsed directly. It never executes guest code,
never asks the host kernel to parse guest filesystems, and has **no dependencies**
beyond the Rust standard library.

```
$ cloud-image-inspector images/generic_alpine-3.24.1-x86_64-uefi-cloudinit-r0.qcow2
== images/generic_alpine-3.24.1-x86_64-uefi-cloudinit-r0.qcow2
container      qcow2 v3, virtual size 214.0 MiB, 64.0 KiB clusters, deflate compression
partitions     gpt table
   1  esp         vfat      512.0 KiB name="EFI"
   2  linux-data  ext4      212.0 MiB label="/" name="/"
boot           UEFI only
root           partition 2 (ext4)
os             Alpine Linux 3.24.1 (ID=alpine VERSION_ID=3.24.1)
shells         bash: no
               /bin/sh: /bin/sh -> /bin/busybox
privilege      sudo: no   doas: yes (/usr/bin/doas)
init           openrc (/sbin/init: /sbin/init -> /bin/busybox)
sshd           sshd: yes (/usr/sbin/sshd)   PAM build: yes (/usr/sbin/sshd.pam)
               UsePAM: (default: no)   sshd_config.d included: true
first boot     cloud-init: yes (/usr/bin/cloud-init), version 26.1-r3 (from apk database)
packages       apk (201 installed, /lib/apk/db/installed)
...
```

## Facts collected

| Fact | Source in the image |
|---|---|
| Container | qcow2 version, virtual size, cluster size, compression type, extended L2, snapshots |
| Partitions | GPT/MBR (incl. extended), type, name, filesystem by superblock magic, label |
| Boot method | UEFI (an EFI System Partition exists), BIOS (BIOS boot partition or MBR boot code) |
| Root filesystem | the partition with an `os-release`; btrfs subvolume (default first); OSTree deployment |
| OS | `/etc/os-release` or `/usr/lib/os-release`: ID, VERSION_ID, ID_LIKE, NAME, PRETTY_NAME, VERSION_CODENAME |
| Login shells | bash present, `/bin/sh` symlink chain (canonical paths), `/etc/shells`, `useradd` default `SHELL` (also `/usr/etc`) |
| Privilege tool | `sudo`, `doas`, `/etc/sudoers.d`, `/etc/doas.d`, `/etc/doas.conf` |
| Init system | `/sbin/init` chain; systemd, OpenRC, runit, busybox init |
| sshd | `sshd`, the PAM build `sshd.pam`, effective `UsePAM` (first value wins, `Include` expanded; `/usr/etc` fallback) |
| First-boot agent | cloud-init and its version (package DB, else Python metadata), `datasource_list`; tiny-cloud; Ignition |
| Packages | apk (`/lib/apk/db/installed`), dpkg (`Status: … installed` only), pacman (`local/*/desc`, honouring `DBPath`), RPM (SQLite with WAL, and ndb): every installed package and version, including several of one name |

`--json` emits all of it; `--all-packages` adds the full package list.

## Formats

| Layer | Supported |
|---|---|
| Container | qcow2 v2/v3: L1/L2, compressed clusters (deflate, zstd), zero clusters, extended L2 subclusters; raw |
| Partition tables | GPT (512 and 4096-byte sectors), MBR with extended/logical partitions, none (whole-disk filesystem) |
| ext2/3/4 | extent trees, ext2/3 block maps, 32/64-bit descriptors, `meta_bg`, inline data, htree dirs, 1 KiB–64 KiB blocks |
| XFS | v4 and v5, AG-encoded addressing, local/extent/B-tree forks, `nrext64`, all five directory formats, remote symlinks |
| btrfs | full chunk tree, B-trees of any height, subvolumes and default subvolume, inline/regular/prealloc extents, zlib/LZO/zstd |
| Decompressors | DEFLATE/zlib (RFC 1950/1951), zstd (RFC 8878, with XXH64), LZO1X and the btrfs LZO container |
| Package DBs | apk, dpkg, pacman (text); SQLite (RPM `rpmdb.sqlite`, WAL applied); RPM ndb (`Packages.db`) |

Not supported, and reported as such: LVM and LUKS volumes, multi-device btrfs,
RAID0/10/5/6 btrfs profiles, qcow2 backing files and external data files
(refused on purpose), encrypted qcow2, RPM Berkeley DB (EL7/EL8).

## Untrusted input

Images come from URLs and uploads, so every parser treats its input as hostile:

- all on-disk reads are bounds-checked (`bytes.rs`), so malformed data is an error
  value, not a panic;
- every length that sizes an allocation is capped (whole-file reads 256 MiB,
  single reads 512 MiB, compressed extents 1 MiB);
- every tree walk has a depth cap **and** a node-visit budget, since corrupt
  pointers can form a DAG that a depth cap alone does not stop;
- qcow2 backing files and external data files are refused, since following
  them would open a host path chosen by the image;
- symlinks resolve inside the image root (absolute targets restart at the image
  root, `..` never climbs above it, 40 hops at most).

## Usage

```
cloud-image-inspector [--json] [--all-packages] IMAGE...
cloud-image-inspector ls     [--partition N] [--subvol ID] IMAGE PATH
cloud-image-inspector cat    [--partition N] [--subvol ID] IMAGE PATH
cloud-image-inspector stat   [--partition N] [--subvol ID] IMAGE PATH
cloud-image-inspector export [--partition N] [--subvol ID] IMAGE PATH DEST
```

File commands use the detected root filesystem unless `--partition` is given.
`CII_STATS=1` prints how often each on-disk format path ran.

## Verification

Run in containers (`tools/Containerfile`, `tools/Containerfile.guestfs`); see
`VERIFICATION.md` for the full record; `tools/verify-all.sh` reruns all of it.
Summary: 13 real cloud images (Alpine ×3, Debian, Ubuntu, Fedora, Fedora CoreOS,
AlmaLinux, Rocky, RHEL 9.7, RHEL 10.1, openSUSE, Arch) and 35 synthetic images,
every file identical to what the kernel or the source tree holds, every fact
confirmed, every package list identical to the distribution's own package manager
(`rpm`, `dpkg`, `apk`, `pacman`); 13,500 corrupted images without a panic or hang.

- **Real images against the kernel** (`tools/verify_real.py`, `tools/verify_config_facts.py`): libguestfs boots
  a real Linux kernel (KVM) that mounts the same root filesystem; its `tar-out`
  of the whole tree is compared entry by entry (type, symlink target, SHA-256 of
  every file) with this tool's `export`. Every fact is re-derived from kernel-side
  lookups; packages are compared with the native package manager run on the
  kernel-extracted database (`rpm --dbpath`, `dpkg-query --admindir`, `apk --root`
  in an Alpine container, `pacman -Q --dbpath` in an Arch container), and with
  `virt-inspector`.
- **Synthetic fixtures** (`tools/make_fixtures.py`, `tools/verify_fixtures.py`):
  one edge-case tree built into 18 filesystem variants with the real `mkfs` tools,
  plus 14 container and partition-layout variants (32 images); every export must
  equal the source tree, and every whole disk read through the tool must equal
  `qemu-img convert -O raw`. Three more are written by a running kernel
  (`tools/kernel_fixtures.py`: holes, unwritten extents, htree dirs,
  mount-time compression) and compared with the kernel's own view.
- **Decoders** (`tools/make-vectors.py`, `tests/compress.rs`, `tests/pkgdb.rs`):
  reference compressor output (zlib, zstd 1–22, python-lzo) and SQLite databases
  with overflow chains and a live WAL.
- **Robustness** (`tests/fuzz_images.rs`, `tests/compress.rs`): corrupted images
  (on the qcow2 file and on the guest disk, aimed at the blocks a clean run reads)
  and corrupted compressed streams must produce errors, never panics or hangs.

## Building

```
podman build -t cii-dev -f tools/Containerfile tools
podman run --rm -v "$PWD":/work -w /work cii-dev cargo build --release
```

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
