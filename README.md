# cloud-image-inspector

Inspect qcow2 and raw cloud images without booting or mounting them — a
zero-dependency Rust CLI from [Virtainer](https://virtainer.io). It reports which
OS is inside a disk image and the facts that decide how a first-boot configuration
has to be written for it. The image is parsed directly, read-only and in
userspace: it never executes guest code, never asks the host kernel to parse guest
filesystems, and has **no dependencies** beyond the Rust standard library.

## Use cases

- Inspect Windows images for edition/build, virtio driver services and files,
  sysprep state, EMS, RTC, power settings and dirty markers.
- Check which OS is inside a qcow2 or raw image without mounting it
  (`/etc/os-release`: ID, VERSION_ID, ID_LIKE, PRETTY_NAME, …).
- Read os-release, cloud-init, sshd and sudo facts from a disk image: is
  cloud-init installed and which version, its `datasource_list`, whether sshd is
  a PAM build and `UsePAM` is on, `sudo` or `doas`.
- Decide how to write first-boot config for an image: cloud-init, tiny-cloud or
  Ignition; bash or only `/bin/sh`; systemd, OpenRC, runit or busybox init; UEFI
  or BIOS boot.
- List the installed packages and versions in an image from its apk, dpkg,
  pacman or RPM database.
- List, read or extract files from an image's ext4, XFS, btrfs, FAT or NTFS filesystem
  without libguestfs and without mounting it.

## Quick start

```
cargo install --locked --git https://github.com/virtainer/cloud-image-inspector
cloud-image-inspector disk.qcow2           # human-readable report
cloud-image-inspector --json disk.qcow2    # machine-readable report
```

All commands and options are under [Usage](#usage); to build in a container,
see [Building](#building).

Example report for the Alpine cloud image:

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
| Root filesystem | Linux: the partition with an `os-release`, btrfs subvolume (default first), OSTree deployment; Windows: an NTFS `Windows/System32/config` tree with a hive or kernel file |
| OS family | `os_family`: `linux`, `windows` or `unknown`, derived from image contents |
| OS | `/etc/os-release` or `/usr/lib/os-release`: ID, VERSION_ID, ID_LIKE, NAME, PRETTY_NAME, VERSION_CODENAME |
| Login shells | bash present, `/bin/sh` symlink chain (canonical paths), `/etc/shells`, `useradd` default `SHELL` (also `/usr/etc`) |
| Privilege tool | `sudo`, `doas`, `/etc/sudoers.d`, `/etc/doas.d`, `/etc/doas.conf` |
| Init system | `/sbin/init` chain; systemd, OpenRC, runit, busybox init |
| Serial console login | `/etc/inittab`, the `/sbin/getty` symlink chain (busybox or util-linux), `agetty`, `login` |
| sshd | `sshd`, the PAM build `sshd.pam`, effective `UsePAM` (first value wins, `Include` expanded; `/usr/etc` fallback) |
| First-boot agent | cloud-init and its version (package DB, else Python metadata), `datasource_list`; tiny-cloud; Ignition |
| Packages | apk (`/lib/apk/db/installed`), dpkg (`Status: … installed` only), pacman (`local/*/desc`, honouring `DBPath`), RPM (SQLite with WAL, and ndb): every installed package and version, including several of one name |
| Windows product | `windows.product_name`, `edition_id`, `installation_type`, integer `build` and `ubr`: SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion |
| Windows architecture | `windows.arch`: the `ntoskrnl.exe` PE machine field (`amd64`, `x86`, `arm64`, `arm`; unknown machines are null) |
| Windows drivers and agent | `windows.drivers.{viostor,netkvm,viosock,virtainer_agent}`: service-key `present`, integer `start`, executable `file`; the agent also has `version` from its PE fixed file-version resource |
| Windows sysprep | `windows.sysprep.image_state`: SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Setup\\State\\ImageState |
| Windows EMS | `windows.ems.bootems`, `ems_enabled`: the EFI System Partition's `EFI/Microsoft/Boot/BCD` hive, including inherited elements |
| Windows RTC and power | `windows.rtc_is_universal`, `hibernation`, `fast_startup`: selected SYSTEM ControlSet's `RealTimeIsUniversal`, `HibernateEnabled`, `HiberbootEnabled` |
| Windows dirty markers | `windows.dirty.system_hive`, `software_hive`: validated base-block sequence mismatches; `ntfs_volume`: `$Volume` dirty flag |

`--json` emits all of it; `--all-packages` adds the full package list.

## Formats

| Layer | Supported |
|---|---|
| Container | qcow2 v2/v3: L1/L2, compressed clusters (deflate, zstd), zero clusters, extended L2 subclusters; raw |
| Partition tables | GPT (512 and 4096-byte sectors), MBR with extended/logical partitions, none (whole-disk filesystem) |
| ext2/3/4 | extent trees, ext2/3 block maps, 32/64-bit descriptors, `meta_bg`, inline data, htree dirs, 1 KiB–64 KiB blocks |
| XFS | v4 and v5, AG-encoded addressing, local/extent/B-tree forks, `nrext64`, all five directory formats, remote symlinks |
| btrfs | full chunk tree, B-trees of any height, subvolumes and default subvolume, inline/regular/prealloc extents, zlib/LZO/zstd |
| FAT12/16/32 | BPB geometry, bounded cluster chains, fixed and cluster-based root directories, checksum-validated long names, nested directories and file ranges |
| NTFS | boot sector, MFT bootstrap and fixups, attribute lists, resident/non-resident streams, signed data runs, sparse/uninitialized zeros, `$INDEX_ROOT`/`$INDEX_ALLOCATION` with bitmap and fixups, `$UpCase` |
| Windows registry | primary regf 1.3–1.6, base checksum/sequence numbers, hive bins and allocated cells, nk/vk/lf/lh/li/ri, big data; SZ/EXPAND_SZ/MULTI_SZ/DWORD/QWORD/BINARY |
| Decompressors | DEFLATE/zlib (RFC 1950/1951), zstd (RFC 8878, with XXH64), LZO1X and the btrfs LZO container |
| Package DBs | apk, dpkg, pacman (text); SQLite (RPM `rpmdb.sqlite`, WAL applied); RPM ndb (`Packages.db`) |

Not supported, and reported as such: LVM and LUKS volumes, multi-device btrfs,
RAID0/10/5/6 btrfs profiles, qcow2 backing files and external data files
(refused on purpose), encrypted qcow2, RPM Berkeley DB (EL7/EL8). Windows readers
also refuse NTFS
compression, EFS and reparse points (including WOF), inaccessible MFT bootstrap
extensions, and FAT OEM short names or non-ASCII case folding. Unicode long
names can be listed and matched exactly. These cases produce errors, never
raw compressed bytes or a guessed absence.

## Windows output

`--json` adds top-level `os_family` and `windows`. A Windows report contains every
Windows field in the table above; Linux `facts` is null. A Linux report keeps its
existing `facts` and has `windows: null`. Unrecognized or ambiguous guest roots
have `os_family: "unknown"`. Windows values that cannot be read or interpreted
are **null**, including missing registry settings: OS defaults are not assumed.
Confirmed missing service keys or files are `false`.

SYSTEM service and power settings use only `Select\Current`'s ControlSet.
`viostor`, `netkvm` and `viosock` use their service `ImagePath`, or their explicit
`Windows/System32/drivers/<name>.sys` location when a readable service key has no
ImagePath set. Missing or unreadable service keys leave file evidence null. The agent
service is searched under `virtainer-guest-agent`, `virtainer_agent` and
`virtainer_guest_agent`; multiple aliases are ambiguous. Its executable is
located from the registered `ImagePath`. An absolute drive is mapped only when
SOFTWARE's `SystemRoot` identifies that drive. Without a usable agent ImagePath,
`file` and `version` are null: there is no assumed installation directory.
`version` is the PE fixed file version, formatted `major.minor.build.revision`.

EMS describes the boot manager's library `bootems` element (`16000020`) and the
boot manager's default Windows OS loader's `ems` element (`260000b0`), selected
by `23000003`. GUID object elements and inheritance lists are decoded from
REG_SZ/REG_MULTI_SZ (or UTF-16 binary data). Inheritance is bounded and conflicts
are unknown. Multiple EFI System Partitions, a dirty BCD hive, or an unreadable
store leave EMS unknown. Missing elements stay null. These are stored settings;
they do not prove that a guest has booted or that its serial console works.

Hives and the NTFS journal are not replayed. A dirty hive's facts describe the
stored snapshot and may omit recent changes; the separate dirty flag preserves
that evidence. No guest executable is run. See [VERIFICATION.md](VERIFICATION.md)
for synthetic coverage and the optional local Windows image check.

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

File commands use the detected Linux or Windows root filesystem unless
`--partition` is given. Ambiguous roots require `--partition N`, including
images containing two Windows installations. Windows/FAT paths accept `/` or
`\` separators; quote backslashes in the shell. Use `--partition N` to read an
EFI or seed volume.
An explicit `--subvol ID` can select a Btrfs data filesystem without an OS root.
If multiple Btrfs filesystems are present, also specify `--partition N`.
`CII_STATS=1` prints how often each on-disk format path ran.

## Verification

Run in containers (`tools/Containerfile`, `tools/Containerfile.guestfs`); see
`VERIFICATION.md` for the full record; `tools/verify-all.sh` reruns all of it.
Linux/container summary from the recorded 2026-10-05 run: 13 real cloud images (Alpine ×3, Debian, Ubuntu, Fedora, Fedora CoreOS,
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

Windows and file-command coverage is self-contained in `tests/windows.rs`: 33
tests and 1,000 corrupted synthetic FAT/NTFS/regf/PE inputs. One additional Windows test requires
a local image and is ignored by default. No real Windows image was verified in
this checkout.

## Building

```
podman build -t cii-dev -f tools/Containerfile tools
podman run --rm -v "$PWD":/work -w /work cii-dev cargo build --release
```

## License

Licensed under the [Apache License, Version 2.0](LICENSE).

## About Virtainer

[Virtainer](https://virtainer.io) is a self-hosted virtualization platform for
hardware you own: it runs full Linux VMs and Docker images as hardware-isolated
machines. Virtainer Free runs on a single host; [Virtainer Pro](https://virtainer.io/pro),
the multi-host edition for clusters, is in development. cloud-image-inspector is
one of [Virtainer's open-source components](https://virtainer.io/open-source).
