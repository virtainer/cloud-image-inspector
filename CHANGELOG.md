# Changelog

## 0.1.0

First release. cloud-image-inspector reports what is inside a qcow2 or raw
cloud image without booting or mounting it. Images are parsed read-only, in
userspace, with no dependencies beyond the Rust standard library; no guest
code is run and the host kernel never parses guest filesystems.

- **Containers:** qcow2 v2/v3 (compressed clusters with deflate or zstd, zero
  clusters, extended L2 subclusters) and raw. qcow2 backing files, external
  data files and encryption are refused.
- **Partition tables:** GPT (512 and 4096-byte sectors), MBR with extended
  partitions, and whole-disk filesystems.
- **Filesystems:** ext2/3/4, XFS (v4 and v5), btrfs (subvolumes; zlib, LZO
  and zstd extents), FAT12/16/32 and NTFS.
- **Linux facts:** os-release, boot method (UEFI or BIOS), init system
  (systemd, OpenRC, runit, busybox), shells, sudo/doas, serial console login,
  sshd and `UsePAM`, and the first-boot agent (cloud-init with version and
  datasources, tiny-cloud, Ignition). Checked against Alpine, Debian, Ubuntu,
  Fedora, Fedora CoreOS, AlmaLinux, Rocky, RHEL 9 and 10, openSUSE and Arch
  cloud images.
- **Package databases:** apk, dpkg, pacman and RPM (SQLite and ndb). RPM
  Berkeley DB (EL7/EL8) is not supported.
- **Windows facts:** product, edition and build, architecture, virtio driver
  services and files (viostor, netkvm, viosock) and the Virtainer guest
  agent, sysprep state, EMS from the BCD store, RTC and power settings, and
  dirty markers on registry hives and the NTFS volume.
- **Output:** a text report or `--json`, with `--all-packages` for the full
  package list.
- **File commands:** `ls`, `cat`, `stat` and `export` read files straight
  from the image's root filesystem, or from any partition with
  `--partition`.
- **Untrusted input:** every read is bounds-checked, allocations are capped,
  and tree walks have depth and visit limits; malformed images produce
  errors, not panics or hangs.

Not supported, and reported as such: LVM, LUKS, multi-device btrfs, and NTFS
compression, EFS and reparse points.
