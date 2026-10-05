//! GPT and MBR (including extended partitions), and filesystem identification by
//! superblock magic.

use crate::bytes::{le16, le32, le64, slice, u8_at};
use crate::error::{corrupt, Result};
use crate::io::ReadAt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TableKind {
    Gpt,
    Mbr,
    /// No partition table: the filesystem starts at offset 0.
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PartKind {
    Esp,
    BiosBoot,
    LinuxData,
    LinuxRoot,
    LinuxUsr,
    Xbootldr,
    Lvm,
    Swap,
    Raid,
    Extended,
    Other,
}

impl PartKind {
    pub fn name(self) -> &'static str {
        match self {
            PartKind::Esp => "esp",
            PartKind::BiosBoot => "bios-boot",
            PartKind::LinuxData => "linux-data",
            PartKind::LinuxRoot => "linux-root",
            PartKind::LinuxUsr => "linux-usr",
            PartKind::Xbootldr => "xbootldr",
            PartKind::Lvm => "lvm",
            PartKind::Swap => "swap",
            PartKind::Raid => "raid",
            PartKind::Extended => "extended",
            PartKind::Other => "other",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Partition {
    pub number: u32,
    pub start: u64,
    pub len: u64,
    pub kind: PartKind,
    /// GPT type GUID or MBR type byte, as text.
    pub type_id: String,
    pub name: String,
    pub bootable_flag: bool,
}

#[derive(Clone, Debug)]
pub struct Table {
    pub kind: TableKind,
    pub sector: u64,
    pub partitions: Vec<Partition>,
    /// The MBR boot-code area (bytes 0..440) is not all zero: a BIOS loader is
    /// installed there (GRUB, syslinux).
    pub mbr_boot_code: bool,
    pub warnings: Vec<String>,
}

fn guid(b: &[u8]) -> String {
    format!(
        "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{}",
        u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        u16::from_le_bytes([b[4], b[5]]),
        u16::from_le_bytes([b[6], b[7]]),
        b[8],
        b[9],
        b[10..16]
            .iter()
            .map(|x| format!("{x:02X}"))
            .collect::<String>()
    )
}

fn gpt_kind(g: &str) -> PartKind {
    match g {
        "C12A7328-F81F-11D2-BA4B-00A0C93EC93B" => PartKind::Esp,
        "21686148-6449-6E6F-744E-656564454649" => PartKind::BiosBoot,
        "0FC63DAF-8483-4772-8E79-3D69D8477DE4" => PartKind::LinuxData,
        // Discoverable Partitions Specification root/usr types (x86-64, x86, aarch64).
        "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709"
        | "44479540-F297-41B2-9AF7-D131D5F0458A"
        | "B921B045-1DF0-41C3-AF44-4C6F280D3FAE" => PartKind::LinuxRoot,
        "8484680C-9521-48C6-9C11-B0720656F69E"
        | "75250D76-8CC6-458E-BD66-BD47CC81A812"
        | "B0E01050-EE5F-4390-949A-9101B17104E9" => PartKind::LinuxUsr,
        "BC13C2FF-59E6-4262-A352-B275FD6F7172" => PartKind::Xbootldr,
        "E6D6D379-F507-44C2-A23C-238F2A3DF928" => PartKind::Lvm,
        "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F" => PartKind::Swap,
        "A19D880F-05FC-4D3B-A006-743F0F84911E" => PartKind::Raid,
        _ => PartKind::Other,
    }
}

fn mbr_kind(t: u8) -> PartKind {
    match t {
        0xef => PartKind::Esp,
        0x83 => PartKind::LinuxData,
        0x8e => PartKind::Lvm,
        0x82 => PartKind::Swap,
        0xfd => PartKind::Raid,
        0x05 | 0x0f | 0x85 => PartKind::Extended,
        _ => PartKind::Other,
    }
}

fn read_gpt(
    dev: &dyn ReadAt,
    sector: u64,
    warnings: &mut Vec<String>,
) -> Result<Option<Vec<Partition>>> {
    if dev.size() < sector * 3 {
        return Ok(None);
    }
    let hdr = dev.read_vec(sector, 92)?;
    if &hdr[0..8] != b"EFI PART" {
        return Ok(None);
    }
    let entries_lba = le64(&hdr, 72)?;
    let count = le32(&hdr, 80)? as usize;
    let esize = le32(&hdr, 84)? as usize;
    if count > 4096 || !(128..=4096).contains(&esize) || !esize.is_multiple_of(8) {
        return corrupt(format!(
            "GPT: implausible table of {count} x {esize}-byte entries"
        ));
    }
    let table = dev.read_vec(
        entries_lba
            .checked_mul(sector)
            .ok_or_else(|| crate::error::Error::Corrupt("GPT: table offset overflow".into()))?,
        count * esize,
    )?;
    let mut parts = Vec::new();
    for (i, e) in table.chunks_exact(esize).enumerate() {
        if e[0..16].iter().all(|b| *b == 0) {
            continue;
        }
        let first = le64(e, 32)?;
        let last = le64(e, 40)?;
        let start = first.checked_mul(sector);
        let len = last
            .checked_sub(first)
            .and_then(|n| n.checked_add(1))
            .and_then(|n| n.checked_mul(sector));
        let (Some(start), Some(len)) = (start, len) else {
            return corrupt(format!("GPT: partition {} has an impossible range", i + 1));
        };
        let Some(len) = clamp(dev, i as u32 + 1, start, len, warnings) else {
            continue;
        };
        let name: Vec<u16> = slice(e, 56, 72)?
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|c| *c != 0)
            .collect();
        let type_id = guid(&e[0..16]);
        let attrs = le64(e, 48)?;
        parts.push(Partition {
            number: i as u32 + 1,
            start,
            len,
            kind: gpt_kind(&type_id),
            type_id,
            name: String::from_utf16_lossy(&name),
            bootable_flag: attrs & (1 << 2) != 0, // "legacy BIOS bootable"
        });
    }
    Ok(Some(parts))
}

/// The kernel's msdos parser rejects a table whose boot indicators are not 0x00 or
/// 0x80: boot code or a filesystem's boot sector also ends in 55AA.
fn plausible_mbr(sector: &[u8]) -> bool {
    (0..4).all(|i| matches!(sector.get(446 + i * 16), Some(0x00) | Some(0x80)))
}

fn mbr_entries(sector: &[u8]) -> Result<Vec<(u8, u8, u64, u64)>> {
    let mut out = Vec::new();
    for i in 0..4 {
        let e = slice(sector, 446 + i * 16, 16)?;
        let status = u8_at(e, 0)?;
        let ptype = u8_at(e, 4)?;
        let lba = le32(e, 8)? as u64;
        let n = le32(e, 12)? as u64;
        if ptype != 0 && n != 0 {
            out.push((status, ptype, lba, n));
        }
    }
    Ok(out)
}

/// Like the kernel: a partition past the end of the disk is truncated (with a
/// warning); one that starts past it is dropped.
fn clamp(
    dev: &dyn ReadAt,
    number: u32,
    start: u64,
    len: u64,
    warnings: &mut Vec<String>,
) -> Option<u64> {
    if start >= dev.size() {
        warnings.push(format!(
            "partition {number} starts past the end of the disk; ignored"
        ));
        return None;
    }
    match start.checked_add(len) {
        Some(end) if end <= dev.size() => Some(len),
        _ => {
            warnings.push(format!(
                "partition {number} extends past the end of the disk; truncated"
            ));
            Some(dev.size() - start)
        }
    }
}

fn read_mbr(dev: &dyn ReadAt, mbr: &[u8], warnings: &mut Vec<String>) -> Result<Vec<Partition>> {
    let mut parts = Vec::new();
    for (i, (status, ptype, lba, n)) in mbr_entries(mbr)?.into_iter().enumerate() {
        let start = lba * 512;
        let Some(len) = clamp(dev, i as u32 + 1, start, n * 512, warnings) else {
            continue;
        };
        let kind = mbr_kind(ptype);
        parts.push(Partition {
            number: i as u32 + 1,
            start,
            len,
            kind,
            type_id: format!("0x{ptype:02x}"),
            name: String::new(),
            bootable_flag: status & 0x80 != 0,
        });
        if kind == PartKind::Extended {
            // Logical partitions: a chain of EBRs, each relative to the extended start.
            let mut ebr = lba;
            for number in 5u32..133 {
                let sec = dev.read_vec(ebr * 512, 512)?;
                if le16(&sec, 510)? != 0xAA55 {
                    break;
                }
                let ents = mbr_entries(&sec)?;
                let Some(&(st, pt, l, cnt)) = ents.first() else {
                    break;
                };
                let s = (ebr + l) * 512;
                let Some(len) = clamp(dev, number, s, cnt * 512, warnings) else {
                    break;
                };
                parts.push(Partition {
                    number,
                    start: s,
                    len,
                    kind: mbr_kind(pt),
                    type_id: format!("0x{pt:02x}"),
                    name: String::new(),
                    bootable_flag: st & 0x80 != 0,
                });
                match ents.get(1) {
                    Some(&(_, _, next, _)) if next != 0 => ebr = lba + next,
                    _ => break,
                }
            }
        }
    }
    Ok(parts)
}

pub fn read_table(dev: &dyn ReadAt) -> Result<Table> {
    let mut warnings = Vec::new();
    if dev.size() < 1024 {
        return Ok(Table {
            kind: TableKind::None,
            sector: 512,
            partitions: Vec::new(),
            mbr_boot_code: false,
            warnings,
        });
    }
    let mbr = dev.read_vec(0, 512)?;
    let mbr_boot_code = mbr[..440].iter().any(|b| *b != 0);
    for sector in [512u64, 4096] {
        if let Some(parts) = read_gpt(dev, sector, &mut warnings)? {
            return Ok(Table {
                kind: TableKind::Gpt,
                sector,
                partitions: parts,
                mbr_boot_code,
                warnings,
            });
        }
    }
    if le16(&mbr, 510)? == 0xAA55 && plausible_mbr(&mbr) {
        let parts = read_mbr(dev, &mbr, &mut warnings)?;
        // A FAT/NTFS boot sector also ends in 55AA; a real MBR has entries.
        if !parts.is_empty() && !parts.iter().any(|p| p.type_id == "0xee") {
            return Ok(Table {
                kind: TableKind::Mbr,
                sector: 512,
                partitions: parts,
                mbr_boot_code,
                warnings,
            });
        }
    }
    Ok(Table {
        kind: TableKind::None,
        sector: 512,
        partitions: Vec::new(),
        mbr_boot_code,
        warnings,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FsType {
    Ext,
    Xfs,
    Btrfs,
    Vfat,
    Swap,
    LvmPv,
    Luks,
    Iso9660,
    Squashfs,
    Erofs,
    Unknown,
}

impl FsType {
    pub fn name(self) -> &'static str {
        match self {
            FsType::Ext => "ext4",
            FsType::Xfs => "xfs",
            FsType::Btrfs => "btrfs",
            FsType::Vfat => "vfat",
            FsType::Swap => "swap",
            FsType::LvmPv => "lvm2-pv",
            FsType::Luks => "luks",
            FsType::Iso9660 => "iso9660",
            FsType::Squashfs => "squashfs",
            FsType::Erofs => "erofs",
            FsType::Unknown => "unknown",
        }
    }
}

pub fn probe(dev: &dyn ReadAt) -> FsType {
    let size = dev.size();
    let head = match dev.read_vec(0, 4096.min(size as usize)) {
        Ok(h) => h,
        Err(_) => return FsType::Unknown,
    };
    let at = |off: usize, magic: &[u8]| head.get(off..off + magic.len()) == Some(magic);
    if at(0, b"XFSB") {
        return FsType::Xfs;
    }
    if at(0, b"LUKS\xba\xbe") {
        return FsType::Luks;
    }
    if at(0, b"hsqs") {
        return FsType::Squashfs;
    }
    if at(1080, &[0x53, 0xEF]) {
        return FsType::Ext;
    }
    if at(1024, &[0xE2, 0xE1, 0xF5, 0xE0]) {
        return FsType::Erofs;
    }
    for s in 0..4 {
        if at(s * 512, b"LABELONE") && at(s * 512 + 24, b"LVM2 001") {
            return FsType::LvmPv;
        }
    }
    if at(4086, b"SWAPSPACE2") || at(4086, b"SWAP-SPACE") {
        return FsType::Swap;
    }
    if at(510, &[0x55, 0xAA]) && (at(0x36, b"FAT") || at(0x52, b"FAT32")) {
        return FsType::Vfat;
    }
    let mut m = [0u8; 8];
    if size > 0x10048 && dev.read_at(0x10040, &mut m).is_ok() && &m == b"_BHRfS_M" {
        return FsType::Btrfs;
    }
    let mut iso = [0u8; 5];
    if size > 0x8006 && dev.read_at(0x8001, &mut iso).is_ok() && &iso == b"CD001" {
        return FsType::Iso9660;
    }
    FsType::Unknown
}
