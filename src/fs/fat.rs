//! Read-only FAT12/16/32. Chains, directory bytes and entry counts are bounded.
use std::collections::HashSet;
use std::rc::Rc;

use crate::bytes::{le16, le32, slice};
use crate::error::{corrupt, limit, unsupported, Result};
use crate::fs::{DirEntry, FileSystem, Kind, NodeId, Stat};
use crate::io::ReadAt;

const ROOT: NodeId = NodeId(1, 0);
const MAX_CHAIN: usize = 131072;
const MAX_DIR: usize = 64 << 20;

pub struct Fat {
    dev: Rc<dyn ReadAt>,
    bits: u8,
    cluster: u64,
    fat: u64,
    fat_bytes: u64,
    data: u64,
    clusters: u32,
    root_offset: u64,
    root_bytes: usize,
    root_cluster: u32,
    pub label: String,
}

impl Fat {
    pub fn open(dev: Rc<dyn ReadAt>) -> Result<Self> {
        let b = dev.read_vec(0, 512)?;
        if le16(&b, 510)? != 0xaa55 {
            return corrupt("FAT: boot signature");
        }
        let sector = le16(&b, 11)? as u64;
        let spc = b[13] as u64;
        let reserved = le16(&b, 14)? as u64;
        let fats = b[16] as u64;
        let roots = le16(&b, 17)? as u64;
        let total16 = le16(&b, 19)? as u64;
        let total = if total16 != 0 {
            total16
        } else {
            le32(&b, 32)? as u64
        };
        let fat16 = le16(&b, 22)? as u64;
        let fat_sectors = if fat16 != 0 {
            fat16
        } else {
            le32(&b, 36)? as u64
        };
        if !(512..=4096).contains(&sector)
            || !sector.is_power_of_two()
            || spc == 0
            || !spc.is_power_of_two()
            || spc > 128
            || reserved == 0
            || !(1..=2).contains(&fats)
            || fat_sectors == 0
        {
            return corrupt("FAT: invalid geometry");
        }
        let root_sectors = (roots * 32).div_ceil(sector);
        let data_sector = reserved + fats * fat_sectors + root_sectors;
        if total <= data_sector || total * sector > dev.size() {
            return corrupt("FAT: volume range");
        }
        let count = (total - data_sector) / spc;
        if count > 0x0ffffff5 {
            return corrupt("FAT: cluster count");
        }
        let bits = if count < 4085 {
            12
        } else if count < 65525 {
            16
        } else {
            32
        };
        if (bits == 32) != (fat16 == 0 && roots == 0) {
            return corrupt("FAT: geometry disagrees with type");
        }
        let fat_bytes = fat_sectors * sector;
        if ((count + 2) * bits as u64).div_ceil(8) > fat_bytes {
            return corrupt("FAT: table too small");
        }
        let active = if bits == 32 {
            if le16(&b, 42)? != 0 {
                return unsupported("FAT32 version");
            }
            let flags = le16(&b, 40)?;
            if flags & 0x80 != 0 {
                (flags & 15) as u64
            } else {
                0
            }
        } else {
            0
        };
        if active >= fats {
            return corrupt("FAT: active table");
        }
        let root_cluster = if bits == 32 {
            le32(&b, 44)? & 0x0fffffff
        } else {
            0
        };
        if bits == 32 && !(2..count as u32 + 2).contains(&root_cluster) {
            return corrupt("FAT: root cluster");
        }
        let label_offset = if bits == 32 { 71 } else { 43 };
        let label = String::from_utf8_lossy(slice(&b, label_offset, 11)?)
            .trim()
            .to_string();
        Ok(Self {
            dev,
            bits,
            cluster: sector * spc,
            fat: (reserved + active * fat_sectors) * sector,
            fat_bytes,
            data: data_sector * sector,
            clusters: count as u32,
            root_offset: (reserved + fats * fat_sectors) * sector,
            root_bytes: (roots * 32) as usize,
            root_cluster,
            label,
        })
    }

    fn cluster_offset(&self, c: u32) -> Result<u64> {
        if !(2..self.clusters + 2).contains(&c) {
            return corrupt("FAT: cluster out of range");
        }
        Ok(self.data + (c as u64 - 2) * self.cluster)
    }

    fn next(&self, c: u32) -> Result<Option<u32>> {
        self.cluster_offset(c)?;
        let off = match self.bits {
            12 => c as u64 + c as u64 / 2,
            16 => c as u64 * 2,
            _ => c as u64 * 4,
        };
        let len = if self.bits == 32 { 4 } else { 2 };
        if off + len > self.fat_bytes {
            return corrupt("FAT: table range");
        }
        let b = self.dev.read_vec(self.fat + off, len as usize)?;
        let n = match self.bits {
            12 => {
                let x = le16(&b, 0)? as u32;
                if c & 1 == 0 {
                    x & 0xfff
                } else {
                    x >> 4
                }
            }
            16 => le16(&b, 0)? as u32,
            _ => le32(&b, 0)? & 0x0fffffff,
        };
        let eoc = match self.bits {
            12 => 0xff8,
            16 => 0xfff8,
            _ => 0x0ffffff8,
        };
        if n >= eoc {
            return Ok(None);
        }
        self.cluster_offset(n)?;
        Ok(Some(n))
    }

    fn chain(&self, first: u32, max_bytes: u64) -> Result<Vec<u32>> {
        if first == 0 && max_bytes == 0 {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        let mut cur = Some(first);
        while let Some(c) = cur {
            self.cluster_offset(c)?;
            if !seen.insert(c) {
                return corrupt("FAT: chain cycle");
            }
            if out.len() >= MAX_CHAIN || (out.len() as u64) * self.cluster >= max_bytes {
                return limit("FAT: chain budget");
            }
            out.push(c);
            cur = self.next(c)?;
        }
        Ok(out)
    }

    /// The 8.3 alias stored in a node's short entry, which still names the file when
    /// a long name exists. `None` for the root or an alias outside ASCII.
    fn short_alias(&self, node: NodeId) -> Result<Option<String>> {
        if node == ROOT {
            return Ok(None);
        }
        self.entry(node)?;
        let b = self.dev.read_vec(node.1, 32)?;
        if b[..11].iter().any(|c| *c >= 128) {
            return Ok(None);
        }
        let base = String::from_utf8_lossy(&b[..8]).trim_end().to_string();
        let ext = String::from_utf8_lossy(&b[8..11]).trim_end().to_string();
        Ok(Some(if ext.is_empty() {
            base
        } else {
            format!("{base}.{ext}")
        }))
    }
    fn entry(&self, node: NodeId) -> Result<(Kind, u64, u32)> {
        if node == ROOT {
            return Ok((Kind::Dir, 0, self.root_cluster));
        }
        if node.0 != 0 || !node.1.is_multiple_of(32) {
            return corrupt("FAT: node");
        }
        let b = self.dev.read_vec(node.1, 32)?;
        if b[0] == 0 || b[0] == 0xe5 || b[11] & 8 != 0 {
            return corrupt("FAT: invalid directory entry");
        }
        let high = if self.bits == 32 {
            le16(&b, 20)? as u32
        } else {
            0
        };
        let c = (high << 16) | le16(&b, 26)? as u32;
        Ok((
            if b[11] & 16 != 0 {
                Kind::Dir
            } else {
                Kind::File
            },
            le32(&b, 28)? as u64,
            c,
        ))
    }
}

impl FileSystem for Fat {
    fn type_name(&self) -> &'static str {
        "vfat"
    }
    fn root(&self) -> NodeId {
        ROOT
    }
    fn stat(&self, node: NodeId) -> Result<Stat> {
        let (kind, size, _) = self.entry(node)?;
        Ok(Stat {
            kind,
            size,
            mode: if kind == Kind::Dir {
                0o040555
            } else {
                0o100444
            },
        })
    }
    fn read_dir(&self, dir: NodeId) -> Result<Vec<DirEntry>> {
        let (kind, _, first) = self.entry(dir)?;
        if kind != Kind::Dir {
            return corrupt("FAT: not a directory");
        }
        let ranges = if dir == ROOT && self.bits != 32 {
            vec![(self.root_offset, self.root_bytes)]
        } else {
            self.chain(first, MAX_DIR as u64)?
                .into_iter()
                .map(|c| self.cluster_offset(c).map(|o| (o, self.cluster as usize)))
                .collect::<Result<Vec<_>>>()?
        };
        let mut out = Vec::new();
        let mut long = Vec::<u16>::new();
        let mut expected = 0u8;
        let mut checksum = 0u8;
        for (offset, len) in ranges {
            let b = self.dev.read_vec(offset, len)?;
            for (i, e) in b.chunks_exact(32).enumerate() {
                if e[0] == 0 {
                    return Ok(out);
                }
                if e[0] == 0xe5 {
                    long.clear();
                    expected = 0;
                    continue;
                }
                if e[11] == 15 {
                    let seq = e[0] & 31;
                    if seq == 0 || seq > 20 || e[0] & 0xa0 != 0 || e[12] != 0 || le16(e, 26)? != 0 {
                        return corrupt("FAT: long name entry");
                    }
                    if e[0] & 0x40 != 0 {
                        long = vec![0xffff; seq as usize * 13];
                        expected = seq;
                        checksum = e[13];
                    }
                    if expected != seq || checksum != e[13] || long.is_empty() {
                        return corrupt("FAT: long name sequence");
                    }
                    for (j, p) in [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30]
                        .iter()
                        .enumerate()
                    {
                        long[(seq as usize - 1) * 13 + j] = le16(e, *p)?;
                    }
                    expected -= 1;
                    continue;
                }
                if e[11] & 8 != 0 {
                    long.clear();
                    expected = 0;
                    continue;
                }
                let sum = e[..11]
                    .iter()
                    .fold(0u8, |s, c| s.rotate_right(1).wrapping_add(*c));
                let name = if !long.is_empty() {
                    if expected != 0 || checksum != sum {
                        return corrupt("FAT: long name checksum");
                    }
                    let end = long
                        .iter()
                        .position(|c| *c == 0 || *c == 0xffff)
                        .unwrap_or(long.len());
                    if end > 255 {
                        return corrupt("FAT: long name length");
                    }
                    String::from_utf16(&long[..end])
                        .map_err(|_| crate::error::Error::Corrupt("FAT: name UTF-16".into()))?
                } else {
                    if e[..11].iter().any(|c| *c >= 128) {
                        return unsupported("FAT: OEM short-name codepage");
                    }
                    let base = std::str::from_utf8(&e[..8])
                        .map_err(|_| crate::error::Error::Corrupt("FAT: short name".into()))?
                        .trim_end();
                    let ext = std::str::from_utf8(&e[8..11])
                        .map_err(|_| crate::error::Error::Corrupt("FAT: extension".into()))?
                        .trim_end();
                    let base = if e[12] & 8 != 0 {
                        base.to_ascii_lowercase()
                    } else {
                        base.to_string()
                    };
                    let ext = if e[12] & 16 != 0 {
                        ext.to_ascii_lowercase()
                    } else {
                        ext.to_string()
                    };
                    if ext.is_empty() {
                        base
                    } else {
                        format!("{base}.{ext}")
                    }
                };
                long.clear();
                expected = 0;
                if name == "." || name == ".." {
                    continue;
                }
                if name.is_empty() || name.contains(['/', '\\', '\0']) {
                    return corrupt("FAT: invalid name");
                }
                if out.len() >= 100000 {
                    return limit("FAT: directory entries");
                }
                out.push(DirEntry {
                    name: name.into_bytes(),
                    node: NodeId(0, offset + i as u64 * 32),
                });
            }
        }
        if !long.is_empty() {
            return corrupt("FAT: unfinished long name");
        }
        Ok(out)
    }
    fn lookup(&self, dir: NodeId, name: &[u8]) -> Result<Option<NodeId>> {
        let entries = self.read_dir(dir)?;
        let mut found = None;
        for e in entries.iter().filter(|e| e.name.eq_ignore_ascii_case(name)) {
            if found.is_some() {
                return corrupt("FAT: ambiguous directory name");
            }
            found = Some(e.node);
        }
        if found.is_none() && name.is_ascii() {
            for e in &entries {
                let alias = self.short_alias(e.node)?;
                if alias.is_some_and(|a| a.as_bytes().eq_ignore_ascii_case(name)) {
                    if found.is_some() {
                        return corrupt("FAT: ambiguous directory name");
                    }
                    found = Some(e.node);
                }
            }
        }
        if found.is_none() && (!name.is_ascii() || entries.iter().any(|e| !e.name.is_ascii())) {
            return unsupported("FAT: non-ASCII case-insensitive lookup");
        }
        Ok(found)
    }
    fn read_file(&self, node: NodeId, max: u64) -> Result<Vec<u8>> {
        let s = self.stat(node)?;
        if s.size > max.min(crate::vfs::MAX_FILE) {
            return limit("FAT: file size");
        }
        self.read_range(node, 0, s.size)
    }
    fn read_range(&self, node: NodeId, offset: u64, len: u64) -> Result<Vec<u8>> {
        let (kind, size, first) = self.entry(node)?;
        if kind != Kind::File {
            return corrupt("FAT: not a file");
        }
        let len = len.min(size.saturating_sub(offset));
        if len > crate::io::MAX_READ as u64 {
            return limit("FAT: range size");
        }
        if len == 0 {
            return Ok(Vec::new());
        }
        let chain = self.chain(first, size.div_ceil(self.cluster) * self.cluster)?;
        if chain.len() as u64 * self.cluster < size {
            return corrupt("FAT: short file chain");
        }
        let mut out = vec![0; len as usize];
        let mut done = 0;
        while done < out.len() {
            let pos = offset + done as u64;
            let c = *chain
                .get((pos / self.cluster) as usize)
                .ok_or_else(|| crate::error::Error::Corrupt("FAT: file chain range".into()))?;
            let within = pos % self.cluster;
            let n = (self.cluster - within).min((out.len() - done) as u64) as usize;
            self.dev
                .read_at(self.cluster_offset(c)? + within, &mut out[done..done + n])?;
            done += n;
        }
        Ok(out)
    }
    fn read_link(&self, _: NodeId) -> Result<Vec<u8>> {
        unsupported("FAT: symlinks")
    }
}
