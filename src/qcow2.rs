//! qcow2 (versions 2 and 3), read-only, written from QEMU's `docs/interop/qcow2.txt`.
//!
//! Untrusted-input stance: an image that names a backing file or an external data
//! file is refused, because following either would make the host open a path the
//! image chose. Encrypted images and unknown incompatible features are refused too.

use std::rc::Rc;

use crate::bytes::{be32, be64, slice, u8_at};
use crate::compress::{inflate, zstd};
use crate::error::{corrupt, unsupported, Result};
use crate::io::{check_range, Lru, ReadAt};

const MAGIC: u32 = 0x5146_49fb; // "QFI\xfb"
const L1_OFFSET_MASK: u64 = 0x00ff_ffff_ffff_fe00;
const L2_COMPRESSED: u64 = 1 << 62;
const L2_ZERO: u64 = 1;

const INCOMPAT_DIRTY: u64 = 1 << 0;
const INCOMPAT_CORRUPT: u64 = 1 << 1;
const INCOMPAT_DATA_FILE: u64 = 1 << 2;
const INCOMPAT_COMPRESSION: u64 = 1 << 3;
const INCOMPAT_EXTL2: u64 = 1 << 4;
const INCOMPAT_KNOWN: u64 = (1 << 5) - 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Compression {
    Deflate,
    Zstd,
}

#[derive(Clone, Debug)]
pub struct Info {
    pub version: u32,
    pub virtual_size: u64,
    pub cluster_size: u64,
    pub compression: Compression,
    pub extended_l2: bool,
    pub dirty: bool,
    pub marked_corrupt: bool,
    pub snapshots: u32,
}

pub struct Qcow2 {
    file: Rc<dyn ReadAt>,
    pub info: Info,
    cluster_bits: u32,
    l2_entries: u64,
    l1: Vec<u64>,
    l2_cache: Lru<u64, Rc<Vec<u8>>>,
    cluster_cache: Lru<u64, Rc<Vec<u8>>>,
}

pub fn is_qcow2(file: &dyn ReadAt) -> bool {
    let mut m = [0u8; 4];
    file.size() >= 4 && file.read_at(0, &mut m).is_ok() && u32::from_be_bytes(m) == MAGIC
}

impl Qcow2 {
    pub fn open(file: Rc<dyn ReadAt>) -> Result<Self> {
        let h = file.read_vec(0, 104.min(file.size() as usize))?;
        if be32(&h, 0)? != MAGIC {
            return corrupt("qcow2: bad magic");
        }
        let version = be32(&h, 4)?;
        if version != 2 && version != 3 {
            return unsupported(format!("qcow2 version {version}"));
        }
        if be64(&h, 8)? != 0 || be32(&h, 16)? != 0 {
            return unsupported("qcow2 with a backing file (refused: it names a host path)");
        }
        let cluster_bits = be32(&h, 20)?;
        if !(9..=21).contains(&cluster_bits) {
            return corrupt(format!("qcow2: cluster_bits {cluster_bits}"));
        }
        let virtual_size = be64(&h, 24)?;
        if be32(&h, 32)? != 0 {
            return unsupported("encrypted qcow2");
        }
        let l1_size = be32(&h, 36)? as u64;
        let l1_offset = be64(&h, 40)?;
        let snapshots = be32(&h, 60)?;

        let (mut incompat, mut compression_type) = (0u64, 0u8);
        if version == 3 {
            incompat = be64(&h, 72)?;
            let header_len = be32(&h, 100)?;
            if header_len > 104 {
                let ext = file.read_vec(104, 1)?;
                compression_type = u8_at(&ext, 0)?;
            }
        }
        if incompat & !INCOMPAT_KNOWN != 0 {
            return unsupported(format!("qcow2 incompatible features {incompat:#x}"));
        }
        if incompat & INCOMPAT_DATA_FILE != 0 {
            return unsupported("qcow2 with an external data file (refused: it names a host path)");
        }
        let compression = match (incompat & INCOMPAT_COMPRESSION != 0, compression_type) {
            (false, _) | (true, 0) => Compression::Deflate,
            (true, 1) => Compression::Zstd,
            (true, t) => return unsupported(format!("qcow2 compression type {t}")),
        };
        let extended_l2 = incompat & INCOMPAT_EXTL2 != 0;
        if extended_l2 && cluster_bits < 14 {
            return corrupt("qcow2: extended L2 needs clusters of at least 16 KiB");
        }

        let cluster_size = 1u64 << cluster_bits;
        let entry = if extended_l2 { 16 } else { 8 };
        let l2_entries = cluster_size / entry;
        let per_l1 = cluster_size * l2_entries;
        let needed = virtual_size.div_ceil(per_l1);
        if l1_size < needed {
            return corrupt(format!(
                "qcow2: L1 has {l1_size} entries, the disk needs {needed}"
            ));
        }
        if l1_size > 32 << 20 {
            return corrupt("qcow2: implausible L1 size");
        }
        check_range(file.size(), l1_offset, (l1_size * 8) as usize)?;
        let raw = file.read_vec(l1_offset, (needed * 8) as usize)?;
        let l1 = raw
            .chunks_exact(8)
            .map(|c| u64::from_be_bytes(c.try_into().unwrap()))
            .collect();

        Ok(Self {
            info: Info {
                version,
                virtual_size,
                cluster_size,
                compression,
                extended_l2,
                dirty: incompat & INCOMPAT_DIRTY != 0,
                marked_corrupt: incompat & INCOMPAT_CORRUPT != 0,
                snapshots,
            },
            file,
            cluster_bits,
            l2_entries,
            l1,
            l2_cache: Lru::new(32),
            cluster_cache: Lru::new(64),
        })
    }

    fn l2_table(&self, offset: u64) -> Result<Rc<Vec<u8>>> {
        if let Some(t) = self.l2_cache.get(offset) {
            return Ok(t);
        }
        if !offset.is_multiple_of(self.info.cluster_size) {
            return corrupt("qcow2: unaligned L2 table");
        }
        let t = Rc::new(
            self.file
                .read_vec(offset, self.info.cluster_size as usize)?,
        );
        self.l2_cache.put(offset, t.clone());
        Ok(t)
    }

    fn compressed_cluster(&self, guest_cluster: u64, entry: u64) -> Result<Rc<Vec<u8>>> {
        if let Some(c) = self.cluster_cache.get(guest_cluster) {
            return Ok(c);
        }
        let csize_shift = 62 - (self.cluster_bits - 8);
        let csize_mask = (1u64 << (self.cluster_bits - 8)) - 1;
        let offset = entry & ((1u64 << csize_shift) - 1);
        let sectors = ((entry >> csize_shift) & csize_mask) + 1;
        let csize = sectors * 512 - (offset & 511);
        // The descriptor may overstate the last sector: clamp to the file.
        let len = csize.min(self.file.size().saturating_sub(offset));
        let data = self.file.read_vec(offset, len as usize)?;
        let cs = self.info.cluster_size as usize;
        let mut out = match self.info.compression {
            Compression::Deflate => inflate::inflate(&data, cs)?.0,
            Compression::Zstd => zstd::decompress_exact(&data, cs)?,
        };
        if out.len() > cs {
            return corrupt("qcow2: compressed cluster inflates past the cluster size");
        }
        out.resize(cs, 0);
        let out = Rc::new(out);
        self.cluster_cache.put(guest_cluster, out.clone());
        Ok(out)
    }

    /// Read within one guest cluster.
    fn read_in_cluster(&self, guest: u64, buf: &mut [u8]) -> Result<()> {
        let cs = self.info.cluster_size;
        let index = guest >> self.cluster_bits;
        let within = guest & (cs - 1);
        let l1i = (index / self.l2_entries) as usize;
        let l2i = (index % self.l2_entries) as usize;
        let l1e = *self
            .l1
            .get(l1i)
            .ok_or_else(|| crate::error::Error::Corrupt("qcow2: L1 index out of range".into()))?;
        let l2_off = l1e & L1_OFFSET_MASK;
        if l2_off == 0 {
            buf.fill(0);
            return Ok(());
        }
        let table = self.l2_table(l2_off)?;
        let esize = if self.info.extended_l2 { 16 } else { 8 };
        let entry = be64(&table, l2i * esize)?;
        if entry & L2_COMPRESSED != 0 {
            crate::stats::hit(match self.info.compression {
                Compression::Deflate => crate::stats::C::qcow2_cluster_deflate,
                Compression::Zstd => crate::stats::C::qcow2_cluster_zstd,
            });
            let c = self.compressed_cluster(index, entry & !(L2_COMPRESSED | (1 << 63)))?;
            buf.copy_from_slice(slice(&c, within as usize, buf.len())?);
            return Ok(());
        }
        let host = entry & L1_OFFSET_MASK;
        if !self.info.extended_l2 {
            if entry & L2_ZERO != 0 {
                crate::stats::hit(crate::stats::C::qcow2_cluster_zero);
                buf.fill(0);
            } else if host == 0 {
                crate::stats::hit(crate::stats::C::qcow2_cluster_unallocated);
                buf.fill(0);
            } else {
                crate::stats::hit(crate::stats::C::qcow2_cluster_data);
                self.file.read_at(host + within, buf)?;
            }
            return Ok(());
        }
        // Extended L2: 32 subclusters, an allocation bitmap and a zero bitmap.
        let bitmap = be64(&table, l2i * 16 + 8)?;
        let sc_size = cs / 32;
        let mut done = 0usize;
        while done < buf.len() {
            let pos = within + done as u64;
            let sc = (pos / sc_size) as u32;
            let n = ((sc_size - pos % sc_size) as usize).min(buf.len() - done);
            let part = &mut buf[done..done + n];
            let zero = bitmap & (1u64 << (32 + sc)) != 0;
            let alloc = bitmap & (1u64 << sc) != 0;
            if alloc && !zero && host != 0 {
                crate::stats::hit(crate::stats::C::qcow2_subcluster);
                self.file.read_at(host + pos, part)?;
            } else {
                part.fill(0);
            }
            done += n;
        }
        Ok(())
    }
}

impl ReadAt for Qcow2 {
    fn size(&self) -> u64 {
        self.info.virtual_size
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_range(self.info.virtual_size, offset, buf.len())?;
        let cs = self.info.cluster_size;
        let mut done = 0usize;
        while done < buf.len() {
            let pos = offset + done as u64;
            let n = ((cs - pos % cs) as usize).min(buf.len() - done);
            self.read_in_cluster(pos, &mut buf[done..done + n])?;
            done += n;
        }
        Ok(())
    }
}
