//! XFS (v4 and v5), read-only, written from the XFS Algorithms & Data Structures
//! book and the kernel's `xfs_format.h` / `xfs_da_format.h`.
//!
//! Streams from the device: only the inodes, B-tree blocks, directory blocks and
//! file data a lookup touches are read. Block numbers in extents and B-tree pointers
//! are AG-encoded (`agno << agblklog | agbno`) and are decoded as such.

use std::rc::Rc;

use crate::bytes::{be16, be32, be64, slice, u8_at};
use crate::error::{corrupt, limit, unsupported, Result};
use crate::fs::{kind_from_mode, DirEntry, FileSystem, Kind, NodeId, Stat};
use crate::io::{Lru, ReadAt};

const SB_MAGIC: u32 = 0x5846_5342; // XFSB
const DINODE_MAGIC: u16 = 0x494e; // IN
const FMT_LOCAL: u8 = 1;
const FMT_EXTENTS: u8 = 2;
const FMT_BTREE: u8 = 3;
const DIFLAG2_NREXT64: u64 = 1 << 4;
const V4_FEAT2_FTYPE: u32 = 0x200;
const V5_INCOMPAT_FTYPE: u32 = 0x1;
const V5_INCOMPAT_KNOWN: u32 = 0x1 | 0x2 | 0x4 | 0x8 | 0x10 | 0x20 | 0x40 | 0x80 | 0x100;
const BMAP_MAGIC: u32 = 0x424d_4150; // BMAP
const BMAP_CRC_MAGIC: u32 = 0x424d_4133; // BMA3
const DIR3_BLOCK: u32 = 0x5844_4233; // XDB3
const DIR3_DATA: u32 = 0x5844_4433; // XDD3
const DIR2_BLOCK: u32 = 0x5844_3242; // XD2B
const DIR2_DATA: u32 = 0x5844_3244; // XD2D
const SYMLINK_MAGIC: u32 = 0x5853_4c4d; // XSLM
/// Directory data lives below this byte offset; leaf and free blocks above it.
const DIR_LEAF_OFFSET: u64 = 32 << 30;
const MAX_EXTENTS: usize = 1 << 20;
const MAX_BTREE_DEPTH: u32 = 10;

pub struct Xfs {
    dev: Rc<dyn ReadAt>,
    bs: u64,
    agblocks: u64,
    agcount: u64,
    agblklog: u32,
    inopblog: u32,
    inode_size: u64,
    dir_block: u64,
    root_ino: u64,
    v5: bool,
    ftype: bool,
    pub label: String,
    inode_cache: Lru<u64, Rc<Inode>>,
}

#[derive(Clone, Copy, Debug)]
struct Extent {
    offset: u64,
    block: u64,
    count: u64,
    unwritten: bool,
}

struct Inode {
    mode: u32,
    size: u64,
    format: u8,
    nextents: u64,
    fork: Vec<u8>,
}

impl Xfs {
    pub fn open(dev: Rc<dyn ReadAt>) -> Result<Self> {
        let sb = dev.read_vec(0, 512)?;
        if be32(&sb, 0)? != SB_MAGIC {
            return corrupt("xfs: bad superblock magic");
        }
        let bs = be32(&sb, 4)? as u64;
        if !(512..=65536).contains(&bs) || !bs.is_power_of_two() {
            return corrupt(format!("xfs: block size {bs}"));
        }
        let version = be16(&sb, 100)? & 0x0f;
        let v5 = version == 5;
        if !(4..=5).contains(&version) {
            return unsupported(format!("xfs: superblock version {version}"));
        }
        let features2 = be32(&sb, 200)?;
        let incompat = if v5 { be32(&sb, 216)? } else { 0 };
        if incompat & !V5_INCOMPAT_KNOWN != 0 {
            return unsupported(format!("xfs: incompatible features {incompat:#x}"));
        }
        let inode_size = be16(&sb, 104)? as u64;
        let inopblog = u8_at(&sb, 123)? as u32;
        let agblklog = u8_at(&sb, 124)? as u32;
        let dirblklog = u8_at(&sb, 192)? as u32;
        let agblocks = be32(&sb, 84)? as u64;
        let agcount = be32(&sb, 88)? as u64;
        if !(256..=2048).contains(&inode_size)
            || inopblog > 7
            || agblklog > 31
            || agblocks == 0
            || agblocks > 1 << agblklog
            || agcount == 0
            || dirblklog > 6
            || (bs << dirblklog) > 65536
        {
            return corrupt("xfs: implausible geometry");
        }
        Ok(Self {
            bs,
            agblocks,
            agcount,
            agblklog,
            inopblog,
            inode_size,
            dir_block: bs << dirblklog,
            root_ino: be64(&sb, 56)?,
            v5,
            ftype: if v5 {
                incompat & V5_INCOMPAT_FTYPE != 0
            } else {
                features2 & V4_FEAT2_FTYPE != 0
            },
            label: crate::bytes::cstr(slice(&sb, 108, 12)?),
            inode_cache: Lru::new(256),
            dev,
        })
    }

    /// Byte offset of an AG-encoded filesystem block.
    fn fsb_offset(&self, fsb: u64) -> Result<u64> {
        let agno = fsb >> self.agblklog;
        let agbno = fsb & ((1u64 << self.agblklog) - 1);
        if agno >= self.agcount || agbno >= self.agblocks {
            return corrupt(format!("xfs: block {fsb:#x} outside the filesystem"));
        }
        Ok((agno * self.agblocks + agbno) * self.bs)
    }

    fn read_blocks(&self, fsb: u64, count: u64) -> Result<Vec<u8>> {
        let len = count
            .checked_mul(self.bs)
            .ok_or_else(|| crate::error::Error::Corrupt("xfs: extent length overflow".into()))?;
        self.dev.read_vec(
            self.fsb_offset(fsb)?,
            crate::bytes::to_usize(len, "xfs extent")?,
        )
    }

    fn inode(&self, ino: u64) -> Result<Rc<Inode>> {
        if let Some(i) = self.inode_cache.get(ino) {
            return Ok(i);
        }
        let ag_bits = self.agblklog + self.inopblog;
        let agno = ino >> ag_bits;
        let agino = ino & ((1u64 << ag_bits) - 1);
        let agbno = agino >> self.inopblog;
        let index = agino & ((1u64 << self.inopblog) - 1);
        if agno >= self.agcount || agbno >= self.agblocks {
            return corrupt(format!("xfs: inode {ino} outside the filesystem"));
        }
        let off = (agno * self.agblocks + agbno) * self.bs + index * self.inode_size;
        let raw = self.dev.read_vec(off, self.inode_size as usize)?;
        if be16(&raw, 0)? != DINODE_MAGIC {
            return corrupt(format!("xfs: inode {ino} has a bad magic"));
        }
        let version = u8_at(&raw, 4)?;
        let core = if version >= 3 { 176 } else { 100 };
        let forkoff = u8_at(&raw, 82)? as usize;
        let fork_len = if forkoff != 0 {
            forkoff * 8
        } else {
            self.inode_size as usize - core
        };
        if core + fork_len > raw.len() {
            return corrupt("xfs: data fork past the inode");
        }
        let flags2 = if version >= 3 { be64(&raw, 120)? } else { 0 };
        let nextents = if flags2 & DIFLAG2_NREXT64 != 0 {
            be64(&raw, 24)?
        } else {
            be32(&raw, 76)? as u64
        };
        let i = Rc::new(Inode {
            mode: be16(&raw, 2)? as u32,
            size: be64(&raw, 56)?,
            format: u8_at(&raw, 5)?,
            nextents,
            fork: raw[core..core + fork_len].to_vec(),
        });
        self.inode_cache.put(ino, i.clone());
        Ok(i)
    }

    fn unpack(rec: &[u8]) -> Result<Extent> {
        let l0 = be64(rec, 0)?;
        let l1 = be64(rec, 8)?;
        Ok(Extent {
            unwritten: l0 >> 63 != 0,
            offset: (l0 >> 9) & ((1u64 << 54) - 1),
            block: ((l0 & 0x1ff) << 43) | (l1 >> 21),
            count: l1 & ((1u64 << 21) - 1),
        })
    }

    fn extents(&self, i: &Inode) -> Result<Vec<Extent>> {
        let mut out = Vec::new();
        crate::stats::hit(if i.format == FMT_BTREE {
            crate::stats::C::xfs_fork_btree
        } else {
            crate::stats::C::xfs_fork_extents
        });
        match i.format {
            FMT_EXTENTS => {
                let n = crate::bytes::to_usize(i.nextents, "xfs extent count")?;
                if n.saturating_mul(16) > i.fork.len() {
                    return corrupt("xfs: more extents than fit in the fork");
                }
                for k in 0..n {
                    out.push(Self::unpack(slice(&i.fork, k * 16, 16)?)?);
                }
            }
            FMT_BTREE => {
                // Root (xfs_bmdr_block): level, numrecs, then keys and pointers
                // sized for the fork's maximum record count.
                let level = be16(&i.fork, 0)? as u32;
                let numrecs = be16(&i.fork, 2)? as usize;
                let maxrecs = (i.fork.len() - 4) / 16;
                if level == 0 || numrecs > maxrecs {
                    return corrupt("xfs: bad bmap btree root");
                }
                let mut budget = 1usize << 18;
                for k in 0..numrecs {
                    let ptr = be64(&i.fork, 4 + maxrecs * 8 + k * 8)?;
                    self.walk_bmbt(ptr, level - 1, 1, &mut out, &mut budget)?;
                }
            }
            FMT_LOCAL => {}
            f => return unsupported(format!("xfs: data fork format {f}")),
        }
        out.sort_by_key(|e| e.offset);
        Ok(out)
    }

    fn walk_bmbt(
        &self,
        fsb: u64,
        level: u32,
        depth: u32,
        out: &mut Vec<Extent>,
        budget: &mut usize,
    ) -> Result<()> {
        if depth > MAX_BTREE_DEPTH {
            return corrupt("xfs: bmap btree too deep");
        }
        *budget = budget.checked_sub(1).ok_or_else(|| {
            crate::error::Error::Limit("xfs: bmap walk visited too many blocks".into())
        })?;
        let b = self.read_blocks(fsb, 1)?;
        let (hdr, magic) = if self.v5 {
            (72, BMAP_CRC_MAGIC)
        } else {
            (24, BMAP_MAGIC)
        };
        if be32(&b, 0)? != magic {
            return corrupt("xfs: bad bmap btree block magic");
        }
        let blevel = be16(&b, 4)? as u32;
        let numrecs = be16(&b, 6)? as usize;
        if blevel != level {
            return corrupt("xfs: bmap btree level mismatch");
        }
        let maxrecs = (b.len() - hdr) / 16;
        if numrecs > maxrecs {
            return corrupt("xfs: bmap btree block over-full");
        }
        for k in 0..numrecs {
            if level == 0 {
                out.push(Self::unpack(slice(&b, hdr + k * 16, 16)?)?);
                if out.len() > MAX_EXTENTS {
                    return limit("xfs: too many extents");
                }
            } else {
                let ptr = be64(&b, hdr + maxrecs * 8 + k * 8)?;
                self.walk_bmbt(ptr, level - 1, depth + 1, out, budget)?;
            }
        }
        Ok(())
    }

    /// Bytes `[start, start+len)` of a file's logical address space (holes read 0).
    fn read_extents_range(&self, extents: &[Extent], start: u64, len: usize) -> Result<Vec<u8>> {
        let mut out = vec![0u8; len];
        let end = start + len as u64;
        for e in extents {
            let es = e.offset * self.bs;
            let ee = es + e.count * self.bs;
            if ee <= start || es >= end {
                continue;
            }
            if e.unwritten {
                crate::stats::hit(crate::stats::C::xfs_unwritten_extent);
                continue;
            }
            let from = es.max(start);
            let to = ee.min(end);
            let skip_blocks = (from - es) / self.bs;
            let within = (from - es) % self.bs;
            let dev_off = self.fsb_offset(e.block + skip_blocks)? + within;
            self.dev.read_at(
                dev_off,
                &mut out[(from - start) as usize..(to - start) as usize],
            )?;
        }
        Ok(out)
    }

    fn shortform_dir(&self, i: &Inode) -> Result<Vec<DirEntry>> {
        let f = &i.fork;
        let count = u8_at(f, 0)? as usize;
        let i8 = u8_at(f, 1)? != 0;
        let isz = if i8 { 8 } else { 4 };
        let read_ino = |off: usize| -> Result<u64> {
            Ok(if i8 {
                be64(f, off)?
            } else {
                be32(f, off)? as u64
            })
        };
        let mut out = vec![DirEntry {
            name: b"..".to_vec(),
            node: NodeId(0, read_ino(2)?),
        }];
        let mut pos = 2 + isz;
        // `count` is the number of entries; a non-zero `i8count` only widens every
        // inode number to 8 bytes.
        for _ in 0..count {
            let namelen = u8_at(f, pos)? as usize;
            let name = slice(f, pos + 3, namelen)?.to_vec();
            pos += 3 + namelen + usize::from(self.ftype);
            out.push(DirEntry {
                name,
                node: NodeId(0, read_ino(pos)?),
            });
            pos += isz;
        }
        Ok(out)
    }

    fn data_block_entries(&self, block: &[u8], out: &mut Vec<DirEntry>) -> Result<()> {
        let magic = be32(block, 0)?;
        let (hdr, is_block) = match magic {
            DIR3_BLOCK => (64, true),
            DIR3_DATA => (64, false),
            DIR2_BLOCK => (16, true),
            DIR2_DATA => (16, false),
            _ => return Ok(()), // hole or a leaf/free block: no entries
        };
        crate::stats::hit(if is_block {
            crate::stats::C::xfs_dir_block
        } else {
            crate::stats::C::xfs_dir_leaf_node_data
        });
        let mut end = block.len();
        if is_block {
            // Block format: leaf entries and a tail (count, stale) close the block.
            let count = be32(block, block.len() - 8)? as usize;
            end = block.len().checked_sub(8 + count * 8).ok_or_else(|| {
                crate::error::Error::Corrupt("xfs: block dir leaf count past the block".into())
            })?;
        }
        let mut pos = hdr;
        while pos + 8 <= end {
            if be16(block, pos)? == 0xffff {
                let len = be16(block, pos + 2)? as usize;
                if len < 8 || !len.is_multiple_of(8) {
                    return corrupt("xfs: bad free entry in a directory block");
                }
                pos += len;
                continue;
            }
            let ino = be64(block, pos)?;
            let namelen = u8_at(block, pos + 8)? as usize;
            if namelen == 0 {
                return corrupt("xfs: empty name in a directory block");
            }
            let name = slice(block, pos + 9, namelen)?.to_vec();
            out.push(DirEntry {
                name,
                node: NodeId(0, ino),
            });
            pos += (8 + 1 + namelen + usize::from(self.ftype) + 2 + 7) & !7;
        }
        Ok(())
    }

    fn symlink_target(&self, i: &Inode) -> Result<Vec<u8>> {
        if i.size > 1024 {
            return corrupt("xfs: symlink target too long");
        }
        let n = i.size as usize;
        if i.format == FMT_LOCAL {
            crate::stats::hit(crate::stats::C::xfs_symlink_local);
            return Ok(slice(&i.fork, 0, n)?.to_vec());
        }
        crate::stats::hit(crate::stats::C::xfs_symlink_remote);
        let ext = self.extents(i)?;
        let mut out = Vec::new();
        for e in ext {
            let data = self.read_blocks(e.block, e.count)?;
            for blk in data.chunks(self.bs as usize) {
                if self.v5 {
                    if be32(blk, 0)? != SYMLINK_MAGIC {
                        return corrupt("xfs: bad remote symlink header");
                    }
                    let bytes = be32(blk, 8)? as usize;
                    out.extend_from_slice(slice(blk, 56, bytes)?);
                } else {
                    out.extend_from_slice(blk);
                }
            }
        }
        if out.len() < n {
            return corrupt("xfs: remote symlink blocks hold less than the link's size");
        }
        out.truncate(n);
        Ok(out)
    }
}

impl FileSystem for Xfs {
    fn type_name(&self) -> &'static str {
        "xfs"
    }

    fn root(&self) -> NodeId {
        NodeId(0, self.root_ino)
    }

    fn stat(&self, node: NodeId) -> Result<Stat> {
        let i = self.inode(node.1)?;
        Ok(Stat {
            kind: kind_from_mode(i.mode),
            size: i.size,
            mode: i.mode,
        })
    }

    fn read_dir(&self, dir: NodeId) -> Result<Vec<DirEntry>> {
        let i = self.inode(dir.1)?;
        if kind_from_mode(i.mode) != Kind::Dir {
            return corrupt("xfs: not a directory");
        }
        if i.format == FMT_LOCAL {
            crate::stats::hit(crate::stats::C::xfs_dir_shortform);
            return self.shortform_dir(&i);
        }
        let ext = self.extents(&i)?;
        // Every directory block that holds data (below the leaf offset).
        let mut blocks: Vec<u64> = Vec::new();
        let fsb_per_dir = self.dir_block / self.bs;
        for e in &ext {
            let first = e.offset / fsb_per_dir;
            let last = (e.offset + e.count).div_ceil(fsb_per_dir);
            for db in first..last {
                if db * self.dir_block >= DIR_LEAF_OFFSET {
                    break;
                }
                if blocks.last() != Some(&db) {
                    blocks.push(db);
                }
                if blocks.len() > MAX_EXTENTS {
                    return limit("xfs: directory too large");
                }
            }
        }
        blocks.dedup();
        let mut out = Vec::new();
        for db in blocks {
            let block =
                self.read_extents_range(&ext, db * self.dir_block, self.dir_block as usize)?;
            self.data_block_entries(&block, &mut out)?;
        }
        Ok(out)
    }

    fn read_file(&self, node: NodeId, max: u64) -> Result<Vec<u8>> {
        let i = self.inode(node.1)?;
        if i.size > max {
            return limit(format!("xfs: file of {} bytes exceeds {max}", i.size));
        }
        if i.format == FMT_LOCAL {
            return Ok(slice(&i.fork, 0, i.size as usize)?.to_vec());
        }
        let ext = self.extents(&i)?;
        self.read_extents_range(&ext, 0, i.size as usize)
    }

    fn read_range(&self, node: NodeId, offset: u64, len: u64) -> Result<Vec<u8>> {
        let i = self.inode(node.1)?;
        let end = i.size.min(offset.saturating_add(len));
        if offset >= end {
            return Ok(Vec::new());
        }
        if (end - offset) as usize > crate::io::MAX_READ {
            return limit("xfs: range read too large");
        }
        if i.format == FMT_LOCAL {
            return Ok(slice(&i.fork, offset as usize, (end - offset) as usize)?.to_vec());
        }
        let ext = self.extents(&i)?;
        self.read_extents_range(&ext, offset, (end - offset) as usize)
    }

    fn read_link(&self, node: NodeId) -> Result<Vec<u8>> {
        let i = self.inode(node.1)?;
        self.symlink_target(&i)
    }
}
