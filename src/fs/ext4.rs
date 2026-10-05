//! ext2/3/4, read-only, written from the kernel's on-disk format documentation
//! (Documentation/filesystems/ext4).
//!
//! Supports extent trees and legacy block maps, 32/64-bit group descriptors,
//! `meta_bg`, inline data, htree directories (read linearly, which is valid: the
//! index blocks look like empty entries) and fast symlinks.

use std::rc::Rc;

use crate::bytes::{le16, le32, slice, u8_at};
use crate::error::{corrupt, limit, unsupported, Result};
use crate::fs::{kind_from_mode, DirEntry, FileSystem, Kind, NodeId, Stat};
use crate::io::{Lru, ReadAt};

const MAGIC: u16 = 0xEF53;
const INCOMPAT_FILETYPE: u32 = 0x2;
const INCOMPAT_RECOVER: u32 = 0x4;
const INCOMPAT_META_BG: u32 = 0x10;
const INCOMPAT_64BIT: u32 = 0x80;
const RO_COMPAT_SPARSE_SUPER: u32 = 0x1;
const FL_EXTENTS: u32 = 0x8_0000;
const FL_INLINE_DATA: u32 = 0x1000_0000;
const FL_ENCRYPT: u32 = 0x800;
const FL_HUGE_FILE: u32 = 0x4_0000;
const EXTENT_MAGIC: u16 = 0xF30A;
const MAX_DEPTH: u32 = 8;
const MAX_EXTENTS: usize = 1 << 20;

pub struct Ext4 {
    dev: Rc<dyn ReadAt>,
    bs: u64,
    first_data_block: u64,
    blocks_per_group: u64,
    inodes_per_group: u64,
    inodes_count: u64,
    inode_size: u64,
    desc_size: u64,
    groups: u64,
    incompat: u32,
    ro_compat: u32,
    first_meta_bg: u64,
    pub label: String,
    pub needs_recovery: bool,
    desc_cache: Lru<u64, Rc<Vec<u8>>>,
}

/// Appends one mapped block to an extent list, merging runs.
type PushBlock<'a> = &'a mut dyn FnMut(u64, u64, &mut Vec<Extent>) -> Result<()>;

#[derive(Clone, Copy)]
struct Extent {
    logical: u64,
    physical: u64,
    len: u64,
    uninit: bool,
}

struct Inode {
    raw: Vec<u8>,
    mode: u32,
    size: u64,
    flags: u32,
}

impl Inode {
    fn i_block(&self) -> &[u8] {
        &self.raw[0x28..0x28 + 60]
    }
}

impl Ext4 {
    pub fn open(dev: Rc<dyn ReadAt>) -> Result<Self> {
        let sb = dev.read_vec(1024, 1024)?;
        if le16(&sb, 0x38)? != MAGIC {
            return corrupt("ext4: bad superblock magic");
        }
        let log = le32(&sb, 0x18)?;
        if log > 6 {
            return corrupt(format!("ext4: block size 1024<<{log}"));
        }
        let bs = 1024u64 << log;
        let rev = le32(&sb, 0x4c)?;
        let inode_size = if rev == 0 {
            128
        } else {
            le16(&sb, 0x58)? as u64
        };
        if inode_size < 128 || inode_size > bs || !inode_size.is_power_of_two() {
            return corrupt(format!("ext4: inode size {inode_size}"));
        }
        let incompat = le32(&sb, 0x60)?;
        let ro_compat = le32(&sb, 0x64)?;
        let desc_size = if incompat & INCOMPAT_64BIT != 0 {
            le16(&sb, 0xfe)? as u64
        } else {
            32
        };
        if !(32..=1024).contains(&desc_size) || !desc_size.is_power_of_two() {
            return corrupt(format!("ext4: descriptor size {desc_size}"));
        }
        let mut blocks = le32(&sb, 0x04)? as u64;
        if incompat & INCOMPAT_64BIT != 0 {
            blocks |= (le32(&sb, 0x150)? as u64) << 32;
        }
        let first_data_block = le32(&sb, 0x14)? as u64;
        let blocks_per_group = le32(&sb, 0x20)? as u64;
        let inodes_per_group = le32(&sb, 0x28)? as u64;
        if blocks_per_group == 0 || inodes_per_group == 0 || blocks <= first_data_block {
            return corrupt("ext4: zero-sized groups");
        }
        if blocks.saturating_mul(bs) > dev.size().saturating_mul(4) {
            return corrupt("ext4: superblock claims far more blocks than the partition holds");
        }
        let groups = (blocks - first_data_block).div_ceil(blocks_per_group);
        Ok(Self {
            bs,
            first_data_block,
            blocks_per_group,
            inodes_per_group,
            inodes_count: le32(&sb, 0x00)? as u64,
            inode_size,
            desc_size,
            groups,
            incompat,
            ro_compat,
            first_meta_bg: le32(&sb, 0x104)? as u64,
            label: crate::bytes::cstr(slice(&sb, 0x78, 16)?),
            needs_recovery: incompat & INCOMPAT_RECOVER != 0,
            desc_cache: Lru::new(16),
            dev,
        })
    }

    fn block(&self, n: u64) -> Result<Vec<u8>> {
        let off = n
            .checked_mul(self.bs)
            .ok_or_else(|| crate::error::Error::Corrupt("ext4: block number overflow".into()))?;
        self.dev.read_vec(off, self.bs as usize)
    }

    fn has_super(&self, group: u64) -> bool {
        if self.ro_compat & RO_COMPAT_SPARSE_SUPER == 0 || group <= 1 {
            return true;
        }
        for base in [3u64, 5, 7] {
            let mut p = base;
            while p < group {
                p *= base;
            }
            if p == group {
                return true;
            }
        }
        false
    }

    fn inode_table(&self, group: u64) -> Result<u64> {
        if group >= self.groups {
            return corrupt("ext4: group out of range");
        }
        let per_block = self.bs / self.desc_size;
        let index = group / per_block;
        let block = if self.incompat & INCOMPAT_META_BG != 0 && index >= self.first_meta_bg {
            let first = index * per_block;
            self.first_data_block + first * self.blocks_per_group + u64::from(self.has_super(first))
        } else {
            self.first_data_block + 1 + index
        };
        let data = match self.desc_cache.get(block) {
            Some(d) => d,
            None => {
                let d = Rc::new(self.block(block)?);
                self.desc_cache.put(block, d.clone());
                d
            }
        };
        let off = ((group % per_block) * self.desc_size) as usize;
        let mut t = le32(&data, off + 0x08)? as u64;
        if self.desc_size >= 64 {
            t |= (le32(&data, off + 0x28)? as u64) << 32;
        }
        Ok(t)
    }

    fn inode(&self, ino: u64) -> Result<Inode> {
        if ino == 0 || ino > self.inodes_count {
            return corrupt(format!("ext4: inode {ino} out of range"));
        }
        let group = (ino - 1) / self.inodes_per_group;
        let index = (ino - 1) % self.inodes_per_group;
        let table = self.inode_table(group)?;
        let off = table
            .checked_mul(self.bs)
            .and_then(|o| o.checked_add(index * self.inode_size))
            .ok_or_else(|| crate::error::Error::Corrupt("ext4: inode offset overflow".into()))?;
        let raw = self.dev.read_vec(off, self.inode_size as usize)?;
        let mode = le16(&raw, 0)? as u32;
        let size = le32(&raw, 4)? as u64 | (le32(&raw, 0x6c)? as u64) << 32;
        let flags = le32(&raw, 0x20)?;
        Ok(Inode {
            raw,
            mode,
            size,
            flags,
        })
    }

    fn extents(&self, ino: &Inode) -> Result<Vec<Extent>> {
        if ino.flags & FL_EXTENTS != 0 {
            let mut out = Vec::new();
            let mut budget = 1usize << 18;
            self.walk_extents(ino.i_block(), 0, &mut out, &mut budget)?;
            out.sort_by_key(|e| e.logical);
            return Ok(out);
        }
        self.block_map(ino)
    }

    fn walk_extents(
        &self,
        node: &[u8],
        depth: u32,
        out: &mut Vec<Extent>,
        budget: &mut usize,
    ) -> Result<()> {
        if depth > MAX_DEPTH {
            return corrupt("ext4: extent tree too deep");
        }
        *budget = budget.checked_sub(1).ok_or_else(|| {
            crate::error::Error::Limit("ext4: extent walk visited too many nodes".into())
        })?;
        if le16(node, 0)? != EXTENT_MAGIC {
            return corrupt("ext4: bad extent header");
        }
        let entries = le16(node, 2)? as usize;
        let level = le16(node, 6)?;
        crate::stats::hit(if level == 0 {
            crate::stats::C::ext4_extent_leaf_node
        } else {
            crate::stats::C::ext4_extent_index_node
        });
        if 12 + entries * 12 > node.len() {
            return corrupt("ext4: extent entries past the node");
        }
        for i in 0..entries {
            let e = slice(node, 12 + i * 12, 12)?;
            if level == 0 {
                let raw_len = le16(e, 4)? as u64;
                let (len, uninit) = if raw_len > 32768 {
                    (raw_len - 32768, true)
                } else {
                    (raw_len, false)
                };
                let physical = (le16(e, 6)? as u64) << 32 | le32(e, 8)? as u64;
                out.push(Extent {
                    logical: le32(e, 0)? as u64,
                    physical,
                    len,
                    uninit,
                });
                if out.len() > MAX_EXTENTS {
                    return limit("ext4: too many extents");
                }
            } else {
                let child = le32(e, 4)? as u64 | (le16(e, 8)? as u64) << 32;
                let block = self.block(child)?;
                self.walk_extents(&block, depth + 1, out, budget)?;
            }
        }
        Ok(())
    }

    /// ext2/3 block map: 12 direct pointers, then single/double/triple indirect.
    fn block_map(&self, ino: &Inode) -> Result<Vec<Extent>> {
        let nblocks = ino.size.div_ceil(self.bs);
        let per = self.bs / 4;
        let mut out: Vec<Extent> = Vec::new();
        let push = |logical: u64, phys: u64, out: &mut Vec<Extent>| -> Result<()> {
            if let Some(last) = out.last_mut() {
                if last.logical + last.len == logical && last.physical + last.len == phys {
                    last.len += 1;
                    return Ok(());
                }
            }
            out.push(Extent {
                logical,
                physical: phys,
                len: 1,
                uninit: false,
            });
            if out.len() > MAX_EXTENTS {
                return limit("ext4: too many mapped blocks");
            }
            Ok(())
        };
        let ib = ino.i_block();
        for i in 0..12u64 {
            if i >= nblocks {
                return Ok(out);
            }
            let p = le32(ib, (i * 4) as usize)? as u64;
            if p != 0 {
                crate::stats::hit(crate::stats::C::ext4_blockmap_direct);
                push(i, p, &mut out)?;
            }
        }
        // (pointer, depth, first logical block it maps)
        let mut base = 12u64;
        for (slot, depth) in [(12usize, 1u32), (13, 2), (14, 3)] {
            let span = per.pow(depth);
            if base >= nblocks {
                break;
            }
            let p = le32(ib, slot * 4)? as u64;
            if p != 0 {
                self.indirect(
                    p,
                    depth,
                    base,
                    nblocks,
                    per,
                    &mut |l, ph, o| push(l, ph, o),
                    &mut out,
                )?;
            }
            base += span;
        }
        Ok(out)
    }

    #[allow(clippy::too_many_arguments)]
    fn indirect(
        &self,
        block: u64,
        depth: u32,
        base: u64,
        nblocks: u64,
        per: u64,
        push: PushBlock,
        out: &mut Vec<Extent>,
    ) -> Result<()> {
        let data = self.block(block)?;
        crate::stats::hit(crate::stats::C::ext4_blockmap_indirect);
        let span = per.pow(depth - 1);
        for i in 0..per {
            let logical = base + i * span;
            if logical >= nblocks {
                break;
            }
            let p = le32(&data, (i * 4) as usize)? as u64;
            if p == 0 {
                continue;
            }
            if depth == 1 {
                push(logical, p, out)?;
            } else {
                self.indirect(p, depth - 1, logical, nblocks, per, push, out)?;
            }
        }
        Ok(())
    }

    /// `i_block` followed by the `system.data` in-inode xattr.
    fn inline_data(&self, ino: &Inode) -> Result<Vec<u8>> {
        let mut data = ino.i_block().to_vec();
        if ino.raw.len() > 128 {
            let extra = le16(&ino.raw, 0x80)? as usize;
            let start = 128 + extra;
            if start + 4 <= ino.raw.len() && le32(&ino.raw, start)? == 0xEA02_0000 {
                let entries = start + 4;
                let mut pos = entries;
                while pos + 16 <= ino.raw.len() {
                    let name_len = u8_at(&ino.raw, pos)? as usize;
                    let index = u8_at(&ino.raw, pos + 1)?;
                    if name_len == 0 && index == 0 {
                        break;
                    }
                    let value_off = le16(&ino.raw, pos + 2)? as usize;
                    let value_size = le32(&ino.raw, pos + 8)? as usize;
                    let name = slice(&ino.raw, pos + 16, name_len)?;
                    if index == 7 && name == b"data" {
                        data.extend_from_slice(slice(&ino.raw, entries + value_off, value_size)?);
                        break;
                    }
                    pos += (16 + name_len + 3) & !3;
                }
            }
        }
        Ok(data)
    }

    fn contents(&self, ino: &Inode, max: u64) -> Result<Vec<u8>> {
        if ino.size > max {
            return limit(format!("ext4: file of {} bytes exceeds {max}", ino.size));
        }
        self.contents_range(ino, 0, ino.size)
    }

    fn contents_range(&self, ino: &Inode, offset: u64, len: u64) -> Result<Vec<u8>> {
        if ino.flags & FL_ENCRYPT != 0 {
            return unsupported("ext4: encrypted inode");
        }
        let end = ino.size.min(offset.saturating_add(len));
        if offset >= end {
            return Ok(Vec::new());
        }
        if (end - offset) as usize > crate::io::MAX_READ {
            return limit("ext4: range read too large");
        }
        if ino.flags & FL_INLINE_DATA != 0 {
            // Past the inline bytes the kernel zero-fills (ext4_readpage_inline);
            // mke2fs writes an all-zero file this way.
            crate::stats::hit(crate::stats::C::ext4_inline_data);
            // Only up to the end of the requested range: `i_size` is untrusted.
            let mut d = self.inline_data(ino)?;
            d.resize(end as usize, 0);
            return Ok(d[offset as usize..].to_vec());
        }
        let mut out = vec![0u8; (end - offset) as usize];
        for e in self.extents(ino)? {
            if e.uninit {
                crate::stats::hit(crate::stats::C::ext4_uninit_extent);
                continue;
            }
            let es = e.logical.saturating_mul(self.bs);
            let ee = es.saturating_add(e.len.saturating_mul(self.bs));
            let (from, to) = (es.max(offset), ee.min(end));
            if from >= to {
                continue;
            }
            let phys = e
                .physical
                .checked_mul(self.bs)
                .and_then(|p| p.checked_add(from - es))
                .ok_or_else(|| {
                    crate::error::Error::Corrupt("ext4: extent offset overflow".into())
                })?;
            self.dev.read_at(
                phys,
                &mut out[(from - offset) as usize..(to - offset) as usize],
            )?;
        }
        Ok(out)
    }

    fn parse_dirents(&self, data: &[u8], out: &mut Vec<DirEntry>) -> Result<()> {
        let filetype = self.incompat & INCOMPAT_FILETYPE != 0;
        let mut pos = 0usize;
        while pos + 8 <= data.len() {
            let ino = le32(data, pos)? as u64;
            let mut rec = le16(data, pos + 4)? as usize;
            if rec == 0 || rec == 65535 {
                // Encodings of a whole 64 KiB block (ext4_rec_len_from_disk).
                rec = if self.bs >= 65536 {
                    data.len() - pos
                } else {
                    return corrupt("ext4: zero dirent length");
                };
            }
            if rec < 8 || pos + rec > data.len() || !rec.is_multiple_of(4) {
                return corrupt("ext4: bad dirent record length");
            }
            let name_len = if filetype {
                u8_at(data, pos + 6)? as usize
            } else {
                le16(data, pos + 6)? as usize
            };
            if ino != 0 && name_len > 0 && 8 + name_len <= rec {
                out.push(DirEntry {
                    name: slice(data, pos + 8, name_len)?.to_vec(),
                    node: NodeId(0, ino),
                });
            }
            pos += rec;
        }
        Ok(())
    }
}

impl FileSystem for Ext4 {
    fn type_name(&self) -> &'static str {
        "ext4"
    }

    fn root(&self) -> NodeId {
        NodeId(0, 2)
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
        let ino = self.inode(dir.1)?;
        if kind_from_mode(ino.mode) != Kind::Dir {
            return corrupt("ext4: not a directory");
        }
        let mut out = Vec::new();
        if ino.flags & FL_INLINE_DATA != 0 {
            let d = self.inline_data(&ino)?;
            let parent = le32(&d, 0)? as u64;
            out.push(DirEntry {
                name: b"..".to_vec(),
                node: NodeId(0, parent),
            });
            self.parse_dirents(slice(&d, 4, 56)?, &mut out)?;
            if d.len() > 60 {
                self.parse_dirents(&d[60..], &mut out)?;
            }
            return Ok(out);
        }
        if ino.flags & 0x1000 != 0 {
            crate::stats::hit(crate::stats::C::ext4_htree_dir);
        }
        let data = self.contents(&ino, 256 << 20)?;
        for block in data.chunks(self.bs as usize) {
            self.parse_dirents(block, &mut out)?;
        }
        Ok(out)
    }

    fn read_file(&self, node: NodeId, max: u64) -> Result<Vec<u8>> {
        let i = self.inode(node.1)?;
        self.contents(&i, max)
    }

    fn read_range(&self, node: NodeId, offset: u64, len: u64) -> Result<Vec<u8>> {
        let i = self.inode(node.1)?;
        self.contents_range(&i, offset, len)
    }

    fn read_link(&self, node: NodeId) -> Result<Vec<u8>> {
        let i = self.inode(node.1)?;
        if i.size > 4096 {
            return corrupt("ext4: symlink target too long");
        }
        if i.flags & FL_INLINE_DATA != 0 {
            return self.contents(&i, 4096);
        }
        let mut blocks = le32(&i.raw, 0x1c)? as u64;
        if i.flags & FL_HUGE_FILE != 0 {
            blocks *= self.bs / 512;
        }
        let ea_blocks = if le32(&i.raw, 0x68)? != 0 {
            self.bs / 512
        } else {
            0
        };
        if blocks.saturating_sub(ea_blocks) == 0 {
            // Fast symlink: the target lives in i_block.
            crate::stats::hit(crate::stats::C::ext4_fast_symlink);
            return Ok(slice(i.i_block(), 0, i.size as usize)?.to_vec());
        }
        crate::stats::hit(crate::stats::C::ext4_block_symlink);
        self.contents(&i, 4096)
    }
}
