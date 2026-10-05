//! btrfs, read-only, single device, written from the on-disk format documentation
//! (btrfs.readthedocs.io "On-disk format") and the kernel's `btrfs_tree.h`.
//!
//! Bootstraps logical→physical mapping from the superblock's system chunk array,
//! loads the full chunk tree, then reads the root tree to find subvolumes. B-trees of
//! any height are searched by key range; file extents may be inline, regular or
//! preallocated, and compressed with zlib, LZO or zstd.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use crate::bytes::{le16, le32, le64, slice, u8_at};
use crate::compress::{inflate, lzo, zstd};
use crate::error::{corrupt, limit, unsupported, Result};
use crate::fs::{kind_from_mode, DirEntry, FileSystem, Kind, NodeId, Stat};
use crate::io::{Lru, ReadAt};

const SUPER_OFFSET: u64 = 0x10000;
const MAGIC: &[u8; 8] = b"_BHRfS_M";
const HEADER: usize = 0x65;
const ITEM: usize = 25;
const KEY_PTR: usize = 33;

const INODE_ITEM: u8 = 1;
const DIR_ITEM: u8 = 84;
const DIR_INDEX: u8 = 96;
const EXTENT_DATA: u8 = 108;
const ROOT_ITEM: u8 = 132;
const ROOT_REF: u8 = 156;
const CHUNK_ITEM: u8 = 228;

const ROOT_TREE_DIR: u64 = 6;
const FS_TREE: u64 = 5;
const FIRST_FREE: u64 = 256;
const LAST_FREE: u64 = u64::MAX - 255;

const INCOMPAT_EXTENT_TREE_V2: u64 = 0x2000;
const INCOMPAT_RAID_STRIPE_TREE: u64 = 0x4000;
const BG_STRIPED: u64 = (1 << 3) | (1 << 6) | (1 << 7) | (1 << 8); // RAID0/10/5/6

const MAX_DEPTH: u32 = 8;
const MAX_ITEMS: usize = 1 << 22;
const MAX_NODE_VISITS: usize = 1 << 18;
/// btrfs never compresses more than 128 KiB into one extent.
const MAX_COMPRESSED_RAM: u64 = 1 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Key {
    pub objectid: u64,
    pub kind: u8,
    pub offset: u64,
}

impl Key {
    fn parse(b: &[u8], off: usize) -> Result<Self> {
        Ok(Key {
            objectid: le64(b, off)?,
            kind: u8_at(b, off + 8)?,
            offset: le64(b, off + 9)?,
        })
    }
    fn range(objectid: u64, kind: u8) -> (Key, Key) {
        (
            Key {
                objectid,
                kind,
                offset: 0,
            },
            Key {
                objectid,
                kind,
                offset: u64::MAX,
            },
        )
    }
}

#[derive(Clone, Copy, Debug)]
struct Chunk {
    logical: u64,
    length: u64,
    physical: u64,
}

#[derive(Clone, Copy, Debug)]
struct TreeRoot {
    bytenr: u64,
    level: u8,
    root_dirid: u64,
}

#[derive(Clone, Debug)]
pub struct Subvolume {
    pub id: u64,
    pub parent: u64,
    pub name: String,
}

pub struct Btrfs {
    dev: Rc<dyn ReadAt>,
    nodesize: u64,
    sectorsize: u64,
    chunks: Vec<Chunk>,
    root_tree: TreeRoot,
    trees: RefCell<HashMap<u64, TreeRoot>>,
    node_cache: Lru<u64, Rc<Vec<u8>>>,
    /// The subvolume treated as `/`.
    pub root_subvolume: u64,
    pub default_subvolume: u64,
    pub subvolumes: Vec<Subvolume>,
    pub label: String,
}

impl Btrfs {
    pub fn open(dev: Rc<dyn ReadAt>) -> Result<Self> {
        let sb = dev.read_vec(SUPER_OFFSET, 4096)?;
        if slice(&sb, 0x40, 8)? != MAGIC {
            return corrupt("btrfs: bad superblock magic");
        }
        let nodesize = le32(&sb, 0x94)? as u64;
        let sectorsize = le32(&sb, 0x90)? as u64;
        if !(4096..=65536).contains(&nodesize)
            || !nodesize.is_power_of_two()
            || !(512..=65536).contains(&sectorsize)
        {
            return corrupt("btrfs: implausible node or sector size");
        }
        let incompat = le64(&sb, 0xbc)?;
        if incompat & (INCOMPAT_EXTENT_TREE_V2 | INCOMPAT_RAID_STRIPE_TREE) != 0 {
            return unsupported(format!("btrfs incompat features {incompat:#x}"));
        }
        if le64(&sb, 0x88)? != 1 {
            return unsupported("btrfs spanning several devices");
        }
        let mut fs = Self {
            dev,
            nodesize,
            sectorsize,
            chunks: Vec::new(),
            root_tree: TreeRoot {
                bytenr: le64(&sb, 0x50)?,
                level: u8_at(&sb, 0xc6)?,
                root_dirid: 0,
            },
            trees: RefCell::new(HashMap::new()),
            node_cache: Lru::new(64),
            root_subvolume: FS_TREE,
            default_subvolume: FS_TREE,
            subvolumes: Vec::new(),
            label: crate::bytes::cstr(slice(&sb, 0x12b, 256)?),
        };
        // Bootstrap: the system chunks are enough to read the chunk tree.
        let size = le32(&sb, 0xa0)? as usize;
        let array = slice(&sb, 0x32b, size.min(2048))?;
        let mut pos = 0;
        while pos < array.len() {
            let key = Key::parse(array, pos)?;
            if key.kind != CHUNK_ITEM {
                return corrupt("btrfs: non-chunk item in the system chunk array");
            }
            let (chunk, len) = Self::parse_chunk(array, pos + 17, key.offset)?;
            fs.add_chunk(chunk)?;
            pos += 17 + len;
        }
        let chunk_root = TreeRoot {
            bytenr: le64(&sb, 0x58)?,
            level: u8_at(&sb, 0xc7)?,
            root_dirid: 0,
        };
        let mut items = Vec::new();
        fs.search(
            chunk_root,
            Key {
                objectid: 0,
                kind: 0,
                offset: 0,
            },
            Key {
                objectid: u64::MAX,
                kind: u8::MAX,
                offset: u64::MAX,
            },
            &mut items,
        )?;
        for (key, data) in &items {
            if key.kind == CHUNK_ITEM {
                let (chunk, _) = Self::parse_chunk(data, 0, key.offset)?;
                fs.add_chunk(chunk)?;
            }
        }
        fs.load_subvolumes()?;
        fs.root_subvolume = fs.default_subvolume;
        Ok(fs)
    }

    fn parse_chunk(b: &[u8], off: usize, logical: u64) -> Result<(Chunk, usize)> {
        let length = le64(b, off)?;
        let kind = le64(b, off + 24)?;
        let stripes = le16(b, off + 44)? as usize;
        if stripes == 0 {
            return corrupt("btrfs: chunk without stripes");
        }
        if kind & BG_STRIPED != 0 && stripes > 1 {
            return unsupported("btrfs striped (RAID0/10/5/6) chunks");
        }
        // SINGLE and DUP: stripe 0 holds a full copy.
        let physical = le64(b, off + 48 + 8)?;
        Ok((
            Chunk {
                logical,
                length,
                physical,
            },
            48 + 32 * stripes,
        ))
    }

    fn add_chunk(&mut self, c: Chunk) -> Result<()> {
        if c.length == 0
            || c.logical.checked_add(c.length).is_none()
            || c.physical
                .checked_add(c.length)
                .is_none_or(|e| e > self.dev.size())
        {
            return corrupt("btrfs: chunk outside the device");
        }
        if !self.chunks.iter().any(|x| x.logical == c.logical) {
            self.chunks.push(c);
            self.chunks.sort_by_key(|x| x.logical);
        }
        Ok(())
    }

    fn read_logical(&self, logical: u64, buf: &mut [u8]) -> Result<()> {
        let mut done = 0usize;
        while done < buf.len() {
            let addr = logical + done as u64;
            let idx = self.chunks.partition_point(|c| c.logical <= addr);
            let c = match idx.checked_sub(1).and_then(|i| self.chunks.get(i)) {
                Some(c) if addr < c.logical + c.length => *c,
                _ => return corrupt(format!("btrfs: logical address {addr:#x} is in no chunk")),
            };
            let n = ((c.logical + c.length - addr) as usize).min(buf.len() - done);
            self.dev
                .read_at(c.physical + (addr - c.logical), &mut buf[done..done + n])?;
            done += n;
        }
        Ok(())
    }

    fn read_logical_vec(&self, logical: u64, len: u64) -> Result<Vec<u8>> {
        let mut v =
            vec![0u8; crate::bytes::to_usize(len, "btrfs extent")?.min(crate::io::MAX_READ)];
        if v.len() as u64 != len {
            return limit("btrfs: extent too large");
        }
        self.read_logical(logical, &mut v)?;
        Ok(v)
    }

    fn node(&self, bytenr: u64) -> Result<Rc<Vec<u8>>> {
        if let Some(n) = self.node_cache.get(bytenr) {
            return Ok(n);
        }
        let mut b = vec![0u8; self.nodesize as usize];
        self.read_logical(bytenr, &mut b)?;
        if le64(&b, 0x30)? != bytenr {
            return corrupt(format!("btrfs: node at {bytenr:#x} claims another address"));
        }
        let n = Rc::new(b);
        self.node_cache.put(bytenr, n.clone());
        Ok(n)
    }

    /// Every item with `min <= key <= max` under `root`, in key order.
    fn search(
        &self,
        root: TreeRoot,
        min: Key,
        max: Key,
        out: &mut Vec<(Key, Vec<u8>)>,
    ) -> Result<()> {
        let mut budget = MAX_NODE_VISITS;
        self.search_node(root.bytenr, root.level, min, max, out, 0, &mut budget)
    }

    #[allow(clippy::too_many_arguments)]
    fn search_node(
        &self,
        bytenr: u64,
        level: u8,
        min: Key,
        max: Key,
        out: &mut Vec<(Key, Vec<u8>)>,
        depth: u32,
        budget: &mut usize,
    ) -> Result<()> {
        if depth > MAX_DEPTH {
            return corrupt("btrfs: tree too deep");
        }
        // Pointers in a corrupt tree can form a DAG that the depth cap alone does not
        // keep from exploding.
        *budget = budget.checked_sub(1).ok_or_else(|| {
            crate::error::Error::Limit("btrfs: search visited too many nodes".into())
        })?;
        let n = self.node(bytenr)?;
        let nlevel = u8_at(&n, 0x64)?;
        if nlevel != level {
            return corrupt("btrfs: node level does not match its parent");
        }
        let nritems = le32(&n, 0x60)? as usize;
        if level == 0 {
            if HEADER + nritems * ITEM > n.len() {
                return corrupt("btrfs: leaf item count past the node");
            }
            for i in 0..nritems {
                let at = HEADER + i * ITEM;
                let key = Key::parse(&n, at)?;
                if key < min || key > max {
                    continue;
                }
                let off = le32(&n, at + 17)? as usize;
                let size = le32(&n, at + 21)? as usize;
                out.push((key, slice(&n, HEADER + off, size)?.to_vec()));
                if out.len() > MAX_ITEMS {
                    return limit("btrfs: too many items");
                }
            }
            return Ok(());
        }
        if HEADER + nritems * KEY_PTR > n.len() {
            return corrupt("btrfs: node pointer count past the node");
        }
        crate::stats::hit(crate::stats::C::btrfs_tree_interior_node);
        for i in 0..nritems {
            let at = HEADER + i * KEY_PTR;
            let key = Key::parse(&n, at)?;
            if key > max {
                break;
            }
            if i + 1 < nritems && Key::parse(&n, at + KEY_PTR)? <= min {
                continue;
            }
            let child = le64(&n, at + 17)?;
            self.search_node(child, level - 1, min, max, out, depth + 1, budget)?;
        }
        Ok(())
    }

    fn tree(&self, id: u64) -> Result<TreeRoot> {
        if let Some(t) = self.trees.borrow().get(&id) {
            return Ok(*t);
        }
        let (min, max) = Key::range(id, ROOT_ITEM);
        let mut items = Vec::new();
        self.search(self.root_tree, min, max, &mut items)?;
        let Some((_, item)) = items.last() else {
            return corrupt(format!("btrfs: no root item for tree {id}"));
        };
        let t = TreeRoot {
            bytenr: le64(item, 176)?,
            level: u8_at(item, 238)?,
            root_dirid: le64(item, 168)?,
        };
        self.trees.borrow_mut().insert(id, t);
        Ok(t)
    }

    fn load_subvolumes(&mut self) -> Result<()> {
        let mut items = Vec::new();
        self.search(
            self.root_tree,
            Key {
                objectid: 0,
                kind: 0,
                offset: 0,
            },
            Key {
                objectid: u64::MAX,
                kind: u8::MAX,
                offset: u64::MAX,
            },
            &mut items,
        )?;
        for (key, data) in &items {
            if key.kind == ROOT_REF && (FIRST_FREE..=LAST_FREE).contains(&key.offset) {
                let len = le16(data, 16)? as usize;
                self.subvolumes.push(Subvolume {
                    id: key.offset,
                    parent: key.objectid,
                    name: String::from_utf8_lossy(slice(data, 18, len)?).into_owned(),
                });
            }
            if key.objectid == ROOT_TREE_DIR && key.kind == DIR_ITEM {
                for (name, loc) in Self::dir_items(data)? {
                    if name == b"default" {
                        self.default_subvolume = loc.objectid;
                    }
                }
            }
        }
        Ok(())
    }

    /// Full path of a subvolume from the top level (`root`, `@/.snapshots`).
    pub fn subvolume_path(&self, id: u64) -> String {
        let mut parts = Vec::new();
        let mut cur = id;
        for _ in 0..64 {
            let Some(s) = self.subvolumes.iter().find(|s| s.id == cur) else {
                break;
            };
            parts.push(s.name.clone());
            cur = s.parent;
        }
        parts.reverse();
        parts.join("/")
    }

    pub fn set_root_subvolume(&mut self, id: u64) {
        self.root_subvolume = id;
    }

    fn dir_items(data: &[u8]) -> Result<Vec<(Vec<u8>, Key)>> {
        let mut out = Vec::new();
        let mut pos = 0;
        while pos + 30 <= data.len() {
            let loc = Key::parse(data, pos)?;
            let data_len = le16(data, pos + 25)? as usize;
            let name_len = le16(data, pos + 27)? as usize;
            out.push((slice(data, pos + 30, name_len)?.to_vec(), loc));
            pos += 30 + name_len + data_len;
        }
        Ok(out)
    }

    fn inode_item(&self, node: NodeId) -> Result<Vec<u8>> {
        let tree = self.tree(node.0)?;
        let k = Key {
            objectid: node.1,
            kind: INODE_ITEM,
            offset: 0,
        };
        let mut items = Vec::new();
        self.search(tree, k, k, &mut items)?;
        match items.pop() {
            Some((_, d)) => Ok(d),
            None => corrupt(format!("btrfs: no inode {} in tree {}", node.1, node.0)),
        }
    }

    /// The kernel decompresses into a buffer of `ram_bytes` and ignores anything
    /// beyond it: a small file's inline extent is compressed from a whole page, so
    /// its stream can expand past `ram_bytes`. Short output is zero-filled.
    fn decompress(&self, kind: u8, data: &[u8], ram: u64) -> Result<Vec<u8>> {
        if ram > MAX_COMPRESSED_RAM {
            return corrupt("btrfs: compressed extent larger than btrfs ever writes");
        }
        let cap = (ram as usize).max(128 << 10) + self.sectorsize as usize;
        let mut out = match kind {
            1 => inflate::zlib_decompress(data, cap)?,
            2 => lzo::btrfs_lzo_decompress(data, self.sectorsize as usize, cap)?,
            3 => zstd::decompress(data, cap)?,
            k => return unsupported(format!("btrfs compression type {k}")),
        };
        out.resize(ram as usize, 0);
        Ok(out)
    }

    fn contents(&self, node: NodeId, size: u64) -> Result<Vec<u8>> {
        self.contents_range(node, size, 0, size)
    }

    /// Bytes `[offset, offset+len)` of a file of `size` bytes.
    fn contents_range(&self, node: NodeId, size: u64, offset: u64, len: u64) -> Result<Vec<u8>> {
        let end = size.min(offset.saturating_add(len));
        if offset >= end {
            return Ok(Vec::new());
        }
        if (end - offset) as usize > crate::io::MAX_READ {
            return limit("btrfs: range read too large");
        }
        let tree = self.tree(node.0)?;
        // Extents starting before `offset` can still cover it; btrfs never writes one
        // longer than 128 MiB, so begin the search that far back.
        let min = Key {
            objectid: node.1,
            kind: EXTENT_DATA,
            offset: offset.saturating_sub(128 << 20),
        };
        let max = Key {
            objectid: node.1,
            kind: EXTENT_DATA,
            offset: end - 1,
        };
        let mut items = Vec::new();
        self.search(tree, min, max, &mut items)?;
        let mut out = vec![0u8; (end - offset) as usize];
        for (key, e) in items {
            let file_off = key.offset;
            if file_off >= end {
                continue;
            }
            let ram = le64(&e, 8)?;
            let compression = u8_at(&e, 16)?;
            if u8_at(&e, 17)? != 0 || le16(&e, 18)? != 0 {
                return unsupported("btrfs: encrypted or encoded extent");
            }
            let data = match u8_at(&e, 20)? {
                0 => {
                    crate::stats::hit(if compression == 0 {
                        crate::stats::C::btrfs_inline_plain
                    } else {
                        crate::stats::C::btrfs_inline_compressed
                    });
                    let raw = &e[21.min(e.len())..];
                    if compression == 0 {
                        raw.to_vec()
                    } else {
                        self.decompress(compression, raw, ram)?
                    }
                }
                1 => {
                    let disk = le64(&e, 21)?;
                    let disk_len = le64(&e, 29)?;
                    let ext_off = le64(&e, 37)?;
                    let num = le64(&e, 45)?.min(size - file_off.min(size));
                    // The part of this extent inside the requested range.
                    let (from, to) = (file_off.max(offset), (file_off + num).min(end));
                    if from >= to {
                        continue;
                    }
                    if disk == 0 {
                        crate::stats::hit(crate::stats::C::btrfs_hole);
                        continue; // hole
                    }
                    crate::stats::hit(match compression {
                        0 => crate::stats::C::btrfs_regular_plain,
                        1 => crate::stats::C::btrfs_regular_zlib,
                        2 => crate::stats::C::btrfs_regular_lzo,
                        _ => crate::stats::C::btrfs_regular_zstd,
                    });
                    let data = if compression == 0 {
                        self.read_logical_vec(disk + ext_off + (from - file_off), to - from)?
                    } else {
                        let raw = self.read_logical_vec(disk, disk_len)?;
                        let plain = self.decompress(compression, &raw, ram)?;
                        let s = crate::bytes::to_usize(
                            ext_off + (from - file_off),
                            "btrfs extent offset",
                        )?;
                        slice(&plain, s, (to - from) as usize)?.to_vec()
                    };
                    out[(from - offset) as usize..(to - offset) as usize].copy_from_slice(&data);
                    continue;
                }
                2 => {
                    crate::stats::hit(crate::stats::C::btrfs_prealloc);
                    continue; // preallocated: reads as zeros
                }
                t => return corrupt(format!("btrfs: extent type {t}")),
            };
            // Inline extent: always at file offset 0.
            let (from, to) = (
                file_off.max(offset),
                (file_off + data.len() as u64).min(end),
            );
            if from < to {
                out[(from - offset) as usize..(to - offset) as usize]
                    .copy_from_slice(&data[(from - file_off) as usize..(to - file_off) as usize]);
            }
        }
        Ok(out)
    }
}

impl FileSystem for Btrfs {
    fn type_name(&self) -> &'static str {
        "btrfs"
    }

    fn root(&self) -> NodeId {
        let dirid = self
            .tree(self.root_subvolume)
            .map(|t| t.root_dirid)
            .unwrap_or(256);
        NodeId(self.root_subvolume, dirid)
    }

    fn stat(&self, node: NodeId) -> Result<Stat> {
        let i = self.inode_item(node)?;
        let mode = le32(&i, 52)?;
        Ok(Stat {
            kind: kind_from_mode(mode),
            size: le64(&i, 16)?,
            mode,
        })
    }

    fn read_dir(&self, dir: NodeId) -> Result<Vec<DirEntry>> {
        if self.stat(dir)?.kind != Kind::Dir {
            return corrupt("btrfs: not a directory");
        }
        let tree = self.tree(dir.0)?;
        let (min, max) = Key::range(dir.1, DIR_INDEX);
        let mut items = Vec::new();
        self.search(tree, min, max, &mut items)?;
        let mut out = Vec::new();
        for (_, data) in items {
            for (name, loc) in Self::dir_items(&data)? {
                let node = if loc.kind == ROOT_ITEM {
                    // A subvolume boundary: continue at that tree's root directory.
                    crate::stats::hit(crate::stats::C::btrfs_subvolume_crossing);
                    NodeId(loc.objectid, self.tree(loc.objectid)?.root_dirid)
                } else {
                    NodeId(dir.0, loc.objectid)
                };
                out.push(DirEntry { name, node });
            }
        }
        Ok(out)
    }

    fn read_file(&self, node: NodeId, max: u64) -> Result<Vec<u8>> {
        let st = self.stat(node)?;
        if st.size > max {
            return limit(format!("btrfs: file of {} bytes exceeds {max}", st.size));
        }
        self.contents(node, st.size)
    }

    fn read_range(&self, node: NodeId, offset: u64, len: u64) -> Result<Vec<u8>> {
        let st = self.stat(node)?;
        self.contents_range(node, st.size, offset, len)
    }

    fn read_link(&self, node: NodeId) -> Result<Vec<u8>> {
        let st = self.stat(node)?;
        if st.size > 4096 {
            return corrupt("btrfs: symlink target too long");
        }
        self.contents(node, st.size)
    }
}
