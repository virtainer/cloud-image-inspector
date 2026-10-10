#![allow(dead_code)]
use cloud_image_inspector::error::Result;
use cloud_image_inspector::io::{check_range, ReadAt};
use std::collections::BTreeMap;
use std::rc::Rc;

pub struct Memory(pub Vec<u8>);
impl ReadAt for Memory {
    fn size(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_at(&self, off: u64, out: &mut [u8]) -> Result<()> {
        check_range(self.size(), off, out.len())?;
        out.copy_from_slice(&self.0[off as usize..off as usize + out.len()]);
        Ok(())
    }
}
pub fn dev(bytes: Vec<u8>) -> Rc<dyn ReadAt> {
    Rc::new(Memory(bytes))
}
pub fn p16(b: &mut [u8], o: usize, n: u16) {
    b[o..o + 2].copy_from_slice(&n.to_le_bytes());
}
pub fn p32(b: &mut [u8], o: usize, n: u32) {
    b[o..o + 4].copy_from_slice(&n.to_le_bytes());
}
pub fn p64(b: &mut [u8], o: usize, n: u64) {
    b[o..o + 8].copy_from_slice(&n.to_le_bytes());
}
pub fn wide(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}
fn align(n: usize, a: usize) -> usize {
    n.div_ceil(a) * a
}

#[derive(Default)]
pub struct Tree {
    pub data: Option<Vec<u8>>,
    pub children: BTreeMap<String, Tree>,
}
impl Tree {
    pub fn insert(&mut self, path: &str, data: Vec<u8>) {
        let mut node = self;
        for c in path.split('/').filter(|c| !c.is_empty()) {
            node = node.children.entry(c.into()).or_default();
        }
        node.data = Some(data);
    }
}

struct FatBuilder {
    bytes: Vec<u8>,
    bits: u8,
    fat: usize,
    data: usize,
    next: u32,
}
impl FatBuilder {
    fn link(&mut self, c: u32, next: u32) {
        let n = if next == u32::MAX {
            match self.bits {
                12 => 0xfff,
                16 => 0xffff,
                _ => 0x0fffffff,
            }
        } else {
            next
        };
        match self.bits {
            12 => {
                let off = self.fat + c as usize * 3 / 2;
                let mut value = u16::from_le_bytes([self.bytes[off], self.bytes[off + 1]]);
                if c & 1 == 0 {
                    value = (value & 0xf000) | n as u16;
                } else {
                    value = (value & 15) | ((n as u16) << 4);
                }
                p16(&mut self.bytes, off, value);
            }
            16 => p16(&mut self.bytes, self.fat + c as usize * 2, n as u16),
            _ => p32(&mut self.bytes, self.fat + c as usize * 4, n),
        }
    }
    fn store(&mut self, data: &[u8]) -> u32 {
        if data.is_empty() {
            return 0;
        }
        let first = self.next;
        for block in data.chunks(512) {
            let c = self.next;
            self.next += 1;
            let o = self.data + (c as usize - 2) * 512;
            self.bytes[o..o + block.len()].copy_from_slice(block);
            self.link(
                c,
                if block.len() == 512 && (c - first + 1) as usize * 512 < data.len() {
                    c + 1
                } else {
                    u32::MAX
                },
            );
        }
        first
    }
    fn directory(&mut self, tree: &Tree) -> Vec<u8> {
        let mut entries = Vec::new();
        for (i, (name, child)) in tree.children.iter().enumerate() {
            let (cluster, size, attr) = if let Some(data) = &child.data {
                (self.store(data), data.len(), 32)
            } else {
                let mut data = self.directory(child);
                data.resize(align(data.len() + 32, 512), 0);
                (self.store(&data), 0, 16)
            };
            let alias = format!("F{i:07}BIN").into_bytes();
            let checksum = alias
                .iter()
                .fold(0u8, |s, b| s.rotate_right(1).wrapping_add(*b));
            let mut words: Vec<u16> = name.encode_utf16().collect();
            words.push(0);
            words.resize(align(words.len(), 13), 0xffff);
            for index in (0..words.len() / 13).rev() {
                let mut e = [0u8; 32];
                e[0] = (index + 1) as u8
                    | if index == words.len() / 13 - 1 {
                        0x40
                    } else {
                        0
                    };
                e[11] = 15;
                e[13] = checksum;
                for (j, off) in [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30]
                    .iter()
                    .enumerate()
                {
                    p16(&mut e, *off, words[index * 13 + j]);
                }
                entries.extend_from_slice(&e);
            }
            let mut e = [0u8; 32];
            e[..11].copy_from_slice(&alias);
            e[11] = attr;
            p16(&mut e, 26, cluster as u16);
            if self.bits == 32 {
                p16(&mut e, 20, (cluster >> 16) as u16);
            }
            p32(&mut e, 28, size as u32);
            entries.extend_from_slice(&e);
        }
        entries
    }
}
pub fn fat(bits: u8, tree: &Tree) -> Vec<u8> {
    let count = match bits {
        12 => 2000,
        16 => 5000,
        _ => 65525,
    };
    let fats = align(((count + 2) * bits as usize).div_ceil(8), 512) / 512;
    let reserved = if bits == 32 { 32 } else { 1 };
    let roots = if bits == 32 { 0 } else { 4 };
    let data = (reserved + fats + roots) * 512;
    let total = data / 512 + count;
    let mut f = FatBuilder {
        bytes: vec![0u8; total * 512],
        bits,
        fat: reserved * 512,
        data,
        next: if bits == 32 { 3 } else { 2 },
    };
    f.bytes[..3].copy_from_slice(&[0xeb, 0x3c, 0x90]);
    p16(&mut f.bytes, 11, 512);
    f.bytes[13] = 1;
    p16(&mut f.bytes, 14, reserved as u16);
    f.bytes[16] = 1;
    p16(&mut f.bytes, 17, (roots * 16) as u16);
    p32(&mut f.bytes, 32, total as u32);
    p16(&mut f.bytes, 510, 0xaa55);
    if bits == 32 {
        p32(&mut f.bytes, 36, fats as u32);
        p32(&mut f.bytes, 44, 2);
        f.bytes[82..90].copy_from_slice(b"FAT32   ");
    } else {
        p16(&mut f.bytes, 22, fats as u16);
        f.bytes[54..62].copy_from_slice(if bits == 12 { b"FAT12   " } else { b"FAT16   " });
    }
    let entries = f.directory(tree);
    if bits == 32 {
        assert!(entries.len() < 512);
        f.bytes[data..data + entries.len()].copy_from_slice(&entries);
        f.link(2, u32::MAX);
    } else {
        assert!(entries.len() < roots * 512);
        let off = (reserved + fats) * 512;
        f.bytes[off..off + entries.len()].copy_from_slice(&entries);
    }
    f.bytes
}

#[derive(Default)]
struct Key {
    values: Vec<(String, u32, Vec<u8>)>,
    children: BTreeMap<String, Key>,
}
pub struct HiveBuilder {
    root: Key,
    cells: Vec<(u32, Vec<u8>)>,
    pos: usize,
    bins: Vec<(usize, usize)>,
    pub index: [u8; 2],
}
impl Default for HiveBuilder {
    fn default() -> Self {
        Self {
            root: Key::default(),
            cells: Vec::new(),
            pos: 32,
            bins: vec![(0, 4096)],
            index: *b"lh",
        }
    }
}
impl HiveBuilder {
    pub fn set(&mut self, path: &str, name: &str, kind: u32, data: Vec<u8>) {
        let mut key = &mut self.root;
        for part in path.split('\\').filter(|c| !c.is_empty()) {
            key = key.children.entry(part.into()).or_default();
        }
        key.values.push((name.into(), kind, data));
    }
    pub fn sz(&mut self, path: &str, name: &str, value: &str) {
        self.set(path, name, 1, wide(&format!("{value}\0")));
    }
    pub fn dw(&mut self, path: &str, name: &str, value: u32) {
        self.set(path, name, 4, value.to_le_bytes().to_vec());
    }
    fn cell(&mut self, data: Vec<u8>) -> u32 {
        let len = align(data.len() + 4, 8);
        let (begin, size) = *self.bins.last().unwrap();
        let end = begin + size;
        if len > end - self.pos {
            self.bins.push((end, align(32 + len, 4096)));
            self.pos = end + 32;
        }
        let off = self.pos as u32;
        self.pos += len;
        self.cells.push((off, data));
        off
    }
    fn key(&mut self, name: &str, parent: u32, key: Key) -> u32 {
        let mut nk = vec![0u8; 76 + name.len()];
        nk[..2].copy_from_slice(b"nk");
        p16(&mut nk, 2, 0x20);
        p32(&mut nk, 16, parent);
        p16(&mut nk, 72, name.len() as u16);
        nk[76..].copy_from_slice(name.as_bytes());
        let off = self.cell(nk.clone());
        let mut children = Vec::new();
        for (name, child) in key.children {
            children.push(self.key(&name, off, child));
        }
        if !children.is_empty() {
            let stride = if self.index == *b"lf" || self.index == *b"lh" {
                8
            } else {
                4
            };
            let sig = if self.index == *b"ri" {
                *b"li"
            } else {
                self.index
            };
            let mut index = vec![0; 4 + children.len() * stride];
            index[..2].copy_from_slice(&sig);
            p16(&mut index, 2, children.len() as u16);
            for (i, c) in children.iter().enumerate() {
                p32(&mut index, 4 + i * stride, *c);
            }
            let mut list = self.cell(index);
            if self.index == *b"ri" {
                let mut ri = vec![0; 8];
                ri[..2].copy_from_slice(b"ri");
                p16(&mut ri, 2, 1);
                p32(&mut ri, 4, list);
                list = self.cell(ri);
            }
            p32(&mut nk, 20, children.len() as u32);
            p32(&mut nk, 28, list);
        }
        let mut values = Vec::new();
        for (name, kind, data) in key.values {
            let mut vk = vec![0u8; 20 + name.len()];
            vk[..2].copy_from_slice(b"vk");
            p16(&mut vk, 2, name.len() as u16);
            p32(&mut vk, 12, kind);
            p16(&mut vk, 16, 1);
            vk[20..].copy_from_slice(name.as_bytes());
            if data.len() <= 4 {
                p32(&mut vk, 4, data.len() as u32 | 0x80000000);
                vk[8..8 + data.len()].copy_from_slice(&data);
            } else {
                p32(&mut vk, 4, data.len() as u32);
                let dataoff = if data.len() > 16344 {
                    let mut list = Vec::new();
                    for segment in data.chunks(16344) {
                        list.extend_from_slice(&self.cell(segment.to_vec()).to_le_bytes());
                    }
                    let count = list.len() / 4;
                    let list = self.cell(list);
                    let mut db = vec![0; 8];
                    db[..2].copy_from_slice(b"db");
                    p16(&mut db, 2, count as u16);
                    p32(&mut db, 4, list);
                    self.cell(db)
                } else {
                    self.cell(data)
                };
                p32(&mut vk, 8, dataoff);
            }
            values.push(self.cell(vk));
        }
        if !values.is_empty() {
            let mut list = Vec::new();
            for v in &values {
                list.extend_from_slice(&v.to_le_bytes());
            }
            p32(&mut nk, 36, values.len() as u32);
            p32(&mut nk, 40, self.cell(list));
        }
        self.cells.iter_mut().find(|(o, _)| *o == off).unwrap().1 = nk;
        off
    }
    pub fn finish(mut self, dirty: bool) -> Vec<u8> {
        let root = std::mem::take(&mut self.root);
        let root = self.key("ROOT", u32::MAX, root);
        let bins = self.bins;
        let (last, size) = *bins.last().unwrap();
        let end = last + size;
        let mut b = vec![0; 4096 + end];
        b[..4].copy_from_slice(b"regf");
        p32(&mut b, 4, 2);
        p32(&mut b, 8, if dirty { 1 } else { 2 });
        p32(&mut b, 20, 1);
        p32(&mut b, 24, 5);
        p32(&mut b, 32, 1);
        p32(&mut b, 36, root);
        p32(&mut b, 40, end as u32);
        p32(&mut b, 44, 1);
        for (begin, len) in &bins {
            let o = 4096 + begin;
            b[o..o + 4].copy_from_slice(b"hbin");
            p32(&mut b, o + 4, *begin as u32);
            p32(&mut b, o + 8, *len as u32);
        }
        let mut lengths = BTreeMap::new();
        for (off, data) in self.cells {
            let o = 4096 + off as usize;
            let len = align(data.len() + 4, 8);
            p32(&mut b, o, (-(len as i32)) as u32);
            b[o + 4..o + 4 + data.len()].copy_from_slice(&data);
            lengths.insert(off as usize, len);
        }
        for (begin, len) in bins {
            let mut pos = begin + 32;
            while pos < begin + len {
                if let Some(size) = lengths.get(&pos) {
                    pos += size;
                } else {
                    let next = lengths
                        .range(pos..begin + len)
                        .next()
                        .map(|(o, _)| *o)
                        .unwrap_or(begin + len);
                    p32(&mut b, 4096 + pos, (next - pos) as u32);
                    pos = next;
                }
            }
        }
        checksum(&mut b);
        b
    }
}
pub fn checksum(b: &mut [u8]) {
    let mut sum = 0;
    for p in (0..508).step_by(4) {
        sum ^= u32::from_le_bytes(b[p..p + 4].try_into().unwrap());
    }
    if sum == 0 {
        sum = 1;
    } else if sum == u32::MAX {
        sum -= 1;
    }
    p32(b, 508, sum);
}

pub fn resident(kind: u32, name: &str, id: u16, data: &[u8]) -> Vec<u8> {
    let n = wide(name);
    let off = align(24 + n.len(), 8);
    let mut b = vec![0; align(off + data.len(), 8)];
    let len = b.len();
    p32(&mut b, 0, kind);
    p32(&mut b, 4, len as u32);
    b[9] = (n.len() / 2) as u8;
    p16(&mut b, 10, 24);
    p16(&mut b, 14, id);
    p32(&mut b, 16, data.len() as u32);
    p16(&mut b, 20, off as u16);
    b[24..24 + n.len()].copy_from_slice(&n);
    b[off..off + data.len()].copy_from_slice(data);
    b
}
#[allow(clippy::too_many_arguments)]
pub fn nonresident(
    kind: u32,
    name: &str,
    id: u16,
    first: u64,
    last: u64,
    size: u64,
    initialized: u64,
    flags: u16,
    runs: &[u8],
) -> Vec<u8> {
    let n = wide(name);
    let off = align(64 + n.len(), 8);
    let mut b = vec![0; align(off + runs.len(), 8)];
    let len = b.len();
    p32(&mut b, 0, kind);
    p32(&mut b, 4, len as u32);
    b[8] = 1;
    b[9] = (n.len() / 2) as u8;
    p16(&mut b, 10, 64);
    p16(&mut b, 12, flags);
    p16(&mut b, 14, id);
    p64(&mut b, 16, first);
    p64(&mut b, 24, last);
    p16(&mut b, 32, off as u16);
    p64(&mut b, 40, (last - first + 1) * 512);
    p64(&mut b, 48, size);
    p64(&mut b, 56, initialized);
    b[64..64 + n.len()].copy_from_slice(&n);
    b[off..off + runs.len()].copy_from_slice(runs);
    b
}
pub fn protect(b: &mut [u8], usa: usize) {
    let count = b.len() / 512 + 1;
    p16(b, 4, usa as u16);
    p16(b, 6, count as u16);
    p16(b, usa, 0xa55a);
    for i in 1..count {
        let word = u16::from_le_bytes([b[i * 512 - 2], b[i * 512 - 1]]);
        p16(b, usa + i * 2, word);
        p16(b, i * 512 - 2, 0xa55a);
    }
}
pub fn record(dir: bool, base: u64, attrs: Vec<Vec<u8>>) -> Vec<u8> {
    let mut b = vec![0; 1024];
    b[..4].copy_from_slice(b"FILE");
    p16(&mut b, 16, 1);
    p16(&mut b, 20, 56);
    p16(&mut b, 22, if dir { 3 } else { 1 });
    p32(&mut b, 28, 1024);
    p64(&mut b, 32, base);
    let mut pos = 56;
    for a in attrs {
        assert!(pos + a.len() + 4 < 1024);
        b[pos..pos + a.len()].copy_from_slice(&a);
        pos += a.len();
    }
    p32(&mut b, pos, u32::MAX);
    p32(&mut b, 24, (pos + 4) as u32);
    protect(&mut b, 48);
    b
}
pub fn index_entry(name: &str, id: u64, child: Option<u64>) -> Vec<u8> {
    let n = wide(name);
    let key = 66 + n.len();
    let size = align(16 + key, 8) + if child.is_some() { 8 } else { 0 };
    let mut b = vec![0; size];
    p64(&mut b, 0, (1 << 48) | id);
    p16(&mut b, 8, size as u16);
    p16(&mut b, 10, key as u16);
    p16(&mut b, 12, if child.is_some() { 1 } else { 0 });
    b[16 + 64] = (n.len() / 2) as u8;
    b[16 + 65] = 1;
    b[82..82 + n.len()].copy_from_slice(&n);
    if let Some(c) = child {
        p64(&mut b, size - 8, c);
    }
    b
}
pub fn index_end(child: Option<u64>) -> Vec<u8> {
    let mut b = vec![0; if child.is_some() { 24 } else { 16 }];
    let len = b.len();
    p16(&mut b, 8, len as u16);
    p16(&mut b, 12, if child.is_some() { 3 } else { 2 });
    if let Some(c) = child {
        p64(&mut b, 16, c);
    }
    b
}
pub fn index_root(entries: &[Vec<u8>]) -> Vec<u8> {
    let size = 32 + entries.iter().map(Vec::len).sum::<usize>();
    let mut b = vec![0; 32];
    p32(&mut b, 0, 0x30);
    p32(&mut b, 4, 1);
    p32(&mut b, 8, 1024);
    b[12] = 2;
    if entries.iter().any(|e| e[12] & 1 != 0) {
        b[28] = 1;
    }
    p32(&mut b, 16, 16);
    p32(&mut b, 20, (size - 16) as u32);
    p32(&mut b, 24, (size - 16) as u32);
    for e in entries {
        b.extend_from_slice(e);
    }
    b
}
pub fn index_block(entries: &[Vec<u8>], vcn: u64) -> Vec<u8> {
    let mut b = vec![0; 1024];
    b[..4].copy_from_slice(b"INDX");
    p64(&mut b, 16, vcn);
    p32(&mut b, 24, 24);
    p32(&mut b, 32, 1000);
    if entries.iter().any(|e| e[12] & 1 != 0) {
        b[36] = 1;
    }
    let mut pos = 48;
    for e in entries {
        b[pos..pos + e.len()].copy_from_slice(e);
        pos += e.len();
    }
    p32(&mut b, 28, (pos - 24) as u32);
    protect(&mut b, 40);
    b
}

pub struct NtfsBuilder {
    pub bytes: Vec<u8>,
    next: u64,
    data: u64,
}
impl NtfsBuilder {
    pub fn new() -> Self {
        let mut b = Self {
            bytes: vec![0; 4 << 20],
            next: 24,
            data: 256,
        };
        b.bytes[3..11].copy_from_slice(b"NTFS    ");
        p16(&mut b.bytes, 11, 512);
        b.bytes[13] = 1;
        p64(&mut b.bytes, 40, 8192);
        p64(&mut b.bytes, 48, 4);
        b.bytes[64] = (-10i8) as u8;
        b.bytes[68] = (-10i8) as u8;
        p16(&mut b.bytes, 510, 0xaa55);
        let mft = nonresident(0x80, "", 0, 0, 127, 65536, 65536, 0, &[0x21, 128, 4, 0, 0]);
        b.put(0, record(false, 0, vec![mft]));
        let mut info = vec![0; 12];
        info[8] = 3;
        info[9] = 1;
        b.put(3, record(false, 0, vec![resident(0x70, "", 0, &info)]));
        b
    }
    pub fn put(&mut self, id: u64, b: Vec<u8>) {
        let pos = 2048 + id as usize * 1024;
        self.bytes[pos..pos + b.len()].copy_from_slice(&b);
    }
    pub fn store(&mut self, bytes: &[u8]) -> u64 {
        let c = self.data;
        self.bytes[c as usize * 512..c as usize * 512 + bytes.len()].copy_from_slice(bytes);
        self.data += bytes.len().div_ceil(512) as u64;
        c
    }
    fn data_attr(&mut self, data: &[u8]) -> Vec<u8> {
        if data.len() < 600 {
            return resident(0x80, "", 0, data);
        }
        let c = self.store(data);
        let count = data.len().div_ceil(512) as u16;
        let mut runs = vec![0x22];
        runs.extend_from_slice(&count.to_le_bytes());
        runs.extend_from_slice(&(c as u16).to_le_bytes());
        runs.push(0);
        nonresident(
            0x80,
            "",
            0,
            0,
            count as u64 - 1,
            data.len() as u64,
            data.len() as u64,
            0,
            &runs,
        )
    }
    fn tree(&mut self, tree: &Tree, id: u64) {
        if let Some(data) = &tree.data {
            let a = self.data_attr(data);
            self.put(id, record(false, 0, vec![a]));
        } else {
            let mut entries = Vec::new();
            for (name, child) in &tree.children {
                let n = self.next;
                self.next += 1;
                assert!(n < 64);
                self.tree(child, n);
                entries.push(index_entry(name, n, None));
            }
            entries.push(index_end(None));
            let root = index_root(&entries);
            self.put(id, record(true, 0, vec![resident(0x90, "$I30", 0, &root)]));
        }
    }
    pub fn finish(mut self, tree: &Tree) -> Vec<u8> {
        self.tree(tree, 5);
        self.bytes
    }
}
pub fn ntfs(tree: &Tree) -> Vec<u8> {
    NtfsBuilder::new().finish(tree)
}

pub fn pe(machine: u16, version: bool) -> Vec<u8> {
    let mut b = vec![0; 1024];
    b[..2].copy_from_slice(b"MZ");
    p32(&mut b, 60, 64);
    b[64..68].copy_from_slice(b"PE\0\0");
    p16(&mut b, 68, machine);
    p16(&mut b, 70, 1);
    p16(&mut b, 84, 240);
    p16(&mut b, 88, 0x20b);
    p32(&mut b, 88 + 108, 16);
    let section = 88 + 240;
    p32(&mut b, section + 12, 0x1000);
    p32(&mut b, section + 16, 512);
    p32(&mut b, section + 20, 512);
    if version {
        p32(&mut b, 88 + 128, 0x1000);
        p32(&mut b, 88 + 132, 512);
        for (offset, id, target) in [(0, 16, 0x80000020), (32, 1, 0x80000040), (64, 1033, 96)] {
            p16(&mut b, 512 + offset + 14, 1);
            p32(&mut b, 512 + offset + 16, id);
            p32(&mut b, 512 + offset + 20, target);
        }
        p32(&mut b, 608, 0x1080);
        p32(&mut b, 612, 92);
        p16(&mut b, 640, 92);
        p16(&mut b, 642, 52);
        let key = wide("VS_VERSION_INFO\0");
        b[646..646 + key.len()].copy_from_slice(&key);
        p32(&mut b, 680, 0xfeef04bd);
        p32(&mut b, 684, 0x10000);
        p32(&mut b, 688, 3);
        p32(&mut b, 692, 4);
    }
    b
}
pub fn windows_tree(dirty: bool, agent: bool) -> Tree {
    let mut system = HiveBuilder::default();
    system.dw("Select", "Current", 2);
    system.dw("ControlSet001\\Services\\viostor", "Start", 3);
    for (name, start) in [("viostor", 0), ("netkvm", 3), ("viosock", 3)] {
        system.dw(&format!("ControlSet002\\Services\\{name}"), "Start", start);
    }
    system.dw(
        "ControlSet002\\Control\\TimeZoneInformation",
        "RealTimeIsUniversal",
        1,
    );
    system.dw("ControlSet002\\Control\\Power", "HibernateEnabled", 0);
    system.dw(
        "ControlSet002\\Control\\Session Manager\\Power",
        "HiberbootEnabled",
        0,
    );
    if agent {
        system.dw("ControlSet002\\Services\\virtainer-guest-agent", "Start", 2);
        system.sz(
            "ControlSet002\\Services\\virtainer-guest-agent",
            "ImagePath",
            "\"C:\\Program Files\\Virtainer\\virtainer-guest-agent.exe\" --service",
        );
    }
    let mut software = HiveBuilder::default();
    let cv = "Microsoft\\Windows NT\\CurrentVersion";
    software.sz(cv, "ProductName", "Windows Server 2022 Datacenter");
    software.sz(cv, "EditionID", "ServerDatacenter");
    software.sz(cv, "InstallationType", "Server");
    software.sz(cv, "CurrentBuildNumber", "20348");
    software.dw(cv, "UBR", 2700);
    software.sz(cv, "SystemRoot", "C:\\Windows");
    software.sz(
        "Microsoft\\Windows\\CurrentVersion\\Setup\\State",
        "ImageState",
        "IMAGE_STATE_GENERALIZE_RESEAL_TO_OOBE",
    );
    let mut tree = Tree::default();
    tree.insert("Windows/System32/config/SYSTEM", system.finish(dirty));
    tree.insert("Windows/System32/config/SOFTWARE", software.finish(false));
    for name in ["viostor", "netkvm", "viosock"] {
        tree.insert(
            &format!("Windows/System32/drivers/{name}.sys"),
            b"driver".to_vec(),
        );
    }
    tree.insert("Windows/System32/ntoskrnl.exe", pe(0x8664, false));
    if agent {
        tree.insert(
            "Program Files/Virtainer/virtainer-guest-agent.exe",
            pe(0x8664, true),
        );
    }
    tree
}
pub fn bcd(inherit: bool) -> Vec<u8> {
    let mut h = HiveBuilder::default();
    let mgr = "Objects\\{9dea862c-5cdd-4e70-acc1-f32b344d4795}\\Elements";
    let id = "{12345678-1234-1234-1234-123456789abc}";
    let loader = format!("Objects\\{id}\\Elements");
    h.dw(&format!("Objects\\{id}\\Description"), "Type", 0x10200003);
    h.set(&format!("{mgr}\\16000020"), "Element", 3, vec![1]);
    h.sz(&format!("{mgr}\\23000003"), "Element", id);
    if inherit {
        let parent = "{01234567-1234-1234-1234-123456789abc}";
        h.set(
            &format!("{loader}\\14000006"),
            "Element",
            7,
            wide(&format!("{parent}\0\0")),
        );
        h.set(
            &format!("Objects\\{parent}\\Elements\\260000b0"),
            "Element",
            3,
            vec![1],
        );
    } else {
        h.set(&format!("{loader}\\260000b0"), "Element", 3, vec![0]);
    }
    h.finish(false)
}
pub fn disk(windows: Vec<u8>, esp: Vec<u8>) -> Vec<u8> {
    let first = 2048usize;
    let second = first + esp.len().div_ceil(512);
    let mut disk = vec![0; (second + windows.len().div_ceil(512)) * 512];
    p16(&mut disk, 510, 0xaa55);
    disk[450] = 0xef;
    p32(&mut disk, 454, first as u32);
    p32(&mut disk, 458, (esp.len() / 512) as u32);
    disk[466] = 7;
    p32(&mut disk, 470, second as u32);
    p32(&mut disk, 474, (windows.len() / 512) as u32);
    disk[first * 512..first * 512 + esp.len()].copy_from_slice(&esp);
    disk[second * 512..second * 512 + windows.len()].copy_from_slice(&windows);
    disk
}

/// A 4 KiB-sector volume whose 4 KiB index blocks are smaller than its clusters.
pub fn large_sector_ntfs_index() -> Vec<u8> {
    const SECTOR: usize = 4096;
    const CLUSTER: usize = 65536;
    let mut bytes = vec![0; 4 << 20];
    bytes[3..11].copy_from_slice(b"NTFS    ");
    p16(&mut bytes, 11, SECTOR as u16);
    bytes[13] = 16;
    let sectors = bytes.len() / SECTOR;
    p64(&mut bytes, 40, sectors as u64);
    p64(&mut bytes, 48, 1);
    bytes[64] = (-10i8) as u8;
    bytes[68] = (-12i8) as u8;
    p16(&mut bytes, 510, 0xaa55);

    let mut mft = nonresident(
        0x80,
        "",
        0,
        0,
        0,
        CLUSTER as u64,
        CLUSTER as u64,
        0,
        &[0x11, 1, 1, 0],
    );
    p64(&mut mft, 40, CLUSTER as u64);
    let mft_record = record(false, 0, vec![mft]);
    bytes[CLUSTER..CLUSTER + 1024].copy_from_slice(&mft_record);
    let volume = record(false, 0, vec![resident(0x70, "", 0, &[0; 12])]);
    bytes[CLUSTER + 3 * 1024..CLUSTER + 4 * 1024].copy_from_slice(&volume);

    // Index blocks smaller than a cluster are addressed in 512-byte units, so the
    // 4 KiB block at byte 4096 of the allocation is VCN 8 even on a 4Kn volume.
    let mut root = index_root(&[index_end(Some(8))]);
    p32(&mut root, 8, SECTOR as u32);
    root[12] = 8; // 512-byte units per index block.
    let mut allocation = nonresident(
        0xa0,
        "$I30",
        1,
        0,
        0,
        (2 * SECTOR) as u64,
        (2 * SECTOR) as u64,
        0,
        &[0x11, 1, 2, 0],
    );
    p64(&mut allocation, 40, CLUSTER as u64);
    let directory = record(
        true,
        0,
        vec![
            resident(0x90, "$I30", 0, &root),
            allocation,
            resident(0xb0, "$I30", 2, &[2]),
        ],
    );
    bytes[CLUSTER + 5 * 1024..CLUSTER + 6 * 1024].copy_from_slice(&directory);
    let file = record(false, 0, vec![resident(0x80, "", 0, b"large-sector index")]);
    bytes[CLUSTER + 24 * 1024..CLUSTER + 25 * 1024].copy_from_slice(&file);

    let mut block = vec![0; SECTOR];
    block[..4].copy_from_slice(b"INDX");
    p64(&mut block, 16, 8);
    p32(&mut block, 24, 40); // Entry offset leaves room for nine USA words.
    p32(&mut block, 32, (SECTOR - 24) as u32);
    let mut pos = 64;
    for entry in [index_entry("file.txt", 24, None), index_end(None)] {
        block[pos..pos + entry.len()].copy_from_slice(&entry);
        pos += entry.len();
    }
    p32(&mut block, 28, (pos - 24) as u32);
    protect(&mut block, 40);
    let offset = 2 * CLUSTER + SECTOR; // Child VCN 8 in 512-byte units.
    bytes[offset..offset + SECTOR].copy_from_slice(&block);
    bytes
}

pub fn two_windows_installations() -> Vec<u8> {
    let mut first = windows_tree(false, false);
    first.insert(
        "Windows/System32/drivers/viostor.sys",
        b"installation one".to_vec(),
    );
    let mut second = windows_tree(false, false);
    second.insert(
        "Windows/System32/drivers/viostor.sys",
        b"installation two".to_vec(),
    );
    let volumes = [ntfs(&first), ntfs(&second)];
    let mut disk = vec![0; 2048 * 512 + volumes.iter().map(Vec::len).sum::<usize>()];
    p16(&mut disk, 510, 0xaa55);
    let mut sector = 2048;
    for (i, volume) in volumes.into_iter().enumerate() {
        let entry = 446 + i * 16;
        disk[entry + 4] = 7;
        p32(&mut disk, entry + 8, sector as u32);
        p32(&mut disk, entry + 12, (volume.len() / 512) as u32);
        disk[sector * 512..sector * 512 + volume.len()].copy_from_slice(&volume);
        sector += volume.len() / 512;
    }
    disk
}

/// Minimal single-device Btrfs data volume, with top-level and nested subvolumes.
pub fn btrfs_data(contents: &[u8]) -> Vec<u8> {
    fn key(b: &mut [u8], off: usize, id: u64, kind: u8, offset: u64) {
        p64(b, off, id);
        b[off + 8] = kind;
        p64(b, off + 9, offset);
    }
    fn checksum(b: &mut [u8]) {
        let mut crc = u32::MAX;
        for byte in &b[32..] {
            crc ^= *byte as u32;
            for _ in 0..8 {
                crc = (crc >> 1) ^ (0x82f63b78 & 0u32.wrapping_sub(crc & 1));
            }
        }
        p32(b, 0, !crc);
    }
    fn leaf(bytes: &mut [u8], address: usize, owner: u64, items: Vec<(u64, u8, u64, Vec<u8>)>) {
        let b = &mut bytes[address..address + 4096];
        p64(b, 0x30, address as u64);
        p64(b, 0x50, 1);
        p64(b, 0x58, owner);
        p32(b, 0x60, items.len() as u32);
        let mut end = 4096;
        for (i, (id, kind, offset, data)) in items.into_iter().enumerate() {
            end -= data.len();
            let at = 0x65 + i * 25;
            key(b, at, id, kind, offset);
            p32(b, at + 17, (end - 0x65) as u32);
            p32(b, at + 21, data.len() as u32);
            b[end..end + data.len()].copy_from_slice(&data);
        }
        checksum(b);
    }
    fn root(address: u64) -> Vec<u8> {
        let mut b = vec![0; 239];
        p64(&mut b, 160, 1);
        p64(&mut b, 168, 256);
        p64(&mut b, 176, address);
        b
    }
    fn files(bytes: &mut [u8], address: usize, owner: u64, data: &[u8]) {
        let mut dir = vec![0; 160];
        p32(&mut dir, 52, 0o040755);
        let mut file = vec![0; 160];
        p64(&mut file, 16, data.len() as u64);
        p32(&mut file, 52, 0o100644);
        let mut entry = vec![0; 34];
        key(&mut entry, 0, 257, 1, 0);
        p16(&mut entry, 27, 4);
        entry[29] = 1;
        entry[30..].copy_from_slice(b"file");
        let mut extent = vec![0; 21];
        p64(&mut extent, 0, 1);
        p64(&mut extent, 8, data.len() as u64);
        extent.extend_from_slice(data);
        leaf(
            bytes,
            address,
            owner,
            vec![
                (256, 1, 0, dir),
                (256, 96, 2, entry),
                (257, 1, 0, file),
                (257, 108, 0, extent),
            ],
        );
    }
    let mut bytes = vec![0; 128 << 10];
    let size = bytes.len();
    let sb = &mut bytes[0x10000..0x11000];
    p64(sb, 0x30, 0x10000);
    sb[0x40..0x48].copy_from_slice(b"_BHRfS_M");
    p64(sb, 0x48, 1);
    p64(sb, 0x50, 0x14000);
    p64(sb, 0x58, 0x15000);
    p64(sb, 0x70, size as u64);
    p64(sb, 0x88, 1);
    p32(sb, 0x90, 4096);
    p32(sb, 0x94, 4096);
    p32(sb, 0xa0, 97);
    key(sb, 0x32b, 256, 228, 0);
    p64(sb, 0x33c, size as u64);
    p64(sb, 0x33c + 24, 2); // System chunk, identity logical-to-physical mapping.
    p16(sb, 0x33c + 44, 1);
    p64(sb, 0x33c + 48, 1);
    checksum(sb);
    let mut reference = vec![0; 22];
    p64(&mut reference, 0, 256);
    p16(&mut reference, 16, 4);
    reference[18..].copy_from_slice(b"data");
    leaf(
        &mut bytes,
        0x14000,
        1,
        vec![
            (5, 132, 0, root(0x16000)),
            (5, 156, 256, reference),
            (256, 132, 0, root(0x17000)),
        ],
    );
    leaf(&mut bytes, 0x15000, 3, vec![]);
    files(&mut bytes, 0x16000, 5, contents);
    files(&mut bytes, 0x17000, 256, b"nested subvolume data");
    bytes
}

pub fn partitioned_volumes(volumes: &[(u8, Vec<u8>)]) -> Vec<u8> {
    assert!(volumes.len() <= 4);
    let mut disk = vec![0; 2048 * 512 + volumes.iter().map(|(_, v)| v.len()).sum::<usize>()];
    p16(&mut disk, 510, 0xaa55);
    let mut sector = 2048;
    for (i, (kind, volume)) in volumes.iter().enumerate() {
        assert!(volume.len().is_multiple_of(512));
        let entry = 446 + i * 16;
        disk[entry + 4] = *kind;
        p32(&mut disk, entry + 8, sector as u32);
        p32(&mut disk, entry + 12, (volume.len() / 512) as u32);
        disk[sector * 512..sector * 512 + volume.len()].copy_from_slice(volume);
        sector += volume.len() / 512;
    }
    disk
}
