//! Positioned reads. Every layer (file → qcow2 → partition → filesystem) is a
//! `ReadAt`, so the filesystem readers never know what container they sit in.

use std::cell::RefCell;
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::rc::Rc;

use crate::error::{corrupt, limit, Result};

/// Largest single read any parser may request. Guards against a lying length field
/// turning into a multi-gigabyte allocation.
pub const MAX_READ: usize = 512 << 20;

pub trait ReadAt {
    fn size(&self) -> u64;
    /// Fill `buf` from `offset`. Reading past `size()` is an error.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()>;

    fn read_vec(&self, offset: u64, len: usize) -> Result<Vec<u8>> {
        if len > MAX_READ {
            return limit(format!("read of {len} bytes exceeds {MAX_READ}"));
        }
        let mut v = vec![0u8; len];
        self.read_at(offset, &mut v)?;
        Ok(v)
    }
}

pub fn check_range(size: u64, offset: u64, len: usize) -> Result<()> {
    match offset.checked_add(len as u64) {
        Some(end) if end <= size => Ok(()),
        _ => corrupt(format!(
            "read of {len} bytes at offset {offset} past end ({size})"
        )),
    }
}

pub struct FileSource {
    file: File,
    size: u64,
}

impl FileSource {
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path)?;
        let size = file.metadata()?.len();
        Ok(Self { file, size })
    }
}

impl ReadAt for FileSource {
    fn size(&self) -> u64 {
        self.size
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_range(self.size, offset, buf.len())?;
        self.file.read_exact_at(buf, offset)?;
        Ok(())
    }
}

/// A sub-range of another source: one partition of a disk.
pub struct Window {
    inner: Rc<dyn ReadAt>,
    start: u64,
    len: u64,
}

impl Window {
    pub fn new(inner: Rc<dyn ReadAt>, start: u64, len: u64) -> Result<Self> {
        match start.checked_add(len) {
            Some(end) if end <= inner.size() => Ok(Self { inner, start, len }),
            _ => corrupt(format!(
                "window {start}+{len} outside a {}-byte device",
                inner.size()
            )),
        }
    }
}

impl ReadAt for Window {
    fn size(&self) -> u64 {
        self.len
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_range(self.len, offset, buf.len())?;
        self.inner.read_at(self.start + offset, buf)
    }
}

/// Small move-to-front cache. Capacities here are tens of entries, so a linear scan
/// beats anything cleverer and keeps the code obviously correct.
pub struct Lru<K: PartialEq + Copy, V: Clone> {
    cap: usize,
    items: RefCell<Vec<(K, V)>>,
}

impl<K: PartialEq + Copy, V: Clone> Lru<K, V> {
    pub fn new(cap: usize) -> Self {
        Self {
            cap: cap.max(1),
            items: RefCell::new(Vec::new()),
        }
    }

    pub fn get(&self, k: K) -> Option<V> {
        let mut items = self.items.borrow_mut();
        let pos = items.iter().position(|(key, _)| *key == k)?;
        let item = items.remove(pos);
        let v = item.1.clone();
        items.insert(0, item);
        Some(v)
    }

    pub fn put(&self, k: K, v: V) {
        let mut items = self.items.borrow_mut();
        if let Some(pos) = items.iter().position(|(key, _)| *key == k) {
            items.remove(pos);
        }
        items.insert(0, (k, v));
        items.truncate(self.cap);
    }
}
