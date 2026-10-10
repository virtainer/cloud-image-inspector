//! Read-only primary registry hives. Transaction logs are never replayed.
use crate::bytes::{le16, le32, le64, slice};
use crate::error::{corrupt, limit, unsupported, Error, Result};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashSet};

const MAX_HIVE: usize = 256 << 20;
const MAX_VALUE: usize = 16 << 20;
const MAX_ITEMS: usize = 65536;
const MAX_SUBKEYS: usize = 131072;
const MAX_INDEXES: usize = 8192;
const MAX_KEYS: usize = 1 << 20;
const MAX_CELL_SCANS: usize = 4 << 20;

// Budgets belong to one lookup, never to the number of cells in the hive.
#[derive(Default)]
struct Lookup {
    cell_scans: usize,
    keys: usize,
    indexes: usize,
}
struct Bin {
    end: usize,
    state: RefCell<BinState>,
}
struct BinState {
    next: usize,
    // One bit per eight-byte slot records validated allocated cell starts.
    allocated: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    String(String),
    ExpandString(String),
    MultiString(Vec<String>),
    Dword(u32),
    Qword(u64),
    Binary(Vec<u8>),
}
impl Value {
    pub fn string(&self) -> Option<&str> {
        match self {
            Self::String(s) | Self::ExpandString(s) => Some(s),
            _ => None,
        }
    }
    pub fn dword(&self) -> Option<u32> {
        match self {
            Self::Dword(n) => Some(*n),
            _ => None,
        }
    }
}

pub struct Hive {
    bytes: Vec<u8>,
    bins: BTreeMap<u32, Bin>,
    root: u32,
    pub dirty: bool,
    minor: u32,
}

pub fn utf16(b: &[u8]) -> Result<String> {
    if !b.len().is_multiple_of(2) {
        return corrupt("UTF-16: odd byte length");
    }
    let words: Vec<u16> = b
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16(&words).map_err(|_| Error::Corrupt("invalid UTF-16".into()))
}

fn name(b: &[u8], compressed: bool) -> Result<String> {
    if compressed {
        Ok(b.iter().map(|c| char::from(*c)).collect())
    } else {
        utf16(b)
    }
}

impl Hive {
    /// Validate the base block before exposing sequence-number evidence.
    pub fn header_dirty(bytes: &[u8]) -> Result<bool> {
        if slice(bytes, 0, 4)? != b"regf"
            || le32(bytes, 20)? != 1
            || !(3..=6).contains(&le32(bytes, 24)?)
            || le32(bytes, 28)? != 0
            || le32(bytes, 32)? != 1
            || le32(bytes, 44)? != 1
        {
            return unsupported("registry: primary regf 1.3 through 1.6 required");
        }
        slice(bytes, 0, 4096)?;
        let mut sum = 0u32;
        for p in (0..508).step_by(4) {
            sum ^= le32(bytes, p)?;
        }
        sum = match sum {
            0 => 1,
            u32::MAX => u32::MAX - 1,
            _ => sum,
        };
        if sum != le32(bytes, 508)? {
            return corrupt("registry: base checksum");
        }
        Ok(le32(bytes, 4)? != le32(bytes, 8)?)
    }
    pub fn open(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() > MAX_HIVE {
            return limit("registry: hive size");
        }
        let dirty = Self::header_dirty(&bytes)?;
        let minor = le32(&bytes, 24)?;
        let root = le32(&bytes, 36)?;
        let bins = le32(&bytes, 40)? as usize;
        if bins == 0 || !bins.is_multiple_of(4096) || bins > MAX_HIVE - 4096 {
            return corrupt("registry: bins size");
        }
        slice(&bytes, 4096, bins)?;
        let mut ranges = BTreeMap::new();
        let mut bin = 0usize;
        while bin < bins {
            let hdr = slice(&bytes, 4096 + bin, 32)?;
            if &hdr[..4] != b"hbin" || le32(hdr, 4)? as usize != bin {
                return corrupt("registry: bin header");
            }
            let size = le32(hdr, 8)? as usize;
            if size < 4096 || !size.is_multiple_of(4096) || size > bins - bin {
                return corrupt("registry: bin range");
            }
            ranges.insert(
                bin as u32,
                Bin {
                    end: bin + size,
                    state: RefCell::new(BinState {
                        next: bin + 32,
                        allocated: Vec::new(),
                    }),
                },
            );
            bin += size;
        }
        let h = Self {
            bytes,
            bins: ranges,
            root,
            dirty,
            minor,
        };
        h.nk(root, &mut Lookup::default())?;
        Ok(h)
    }
    fn cell(&self, offset: u32, work: &mut Lookup) -> Result<&[u8]> {
        let invalid = || Error::Corrupt("registry: reference is not an allocated cell".into());
        let (&start, bin) = self.bins.range(..=offset).next_back().ok_or_else(invalid)?;
        let pos = offset as usize;
        if pos < start as usize + 32 || pos >= bin.end || !pos.is_multiple_of(8) {
            return Err(invalid());
        }
        let mut state = bin.state.borrow_mut();
        if state.allocated.is_empty() {
            state.allocated.resize((bin.end - start as usize) / 64, 0);
        }
        // Scan only the prefix of this bin needed to prove the cell boundary.
        // Cache boundaries so repeated path lookups do not rescan cell headers.
        while state.next <= pos {
            if work.cell_scans >= MAX_CELL_SCANS {
                return limit("registry: lookup cell scan budget");
            }
            work.cell_scans += 1;
            let next = state.next;
            let raw = le32(&self.bytes, 4096 + next)? as i32;
            let len = raw.unsigned_abs() as usize;
            if len < 8 || !len.is_multiple_of(8) || len > bin.end - next {
                return corrupt("registry: cell size");
            }
            if raw < 0 {
                let slot = (next - start as usize) / 8;
                state.allocated[slot / 8] |= 1 << (slot % 8);
            }
            state.next += len;
        }
        let slot = (pos - start as usize) / 8;
        if state.allocated[slot / 8] & (1 << (slot % 8)) == 0 {
            return Err(invalid());
        }
        let len = (le32(&self.bytes, 4096 + pos)? as i32).unsigned_abs() as usize;
        slice(&self.bytes, 4096 + pos + 4, len - 4)
    }
    fn nk(&self, offset: u32, work: &mut Lookup) -> Result<&[u8]> {
        let c = self.cell(offset, work)?;
        if slice(c, 0, 2)? != b"nk" {
            return corrupt("registry: expected nk");
        }
        slice(c, 0, 76)?;
        Ok(c)
    }
    fn key_name(&self, offset: u32, work: &mut Lookup) -> Result<String> {
        let c = self.nk(offset, work)?;
        name(
            slice(c, 76, le16(c, 72)? as usize)?,
            le16(c, 2)? & 0x20 != 0,
        )
    }
    fn index(
        &self,
        offset: u32,
        depth: usize,
        work: &mut Lookup,
        seen: &mut HashSet<u32>,
        out: &mut Vec<u32>,
    ) -> Result<()> {
        if depth > 32 || work.indexes >= MAX_INDEXES {
            return limit("registry: subkey index budget");
        }
        work.indexes += 1;
        if !seen.insert(offset) {
            return corrupt("registry: subkey index cycle/alias");
        }
        let c = self.cell(offset, work)?;
        let sig = slice(c, 0, 2)?;
        let n = le16(c, 2)? as usize;
        let stride = match sig {
            b"lf" | b"lh" => 8,
            b"li" | b"ri" => 4,
            _ => return corrupt("registry: subkey index signature"),
        };
        slice(c, 4, n * stride)?;
        for i in 0..n {
            let child = le32(c, 4 + i * stride)?;
            if sig == b"ri" {
                self.index(child, depth + 1, work, seen, out)?;
            } else {
                if out.len() >= MAX_SUBKEYS || work.keys >= MAX_KEYS {
                    return limit("registry: subkeys");
                }
                work.keys += 1;
                self.nk(child, work)?;
                out.push(child);
            }
        }
        Ok(())
    }
    pub fn children(&self, key: u32) -> Result<Vec<(String, u32)>> {
        self.children_at(key, &mut Lookup::default())
    }
    fn children_at(&self, key: u32, work: &mut Lookup) -> Result<Vec<(String, u32)>> {
        let c = self.nk(key, work)?;
        let n = le32(c, 20)? as usize;
        if n > MAX_SUBKEYS {
            return limit("registry: subkeys");
        }
        // Volatile subkeys are memory-only. Their stale count and list pointer
        // can survive in a saved hive, but must never be followed on disk.
        if n == 0 {
            return Ok(Vec::new());
        }
        let mut offsets = Vec::new();
        self.index(le32(c, 28)?, 0, work, &mut HashSet::new(), &mut offsets)?;
        if offsets.len() != n {
            return corrupt("registry: subkey count");
        }
        let mut seen = HashSet::new();
        let mut result = Vec::new();
        for off in offsets {
            let child = self.nk(off, work)?;
            if le32(child, 16)? != key {
                return corrupt("registry: subkey parent");
            }
            let s = self.key_name(off, work)?;
            if !seen.insert(s.to_ascii_uppercase()) {
                return corrupt("registry: duplicate subkey");
            }
            result.push((s, off));
        }
        Ok(result)
    }
    pub fn key(&self, path: &str) -> Result<Option<u32>> {
        self.key_at(path, &mut Lookup::default())
    }
    fn key_at(&self, path: &str, work: &mut Lookup) -> Result<Option<u32>> {
        let mut key = self.root;
        let mut seen = HashSet::from([key]);
        for (i, part) in path
            .split(['\\', '/'])
            .filter(|p| !p.is_empty())
            .enumerate()
        {
            if i >= 128 {
                return limit("registry: key path depth");
            }
            if !part.is_ascii() {
                return unsupported("registry: non-ASCII case-insensitive key lookup");
            }
            let children = self.children_at(key, work)?;
            match children.iter().find(|(n, _)| n.eq_ignore_ascii_case(part)) {
                Some((_, child)) => {
                    if !seen.insert(*child) {
                        return corrupt("registry: key path cycle");
                    }
                    key = *child;
                }
                None if children.iter().any(|(n, _)| !n.is_ascii()) => {
                    return unsupported("registry: non-ASCII case-insensitive key lookup")
                }
                None => return Ok(None),
            }
        }
        Ok(Some(key))
    }
    fn data(&self, offset: u32, len: usize, work: &mut Lookup) -> Result<Vec<u8>> {
        if len > MAX_VALUE {
            return limit("registry: value size");
        }
        let c = self.cell(offset, work)?;
        if len <= 16344 || self.minor < 5 {
            return Ok(slice(c, 0, len)?.to_vec());
        }
        if slice(c, 0, 2)? != b"db" {
            return corrupt("registry: expected big data");
        }
        let count = le16(c, 2)? as usize;
        if count != len.div_ceil(16344) {
            return corrupt("registry: big data segment count");
        }
        let list = self.cell(le32(c, 4)?, work)?;
        slice(list, 0, count * 4)?;
        let mut out = Vec::with_capacity(len);
        let mut seen = HashSet::new();
        for i in 0..count {
            let off = le32(list, i * 4)?;
            if !seen.insert(off) {
                return corrupt("registry: duplicate big data segment");
            }
            let size = (len - out.len()).min(16344);
            out.extend_from_slice(slice(self.cell(off, work)?, 0, size)?);
        }
        Ok(out)
    }
    pub fn value(&self, path: &str, wanted: &str) -> Result<Option<Value>> {
        let mut work = Lookup::default();
        let Some(key) = self.key_at(path, &mut work)? else {
            return Ok(None);
        };
        self.value_from(key, wanted, &mut work)
    }
    pub fn value_at(&self, key: u32, wanted: &str) -> Result<Option<Value>> {
        self.value_from(key, wanted, &mut Lookup::default())
    }
    fn value_from(&self, key: u32, wanted: &str, work: &mut Lookup) -> Result<Option<Value>> {
        if !wanted.is_ascii() {
            return unsupported("registry: non-ASCII value lookup");
        }
        let nk = self.nk(key, work)?;
        let count = le32(nk, 36)? as usize;
        if count > MAX_ITEMS {
            return limit("registry: value count");
        }
        if count == 0 {
            return Ok(None);
        }
        let list = self.cell(le32(nk, 40)?, work)?;
        slice(list, 0, count * 4)?;
        let mut found = None;
        let mut non_ascii = false;
        let mut seen = HashSet::new();
        for i in 0..count {
            let c = self.cell(le32(list, i * 4)?, work)?;
            if slice(c, 0, 2)? != b"vk" {
                return corrupt("registry: expected vk");
            }
            let s = name(slice(c, 20, le16(c, 2)? as usize)?, le16(c, 16)? & 1 != 0)?;
            non_ascii |= !s.is_ascii();
            if !seen.insert(s.to_ascii_uppercase()) {
                return corrupt("registry: duplicate value");
            }
            if s.eq_ignore_ascii_case(wanted) {
                found = Some(c);
            }
        }
        let Some(c) = found else {
            if non_ascii {
                return unsupported("registry: non-ASCII case-insensitive value lookup");
            }
            return Ok(None);
        };
        let size = le32(c, 4)?;
        let len = (size & 0x7fffffff) as usize;
        let b = if size & 0x80000000 != 0 {
            if len > 4 {
                return corrupt("registry: inline value length");
            }
            slice(c, 8, len)?.to_vec()
        } else if len == 0 {
            Vec::new()
        } else {
            self.data(le32(c, 8)?, len, work)?
        };
        let kind = le32(c, 12)?;
        Ok(Some(match kind {
            1 | 2 => {
                let s = utf16(&b)?;
                let s = s.trim_end_matches('\0').to_string();
                if s.contains('\0') {
                    return corrupt("registry: embedded string NUL");
                }
                if kind == 1 {
                    Value::String(s)
                } else {
                    Value::ExpandString(s)
                }
            }
            3 => Value::Binary(b),
            4 if b.len() == 4 => Value::Dword(le32(&b, 0)?),
            11 if b.len() == 8 => Value::Qword(le64(&b, 0)?),
            7 => {
                let s = utf16(&b)?;
                if !s.ends_with("\0\0") {
                    return corrupt("registry: MULTI_SZ terminator");
                }
                let mut strings = Vec::new();
                for part in s
                    .trim_end_matches('\0')
                    .split('\0')
                    .filter(|p| !p.is_empty())
                {
                    if strings.len() >= MAX_ITEMS {
                        return limit("registry: MULTI_SZ item count");
                    }
                    strings.push(part.to_string());
                }
                Value::MultiString(strings)
            }
            4 | 11 => return corrupt("registry: integer length"),
            _ => return unsupported(format!("registry: value type {kind}")),
        }))
    }
}
