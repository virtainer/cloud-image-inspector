//! Read-only primary registry hives. Transaction logs are never replayed.
use crate::bytes::{le16, le32, le64, slice};
use crate::error::{corrupt, limit, unsupported, Error, Result};
use std::collections::{BTreeMap, HashSet};

const MAX_HIVE: usize = 256 << 20;
const MAX_VALUE: usize = 16 << 20;
const MAX_ITEMS: usize = 65536;

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
    cells: BTreeMap<u32, usize>,
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
        let mut cells = BTreeMap::new();
        let mut bin = 0usize;
        let mut count = 0;
        while bin < bins {
            let hdr = slice(&bytes, 4096 + bin, 32)?;
            if &hdr[..4] != b"hbin" || le32(hdr, 4)? as usize != bin {
                return corrupt("registry: bin header");
            }
            let size = le32(hdr, 8)? as usize;
            if size < 4096 || !size.is_multiple_of(4096) || size > bins - bin {
                return corrupt("registry: bin range");
            }
            let mut pos = bin + 32;
            while pos < bin + size {
                count += 1;
                if count > 1_000_000 {
                    return limit("registry: cell budget");
                }
                let raw = le32(&bytes, 4096 + pos)? as i32;
                let len = raw.unsigned_abs() as usize;
                if len < 8 || !len.is_multiple_of(8) || len > bin + size - pos {
                    return corrupt("registry: cell size");
                }
                if raw < 0 {
                    cells.insert(pos as u32, len - 4);
                }
                pos += len;
            }
            bin += size;
        }
        let h = Self {
            bytes,
            cells,
            root,
            dirty,
            minor,
        };
        h.nk(root)?;
        Ok(h)
    }
    fn cell(&self, offset: u32) -> Result<&[u8]> {
        let len = self
            .cells
            .get(&offset)
            .ok_or_else(|| Error::Corrupt("registry: reference is not an allocated cell".into()))?;
        slice(&self.bytes, 4096 + offset as usize + 4, *len)
    }
    fn nk(&self, offset: u32) -> Result<&[u8]> {
        let c = self.cell(offset)?;
        if slice(c, 0, 2)? != b"nk" {
            return corrupt("registry: expected nk");
        }
        slice(c, 0, 76)?;
        Ok(c)
    }
    fn key_name(&self, offset: u32) -> Result<String> {
        let c = self.nk(offset)?;
        name(
            slice(c, 76, le16(c, 72)? as usize)?,
            le16(c, 2)? & 0x20 != 0,
        )
    }
    fn index(
        &self,
        offset: u32,
        depth: usize,
        seen: &mut HashSet<u32>,
        out: &mut Vec<u32>,
    ) -> Result<()> {
        if depth > 32 || seen.len() >= MAX_ITEMS || out.len() >= MAX_ITEMS {
            return limit("registry: subkey index budget");
        }
        if !seen.insert(offset) {
            return corrupt("registry: subkey index cycle/alias");
        }
        let c = self.cell(offset)?;
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
                self.index(child, depth + 1, seen, out)?;
            } else {
                if out.len() >= MAX_ITEMS {
                    return limit("registry: subkeys");
                }
                self.nk(child)?;
                out.push(child);
            }
        }
        Ok(())
    }
    pub fn children(&self, key: u32) -> Result<Vec<(String, u32)>> {
        let c = self.nk(key)?;
        let n = le32(c, 20)? as usize;
        if n > MAX_ITEMS {
            return limit("registry: subkeys");
        }
        if le32(c, 24)? != 0 {
            return unsupported("registry: persistent volatile subkeys");
        }
        if n == 0 {
            return Ok(Vec::new());
        }
        let mut offsets = Vec::new();
        self.index(le32(c, 28)?, 0, &mut HashSet::new(), &mut offsets)?;
        if offsets.len() != n {
            return corrupt("registry: subkey count");
        }
        let mut seen = HashSet::new();
        let mut result = Vec::new();
        for off in offsets {
            let child = self.nk(off)?;
            if le32(child, 16)? != key {
                return corrupt("registry: subkey parent");
            }
            let s = self.key_name(off)?;
            if !seen.insert(s.to_ascii_uppercase()) {
                return corrupt("registry: duplicate subkey");
            }
            result.push((s, off));
        }
        Ok(result)
    }
    pub fn key(&self, path: &str) -> Result<Option<u32>> {
        let mut key = self.root;
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
            let children = self.children(key)?;
            match children.iter().find(|(n, _)| n.eq_ignore_ascii_case(part)) {
                Some((_, child)) => key = *child,
                None if children.iter().any(|(n, _)| !n.is_ascii()) => {
                    return unsupported("registry: non-ASCII case-insensitive key lookup")
                }
                None => return Ok(None),
            }
        }
        Ok(Some(key))
    }
    fn data(&self, offset: u32, len: usize) -> Result<Vec<u8>> {
        if len > MAX_VALUE {
            return limit("registry: value size");
        }
        let c = self.cell(offset)?;
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
        let list = self.cell(le32(c, 4)?)?;
        slice(list, 0, count * 4)?;
        let mut out = Vec::with_capacity(len);
        let mut seen = HashSet::new();
        for i in 0..count {
            let off = le32(list, i * 4)?;
            if !seen.insert(off) {
                return corrupt("registry: duplicate big data segment");
            }
            let size = (len - out.len()).min(16344);
            out.extend_from_slice(slice(self.cell(off)?, 0, size)?);
        }
        Ok(out)
    }
    pub fn value(&self, path: &str, wanted: &str) -> Result<Option<Value>> {
        let Some(key) = self.key(path)? else {
            return Ok(None);
        };
        self.value_at(key, wanted)
    }
    pub fn value_at(&self, key: u32, wanted: &str) -> Result<Option<Value>> {
        if !wanted.is_ascii() {
            return unsupported("registry: non-ASCII value lookup");
        }
        let nk = self.nk(key)?;
        let count = le32(nk, 36)? as usize;
        if count > MAX_ITEMS {
            return limit("registry: value count");
        }
        if count == 0 {
            return Ok(None);
        }
        let list = self.cell(le32(nk, 40)?)?;
        slice(list, 0, count * 4)?;
        let mut found = None;
        let mut non_ascii = false;
        let mut seen = HashSet::new();
        for i in 0..count {
            let c = self.cell(le32(list, i * 4)?)?;
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
            self.data(le32(c, 8)?, len)?
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
