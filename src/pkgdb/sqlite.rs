//! Minimal SQLite reader: enough to walk a table B-tree, from the file-format
//! specification (sqlite.org/fileformat.html). Applies committed WAL frames, since
//! a database copied out of a guest may still have a `-wal` file beside it.

use std::collections::HashMap;

use crate::bytes::{be16, be32, slice, u8_at};
use crate::error::{corrupt, limit, unsupported, Result};

const MAX_DEPTH: u32 = 32;
const MAX_ROWS: usize = 1 << 21;

pub struct Db {
    main: Vec<u8>,
    wal: Vec<u8>,
    wal_pages: HashMap<u32, usize>,
    page_size: usize,
    usable: usize,
}

#[derive(Debug, Clone)]
pub enum Value {
    Null,
    Int(i64),
    Float(f64),
    Text(Vec<u8>),
    Blob(Vec<u8>),
}

fn varint(b: &[u8], pos: &mut usize) -> Result<u64> {
    let mut v: u64 = 0;
    for i in 0..9 {
        let byte = u8_at(b, *pos)?;
        *pos += 1;
        if i == 8 {
            return Ok((v << 8) | byte as u64);
        }
        v = (v << 7) | (byte & 0x7f) as u64;
        if byte & 0x80 == 0 {
            return Ok(v);
        }
    }
    Ok(v)
}

impl Db {
    pub fn open(main: Vec<u8>, wal: Option<Vec<u8>>) -> Result<Self> {
        if main.len() < 100 || &main[..16] != b"SQLite format 3\0" {
            return corrupt("sqlite: bad header");
        }
        let ps = be16(&main, 16)? as usize;
        let page_size = if ps == 1 { 65536 } else { ps };
        if !(512..=65536).contains(&page_size) || !page_size.is_power_of_two() {
            return corrupt("sqlite: bad page size");
        }
        let reserved = u8_at(&main, 20)? as usize;
        let usable = page_size - reserved;
        if usable < 480 {
            return corrupt("sqlite: usable page size too small");
        }
        let mut db = Self {
            main,
            wal: Vec::new(),
            wal_pages: HashMap::new(),
            page_size,
            usable,
        };
        if let Some(w) = wal {
            db.apply_wal(w)?;
        }
        Ok(db)
    }

    fn apply_wal(&mut self, wal: Vec<u8>) -> Result<()> {
        if wal.len() < 32 {
            return Ok(()); // empty WAL: nothing uncommitted
        }
        let magic = be32(&wal, 0)?;
        if magic != 0x377f_0682 && magic != 0x377f_0683 {
            return corrupt("sqlite: bad WAL magic");
        }
        if be32(&wal, 8)? as usize != self.page_size {
            return corrupt("sqlite: WAL page size differs");
        }
        let (s1, s2) = (be32(&wal, 16)?, be32(&wal, 20)?);
        let frame = 24 + self.page_size;
        let mut pending: Vec<(u32, usize)> = Vec::new();
        let mut pos = 32;
        while pos + frame <= wal.len() {
            if be32(&wal, pos + 8)? != s1 || be32(&wal, pos + 12)? != s2 {
                break; // a frame from an older generation: the valid log ends here
            }
            pending.push((be32(&wal, pos)?, pos + 24));
            if be32(&wal, pos + 4)? != 0 {
                // Commit frame: everything pending is now part of the database.
                for (page, off) in pending.drain(..) {
                    crate::stats::hit(crate::stats::C::sqlite_wal_frame);
                    self.wal_pages.insert(page, off);
                }
            }
            pos += frame;
        }
        self.wal = wal;
        Ok(())
    }

    fn page(&self, n: u32) -> Result<&[u8]> {
        if n == 0 {
            return corrupt("sqlite: page 0");
        }
        if let Some(&off) = self.wal_pages.get(&n) {
            return slice(&self.wal, off, self.page_size);
        }
        slice(
            &self.main,
            (n as usize - 1) * self.page_size,
            self.page_size,
        )
    }

    fn payload(&self, page: &[u8], cell: usize, total: usize) -> Result<Vec<u8>> {
        let u = self.usable;
        let x = u - 35;
        let local = if total <= x {
            total
        } else {
            let m = ((u - 12) * 32 / 255) - 23;
            let k = m + (total - m) % (u - 4);
            if k <= x {
                k
            } else {
                m
            }
        };
        let mut out = slice(page, cell, local)?.to_vec();
        if local < total {
            let mut next = be32(page, cell + local)?;
            let mut guard = 0;
            while out.len() < total {
                guard += 1;
                if next == 0 || guard > 1 << 20 {
                    return corrupt("sqlite: overflow chain ends early");
                }
                let p = self.page(next)?;
                crate::stats::hit(crate::stats::C::sqlite_overflow_page);
                next = be32(p, 0)?;
                let n = (total - out.len()).min(u - 4);
                out.extend_from_slice(slice(p, 4, n)?);
            }
        }
        Ok(out)
    }

    /// Every row of the table B-tree rooted at `root`: `(rowid, record payload)`.
    pub fn rows(&self, root: u32, out: &mut Vec<(i64, Vec<u8>)>) -> Result<()> {
        let mut budget = 1usize << 20;
        self.walk(root, out, 0, &mut budget)
    }

    fn walk(
        &self,
        n: u32,
        out: &mut Vec<(i64, Vec<u8>)>,
        depth: u32,
        budget: &mut usize,
    ) -> Result<()> {
        if depth > MAX_DEPTH {
            return corrupt("sqlite: b-tree too deep");
        }
        *budget = budget.checked_sub(1).ok_or_else(|| {
            crate::error::Error::Limit("sqlite: walk visited too many pages".into())
        })?;
        let page = self.page(n)?;
        let hdr = if n == 1 { 100 } else { 0 };
        let kind = u8_at(page, hdr)?;
        let ncells = be16(page, hdr + 3)? as usize;
        match kind {
            0x0d => {
                for i in 0..ncells {
                    let mut pos = be16(page, hdr + 8 + i * 2)? as usize;
                    let total = crate::bytes::to_usize(varint(page, &mut pos)?, "sqlite payload")?;
                    let rowid = varint(page, &mut pos)? as i64;
                    if total > 64 << 20 {
                        return limit("sqlite: row too large");
                    }
                    out.push((rowid, self.payload(page, pos, total)?));
                    if out.len() > MAX_ROWS {
                        return limit("sqlite: too many rows");
                    }
                }
            }
            0x05 => {
                for i in 0..ncells {
                    let pos = be16(page, hdr + 12 + i * 2)? as usize;
                    self.walk(be32(page, pos)?, out, depth + 1, budget)?;
                }
                self.walk(be32(page, hdr + 8)?, out, depth + 1, budget)?;
            }
            k => {
                return corrupt(format!(
                    "sqlite: page {n} is not a table b-tree page ({k:#x})"
                ))
            }
        }
        Ok(())
    }

    /// Root page of a table, from `sqlite_schema` (page 1).
    pub fn table_root(&self, name: &str) -> Result<Option<u32>> {
        let mut rows = Vec::new();
        self.rows(1, &mut rows)?;
        for (_, payload) in rows {
            let v = record(&payload)?;
            if let (Some(Value::Text(t)), Some(Value::Text(n)), Some(Value::Int(root))) =
                (v.first(), v.get(1), v.get(3))
            {
                if t == b"table" && n.eq_ignore_ascii_case(name.as_bytes()) {
                    return Ok(Some(*root as u32));
                }
            }
        }
        Ok(None)
    }
}

pub fn record(payload: &[u8]) -> Result<Vec<Value>> {
    let mut pos = 0;
    let header = crate::bytes::to_usize(varint(payload, &mut pos)?, "sqlite record header")?;
    if header > payload.len() {
        return corrupt("sqlite: record header past the payload");
    }
    let mut types = Vec::new();
    while pos < header {
        types.push(varint(payload, &mut pos)?);
    }
    let mut data = header;
    let mut out = Vec::with_capacity(types.len());
    for t in types {
        let (len, v) = match t {
            0 => (0, Value::Null),
            1..=6 => {
                let n = [0, 1, 2, 3, 4, 6, 8][t as usize];
                let b = slice(payload, data, n)?;
                let mut x: i64 = if b[0] & 0x80 != 0 { -1 } else { 0 };
                for &byte in b {
                    x = (x << 8) | byte as i64;
                }
                (n, Value::Int(x))
            }
            7 => {
                let b = slice(payload, data, 8)?;
                (8, Value::Float(f64::from_be_bytes(b.try_into().unwrap())))
            }
            8 => (0, Value::Int(0)),
            9 => (0, Value::Int(1)),
            10 | 11 => return unsupported("sqlite: reserved serial type"),
            t if t % 2 == 0 => {
                let n = ((t - 12) / 2) as usize;
                (n, Value::Blob(slice(payload, data, n)?.to_vec()))
            }
            t => {
                let n = ((t - 13) / 2) as usize;
                (n, Value::Text(slice(payload, data, n)?.to_vec()))
            }
        };
        data += len;
        out.push(v);
    }
    Ok(out)
}
