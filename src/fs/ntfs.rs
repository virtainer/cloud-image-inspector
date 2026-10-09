//! Read-only NTFS metadata and streams. No journal replay, decompression or EFS.
use crate::bytes::{le16, le32, le64, slice, to_usize};
use crate::error::{corrupt, limit, unsupported, Error, Result};
use crate::fs::{DirEntry, FileSystem, Kind, NodeId, Stat};
use crate::io::ReadAt;
use crate::registry::utf16;
use std::collections::HashSet;
use std::rc::Rc;

const REF_MASK: u64 = (1 << 48) - 1;
const MAX_RUNS: usize = 65536;
const MAX_ATTRS: usize = 1024;
const MAX_LIST: u64 = 4 << 20;

#[derive(Clone)]
struct Run {
    vcn: u64,
    count: u64,
    lcn: Option<u64>,
}
#[derive(Clone)]
struct Attr {
    kind: u32,
    id: u16,
    name: String,
    raw: Vec<u8>,
}
#[derive(Clone, Default)]
struct Stream {
    resident: Option<Vec<u8>>,
    runs: Vec<Run>,
    size: u64,
    initialized: u64,
}
struct ListEntry {
    kind: u32,
    id: u16,
    name: String,
    vcn: u64,
    reference: u64,
}

pub struct Ntfs {
    dev: Rc<dyn ReadAt>,
    cluster: u64,
    volume: u64,
    record_size: usize,
    index_size: usize,
    mft: Stream,
    pub label: String,
}

fn fail(msg: &str) -> Error {
    Error::Corrupt(format!("NTFS: {msg}"))
}
fn mul(a: u64, b: u64) -> Result<u64> {
    a.checked_mul(b).ok_or_else(|| fail("offset overflow"))
}
fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b).ok_or_else(|| fail("offset overflow"))
}
fn structure_size(code: u8, cluster: u64) -> Result<usize> {
    let signed = code as i8;
    let n = if signed < 0 {
        1u64.checked_shl((-(signed as i16)) as u32)
            .ok_or_else(|| fail("record size"))?
    } else {
        mul(code as u64, cluster)?
    };
    if !(512..=65536).contains(&n) || !n.is_power_of_two() {
        return corrupt("NTFS: structure size");
    }
    Ok(n as usize)
}

/// NTFS multi-sector transfer protection always uses 512-byte strides.
fn fixup(mut b: Vec<u8>, magic: &[u8]) -> Result<Vec<u8>> {
    if slice(&b, 0, 4)? != magic || !b.len().is_multiple_of(512) {
        return corrupt("NTFS: record signature/size");
    }
    let off = le16(&b, 4)? as usize;
    let n = le16(&b, 6)? as usize;
    if n != b.len() / 512 + 1 || off < 8 || !off.is_multiple_of(2) || off + n * 2 > 510 {
        return corrupt("NTFS: fixup array");
    }
    let usa = slice(&b, off, n * 2)?.to_vec();
    let marker = le16(&usa, 0)?;
    for i in 1..n {
        let end = i * 512 - 2;
        if le16(&b, end)? != marker {
            return corrupt("NTFS: torn record (fixup mismatch)");
        }
        b[end..end + 2].copy_from_slice(slice(&usa, i * 2, 2)?);
    }
    Ok(b)
}

fn parse_attrs(b: &[u8]) -> Result<Vec<Attr>> {
    let start = le16(b, 20)? as usize;
    let used = le32(b, 24)? as usize;
    if start < 42
        || !start.is_multiple_of(8)
        || used > b.len()
        || used < start + 4
        || le32(b, 28)? as usize != b.len()
    {
        return corrupt("NTFS: FILE attribute range");
    }
    if le16(b, 4)? < 42 || le16(b, 4)? as usize + le16(b, 6)? as usize * 2 > start {
        return corrupt("NTFS: FILE fixup array overlaps header/attributes");
    }
    let mut out = Vec::new();
    let mut pos = start;
    while pos + 4 <= used {
        let kind = le32(b, pos)?;
        if kind == u32::MAX {
            return Ok(out);
        }
        if out.len() >= 256 {
            return limit("NTFS: attributes per record");
        }
        let len = le32(b, pos + 4)? as usize;
        if len < 24 || !len.is_multiple_of(8) || len > used - pos {
            return corrupt("NTFS: attribute size");
        }
        let a = slice(b, pos, len)?;
        let nonresident = a[8];
        if nonresident > 1 || (nonresident == 1 && len < 64) {
            return corrupt("NTFS: attribute header");
        }
        let namelen = a[9] as usize * 2;
        let nameoff = le16(a, 10)? as usize;
        let header = if nonresident == 1 { 64 } else { 24 };
        if namelen != 0 && nameoff < header {
            return corrupt("NTFS: attribute name range");
        }
        let name = utf16(slice(a, nameoff, namelen)?)?;
        if nonresident == 0 {
            let off = le16(a, 20)? as usize;
            if off < header || (namelen != 0 && off < nameoff + namelen) {
                return corrupt("NTFS: resident value range");
            }
            slice(a, off, le32(a, 16)? as usize)?;
        }
        let id = le16(a, 14)?;
        if out.iter().any(|x: &Attr| x.id == id) {
            return corrupt("NTFS: duplicate attribute id");
        }
        out.push(Attr {
            kind,
            id,
            name,
            raw: a.to_vec(),
        });
        pos += len;
    }
    corrupt("NTFS: missing attribute terminator")
}

fn attr_vcn(a: &Attr) -> Result<u64> {
    if a.raw[8] == 0 {
        Ok(0)
    } else {
        le64(&a.raw, 16)
    }
}
fn list_entries(b: &[u8]) -> Result<Vec<ListEntry>> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < b.len() {
        if out.len() >= MAX_ATTRS {
            return limit("NTFS: attribute list entries");
        }
        let kind = le32(b, pos)?;
        if kind == u32::MAX || kind == 0 {
            if b[pos..].iter().all(|x| *x == 0 || *x == 0xff) {
                break;
            }
            return corrupt("NTFS: list padding");
        }
        let len = le16(b, pos + 4)? as usize;
        if len < 26 || !len.is_multiple_of(8) {
            return corrupt("NTFS: list entry size");
        }
        let e = slice(b, pos, len)?;
        let n = e[6] as usize * 2;
        let off = e[7] as usize;
        if n != 0 && off < 26 {
            return corrupt("NTFS: list name range");
        }
        out.push(ListEntry {
            kind,
            name: utf16(slice(e, off, n)?)?,
            vcn: le64(e, 8)?,
            reference: le64(e, 16)?,
            id: le16(e, 24)?,
        });
        pos += len;
    }
    Ok(out)
}

impl Ntfs {
    pub fn open(dev: Rc<dyn ReadAt>) -> Result<Self> {
        let b = dev.read_vec(0, 512)?;
        if slice(&b, 3, 8)? != b"NTFS    " || le16(&b, 510)? != 0xaa55 {
            return corrupt("NTFS: boot signature");
        }
        let sector = le16(&b, 11)? as u64;
        let spc = b[13] as u64;
        if !(512..=4096).contains(&sector)
            || !sector.is_power_of_two()
            || spc == 0
            || !spc.is_power_of_two()
            || spc > 128
        {
            return corrupt("NTFS: geometry");
        }
        let cluster = sector * spc;
        let volume = mul(le64(&b, 40)?, sector)?;
        if volume < cluster || volume > dev.size() {
            return corrupt("NTFS: volume range");
        }
        let record_size = structure_size(b[64], cluster)?;
        let index_size = structure_size(b[68], cluster)?;
        let mft_offset = mul(le64(&b, 48)?, cluster)?;
        if add(mft_offset, record_size as u64)? > volume {
            return corrupt("NTFS: MFT range");
        }
        let rec = fixup(dev.read_vec(mft_offset, record_size)?, b"FILE")?;
        if le16(&rec, 22)? & 1 == 0 || le64(&rec, 32)? != 0 {
            return corrupt("NTFS: MFT base record");
        }
        let mut attrs = parse_attrs(&rec)?;
        let mut fs = Self {
            dev,
            cluster,
            volume,
            record_size,
            index_size,
            mft: Stream::default(),
            label: String::new(),
        };
        fs.mft = fs
            .stream(&attrs, 0x80, "")?
            .ok_or_else(|| fail("MFT has no data"))?;
        // Bootstrap extension records using the already mapped prefix of $MFT.
        if let Some(list) = fs.stream(&attrs, 0x20, "")? {
            let entries = list_entries(&fs.whole(&list, MAX_LIST)?)?;
            let mut pending: Vec<_> = entries
                .into_iter()
                .filter(|e| e.kind == 0x80 && e.name.is_empty() && e.reference & REF_MASK != 0)
                .collect();
            let mut seen = HashSet::new();
            let mut attempts = 0;
            let mut mapped_runs = 0;
            while !pending.is_empty() {
                let before = pending.len();
                let mut rest = Vec::new();
                for e in pending {
                    attempts += 1;
                    if attempts > 4096 {
                        return limit("NTFS: MFT bootstrap record reads");
                    }
                    let Ok(r) = fs.record_ref(e.reference) else {
                        rest.push(e);
                        continue;
                    };
                    let base = le64(&r, 32)?;
                    if base & REF_MASK != 0 || base >> 48 != le16(&rec, 16)? as u64 {
                        return corrupt("NTFS: MFT extension base reference");
                    }
                    let extra = parse_attrs(&r)?;
                    let a = fs.match_entry(&extra, &e)?;
                    if !seen.insert((e.reference, e.id)) {
                        return corrupt("NTFS: duplicate MFT list extent");
                    }
                    attrs.push(a.clone());
                    if attrs.len() > MAX_ATTRS {
                        return limit("NTFS: MFT attributes");
                    }
                    mapped_runs += fs.mft.runs.len();
                    if mapped_runs > 1_000_000 {
                        return limit("NTFS: MFT bootstrap mapping work");
                    }
                    fs.mft = fs
                        .stream(&attrs, 0x80, "")?
                        .ok_or_else(|| fail("MFT stream"))?;
                }
                if rest.len() == before {
                    return unsupported("NTFS: MFT extension bootstrap is inaccessible");
                }
                pending = rest;
            }
        }
        fs.validate_stream(&fs.mft)?;
        if fs.mft.resident.is_some()
            || fs.mft.runs.iter().any(|r| r.lcn.is_none())
            || !fs.mft.size.is_multiple_of(fs.record_size as u64)
        {
            return corrupt("NTFS: invalid MFT data stream");
        }
        if let Ok(attrs) = fs.attributes(NodeId(0, 3)) {
            if let Ok(Some(s)) = fs.stream(&attrs, 0x60, "") {
                if let Ok(b) = fs.whole(&s, 4096) {
                    fs.label = utf16(&b).unwrap_or_default();
                }
            }
        }
        Ok(fs)
    }
    fn match_entry<'a>(&self, attrs: &'a [Attr], e: &ListEntry) -> Result<&'a Attr> {
        for a in attrs {
            if a.kind == e.kind && a.id == e.id && a.name == e.name && attr_vcn(a)? == e.vcn {
                return Ok(a);
            }
        }
        corrupt("NTFS: attribute list does not match extension")
    }
    fn record_ref(&self, reference: u64) -> Result<Vec<u8>> {
        if reference >> 48 == 0 {
            return corrupt("NTFS: zero sequence in file reference");
        }
        self.record(NodeId(reference >> 48, reference & REF_MASK))
    }
    fn record(&self, node: NodeId) -> Result<Vec<u8>> {
        let offset = mul(node.1, self.record_size as u64)?;
        if add(offset, self.record_size as u64)? > self.mft.size {
            return corrupt("NTFS: MFT record past stream");
        }
        let b = fixup(
            self.range(&self.mft, offset, self.record_size as u64)?,
            b"FILE",
        )?;
        if le16(&b, 22)? & 1 == 0 || (node.0 != 0 && le16(&b, 16)? as u64 != node.0) {
            return corrupt("NTFS: unallocated/stale FILE reference");
        }
        Ok(b)
    }
    fn attributes(&self, node: NodeId) -> Result<Vec<Attr>> {
        let b = self.record(node)?;
        if le64(&b, 32)? != 0 {
            return corrupt("NTFS: expected base record");
        }
        let mut attrs = parse_attrs(&b)?;
        let Some(list) = self.stream(&attrs, 0x20, "")? else {
            return Ok(attrs);
        };
        let entries = list_entries(&self.whole(&list, MAX_LIST)?)?;
        let mut seen = HashSet::new();
        let mut attribute_bytes = b.len();
        for e in entries {
            if !seen.insert((e.reference, e.id)) {
                return corrupt("NTFS: duplicate attribute list entry");
            }
            if e.reference & REF_MASK == node.1 {
                if e.reference >> 48 != le16(&b, 16)? as u64 {
                    return corrupt("NTFS: stale base list reference");
                }
                self.match_entry(&attrs, &e)?;
                continue;
            }
            let r = self.record_ref(e.reference)?;
            let base = le64(&r, 32)?;
            if base & REF_MASK != node.1 || base >> 48 != le16(&b, 16)? as u64 {
                return corrupt("NTFS: extension base reference");
            }
            let extra = parse_attrs(&r)?;
            let a = self.match_entry(&extra, &e)?;
            attribute_bytes += a.raw.len();
            if attribute_bytes > 16 << 20 {
                return limit("NTFS: attribute bytes");
            }
            attrs.push(a.clone());
            if attrs.len() > MAX_ATTRS {
                return limit("NTFS: attribute count");
            }
        }
        Ok(attrs)
    }
    fn stream(&self, attrs: &[Attr], kind: u32, name: &str) -> Result<Option<Stream>> {
        let mut parts: Vec<_> = attrs
            .iter()
            .filter(|a| a.kind == kind && a.name == name)
            .collect();
        if parts.is_empty() {
            return Ok(None);
        }
        parts.sort_by_key(|a| attr_vcn(a).unwrap_or(u64::MAX));
        if parts[0].raw[8] == 0 {
            if parts.len() != 1 || le16(&parts[0].raw, 12)? != 0 {
                return corrupt("NTFS: resident stream flags/extents");
            }
            let b = &parts[0].raw;
            let data = slice(b, le16(b, 20)? as usize, le32(b, 16)? as usize)?.to_vec();
            return Ok(Some(Stream {
                size: data.len() as u64,
                initialized: data.len() as u64,
                resident: Some(data),
                runs: Vec::new(),
            }));
        }
        if attr_vcn(parts[0])? != 0 {
            return corrupt("NTFS: stream missing first extent");
        }
        let size = le64(&parts[0].raw, 48)?;
        let initialized = le64(&parts[0].raw, 56)?;
        if initialized > size {
            return corrupt("NTFS: initialized size exceeds data size");
        }
        let mut runs = Vec::new();
        let mut previous_end = 0;
        for a in parts {
            let b = &a.raw;
            if b[8] != 1 {
                return corrupt("NTFS: mixed resident/nonresident stream");
            }
            let flags = le16(b, 12)?;
            // Sparse allocation units use this field too, without compressing data.
            if flags & 1 != 0 || (le16(b, 34)? != 0 && flags & 0x8000 == 0) {
                return unsupported("NTFS: compressed stream");
            }
            if flags & 0x4000 != 0 {
                return unsupported("NTFS: encrypted stream (EFS)");
            }
            if flags & !0xc001 != 0 {
                return unsupported("NTFS: stream flags");
            }
            let first = le64(b, 16)?;
            let last = le64(b, 24)?;
            if first < previous_end || last < first || last == u64::MAX {
                return corrupt("NTFS: overlapping/invalid extent VCN");
            }
            let off = le16(b, 32)? as usize;
            if off < 64 || (b[9] != 0 && off < le16(b, 10)? as usize + b[9] as usize * 2) {
                return corrupt("NTFS: mapping pairs offset");
            }
            let mut pos = off;
            let mut vcn = first;
            let mut lcn = 0i64;
            loop {
                let header = *b
                    .get(pos)
                    .ok_or_else(|| fail("unterminated mapping pairs"))?;
                pos += 1;
                if header == 0 {
                    break;
                }
                if runs.len() >= MAX_RUNS {
                    return limit("NTFS: data runs");
                }
                let n = (header & 15) as usize;
                let m = (header >> 4) as usize;
                if n == 0 || n > 8 || m > 8 {
                    return corrupt("NTFS: mapping pair width");
                }
                let count_bytes = slice(b, pos, n)?;
                pos += n;
                let mut raw = [0u8; 8];
                raw[..n].copy_from_slice(count_bytes);
                let count = u64::from_le_bytes(raw);
                if count == 0 {
                    return corrupt("NTFS: zero-length run");
                }
                let physical = if m == 0 {
                    None
                } else {
                    let delta = slice(b, pos, m)?;
                    pos += m;
                    let mut signed = if delta[m - 1] & 128 != 0 {
                        [0xff; 8]
                    } else {
                        [0; 8]
                    };
                    signed[..m].copy_from_slice(delta);
                    lcn = lcn
                        .checked_add(i64::from_le_bytes(signed))
                        .ok_or_else(|| fail("LCN overflow"))?;
                    if lcn < 0 || mul(add(lcn as u64, count)?, self.cluster)? > self.volume {
                        return corrupt("NTFS: physical run range");
                    }
                    Some(lcn as u64)
                };
                let end = add(vcn, count)?;
                if end > last + 1 {
                    return corrupt("NTFS: run exceeds extent");
                }
                runs.push(Run {
                    vcn,
                    count,
                    lcn: physical,
                });
                vcn = end;
            }
            if vcn != last + 1 {
                return corrupt("NTFS: mapping pairs VCN coverage");
            }
            previous_end = vcn;
        }
        Ok(Some(Stream {
            resident: None,
            runs,
            size,
            initialized,
        }))
    }
    fn validate_stream(&self, s: &Stream) -> Result<()> {
        if s.resident.is_some() {
            return Ok(());
        }
        let mut end = 0;
        for r in &s.runs {
            if r.vcn != end {
                return corrupt("NTFS: stream extent gap");
            }
            end = add(r.vcn, r.count)?;
        }
        if mul(end, self.cluster)? < s.size {
            return corrupt("NTFS: truncated stream extents");
        }
        Ok(())
    }
    fn range(&self, s: &Stream, offset: u64, len: u64) -> Result<Vec<u8>> {
        let len = len.min(s.size.saturating_sub(offset));
        if len > crate::io::MAX_READ as u64 {
            return limit("NTFS: read size");
        }
        if len == 0 {
            return Ok(Vec::new());
        }
        if let Some(b) = &s.resident {
            return Ok(slice(b, offset as usize, len as usize)?.to_vec());
        }
        let mut out = vec![0u8; len as usize];
        let end = add(offset, len)?.min(s.initialized);
        let mut pos = offset;
        for r in &s.runs {
            if pos >= end {
                break;
            }
            let begin = mul(r.vcn, self.cluster)?;
            let stop = mul(add(r.vcn, r.count)?, self.cluster)?;
            if stop <= pos {
                continue;
            }
            if begin > pos {
                return corrupt("NTFS: read through unmapped VCN");
            }
            let n = (stop.min(end) - pos) as usize;
            if let Some(lcn) = r.lcn {
                self.dev.read_at(
                    add(mul(lcn, self.cluster)?, pos - begin)?,
                    &mut out[(pos - offset) as usize..(pos - offset) as usize + n],
                )?;
            }
            pos += n as u64;
        }
        if pos < end {
            return corrupt("NTFS: short stream mapping");
        }
        Ok(out)
    }
    fn whole(&self, s: &Stream, max: u64) -> Result<Vec<u8>> {
        if s.size > max.min(crate::vfs::MAX_FILE) {
            return limit("NTFS: whole stream size");
        }
        self.validate_stream(s)?;
        self.range(s, 0, s.size)
    }
    pub fn dirty(&self) -> Result<bool> {
        let attrs = self.attributes(NodeId(0, 3))?;
        let s = self
            .stream(&attrs, 0x70, "")?
            .ok_or_else(|| fail("missing volume information"))?;
        Ok(le16(&self.whole(&s, 4096)?, 10)? & 1 != 0)
    }
    fn index_entries(
        &self,
        b: &[u8],
        hdr: usize,
        depth: usize,
        out: &mut Vec<DirEntry>,
        todo: &mut Vec<(u64, usize)>,
    ) -> Result<()> {
        let h = slice(b, hdr, 16)?;
        if h[12] > 1 {
            return corrupt("NTFS: index node flag");
        }
        let start = le32(h, 0)? as usize;
        let end = le32(h, 4)? as usize;
        let allocated = le32(h, 8)? as usize;
        if start < 16 || end < start || allocated < end || allocated > b.len() - hdr {
            return corrupt("NTFS: index header bounds");
        }
        let mut pos = start;
        while pos < end {
            let e = slice(b, hdr + pos, end - pos)?;
            let len = le16(e, 8)? as usize;
            let keylen = le16(e, 10)? as usize;
            let flags = le16(e, 12)?;
            if len < 16 || !len.is_multiple_of(8) || len > end - pos || flags & !3 != 0 {
                return corrupt("NTFS: index entry");
            }
            if (flags & 1 != 0) != (h[12] == 1) {
                return corrupt("NTFS: index child flag disagrees with node");
            }
            let tail = if flags & 1 != 0 { 8 } else { 0 };
            if len < 16 + tail || keylen > len - 16 - tail {
                return corrupt("NTFS: index key length");
            }
            if flags & 1 != 0 {
                if depth >= 32 || todo.len() >= 8192 {
                    return limit("NTFS: index tree budget");
                }
                todo.push((le64(e, len - 8)?, depth + 1));
            }
            if flags & 2 != 0 {
                if keylen != 0 || pos + len != end {
                    return corrupt("NTFS: index end entry");
                }
                return Ok(());
            }
            let key = slice(e, 16, keylen)?;
            if keylen < 66 || key[65] > 3 || keylen != 66 + key[64] as usize * 2 {
                return corrupt("NTFS: FILE_NAME index key");
            }
            let name = utf16(slice(key, 66, key[64] as usize * 2)?)?;
            if name.is_empty() || name.contains(['/', '\\', '\0']) {
                return corrupt("NTFS: invalid filename");
            }
            let reference = le64(e, 0)?;
            if reference >> 48 == 0 {
                return corrupt("NTFS: zero sequence in directory reference");
            }
            if out.len() >= 100000 {
                return limit("NTFS: directory entries");
            }
            if name != "." && name != ".." {
                out.push(DirEntry {
                    name: name.into_bytes(),
                    node: NodeId(reference >> 48, reference & REF_MASK),
                });
            }
            pos += len;
        }
        corrupt("NTFS: index lacks end entry")
    }
}

impl FileSystem for Ntfs {
    fn type_name(&self) -> &'static str {
        "ntfs"
    }
    fn root(&self) -> NodeId {
        NodeId(0, 5)
    }
    fn stat(&self, node: NodeId) -> Result<Stat> {
        let b = self.record(node)?;
        let attrs = self.attributes(node)?;
        if attrs.iter().any(|a| a.kind == 0xc0) {
            return unsupported("NTFS: reparse point (including WOF)");
        }
        let dir = le16(&b, 22)? & 2 != 0;
        let size = if dir {
            0
        } else {
            self.stream(&attrs, 0x80, "")?
                .ok_or_else(|| fail("file has no unnamed DATA"))?
                .size
        };
        Ok(Stat {
            kind: if dir { Kind::Dir } else { Kind::File },
            size,
            mode: if dir { 0o040555 } else { 0o100444 },
        })
    }
    fn read_dir(&self, node: NodeId) -> Result<Vec<DirEntry>> {
        if self.stat(node)?.kind != Kind::Dir {
            return corrupt("NTFS: not a directory");
        }
        let attrs = self.attributes(node)?;
        let root = self
            .stream(&attrs, 0x90, "$I30")?
            .ok_or_else(|| fail("missing directory index root"))?;
        let b = self.whole(&root, 65536)?;
        if le32(&b, 0)? != 0x30 || le32(&b, 4)? != 1 || le32(&b, 8)? as usize != self.index_size {
            return unsupported("NTFS: directory index format");
        }
        let mut out = Vec::new();
        let mut todo = Vec::new();
        self.index_entries(&b, 16, 0, &mut out, &mut todo)?;
        if !todo.is_empty() {
            let allocation = self
                .stream(&attrs, 0xa0, "$I30")?
                .ok_or_else(|| fail("missing index allocation"))?;
            self.validate_stream(&allocation)?;
            let bitmap = self
                .stream(&attrs, 0xb0, "$I30")?
                .ok_or_else(|| fail("missing index bitmap"))?;
            let bitmap = self.whole(&bitmap, MAX_LIST)?;
            // Index records smaller than a cluster are addressed in fixed 512-byte
            // units, independent of the volume's sector size (as ntfs-3g does).
            let unit = if self.cluster > self.index_size as u64 {
                512
            } else {
                self.cluster
            };
            let mut seen = HashSet::new();
            while let Some((vcn, depth)) = todo.pop() {
                if seen.len() >= 8192 {
                    return limit("NTFS: index blocks");
                }
                if !seen.insert(vcn) {
                    return corrupt("NTFS: directory index cycle/alias");
                }
                let offset = mul(vcn, unit)?;
                if !offset.is_multiple_of(self.index_size as u64)
                    || add(offset, self.index_size as u64)? > allocation.size
                {
                    return corrupt("NTFS: index block range");
                }
                let bit = offset / self.index_size as u64;
                if bitmap
                    .get(to_usize(bit / 8, "NTFS bitmap offset")?)
                    .is_none_or(|b| b & (1 << (bit % 8)) == 0)
                {
                    return corrupt("NTFS: index block is unallocated");
                }
                let block = fixup(
                    self.range(&allocation, offset, self.index_size as u64)?,
                    b"INDX",
                )?;
                if le64(&block, 16)? != vcn {
                    return corrupt("NTFS: index VCN mismatch");
                }
                self.index_entries(&block, 24, depth, &mut out, &mut todo)?;
            }
        }
        Ok(out)
    }
    fn lookup(&self, dir: NodeId, name: &[u8]) -> Result<Option<NodeId>> {
        let entries = self.read_dir(dir)?;
        if name.is_ascii() && entries.iter().all(|e| e.name.is_ascii()) {
            let mut found = None;
            for e in entries.iter().filter(|e| e.name.eq_ignore_ascii_case(name)) {
                if found.is_some_and(|n| n != e.node) {
                    return corrupt("NTFS: ambiguous directory name");
                }
                found = Some(e.node);
            }
            return Ok(found);
        }
        let wanted = std::str::from_utf8(name).map_err(|_| fail("lookup UTF-8"))?;
        let table = self
            .stream(&self.attributes(NodeId(0, 10))?, 0x80, "")?
            .ok_or_else(|| fail("missing $UpCase"))?;
        let table = self.whole(&table, 131072)?;
        if table.len() != 131072 {
            return corrupt("NTFS: $UpCase size");
        }
        let fold = |s: &str| -> Result<Vec<u16>> {
            s.encode_utf16()
                .map(|c| le16(&table, c as usize * 2))
                .collect()
        };
        let wanted = fold(wanted)?;
        let mut found = None;
        for e in entries {
            let s = std::str::from_utf8(&e.name).map_err(|_| fail("filename UTF-8"))?;
            if fold(s)? == wanted {
                if found.is_some_and(|n| n != e.node) {
                    return corrupt("NTFS: ambiguous directory name");
                }
                found = Some(e.node);
            }
        }
        Ok(found)
    }
    fn read_file(&self, node: NodeId, max: u64) -> Result<Vec<u8>> {
        if self.stat(node)?.kind != Kind::File {
            return corrupt("NTFS: not a file");
        }
        let s = self
            .stream(&self.attributes(node)?, 0x80, "")?
            .ok_or_else(|| fail("missing file data"))?;
        self.whole(&s, max)
    }
    fn read_range(&self, node: NodeId, offset: u64, len: u64) -> Result<Vec<u8>> {
        if self.stat(node)?.kind != Kind::File {
            return corrupt("NTFS: not a file");
        }
        let s = self
            .stream(&self.attributes(node)?, 0x80, "")?
            .ok_or_else(|| fail("missing file data"))?;
        self.validate_stream(&s)?;
        self.range(&s, offset, len)
    }
    fn read_link(&self, _: NodeId) -> Result<Vec<u8>> {
        unsupported("NTFS: reparse points")
    }
}
