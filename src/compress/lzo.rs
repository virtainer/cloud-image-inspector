//! LZO1X decompression, and the segmented container btrfs wraps it in.
//!
//! Instruction semantics follow the Linux kernel's `lzo1x_decompress_safe.c`; this is
//! an independent implementation with every read and copy bounds-checked.

use crate::error::{corrupt, limit, Result};

struct Lzo<'a> {
    input: &'a [u8],
    ip: usize,
    out: Vec<u8>,
    max: usize,
}

impl Lzo<'_> {
    fn byte(&mut self) -> Result<usize> {
        let b = *self
            .input
            .get(self.ip)
            .ok_or_else(|| crate::error::Error::Corrupt("lzo: input ended early".into()))?;
        self.ip += 1;
        Ok(b as usize)
    }

    fn le16(&mut self) -> Result<usize> {
        let lo = self.byte()?;
        let hi = self.byte()?;
        Ok(lo | (hi << 8))
    }

    /// A run of zero bytes counts 255 each, then one byte adds the rest.
    fn extended(&mut self, base: usize) -> Result<usize> {
        let mut zeros = 0usize;
        while *self
            .input
            .get(self.ip)
            .ok_or_else(|| crate::error::Error::Corrupt("lzo: input ended in a length".into()))?
            == 0
        {
            zeros += 1;
            self.ip += 1;
            if zeros > self.input.len() {
                return corrupt("lzo: runaway length");
            }
        }
        Ok(base + zeros * 255 + self.byte()?)
    }

    fn literals(&mut self, n: usize) -> Result<()> {
        if self.out.len() + n > self.max {
            return limit("lzo: output exceeds the expected size");
        }
        let src = self.input.get(self.ip..self.ip + n).ok_or_else(|| {
            crate::error::Error::Corrupt("lzo: literal run past the input".into())
        })?;
        self.out.extend_from_slice(src);
        self.ip += n;
        Ok(())
    }

    fn matched(&mut self, dist: usize, len: usize) -> Result<()> {
        if dist == 0 || dist > self.out.len() {
            return corrupt("lzo: match distance outside the output");
        }
        if self.out.len() + len > self.max {
            return limit("lzo: output exceeds the expected size");
        }
        let start = self.out.len() - dist;
        for k in 0..len {
            let b = self.out[start + k];
            self.out.push(b);
        }
        Ok(())
    }
}

pub fn lzo1x_decompress(input: &[u8], max: usize) -> Result<Vec<u8>> {
    let mut z = Lzo {
        input,
        ip: 0,
        out: Vec::new(),
        max,
    };
    // `state`: literals copied by the previous instruction (1..3), or 4 after a long
    // literal run, or 0 at a point where a literal run may start.
    let mut state = 0usize;
    if *input.first().unwrap_or(&0) > 17 {
        let t = z.byte()? - 17;
        z.literals(t)?;
        state = if t < 4 { t } else { 4 };
    }
    loop {
        let t = z.byte()?;
        let (dist, len, next) = if t < 16 {
            if state == 0 {
                let len = if t == 0 { z.extended(15)? } else { t };
                z.literals(len + 3)?;
                state = 4;
                continue;
            }
            let next = t & 3;
            let b = z.byte()?;
            if state == 4 {
                (1 + 0x800 + (t >> 2) + (b << 2), 3, next)
            } else {
                (1 + (t >> 2) + (b << 2), 2, next)
            }
        } else if t >= 64 {
            let b = z.byte()?;
            (1 + ((t >> 2) & 7) + (b << 3), (t >> 5) + 1, t & 3)
        } else if t >= 32 {
            let len = if t & 31 == 0 { z.extended(31)? } else { t & 31 };
            let v = z.le16()?;
            (1 + (v >> 2), len + 2, v & 3)
        } else {
            let len = if t & 7 == 0 { z.extended(7)? } else { t & 7 };
            let v = z.le16()?;
            let d = ((t & 8) << 11) + (v >> 2);
            if d == 0 {
                return Ok(z.out); // end-of-stream marker
            }
            (d + 0x4000, len + 2, v & 3)
        };
        z.matched(dist, len)?;
        z.literals(next)?;
        state = next;
    }
}

/// btrfs LZO extent: `u32` total length, then per-sector segments, each a `u32` length
/// and LZO1X data. A segment header never straddles a sector boundary.
pub fn btrfs_lzo_decompress(data: &[u8], sector: usize, max: usize) -> Result<Vec<u8>> {
    let total = crate::bytes::le32(data, 0)? as usize;
    if total > data.len() || sector < 512 {
        return corrupt("btrfs lzo: header length past the extent");
    }
    let mut out = Vec::new();
    let mut pos = 4;
    while pos < total {
        let room = sector - pos % sector;
        if room < 4 {
            pos += room;
            if pos >= total {
                break;
            }
        }
        let seg = crate::bytes::le32(data, pos)? as usize;
        pos += 4;
        let body = crate::bytes::slice(data, pos, seg)?;
        let part = lzo1x_decompress(body, max.saturating_sub(out.len()))?;
        out.extend_from_slice(&part);
        pos += seg;
    }
    Ok(out)
}
