//! Zstandard decoder, written from RFC 8878.
//!
//! Decodes whole frames into memory (no dictionary support: neither qcow2 nor btrfs
//! uses dictionaries). Verifies the optional XXH64 content checksum.

use crate::compress::xxhash::xxh64;
use crate::error::{corrupt, limit, unsupported, Result};

const MAGIC: u32 = 0xFD2F_B528;
const MAX_BLOCK: usize = 128 << 10;

// ---------------------------------------------------------------- bit readers

/// Little-endian, LSB-first forward reader (FSE table descriptions).
struct FwdBits<'a> {
    data: &'a [u8],
    bit: usize,
}

impl<'a> FwdBits<'a> {
    fn peek(&self, n: u32) -> u32 {
        let mut v: u64 = 0;
        let byte = self.bit / 8;
        for i in 0..5 {
            v |= (*self.data.get(byte + i).unwrap_or(&0) as u64) << (8 * i);
        }
        ((v >> (self.bit % 8)) & ((1u64 << n) - 1)) as u32
    }
    fn consume(&mut self, n: u32) {
        self.bit += n as usize;
    }
    fn read(&mut self, n: u32) -> u32 {
        let v = self.peek(n);
        self.consume(n);
        v
    }
}

/// Backward reader: the stream starts at the last byte's highest set bit and runs
/// towards the first byte. The first bit read is the most significant.
struct BackBits<'a> {
    data: &'a [u8],
    /// Unread bits. Goes negative when a reader asks for more than exists; those
    /// missing bits read as zero, and `overflowed()` reports it.
    left: isize,
}

impl<'a> BackBits<'a> {
    fn new(data: &'a [u8]) -> Result<Self> {
        let last = match data.last() {
            Some(&b) if b != 0 => b,
            _ => return corrupt("zstd: bitstream without an end marker"),
        };
        let pad = last.leading_zeros() as isize + 1;
        Ok(Self {
            data,
            left: data.len() as isize * 8 - pad,
        })
    }

    #[inline]
    fn peek(&self, n: u32) -> u64 {
        if n == 0 {
            return 0;
        }
        let end = self.left;
        let start = end - n as isize;
        if end <= 0 {
            return 0;
        }
        let s = start.max(0) as usize;
        let e = end as usize;
        let (b0, b1) = (s / 8, e.div_ceil(8));
        let mut acc: u128 = 0;
        for (i, idx) in (b0..b1).enumerate() {
            acc |= (self.data[idx] as u128) << (8 * i);
        }
        let width = e - s;
        let mut v = ((acc >> (s - b0 * 8)) & ((1u128 << width) - 1)) as u64;
        if start < 0 {
            v <<= (-start) as u32;
        }
        v
    }

    #[inline]
    fn read(&mut self, n: u32) -> u64 {
        let v = self.peek(n);
        self.left -= n as isize;
        v
    }

    fn overflowed(&self) -> bool {
        self.left < 0
    }
}

// ------------------------------------------------------------------ FSE tables

#[derive(Clone, Copy, Default)]
struct FseEntry {
    symbol: u8,
    bits: u8,
    base: u16,
}

#[derive(Clone)]
struct Fse {
    log: u32,
    table: Vec<FseEntry>,
}

impl Fse {
    fn rle(symbol: u8) -> Self {
        Fse {
            log: 0,
            table: vec![FseEntry {
                symbol,
                bits: 0,
                base: 0,
            }],
        }
    }

    fn build(counts: &[i16], log: u32) -> Result<Self> {
        let size = 1usize << log;
        let mut table = vec![FseEntry::default(); size];
        let mut next = vec![0u32; counts.len()];
        let mut high = size as isize - 1;
        for (s, &c) in counts.iter().enumerate() {
            if c == -1 {
                if high < 0 {
                    return corrupt("zstd: FSE table over-full");
                }
                table[high as usize].symbol = s as u8;
                high -= 1;
                next[s] = 1;
            } else {
                next[s] = c.max(0) as u32;
            }
        }
        let step = (size >> 1) + (size >> 3) + 3;
        let mask = size - 1;
        let mut pos = 0usize;
        for (s, &c) in counts.iter().enumerate() {
            for _ in 0..c.max(0) {
                table[pos].symbol = s as u8;
                loop {
                    pos = (pos + step) & mask;
                    if pos as isize <= high {
                        break;
                    }
                }
            }
        }
        if pos != 0 {
            return corrupt("zstd: FSE distribution does not fill the table");
        }
        for e in table.iter_mut() {
            let s = e.symbol as usize;
            let n = next[s];
            if n == 0 {
                return corrupt("zstd: FSE state for a zero-probability symbol");
            }
            next[s] += 1;
            let bits = log - (31 - n.leading_zeros());
            e.bits = bits as u8;
            e.base = ((n << bits) as usize - size) as u16;
        }
        Ok(Fse { log, table })
    }

    /// Parse a table description. Returns the table and the bytes consumed.
    fn read(data: &[u8], max_symbol: usize, max_log: u32) -> Result<(Self, usize)> {
        let mut br = FwdBits { data, bit: 0 };
        let log = br.read(4) + 5;
        if log > max_log {
            return corrupt(format!("zstd: FSE accuracy {log} above {max_log}"));
        }
        let mut counts = vec![0i16; max_symbol + 1];
        let mut remaining: i32 = (1 << log) + 1;
        let mut threshold: i32 = 1 << log;
        let mut nbits = log + 1;
        let mut sym = 0usize;
        let mut prev0 = false;
        while remaining > 1 {
            if prev0 {
                loop {
                    let r = br.read(2) as usize;
                    sym += r;
                    if r != 3 {
                        break;
                    }
                    if sym > max_symbol {
                        return corrupt("zstd: FSE zero run past the last symbol");
                    }
                }
            }
            if sym > max_symbol {
                return corrupt("zstd: FSE description has too many symbols");
            }
            let max = 2 * threshold - 1 - remaining;
            let low = br.peek(nbits - 1) as i32;
            let mut count = if low < max {
                br.consume(nbits - 1);
                low
            } else {
                let mut v = br.peek(nbits) as i32;
                if v >= threshold {
                    v -= max;
                }
                br.consume(nbits);
                v
            };
            count -= 1;
            remaining -= count.abs();
            counts[sym] = count as i16;
            sym += 1;
            prev0 = count == 0;
            while remaining < threshold {
                nbits -= 1;
                threshold >>= 1;
            }
        }
        if remaining != 1 {
            return corrupt("zstd: FSE probabilities do not sum to the table size");
        }
        let used = br.bit.div_ceil(8);
        if used > data.len() {
            return corrupt("zstd: FSE description runs past its section");
        }
        counts.truncate(sym);
        Ok((Self::build(&counts, log)?, used))
    }
}

const LL_DEFAULT: [i16; 36] = [
    4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1,
    -1, -1, -1, -1,
];
const ML_DEFAULT: [i16; 53] = [
    1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1,
];
const OF_DEFAULT: [i16; 29] = [
    1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1,
];

const LL_BASE: [u32; 36] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 22, 24, 28, 32, 40, 48, 64,
    128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536,
];
const LL_BITS: [u8; 36] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11,
    12, 13, 14, 15, 16,
];
const ML_BASE: [u32; 53] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
    28, 29, 30, 31, 32, 33, 34, 35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027,
    2051, 4099, 8195, 16387, 32771, 65539,
];
const ML_BITS: [u8; 53] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
];

// -------------------------------------------------------------------- Huffman

#[derive(Clone)]
struct Huf {
    max_bits: u32,
    /// Indexed by the next `max_bits` bits: (symbol, code length).
    table: Vec<(u8, u8)>,
}

impl Huf {
    fn from_weights(mut weights: Vec<u8>) -> Result<Self> {
        if weights.is_empty() || weights.len() > 255 {
            return corrupt("zstd: bad Huffman weight count");
        }
        let mut total: u32 = 0;
        for &w in &weights {
            if w > 11 {
                return corrupt("zstd: Huffman weight above 11");
            }
            if w > 0 {
                total += 1 << (w - 1);
            }
        }
        if total == 0 {
            return corrupt("zstd: all Huffman weights are zero");
        }
        let max_bits = 32 - total.leading_zeros(); // highbit(total) + 1
        if max_bits > 11 {
            return corrupt("zstd: Huffman code too long");
        }
        let left = (1u32 << max_bits) - total;
        if !left.is_power_of_two() {
            return corrupt("zstd: Huffman weights do not complete a tree");
        }
        weights.push((31 - left.leading_zeros() + 1) as u8);

        let mut rank_count = [0u32; 13];
        for &w in &weights {
            rank_count[w as usize] += 1;
        }
        let mut rank_start = [0u32; 13];
        let mut next = 0u32;
        for w in 1..=max_bits as usize {
            rank_start[w] = next;
            next += rank_count[w] << (w - 1);
        }
        if next != 1 << max_bits {
            return corrupt("zstd: Huffman ranks do not fill the table");
        }
        let mut table = vec![(0u8, 0u8); 1 << max_bits];
        for (s, &w) in weights.iter().enumerate() {
            if w == 0 {
                continue;
            }
            let len = 1u32 << (w - 1);
            let start = rank_start[w as usize];
            for e in &mut table[start as usize..(start + len) as usize] {
                *e = (s as u8, (max_bits + 1 - w as u32) as u8);
            }
            rank_start[w as usize] += len;
        }
        Ok(Huf { max_bits, table })
    }

    /// Tree description at the start of a compressed literals section.
    fn read(data: &[u8]) -> Result<(Self, usize)> {
        let header = *data
            .first()
            .ok_or_else(|| crate::error::Error::Corrupt("zstd: empty Huffman description".into()))?
            as usize;
        if header >= 128 {
            let n = header - 127;
            let bytes = n.div_ceil(2);
            let raw = data.get(1..1 + bytes).ok_or_else(|| {
                crate::error::Error::Corrupt("zstd: truncated Huffman weights".into())
            })?;
            let mut weights = Vec::with_capacity(n);
            for i in 0..n {
                let b = raw[i / 2];
                weights.push(if i % 2 == 0 { b >> 4 } else { b & 0x0f });
            }
            return Ok((Self::from_weights(weights)?, 1 + bytes));
        }
        let body = data.get(1..1 + header).ok_or_else(|| {
            crate::error::Error::Corrupt("zstd: truncated FSE Huffman weights".into())
        })?;
        let (fse, used) = Fse::read(body, 255, 6)?;
        let mut bits = BackBits::new(&body[used..])?;
        let mut s1 = bits.read(fse.log) as usize;
        let mut s2 = bits.read(fse.log) as usize;
        let mut weights = Vec::new();
        loop {
            if weights.len() > 254 {
                return corrupt("zstd: too many Huffman weights");
            }
            let e = fse.table[s1];
            weights.push(e.symbol);
            s1 = e.base as usize + bits.read(e.bits as u32) as usize;
            if bits.overflowed() {
                weights.push(fse.table[s2].symbol);
                break;
            }
            let e = fse.table[s2];
            weights.push(e.symbol);
            s2 = e.base as usize + bits.read(e.bits as u32) as usize;
            if bits.overflowed() {
                weights.push(fse.table[s1].symbol);
                break;
            }
        }
        Ok((Self::from_weights(weights)?, 1 + header))
    }

    fn decode_stream(&self, data: &[u8], n: usize, out: &mut Vec<u8>) -> Result<()> {
        let mut bits = BackBits::new(data)?;
        for _ in 0..n {
            let (sym, len) = self.table[bits.peek(self.max_bits) as usize];
            bits.left -= len as isize;
            out.push(sym);
        }
        if bits.left != 0 {
            return corrupt("zstd: Huffman stream length does not match");
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------- frame

#[derive(Default)]
struct Ctx {
    huf: Option<Huf>,
    ll: Option<Fse>,
    of: Option<Fse>,
    ml: Option<Fse>,
    rep: [usize; 3],
}

fn need(data: &[u8], pos: usize, n: usize) -> Result<&[u8]> {
    data.get(pos..pos + n)
        .ok_or_else(|| crate::error::Error::Corrupt("zstd: truncated input".into()))
}

fn literals(block: &[u8], ctx: &mut Ctx) -> Result<(Vec<u8>, usize)> {
    let b0 = block[0];
    let kind = b0 & 3;
    let format = (b0 >> 2) & 3;
    match kind {
        0 | 1 => {
            let (size, hdr) = match format {
                0 | 2 => ((b0 >> 3) as usize, 1),
                1 => {
                    let h = need(block, 0, 2)?;
                    (((h[0] >> 4) as usize) | ((h[1] as usize) << 4), 2)
                }
                _ => {
                    let h = need(block, 0, 3)?;
                    (
                        ((h[0] >> 4) as usize) | ((h[1] as usize) << 4) | ((h[2] as usize) << 12),
                        3,
                    )
                }
            };
            if size > MAX_BLOCK {
                return corrupt("zstd: literal section too large");
            }
            if kind == 0 {
                Ok((need(block, hdr, size)?.to_vec(), hdr + size))
            } else {
                Ok((
                    vec![*need(block, hdr, 1)?.first().unwrap_or(&0); size],
                    hdr + 1,
                ))
            }
        }
        _ => {
            let (regen, comp, hdr, streams) = match format {
                0 | 1 => {
                    let h = need(block, 0, 3)?;
                    let v = h[0] as u32 | (h[1] as u32) << 8 | (h[2] as u32) << 16;
                    (
                        (v >> 4) & 0x3ff,
                        (v >> 14) & 0x3ff,
                        3,
                        if format == 0 { 1 } else { 4 },
                    )
                }
                2 => {
                    let h = need(block, 0, 4)?;
                    let v = u32::from_le_bytes([h[0], h[1], h[2], h[3]]);
                    ((v >> 4) & 0x3fff, (v >> 18) & 0x3fff, 4, 4)
                }
                _ => {
                    let h = need(block, 0, 5)?;
                    let v = u64::from_le_bytes([h[0], h[1], h[2], h[3], h[4], 0, 0, 0]);
                    (
                        ((v >> 4) & 0x3ffff) as u32,
                        ((v >> 22) & 0x3ffff) as u32,
                        5,
                        4,
                    )
                }
            };
            let (regen, comp) = (regen as usize, comp as usize);
            if regen > MAX_BLOCK {
                return corrupt("zstd: literal section too large");
            }
            let body = need(block, hdr, comp)?;
            let mut pos = 0;
            if kind == 2 {
                let (huf, used) = Huf::read(body)?;
                ctx.huf = Some(huf);
                pos = used;
            }
            let huf = ctx.huf.as_ref().ok_or_else(|| {
                crate::error::Error::Corrupt("zstd: treeless literals with no previous tree".into())
            })?;
            let streams_data = &body[pos.min(body.len())..];
            let mut out = Vec::with_capacity(regen);
            if streams == 1 {
                huf.decode_stream(streams_data, regen, &mut out)?;
            } else {
                let jt = need(streams_data, 0, 6)?;
                let s1 = u16::from_le_bytes([jt[0], jt[1]]) as usize;
                let s2 = u16::from_le_bytes([jt[2], jt[3]]) as usize;
                let s3 = u16::from_le_bytes([jt[4], jt[5]]) as usize;
                let rest = &streams_data[6..];
                if s1 + s2 + s3 > rest.len() {
                    return corrupt("zstd: Huffman jump table past the section");
                }
                let seg = regen.div_ceil(4);
                if 3 * seg > regen {
                    return corrupt("zstd: too few literals for four streams");
                }
                let (a, r) = rest.split_at(s1);
                let (b, r) = r.split_at(s2);
                let (c, d) = r.split_at(s3);
                huf.decode_stream(a, seg, &mut out)?;
                huf.decode_stream(b, seg, &mut out)?;
                huf.decode_stream(c, seg, &mut out)?;
                huf.decode_stream(d, regen - 3 * seg, &mut out)?;
            }
            Ok((out, hdr + comp))
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn seq_table(
    mode: u8,
    data: &[u8],
    pos: &mut usize,
    slot: &mut Option<Fse>,
    default: &[i16],
    default_log: u32,
    max_symbol: usize,
    max_log: u32,
) -> Result<()> {
    match mode {
        0 => *slot = Some(Fse::build(default, default_log)?),
        1 => {
            let s = *need(data, *pos, 1)?.first().unwrap_or(&0);
            if s as usize > max_symbol {
                return corrupt("zstd: RLE symbol out of range");
            }
            *slot = Some(Fse::rle(s));
            *pos += 1;
        }
        2 => {
            let (t, used) = Fse::read(data.get(*pos..).unwrap_or(&[]), max_symbol, max_log)?;
            *slot = Some(t);
            *pos += used;
        }
        _ => {
            if slot.is_none() {
                return corrupt("zstd: repeat mode with no previous table");
            }
        }
    }
    Ok(())
}

fn compressed_block(block: &[u8], ctx: &mut Ctx, out: &mut Vec<u8>, max: usize) -> Result<()> {
    if block.is_empty() {
        return corrupt("zstd: empty compressed block");
    }
    let (lits, mut pos) = literals(block, ctx)?;
    let b0 = *need(block, pos, 1)?.first().unwrap_or(&0) as usize;
    let nseq = if b0 == 0 {
        pos += 1;
        0
    } else if b0 < 128 {
        pos += 1;
        b0
    } else if b0 < 255 {
        let b1 = need(block, pos + 1, 1)?[0] as usize;
        pos += 2;
        ((b0 - 128) << 8) + b1
    } else {
        let b = need(block, pos + 1, 2)?;
        pos += 3;
        b[0] as usize + ((b[1] as usize) << 8) + 0x7f00
    };
    if nseq == 0 {
        if out.len() + lits.len() > max {
            return limit("zstd: output exceeds the expected size");
        }
        out.extend_from_slice(&lits);
        return Ok(());
    }
    let modes = need(block, pos, 1)?[0];
    pos += 1;
    if modes & 3 != 0 {
        return corrupt("zstd: reserved sequence mode bits set");
    }
    seq_table(
        modes >> 6,
        block,
        &mut pos,
        &mut ctx.ll,
        &LL_DEFAULT,
        6,
        35,
        9,
    )?;
    seq_table(
        (modes >> 4) & 3,
        block,
        &mut pos,
        &mut ctx.of,
        &OF_DEFAULT,
        5,
        31,
        8,
    )?;
    seq_table(
        (modes >> 2) & 3,
        block,
        &mut pos,
        &mut ctx.ml,
        &ML_DEFAULT,
        6,
        52,
        9,
    )?;
    let (ll, of, ml) = (
        ctx.ll.as_ref().unwrap(),
        ctx.of.as_ref().unwrap(),
        ctx.ml.as_ref().unwrap(),
    );

    let mut bits = BackBits::new(block.get(pos..).unwrap_or(&[]))?;
    let mut ls = bits.read(ll.log) as usize;
    let mut os = bits.read(of.log) as usize;
    let mut ms = bits.read(ml.log) as usize;
    let mut lit_pos = 0usize;
    for i in 0..nseq {
        let (le, oe, me) = (ll.table[ls], of.table[os], ml.table[ms]);
        let of_code = oe.symbol as u32;
        if of_code > 31
            || le.symbol as usize >= LL_BASE.len()
            || me.symbol as usize >= ML_BASE.len()
        {
            return corrupt("zstd: sequence code out of range");
        }
        let of_value = (1u64 << of_code) + bits.read(of_code);
        let mlen = ML_BASE[me.symbol as usize] as usize
            + bits.read(ML_BITS[me.symbol as usize] as u32) as usize;
        let llen = LL_BASE[le.symbol as usize] as usize
            + bits.read(LL_BITS[le.symbol as usize] as u32) as usize;

        let rep = &mut ctx.rep;
        let offset = if of_value > 3 {
            let o = (of_value - 3) as usize;
            *rep = [o, rep[0], rep[1]];
            o
        } else {
            let idx = if llen == 0 {
                of_value as usize
            } else {
                of_value as usize - 1
            };
            match idx {
                0 => rep[0],
                1 => {
                    *rep = [rep[1], rep[0], rep[2]];
                    rep[0]
                }
                2 => {
                    *rep = [rep[2], rep[0], rep[1]];
                    rep[0]
                }
                _ => {
                    let o = rep[0].wrapping_sub(1);
                    if o == 0 {
                        return corrupt("zstd: repeat offset of zero");
                    }
                    *rep = [o, rep[0], rep[1]];
                    o
                }
            }
        };

        if i + 1 != nseq {
            ls = le.base as usize + bits.read(le.bits as u32) as usize;
            ms = me.base as usize + bits.read(me.bits as u32) as usize;
            os = oe.base as usize + bits.read(oe.bits as u32) as usize;
        }

        let lit = lits.get(lit_pos..lit_pos + llen).ok_or_else(|| {
            crate::error::Error::Corrupt("zstd: sequence uses more literals than decoded".into())
        })?;
        if out.len() + llen + mlen > max {
            return limit("zstd: output exceeds the expected size");
        }
        out.extend_from_slice(lit);
        lit_pos += llen;
        if offset == 0 || offset > out.len() {
            return corrupt("zstd: match offset outside the output");
        }
        let start = out.len() - offset;
        if offset >= mlen {
            out.extend_from_within(start..start + mlen);
        } else {
            for k in 0..mlen {
                let b = out[start + k];
                out.push(b);
            }
        }
    }
    if bits.left != 0 {
        return corrupt("zstd: sequence bitstream not fully consumed");
    }
    let tail = &lits[lit_pos.min(lits.len())..];
    if out.len() + tail.len() > max {
        return limit("zstd: output exceeds the expected size");
    }
    out.extend_from_slice(tail);
    Ok(())
}

fn frame(data: &[u8], out: &mut Vec<u8>, max: usize) -> Result<usize> {
    let fhd = need(data, 4, 1)?[0];
    let fcs_flag = fhd >> 6;
    let single = fhd & 0x20 != 0;
    let checksum = fhd & 0x04 != 0;
    let dict_flag = fhd & 3;
    if fhd & 0x08 != 0 {
        return corrupt("zstd: reserved frame header bit set");
    }
    let mut pos = 5;
    if !single {
        pos += 1; // window descriptor: the whole frame is kept in memory anyway
    }
    let dict_len = [0, 1, 2, 4][dict_flag as usize];
    if dict_len > 0 {
        let d = need(data, pos, dict_len)?;
        if d.iter().any(|b| *b != 0) {
            return unsupported("zstd: frames that need a dictionary");
        }
        pos += dict_len;
    }
    let fcs_len = match fcs_flag {
        0 => usize::from(single),
        1 => 2,
        2 => 4,
        _ => 8,
    };
    let mut content_size: Option<u64> = None;
    if fcs_len > 0 {
        let b = need(data, pos, fcs_len)?;
        let mut v = 0u64;
        for (i, x) in b.iter().enumerate() {
            v |= (*x as u64) << (8 * i);
        }
        if fcs_len == 2 {
            v += 256;
        }
        content_size = Some(v);
        pos += fcs_len;
    }
    if let Some(cs) = content_size {
        if cs > (max - out.len()) as u64 {
            return limit("zstd: frame larger than the expected size");
        }
        out.reserve(cs as usize);
    }
    let frame_start = out.len();
    let mut ctx = Ctx {
        rep: [1, 4, 8],
        ..Default::default()
    };
    loop {
        let h = need(data, pos, 3)?;
        let bh = h[0] as u32 | (h[1] as u32) << 8 | (h[2] as u32) << 16;
        pos += 3;
        let last = bh & 1 != 0;
        let size = (bh >> 3) as usize;
        match (bh >> 1) & 3 {
            0 => {
                if size > MAX_BLOCK || out.len() + size > max {
                    return limit("zstd: raw block too large");
                }
                out.extend_from_slice(need(data, pos, size)?);
                pos += size;
            }
            1 => {
                if size > MAX_BLOCK || out.len() + size > max {
                    return limit("zstd: RLE block too large");
                }
                let b = need(data, pos, 1)?[0];
                out.resize(out.len() + size, b);
                pos += 1;
            }
            2 => {
                if size > MAX_BLOCK {
                    return corrupt("zstd: compressed block too large");
                }
                compressed_block(need(data, pos, size)?, &mut ctx, out, max)?;
                pos += size;
            }
            _ => return corrupt("zstd: reserved block type"),
        }
        if last {
            break;
        }
    }
    if let Some(cs) = content_size {
        if (out.len() - frame_start) as u64 != cs {
            return corrupt("zstd: frame content size mismatch");
        }
    }
    if checksum {
        let c = need(data, pos, 4)?;
        let want = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
        if xxh64(&out[frame_start..], 0) as u32 != want {
            return corrupt("zstd: content checksum mismatch");
        }
        pos += 4;
    }
    Ok(pos)
}

/// Decode frames until `want` bytes are produced, ignoring whatever follows. A qcow2
/// compressed cluster's sector-rounded descriptor can cover the start of the next
/// cluster's frame; QEMU likewise stops once the cluster is full.
pub fn decompress_exact(data: &[u8], want: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut pos = 0;
    while out.len() < want {
        let magic = u32::from_le_bytes(need(data, pos, 4)?.try_into().unwrap());
        if magic != MAGIC {
            return corrupt("zstd: bad frame magic");
        }
        pos += frame(&data[pos..], &mut out, want)?;
    }
    Ok(out)
}

/// Decode every frame in `data`. Skippable frames are skipped; trailing zero padding
/// (btrfs pads compressed extents to the sector size) ends the input.
pub fn decompress(data: &[u8], max: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut pos = 0;
    let mut frames = 0;
    while pos + 4 <= data.len() {
        let magic = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        if magic == MAGIC {
            pos += frame(&data[pos..], &mut out, max)?;
            frames += 1;
        } else if magic & 0xFFFF_FFF0 == 0x184D_2A50 {
            let len = u32::from_le_bytes(need(data, pos + 4, 4)?.try_into().unwrap()) as usize;
            pos += 8 + len;
        } else if data[pos..].iter().all(|b| *b == 0) {
            break;
        } else {
            return corrupt("zstd: bad frame magic");
        }
    }
    if frames == 0 {
        return corrupt("zstd: no frame");
    }
    Ok(out)
}
