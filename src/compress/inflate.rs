//! DEFLATE (RFC 1951) and the zlib wrapper (RFC 1950).
//!
//! Structure follows Mark Adler's `puff.c` (zlib licence): canonical Huffman codes
//! described by per-length counts plus a symbol list, decoded one bit at a time, with
//! a 9-bit lookup table in front for speed. qcow2 stores clusters as raw DEFLATE
//! (`windowBits = -12`); btrfs stores zlib streams.

use crate::error::{corrupt, limit, Result};

const MAXBITS: usize = 15;
const FAST_BITS: u32 = 9;

struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
    buf: u64,
    cnt: u32,
}

impl<'a> Bits<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            buf: 0,
            cnt: 0,
        }
    }

    #[inline]
    fn refill(&mut self) {
        while self.cnt <= 56 && self.pos < self.data.len() {
            self.buf |= (self.data[self.pos] as u64) << self.cnt;
            self.pos += 1;
            self.cnt += 8;
        }
    }

    #[inline]
    fn need(&mut self, n: u32) -> Result<()> {
        if self.cnt < n {
            self.refill();
            if self.cnt < n {
                return corrupt("deflate: input ended inside a block");
            }
        }
        Ok(())
    }

    #[inline]
    fn bits(&mut self, n: u32) -> Result<u32> {
        if n == 0 {
            return Ok(0);
        }
        self.need(n)?;
        let v = (self.buf & ((1u64 << n) - 1)) as u32;
        self.buf >>= n;
        self.cnt -= n;
        Ok(v)
    }

    /// Discard to the next byte boundary (stored blocks).
    fn align(&mut self) {
        let drop = self.cnt % 8;
        self.buf >>= drop;
        self.cnt -= drop;
    }

    /// Bytes consumed so far, counting buffered-but-unused whole bytes as unread.
    fn consumed(&self) -> usize {
        self.pos - (self.cnt / 8) as usize
    }
}

struct Huffman {
    count: [u16; MAXBITS + 1],
    symbol: Vec<u16>,
    /// Indexed by the next FAST_BITS input bits (LSB-first): (symbol, length) or
    /// length 0 when the code is longer than FAST_BITS.
    fast: Vec<(u16, u8)>,
}

impl Huffman {
    /// Build from code lengths. Returns the code and "left": 0 complete, >0
    /// incomplete. Over-subscribed sets are corrupt.
    fn new(lengths: &[u8]) -> Result<(Self, i32)> {
        let mut count = [0u16; MAXBITS + 1];
        for &l in lengths {
            count[l as usize] += 1;
        }
        let mut left: i32 = 1;
        for &c in count.iter().skip(1) {
            left <<= 1;
            left -= c as i32;
            if left < 0 {
                return corrupt("deflate: over-subscribed Huffman code");
            }
        }
        let mut offs = [0u16; MAXBITS + 1];
        for len in 1..MAXBITS {
            offs[len + 1] = offs[len] + count[len];
        }
        let mut symbol = vec![0u16; lengths.len()];
        for (s, &l) in lengths.iter().enumerate() {
            if l != 0 {
                symbol[offs[l as usize] as usize] = s as u16;
                offs[l as usize] += 1;
            }
        }
        // Fast table: walk every code of length <= FAST_BITS in canonical order.
        let mut fast = vec![(0u16, 0u8); 1 << FAST_BITS];
        let mut code: u32 = 0;
        let mut index = 0usize;
        for len in 1..=MAXBITS as u32 {
            for _ in 0..count[len as usize] {
                if len <= FAST_BITS {
                    // Canonical codes are MSB-first; the bit reader is LSB-first.
                    let rev = code.reverse_bits() >> (32 - len);
                    let mut fill = rev as usize;
                    while fill < fast.len() {
                        fast[fill] = (symbol[index], len as u8);
                        fill += 1 << len;
                    }
                }
                code += 1;
                index += 1;
            }
            code <<= 1;
        }
        Ok((
            Self {
                count,
                symbol,
                fast,
            },
            left,
        ))
    }
}

fn decode(bits: &mut Bits, h: &Huffman) -> Result<u16> {
    bits.refill();
    if bits.cnt >= FAST_BITS {
        let (sym, len) = h.fast[(bits.buf & ((1 << FAST_BITS) - 1)) as usize];
        if len != 0 {
            bits.buf >>= len;
            bits.cnt -= len as u32;
            return Ok(sym);
        }
    }
    // Slow path (puff's `decode`): one bit at a time.
    let mut code: i32 = 0;
    let mut first: i32 = 0;
    let mut index: i32 = 0;
    for len in 1..=MAXBITS {
        code |= bits.bits(1)? as i32;
        let count = h.count[len] as i32;
        if code - count < first {
            return Ok(h.symbol[(index + (code - first)) as usize]);
        }
        index += count;
        first += count;
        first <<= 1;
        code <<= 1;
    }
    corrupt("deflate: ran out of codes")
}

const LBASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LEXT: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DBASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DEXT: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

fn codes(
    bits: &mut Bits,
    out: &mut Vec<u8>,
    lencode: &Huffman,
    distcode: &Huffman,
    max: usize,
) -> Result<()> {
    loop {
        let sym = decode(bits, lencode)? as usize;
        if sym < 256 {
            if out.len() >= max {
                return limit("deflate: output exceeds the expected size");
            }
            out.push(sym as u8);
        } else if sym == 256 {
            return Ok(());
        } else {
            let sym = sym - 257;
            if sym >= 29 {
                return corrupt("deflate: invalid length symbol");
            }
            let len = LBASE[sym] as usize + bits.bits(LEXT[sym] as u32)? as usize;
            let dsym = decode(bits, distcode)? as usize;
            if dsym >= 30 {
                return corrupt("deflate: invalid distance symbol");
            }
            let dist = DBASE[dsym] as usize + bits.bits(DEXT[dsym] as u32)? as usize;
            if dist > out.len() {
                return corrupt("deflate: distance too far back");
            }
            if out.len() + len > max {
                return limit("deflate: output exceeds the expected size");
            }
            let start = out.len() - dist;
            if dist >= len {
                out.extend_from_within(start..start + len);
            } else {
                for i in 0..len {
                    let b = out[start + i];
                    out.push(b);
                }
            }
        }
    }
}

fn fixed_tables() -> Result<(Huffman, Huffman)> {
    let mut l = [0u8; 288];
    l[..144].fill(8);
    l[144..256].fill(9);
    l[256..280].fill(7);
    l[280..].fill(8);
    let (lencode, _) = Huffman::new(&l)?;
    let (distcode, _) = Huffman::new(&[5u8; 30])?;
    Ok((lencode, distcode))
}

fn dynamic_tables(bits: &mut Bits) -> Result<(Huffman, Huffman)> {
    const ORDER: [usize; 19] = [
        16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
    ];
    let nlen = bits.bits(5)? as usize + 257;
    let ndist = bits.bits(5)? as usize + 1;
    let ncode = bits.bits(4)? as usize + 4;
    if nlen > 286 || ndist > 30 {
        return corrupt("deflate: bad dynamic block counts");
    }
    let mut lengths = [0u8; 320];
    for &o in ORDER.iter().take(ncode) {
        lengths[o] = bits.bits(3)? as u8;
    }
    let (lencode, left) = Huffman::new(&lengths[..19])?;
    if left != 0 {
        return corrupt("deflate: incomplete code-length code");
    }
    let mut index = 0;
    while index < nlen + ndist {
        let sym = decode(bits, &lencode)?;
        if sym < 16 {
            lengths[index] = sym as u8;
            index += 1;
            continue;
        }
        let (len, rep) = match sym {
            16 => {
                if index == 0 {
                    return corrupt("deflate: repeat with no previous length");
                }
                (lengths[index - 1], 3 + bits.bits(2)? as usize)
            }
            17 => (0, 3 + bits.bits(3)? as usize),
            _ => (0, 11 + bits.bits(7)? as usize),
        };
        if index + rep > nlen + ndist {
            return corrupt("deflate: too many code lengths");
        }
        lengths[index..index + rep].fill(len);
        index += rep;
    }
    if lengths[256] == 0 {
        return corrupt("deflate: no end-of-block code");
    }
    let (l, left) = Huffman::new(&lengths[..nlen])?;
    if left > 0 && nlen - l.count[0] as usize != 1 {
        return corrupt("deflate: incomplete literal/length code");
    }
    let (d, left) = Huffman::new(&lengths[nlen..nlen + ndist])?;
    if left > 0 && ndist - d.count[0] as usize != 1 {
        return corrupt("deflate: incomplete distance code");
    }
    Ok((l, d))
}

/// Decompress one raw DEFLATE stream. Returns the output and the input bytes used.
pub fn inflate(input: &[u8], max_out: usize) -> Result<(Vec<u8>, usize)> {
    let mut bits = Bits::new(input);
    let mut out = Vec::new();
    loop {
        let last = bits.bits(1)?;
        match bits.bits(2)? {
            0 => {
                bits.align();
                let len = bits.bits(16)? as usize;
                let nlen = bits.bits(16)? as usize;
                if len != (!nlen & 0xffff) {
                    return corrupt("deflate: stored block length check failed");
                }
                if out.len() + len > max_out {
                    return limit("deflate: output exceeds the expected size");
                }
                for _ in 0..len {
                    out.push(bits.bits(8)? as u8);
                }
            }
            1 => {
                let (l, d) = fixed_tables()?;
                codes(&mut bits, &mut out, &l, &d, max_out)?;
            }
            2 => {
                let (l, d) = dynamic_tables(&mut bits)?;
                codes(&mut bits, &mut out, &l, &d, max_out)?;
            }
            _ => return corrupt("deflate: reserved block type"),
        }
        if last == 1 {
            break;
        }
    }
    Ok((out, bits.consumed()))
}

pub fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for chunk in data.chunks(5552) {
        for &x in chunk {
            a += x as u32;
            b += a;
        }
        a %= 65521;
        b %= 65521;
    }
    (b << 16) | a
}

/// RFC 1950 zlib stream: 2-byte header, DEFLATE, big-endian Adler-32.
pub fn zlib_decompress(input: &[u8], max_out: usize) -> Result<Vec<u8>> {
    if input.len() < 2 {
        return corrupt("zlib: stream too short");
    }
    let (cmf, flg) = (input[0], input[1]);
    if cmf & 0x0f != 8 || !((cmf as u16) << 8 | flg as u16).is_multiple_of(31) {
        return corrupt("zlib: bad header");
    }
    if flg & 0x20 != 0 {
        return corrupt("zlib: preset dictionaries are not used by any format read here");
    }
    let (out, used) = inflate(&input[2..], max_out)?;
    if let Some(sum) = input.get(2 + used..2 + used + 4) {
        let want = u32::from_be_bytes([sum[0], sum[1], sum[2], sum[3]]);
        if want != adler32(&out) {
            return corrupt("zlib: Adler-32 mismatch");
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real compressor output is checked against generated vectors in tests/compress.rs.
    #[test]
    fn stored_block() {
        // BFINAL=1, BTYPE=00, LEN=3, NLEN=!3.
        let s = [0x01, 0x03, 0x00, 0xfc, 0xff, b'a', b'b', b'c'];
        assert_eq!(inflate(&s, 10).unwrap().0, b"abc");
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
    }

    #[test]
    fn garbage_is_an_error() {
        assert!(inflate(&[0xff, 0xff, 0xff], 100).is_err());
        assert!(zlib_decompress(&[0x78, 0x9c, 0x00], 100).is_err());
    }
}
