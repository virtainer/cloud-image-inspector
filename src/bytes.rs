//! Bounds-checked integer access. Every on-disk structure is read through these, so a
//! truncated or lying structure becomes `Error::Corrupt` instead of an index panic.

use crate::error::{corrupt, Result};

#[inline]
pub fn slice(b: &[u8], off: usize, len: usize) -> Result<&[u8]> {
    match off.checked_add(len) {
        Some(end) if end <= b.len() => Ok(&b[off..end]),
        _ => corrupt(format!(
            "read of {len} bytes at {off} past end of {}-byte buffer",
            b.len()
        )),
    }
}

#[inline]
fn arr<const N: usize>(b: &[u8], off: usize) -> Result<[u8; N]> {
    let s = slice(b, off, N)?;
    let mut a = [0u8; N];
    a.copy_from_slice(s);
    Ok(a)
}

#[inline]
pub fn u8_at(b: &[u8], off: usize) -> Result<u8> {
    Ok(arr::<1>(b, off)?[0])
}
#[inline]
pub fn le16(b: &[u8], off: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(arr(b, off)?))
}
#[inline]
pub fn le32(b: &[u8], off: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(arr(b, off)?))
}
#[inline]
pub fn le64(b: &[u8], off: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(arr(b, off)?))
}
#[inline]
pub fn be16(b: &[u8], off: usize) -> Result<u16> {
    Ok(u16::from_be_bytes(arr(b, off)?))
}
#[inline]
pub fn be32(b: &[u8], off: usize) -> Result<u32> {
    Ok(u32::from_be_bytes(arr(b, off)?))
}
#[inline]
pub fn be64(b: &[u8], off: usize) -> Result<u64> {
    Ok(u64::from_be_bytes(arr(b, off)?))
}

/// `usize` from a `u64` that came off disk.
#[inline]
pub fn to_usize(v: u64, what: &str) -> Result<usize> {
    usize::try_from(v).or_else(|_| corrupt(format!("{what} {v} does not fit in memory")))
}

/// Text up to the first NUL (or the end), lossily decoded.
pub fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|c| *c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_past_the_end_are_errors_not_panics() {
        let b = [1u8, 2, 3];
        assert!(le32(&b, 0).is_err());
        assert!(le16(&b, 2).is_err());
        assert!(slice(&b, usize::MAX, 2).is_err());
        assert_eq!(le16(&b, 1).unwrap(), 0x0302);
        assert_eq!(be16(&b, 0).unwrap(), 0x0102);
    }
}
