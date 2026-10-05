//! Decompressors for what cloud images actually contain: DEFLATE/zlib (qcow2's
//! default, btrfs zlib), zstd (qcow2 `compression_type=zstd`, btrfs zstd) and LZO
//! (btrfs lzo).

pub mod inflate;
pub mod lzo;
pub mod xxhash;
pub mod zstd;
