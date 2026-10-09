//! Read-only, userspace inspection of cloud disk images.
//!
//! Layers: [`qcow2`] (or raw) → [`partition`] → [`fs`] (ext4, XFS, btrfs, FAT, NTFS) →
//! [`vfs`] path resolution → [`facts`]. Every layer treats its input as hostile:
//! reads are bounds-checked, sizes and depths are capped, and malformed data is an
//! error value, not a panic.

pub mod bytes;
pub mod compress;
pub mod error;
pub mod facts;
pub mod fs;
pub mod io;
pub mod json;
pub mod partition;
pub mod pkgdb;
pub mod qcow2;
pub mod registry;
pub mod report;
pub mod stats;
pub mod vfs;
pub mod windows;
