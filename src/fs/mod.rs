//! The read-only filesystem interface every reader implements, kept to exactly
//! what path resolution and fact collection need.

pub mod btrfs;
pub mod ext4;
pub mod fat;
pub mod ntfs;
pub mod xfs;

use crate::error::Result;

/// A node in some filesystem. ext4 and XFS use `(0, inode)`; btrfs uses
/// `(tree id, objectid)` because inode numbers are per subvolume. NTFS uses
/// `(sequence, MFT record)` (sequence 0 means an internal well-known record);
/// FAT uses directory-entry offsets, with a separate root marker.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NodeId(pub u64, pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    File,
    Dir,
    Symlink,
    Other,
}

#[derive(Clone, Copy, Debug)]
pub struct Stat {
    pub kind: Kind,
    pub size: u64,
    pub mode: u32,
}

pub fn kind_from_mode(mode: u32) -> Kind {
    match mode & 0o170000 {
        0o100000 => Kind::File,
        0o040000 => Kind::Dir,
        0o120000 => Kind::Symlink,
        _ => Kind::Other,
    }
}

pub struct DirEntry {
    pub name: Vec<u8>,
    pub node: NodeId,
}

pub trait FileSystem {
    fn type_name(&self) -> &'static str;
    fn root(&self) -> NodeId;
    fn stat(&self, node: NodeId) -> Result<Stat>;
    fn read_dir(&self, dir: NodeId) -> Result<Vec<DirEntry>>;
    /// Whole file contents, refusing files larger than `max`.
    fn read_file(&self, node: NodeId, max: u64) -> Result<Vec<u8>>;
    /// Bytes `[offset, offset+len)` of a file, cut short at end of file.
    fn read_range(&self, node: NodeId, offset: u64, len: u64) -> Result<Vec<u8>>;
    fn read_link(&self, node: NodeId) -> Result<Vec<u8>>;

    fn lookup(&self, dir: NodeId, name: &[u8]) -> Result<Option<NodeId>> {
        Ok(self
            .read_dir(dir)?
            .into_iter()
            .find(|e| e.name == name)
            .map(|e| e.node))
    }
}
