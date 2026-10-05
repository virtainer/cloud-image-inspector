//! Opt-in path counters (`CII_STATS=1`): how often each on-disk format path ran.
//! Verification uses them to show which code paths a test run actually exercised.

use std::sync::atomic::{AtomicU64, Ordering};

macro_rules! counters {
    ($($name:ident),* $(,)?) => {
        #[derive(Clone, Copy)]
        #[allow(non_camel_case_types)]
        pub enum C { $($name),* }
        const NAMES: &[&str] = &[$(stringify!($name)),*];
    };
}

counters!(
    qcow2_cluster_data,
    qcow2_cluster_deflate,
    qcow2_cluster_zstd,
    qcow2_cluster_zero,
    qcow2_cluster_unallocated,
    qcow2_subcluster,
    ext4_extent_leaf_node,
    ext4_extent_index_node,
    ext4_blockmap_direct,
    ext4_blockmap_indirect,
    ext4_inline_data,
    ext4_uninit_extent,
    ext4_fast_symlink,
    ext4_block_symlink,
    ext4_htree_dir,
    xfs_fork_extents,
    xfs_fork_btree,
    xfs_dir_shortform,
    xfs_dir_block,
    xfs_dir_leaf_node_data,
    xfs_symlink_local,
    xfs_symlink_remote,
    xfs_unwritten_extent,
    btrfs_tree_interior_node,
    btrfs_inline_plain,
    btrfs_inline_compressed,
    btrfs_regular_plain,
    btrfs_regular_zlib,
    btrfs_regular_lzo,
    btrfs_regular_zstd,
    btrfs_prealloc,
    btrfs_hole,
    btrfs_subvolume_crossing,
    sqlite_overflow_page,
    sqlite_wal_frame,
);

static COUNTS: [AtomicU64; NAMES.len()] = [const { AtomicU64::new(0) }; NAMES.len()];

#[inline]
pub fn hit(c: C) {
    COUNTS[c as usize].fetch_add(1, Ordering::Relaxed);
}

pub fn report() -> String {
    NAMES
        .iter()
        .zip(COUNTS.iter())
        .map(|(n, c)| format!("{n}={}", c.load(Ordering::Relaxed)))
        .collect::<Vec<_>>()
        .join(" ")
}
