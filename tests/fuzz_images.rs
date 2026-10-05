//! Corrupt fixture images and run the whole pipeline on them: it must return
//! errors, never panic or hang. Corruption is a copy-on-write overlay, applied to
//! the qcow2 file itself or to the guest-visible disk.
//!
//! CII_FUZZ_ITERS (default 150) iterations per image; CII_FUZZ_IMAGES overrides the
//! image list. Skips when the fixtures have not been built.

use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use cloud_image_inspector::error::Result;
use cloud_image_inspector::facts::{inspect_disk, open_source, with_view_of, Container};
use cloud_image_inspector::fs::{Kind, NodeId};
use cloud_image_inspector::io::{FileSource, ReadAt};
use cloud_image_inspector::vfs::Vfs;

struct Overlay {
    base: Rc<dyn ReadAt>,
    patches: Vec<(u64, u8)>,
}

impl ReadAt for Overlay {
    fn size(&self) -> u64 {
        self.base.size()
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.base.read_at(offset, buf)?;
        let end = offset + buf.len() as u64;
        let start = self.patches.partition_point(|p| p.0 < offset);
        for &(o, v) in &self.patches[start..] {
            if o >= end {
                break;
            }
            buf[(o - offset) as usize] = v;
        }
        Ok(())
    }
}

/// Records which 4 KiB blocks a clean run reads: the metadata (and small files) the
/// parsers actually interpret, where corruption is worth aiming.
struct Recorder {
    base: Rc<dyn ReadAt>,
    seen: std::cell::RefCell<std::collections::BTreeSet<u64>>,
}

impl ReadAt for Recorder {
    fn size(&self) -> u64 {
        self.base.size()
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let mut s = self.seen.borrow_mut();
        let mut b = offset & !4095;
        while b < offset + buf.len() as u64 && s.len() < 400_000 {
            s.insert(b);
            b += 4096;
        }
        drop(s);
        self.base.read_at(offset, buf)
    }
}

fn read_blocks(base: Rc<dyn ReadAt>, guest: bool) -> Vec<u64> {
    let rec = Rc::new(Recorder {
        base,
        seen: Default::default(),
    });
    if guest {
        let _ = inspect_disk(rec.clone());
    } else {
        let mut c = Container::default();
        if let Ok(d) = open_source(rec.clone(), &mut c) {
            let _ = inspect_disk(d);
        }
    }
    let v: Vec<u64> = rec.seen.borrow().iter().copied().collect();
    v
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

/// Offsets of non-zero 4 KiB blocks: metadata lives there, so corrupting them hits
/// the parsers instead of free space.
fn nonzero_blocks(dev: &dyn ReadAt, cap: usize) -> Vec<u64> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 4096];
    let mut off = 0;
    while off + 4096 <= dev.size() && out.len() < cap {
        if dev.read_at(off, &mut buf).is_ok() && buf.iter().any(|b| *b != 0) {
            out.push(off);
        }
        off += 4096;
    }
    out
}

fn walk(v: &Vfs, node: NodeId, depth: usize, budget: &mut usize) {
    if depth > 64 || *budget == 0 {
        return;
    }
    let Ok(entries) = v.fs.read_dir(node) else {
        return;
    };
    for e in entries {
        if *budget == 0 {
            return;
        }
        *budget -= 1;
        if e.name == b"." || e.name == b".." {
            continue;
        }
        match v.fs.stat(e.node).map(|s| s.kind) {
            Ok(Kind::Dir) => walk(v, e.node, depth + 1, budget),
            Ok(Kind::File) => drop(v.fs.read_range(e.node, 0, 1 << 20)),
            Ok(Kind::Symlink) => drop(v.fs.read_link(e.node)),
            _ => {}
        }
    }
}

fn pipeline(disk: Rc<dyn ReadAt>) {
    let _ = inspect_disk(disk.clone());
    let _ = with_view_of(disk, None, None, |v| {
        let mut budget = 3000;
        walk(v, v.root, 0, &mut budget);
    });
}

#[test]
fn corrupted_images_fail_cleanly() {
    let images: Vec<String> = match std::env::var("CII_FUZZ_IMAGES") {
        Ok(list) => list.split(',').map(str::to_string).collect(),
        Err(_) => [
            "ext4-default",
            "ext2-blockmap",
            "ext4-inline",
            "xfs-default",
            "xfs-v4",
            "btrfs-zstd",
            "btrfs-node4k-zstd15",
            "c-zstd",
            "c-extl2",
        ]
        .iter()
        .map(|n| format!("fixtures/out/fs/{n}.qcow2"))
        .collect(),
    };
    if !std::path::Path::new(&images[0]).exists() {
        assert!(
            std::env::var_os("CII_REQUIRE").is_none(),
            "fixtures missing; run tools/make_fixtures.py first"
        );
        eprintln!("no fixtures; run tools/make_fixtures.py");
        return;
    }
    let iters: u64 = std::env::var("CII_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(150);
    // Watchdog: any single iteration taking longer than this is a hang.
    let progress = Arc::new(AtomicU64::new(0));
    let p2 = progress.clone();
    let started = Instant::now();
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(5));
        let last = p2.load(Ordering::Relaxed);
        if started.elapsed().as_secs() > last + 60 {
            eprintln!("HANG: no progress for 60 s (see the last 'iteration' line)");
            std::process::abort();
        }
    });
    let mut total = 0;
    for img in &images {
        let file: Rc<dyn ReadAt> = Rc::new(FileSource::open(std::path::Path::new(img)).unwrap());
        let mut c = Container::default();
        let disk = open_source(file.clone(), &mut c).unwrap();
        // Half the corruptions land in blocks a clean inspection reads, half anywhere
        // non-zero (file data, structures only the tree walk reaches).
        let guest_read = read_blocks(disk.clone(), true);
        let file_read = read_blocks(file.clone(), false);
        let guest_blocks = nonzero_blocks(&*disk, 200_000);
        let file_blocks = nonzero_blocks(&*file, 200_000);
        eprintln!(
            "{img}: {} guest blocks read by a clean run, {} qcow2-file blocks",
            guest_read.len(),
            file_read.len()
        );
        for i in 0..iters {
            let mut rng = Rng(0x9E37_79B9_7F4A_7C15 ^ (i * 0x1_0000_0001) ^ total);
            let on_file = i % 4 == 0;
            let aimed = i % 2 == 1;
            let blocks = match (on_file, aimed) {
                (true, true) => &file_read,
                (true, false) => &file_blocks,
                (false, true) => &guest_read,
                (false, false) => &guest_blocks,
            };
            let mut patches: Vec<(u64, u8)> = (0..1 + rng.next() % 64)
                .map(|_| {
                    let b = blocks[(rng.next() as usize) % blocks.len()];
                    (b + rng.next() % 4096, rng.next() as u8)
                })
                .collect();
            patches.sort_by_key(|p| p.0);
            patches.dedup_by_key(|p| p.0);
            eprintln!(
                "iteration {img} #{i} ({} patches on the {})",
                patches.len(),
                if on_file { "qcow2 file" } else { "guest disk" }
            );
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if on_file {
                    let corrupted: Rc<dyn ReadAt> = Rc::new(Overlay {
                        base: file.clone(),
                        patches: patches.clone(),
                    });
                    let mut c = Container::default();
                    if let Ok(d) = open_source(corrupted, &mut c) {
                        pipeline(d);
                    }
                } else {
                    pipeline(Rc::new(Overlay {
                        base: disk.clone(),
                        patches: patches.clone(),
                    }));
                }
            }));
            assert!(
                outcome.is_ok(),
                "panic on {img} iteration {i} with patches {patches:?}"
            );
            progress.store(started.elapsed().as_secs(), Ordering::Relaxed);
            total += 1;
        }
    }
    eprintln!("{total} corrupted images processed without a panic or hang");
}
