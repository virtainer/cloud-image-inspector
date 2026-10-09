//! Path resolution over a `FileSystem`, inside the image's own root.
//!
//! Symlinks resolve the way the guest kernel would: absolute targets restart at the
//! image root (never the host's), `..` never climbs above it, and the number of
//! symlinks followed is capped (Linux uses 40).

use std::borrow::Cow;
use std::collections::VecDeque;

use crate::error::{corrupt, limit, Result};
use crate::fs::{FileSystem, Kind, NodeId, Stat};

const MAX_SYMLINKS: usize = 40;
const MAX_COMPONENTS: usize = 4096;
/// Default cap for reading a whole file into memory.
pub const MAX_FILE: u64 = 256 << 20;

pub struct Vfs<'a> {
    pub fs: &'a dyn FileSystem,
    /// The directory treated as `/`: the filesystem root, or an OSTree deployment.
    pub root: NodeId,
}

fn split(path: &[u8]) -> impl Iterator<Item = Vec<u8>> + '_ {
    path.split(|c| *c == b'/')
        .filter(|c| !c.is_empty())
        .map(|c| c.to_vec())
}

impl<'a> Vfs<'a> {
    pub fn new(fs: &'a dyn FileSystem) -> Self {
        Self {
            fs,
            root: fs.root(),
        }
    }

    pub fn with_root(fs: &'a dyn FileSystem, root: NodeId) -> Self {
        Self { fs, root }
    }

    /// Resolve `path`. `follow_last` decides whether a final symlink is followed.
    pub fn resolve(&self, path: &str, follow_last: bool) -> Result<Option<NodeId>> {
        let path = if matches!(self.fs.type_name(), "ntfs" | "vfat") {
            Cow::Owned(path.replace('\\', "/"))
        } else {
            Cow::Borrowed(path)
        };
        let mut stack: Vec<NodeId> = vec![self.root];
        let mut todo: VecDeque<Vec<u8>> = split(path.as_bytes()).collect();
        let mut hops = 0;
        let mut steps = 0;
        while let Some(comp) = todo.pop_front() {
            steps += 1;
            if steps > MAX_COMPONENTS {
                return limit("path resolution: too many components");
            }
            if comp == b"." {
                continue;
            }
            if comp == b".." {
                if stack.len() > 1 {
                    stack.pop();
                }
                continue;
            }
            let dir = *stack.last().unwrap();
            let Some(node) = self.fs.lookup(dir, &comp)? else {
                return Ok(None);
            };
            let st = self.fs.stat(node)?;
            let last = todo.is_empty();
            if st.kind == Kind::Symlink && (!last || follow_last) {
                hops += 1;
                if hops > MAX_SYMLINKS {
                    return corrupt("path resolution: symlink loop");
                }
                let target = self.fs.read_link(node)?;
                if target.first() == Some(&b'/') {
                    stack.truncate(1);
                }
                let mut next: VecDeque<Vec<u8>> = split(&target).collect();
                next.extend(todo.drain(..));
                todo = next;
                continue;
            }
            if last {
                return Ok(Some(node));
            }
            if st.kind != Kind::Dir {
                return Ok(None);
            }
            stack.push(node);
        }
        Ok(stack.last().copied())
    }

    pub fn stat(&self, path: &str) -> Option<Stat> {
        let n = self.resolve(path, true).ok().flatten()?;
        self.fs.stat(n).ok()
    }

    pub fn exists(&self, path: &str) -> bool {
        self.stat(path).is_some()
    }

    pub fn is_file(&self, path: &str) -> bool {
        self.stat(path).is_some_and(|s| s.kind == Kind::File)
    }

    pub fn is_dir(&self, path: &str) -> bool {
        self.stat(path).is_some_and(|s| s.kind == Kind::Dir)
    }

    /// A regular file's contents; `None` if missing, not a file, or unreadable.
    pub fn read(&self, path: &str) -> Option<Vec<u8>> {
        self.read_max(path, MAX_FILE).ok().flatten()
    }

    pub fn read_max(&self, path: &str, max: u64) -> Result<Option<Vec<u8>>> {
        let Some(n) = self.resolve(path, true)? else {
            return Ok(None);
        };
        if self.fs.stat(n)?.kind != Kind::File {
            return Ok(None);
        }
        self.fs.read_file(n, max).map(Some)
    }

    pub fn read_string(&self, path: &str) -> Option<String> {
        self.read(path)
            .map(|b| String::from_utf8_lossy(&b).into_owned())
    }

    pub fn list(&self, path: &str) -> Option<Vec<String>> {
        let n = self.resolve(path, true).ok().flatten()?;
        if self.fs.stat(n).ok()?.kind != Kind::Dir {
            return None;
        }
        let mut names: Vec<String> = self
            .fs
            .read_dir(n)
            .ok()?
            .into_iter()
            .map(|e| String::from_utf8_lossy(&e.name).into_owned())
            .filter(|n| n != "." && n != "..")
            .collect();
        names.sort();
        Some(names)
    }

    /// The target text of a symlink at `path` (the last component is not followed).
    pub fn read_link(&self, path: &str) -> Option<String> {
        let n = self.resolve(path, false).ok().flatten()?;
        if self.fs.stat(n).ok()?.kind != Kind::Symlink {
            return None;
        }
        self.fs
            .read_link(n)
            .ok()
            .map(|t| String::from_utf8_lossy(&t).into_owned())
    }

    /// The canonical path of a directory: every symlink in it resolved, the way
    /// `realpath` would inside the image (`/bin` → `/usr/bin` on usr-merged systems).
    pub fn real_dir(&self, path: &str) -> String {
        let mut real: Vec<String> = Vec::new();
        let mut todo: VecDeque<String> = path
            .split('/')
            .filter(|c| !c.is_empty())
            .map(str::to_string)
            .collect();
        let mut hops = 0;
        while let Some(c) = todo.pop_front() {
            match c.as_str() {
                "." => continue,
                ".." => {
                    real.pop();
                    continue;
                }
                _ => {}
            }
            let here = format!(
                "/{}",
                real.iter()
                    .chain(std::iter::once(&c))
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("/")
            );
            match self.read_link(&here) {
                Some(t) if hops < MAX_SYMLINKS => {
                    hops += 1;
                    if t.starts_with('/') {
                        real.clear();
                    }
                    let mut next: VecDeque<String> = t
                        .split('/')
                        .filter(|x| !x.is_empty())
                        .map(str::to_string)
                        .collect();
                    next.extend(todo.drain(..));
                    todo = next;
                }
                _ => real.push(c),
            }
        }
        format!("/{}", real.join("/"))
    }

    /// Follow a chain of symlinks from `path`, returning each hop as a canonical path:
    /// `/bin/sh` → `/usr/bin/dash` (with `/bin` → `usr/bin` and `sh` → `dash`).
    pub fn link_chain(&self, path: &str) -> Vec<String> {
        let mut chain = vec![path.to_string()];
        let mut cur = path.to_string();
        for _ in 0..MAX_SYMLINKS {
            let Some(target) = self.read_link(&cur) else {
                break;
            };
            let (parent, _) = cur.rsplit_once('/').unwrap_or(("", ""));
            let base = self.real_dir(parent);
            let next = if target.starts_with('/') {
                normalize(&target)
            } else {
                normalize(&format!("{base}/{target}"))
            };
            // Canonicalise the new hop's directory too, so the last entry is the
            // file's real location.
            let (np, nn) = next.rsplit_once('/').unwrap_or(("", &next));
            cur = normalize(&format!("{}/{nn}", self.real_dir(np)));
            chain.push(cur.clone());
        }
        chain
    }
}

/// Lexically normalise an absolute path (`/usr/bin/../lib` → `/usr/lib`).
pub fn normalize(path: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for c in path.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            c => out.push(c),
        }
    }
    format!("/{}", out.join("/"))
}
