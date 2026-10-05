//! Installed-package databases, read straight out of the image: apk, dpkg and
//! pacman (text), RPM (SQLite holding binary RPM headers).

pub mod sqlite;

use std::collections::BTreeMap;

use crate::bytes::{be32, slice};
use crate::error::{corrupt, limit, Result};
use crate::vfs::Vfs;

#[derive(Debug, Clone, Default)]
pub struct Packages {
    pub manager: String,
    pub database: String,
    /// name → every installed version (`[epoch:]version-release` for RPM). RPM can
    /// hold several packages of one name: one `gpg-pubkey` per imported key, several
    /// kernels, multilib pairs.
    pub installed: BTreeMap<String, Vec<String>>,
    pub note: Option<String>,
}

impl Packages {
    /// Number of installed packages (not names).
    pub fn count(&self) -> usize {
        self.installed.values().map(Vec::len).sum()
    }

    pub fn version(&self, name: &str) -> Option<String> {
        self.installed.get(name).map(|v| v.join(", "))
    }
}

fn add(map: &mut BTreeMap<String, Vec<String>>, name: String, version: String) {
    let v = map.entry(name).or_default();
    v.push(version);
    v.sort();
}

/// apk's installed database (`/lib/apk/db/installed`, kept by apk-tools 2 and 3):
/// one stanza per installed package, `P:` name and `V:` version.
pub fn parse_apk(text: &str) -> BTreeMap<String, Vec<String>> {
    parse_stanzas(text, "P:", "V:", None)
}

/// dpkg's status file: only stanzas whose `Status:` ends in "installed" are
/// installed (removed packages with config files left stay listed as
/// `deinstall ok config-files`).
pub fn parse_dpkg(text: &str) -> BTreeMap<String, Vec<String>> {
    parse_stanzas(
        text,
        "Package: ",
        "Version: ",
        Some(("Status: ", " installed")),
    )
}

/// One pacman `local/<name>-<version>/desc` file: `%NAME%` and `%VERSION%` (which
/// carries the epoch, `1:2.0-1`), each followed by its value line.
pub fn parse_pacman_desc(desc: &str) -> Option<(String, String)> {
    let field = |name: &str| {
        let mut lines = desc.lines();
        while let Some(l) = lines.next() {
            if l.trim_end() == name {
                return lines
                    .next()
                    .map(|v| v.trim().to_string())
                    .filter(|v| !v.is_empty());
            }
        }
        None
    };
    Some((field("%NAME%")?, field("%VERSION%")?))
}

/// pacman's database directory: `DBPath` from `/etc/pacman.conf` when set,
/// else `/var/lib/pacman/`.
fn pacman_dbpath(v: &Vfs) -> String {
    let conf = v.read_string("/etc/pacman.conf").unwrap_or_default();
    let set = conf.lines().find_map(|l| {
        let l = l.trim();
        let (k, val) = l.split_once('=')?;
        (k.trim() == "DBPath").then(|| val.trim().to_string())
    });
    let dir = set.unwrap_or_else(|| "/var/lib/pacman/".into());
    format!("{}/", dir.trim_end_matches('/'))
}

pub fn read(v: &Vfs) -> Option<Packages> {
    for path in ["/lib/apk/db/installed", "/usr/lib/apk/db/installed"] {
        if let Some(text) = v.read_string(path) {
            return Some(Packages {
                manager: "apk".into(),
                database: path.into(),
                installed: parse_apk(&text),
                note: None,
            });
        }
    }
    if let Some(text) = v.read_string("/var/lib/dpkg/status") {
        return Some(Packages {
            manager: "dpkg".into(),
            database: "/var/lib/dpkg/status".into(),
            installed: parse_dpkg(&text),
            note: None,
        });
    }
    let local = format!("{}local", pacman_dbpath(v));
    if let Some(dirs) = v.list(&local) {
        let mut installed = BTreeMap::new();
        let mut unreadable = 0;
        for d in dirs {
            if !v.is_dir(&format!("{local}/{d}")) {
                continue; // ALPM_DB_VERSION
            }
            match v
                .read_string(&format!("{local}/{d}/desc"))
                .as_deref()
                .and_then(parse_pacman_desc)
            {
                Some((n, ver)) => add(&mut installed, n, ver),
                None => unreadable += 1,
            }
        }
        return Some(Packages {
            manager: "pacman".into(),
            database: local,
            installed,
            note: (unreadable > 0)
                .then(|| format!("{unreadable} package entries without a readable desc")),
        });
    }
    for dir in ["/usr/lib/sysimage/rpm", "/var/lib/rpm"] {
        let db = format!("{dir}/rpmdb.sqlite");
        if let Some(main) = v.read(&db) {
            let wal = v.read(&format!("{db}-wal"));
            let (installed, note) = match rpm_sqlite(main, wal) {
                Ok(p) => (p, None),
                Err(e) => (BTreeMap::new(), Some(format!("could not read {db}: {e}"))),
            };
            return Some(Packages {
                manager: "rpm".into(),
                database: db,
                installed,
                note,
            });
        }
        let ndb = format!("{dir}/Packages.db");
        if let Some(data) = v.read(&ndb) {
            let (installed, note) = match rpm_ndb(&data) {
                Ok(p) => (p, None),
                Err(e) => (BTreeMap::new(), Some(format!("could not read {ndb}: {e}"))),
            };
            return Some(Packages {
                manager: "rpm".into(),
                database: ndb,
                installed,
                note,
            });
        }
        let bdb = format!("{dir}/Packages");
        if v.is_file(&bdb) {
            return Some(Packages {
                manager: "rpm".into(),
                database: bdb,
                installed: BTreeMap::new(),
                note: Some("RPM Berkeley DB database format is not read".into()),
            });
        }
    }
    None
}

fn parse_stanzas(
    text: &str,
    name_key: &str,
    ver_key: &str,
    status: Option<(&str, &str)>,
) -> BTreeMap<String, Vec<String>> {
    let mut out = BTreeMap::new();
    for stanza in text.split("\n\n") {
        let (mut name, mut ver, mut ok) = (None, None, status.is_none());
        for l in stanza.lines() {
            if let Some(n) = l.strip_prefix(name_key) {
                name = Some(n.trim().to_string());
            } else if let Some(x) = l.strip_prefix(ver_key) {
                ver = Some(x.trim().to_string());
            } else if let Some((k, want)) = status {
                if let Some(s) = l.strip_prefix(k) {
                    ok = s.ends_with(want);
                }
            }
        }
        if let (Some(n), Some(x), true) = (name, ver, ok) {
            add(&mut out, n, x);
        }
    }
    out
}

const RPMTAG_NAME: u32 = 1000;
const RPMTAG_VERSION: u32 = 1001;
const RPMTAG_RELEASE: u32 = 1002;
const RPMTAG_EPOCH: u32 = 1003;

pub fn rpm_sqlite(main: Vec<u8>, wal: Option<Vec<u8>>) -> Result<BTreeMap<String, Vec<String>>> {
    let db = sqlite::Db::open(main, wal)?;
    let root = db
        .table_root("Packages")?
        .ok_or_else(|| crate::error::Error::Corrupt("rpmdb: no Packages table".into()))?;
    let mut rows = Vec::new();
    db.rows(root, &mut rows)?;
    let mut out = BTreeMap::new();
    for (_, payload) in rows {
        let rec = sqlite::record(&payload)?;
        let Some(sqlite::Value::Blob(blob)) =
            rec.iter().find(|v| matches!(v, sqlite::Value::Blob(_)))
        else {
            continue;
        };
        let (name, version) = rpm_header(blob)?;
        add(&mut out, name, version);
    }
    Ok(out)
}

/// RPM's "ndb" package database (`Packages.db`, openSUSE), after rpm's
/// `lib/backend/ndb/rpmpkg.c`: 16-byte slots in the first `slotnpages` 4 KiB pages
/// (after a 32-byte header) point at blobs of 16-byte blocks; each blob is a header
/// between a `BlbS` head and a `BlbE` tail. All integers are little-endian.
pub fn rpm_ndb(data: &[u8]) -> Result<BTreeMap<String, Vec<String>>> {
    use crate::bytes::le32;
    const PAGE: usize = 4096;
    if le32(data, 0)? != u32::from_le_bytes(*b"RpmP") {
        return corrupt("ndb: bad magic");
    }
    if le32(data, 4)? != 0 {
        return corrupt("ndb: unknown version");
    }
    let slot_pages = le32(data, 12)? as usize;
    if slot_pages == 0 || slot_pages * PAGE > data.len() {
        return corrupt("ndb: slot pages past the file");
    }
    let mut out = BTreeMap::new();
    for i in 2..slot_pages * PAGE / 16 {
        let s = i * 16;
        if le32(data, s)? != u32::from_le_bytes(*b"Slot") {
            continue;
        }
        let pkgidx = le32(data, s + 4)?;
        let blkoff = le32(data, s + 8)? as usize;
        let blkcnt = le32(data, s + 12)? as usize;
        if pkgidx == 0 {
            continue;
        }
        let blob = slice(data, blkoff * 16, blkcnt * 16)?;
        if le32(blob, 0)? != u32::from_le_bytes(*b"BlbS") || le32(blob, 4)? != pkgidx {
            return corrupt(format!("ndb: slot {i} does not point at its blob"));
        }
        let len = le32(blob, 12)? as usize;
        let tail = blob
            .len()
            .checked_sub(12)
            .ok_or_else(|| crate::error::Error::Corrupt("ndb: blob too short".into()))?;
        if le32(blob, tail + 8)? != u32::from_le_bytes(*b"BlbE")
            || le32(blob, tail + 4)? as usize != len
        {
            return corrupt(format!("ndb: blob {pkgidx} has a bad tail"));
        }
        let (name, version) = rpm_header(slice(blob, 16, len)?)?;
        add(&mut out, name, version);
    }
    Ok(out)
}

/// An RPM header as rpmdb stores it: `il`, `dl`, `il` index entries, data store.
pub fn rpm_header(blob: &[u8]) -> Result<(String, String)> {
    let il = be32(blob, 0)? as usize;
    let dl = be32(blob, 4)? as usize;
    if il > 1 << 16 || dl > 256 << 20 {
        return limit("rpm header too large");
    }
    let store_at = 8 + il * 16;
    let store = slice(blob, store_at, dl)?;
    let (mut name, mut ver, mut rel, mut epoch) = (None, None, None, None);
    for i in 0..il {
        let e = slice(blob, 8 + i * 16, 16)?;
        let tag = be32(e, 0)?;
        let ty = be32(e, 4)?;
        let off = be32(e, 8)? as usize;
        let string = || -> Result<String> {
            let s = store.get(off..).ok_or_else(|| {
                crate::error::Error::Corrupt("rpm: string offset past the store".into())
            })?;
            Ok(crate::bytes::cstr(s))
        };
        match (tag, ty) {
            (RPMTAG_NAME, 6) => name = Some(string()?),
            (RPMTAG_VERSION, 6) => ver = Some(string()?),
            (RPMTAG_RELEASE, 6) => rel = Some(string()?),
            (RPMTAG_EPOCH, 4) => epoch = Some(be32(store, off)?),
            _ => {}
        }
    }
    match (name, ver, rel) {
        (Some(n), Some(v), Some(r)) => {
            let e = epoch.map(|e| format!("{e}:")).unwrap_or_default();
            Ok((n, format!("{e}{v}-{r}")))
        }
        _ => corrupt("rpm header without name/version/release"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apk_stanzas() {
        let db = "C:Q1abc=\nP:musl\nV:1.2.5-r10\nA:x86_64\nS:1\nF:lib\nR:ld-musl-x86_64.so.1\n\n\
                  C:Q1def=\nP:busybox\nV:1.37.0-r31\no:busybox\n\n";
        let m = parse_apk(db);
        assert_eq!(m["musl"], vec!["1.2.5-r10"]);
        assert_eq!(m["busybox"], vec!["1.37.0-r31"]);
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn dpkg_counts_only_installed() {
        let st = "Package: bash\nStatus: install ok installed\nVersion: 5.2-1\n\n\
                  Package: gone\nStatus: deinstall ok config-files\nVersion: 1.0\n\n\
                  Package: half\nStatus: install ok half-installed\nVersion: 2.0\n\n\
                  Package: held\nStatus: hold ok installed\nVersion: 1:3.0-2\n";
        let m = parse_dpkg(st);
        assert_eq!(m.keys().collect::<Vec<_>>(), ["bash", "held"]);
        assert_eq!(m["held"], vec!["1:3.0-2"]);
    }

    #[test]
    fn pacman_desc_with_epoch() {
        let desc = "%NAME%\nopenssh\n\n%VERSION%\n1:10.5p1-1\n\n%BASE%\nopenssh\n";
        assert_eq!(
            parse_pacman_desc(desc),
            Some(("openssh".into(), "1:10.5p1-1".into()))
        );
        assert_eq!(parse_pacman_desc("%NAME%\nx\n"), None);
    }
}
