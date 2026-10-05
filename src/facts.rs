//! Find the root filesystem and collect the facts that decide how a first-boot
//! configuration has to be written for this guest.

use std::path::Path;
use std::rc::Rc;

use crate::error::Result;
use crate::fs::btrfs::Btrfs;
use crate::fs::ext4::Ext4;
use crate::fs::xfs::Xfs;
use crate::fs::{FileSystem, NodeId};
use crate::io::{FileSource, ReadAt, Window};
use crate::partition::{self, FsType, PartKind, TableKind};
use crate::pkgdb::{self, Packages};
use crate::qcow2::{self, Qcow2};
use crate::vfs::Vfs;

/// Packages whose versions are reported by name (whichever exist in the image).
pub const KEY_PACKAGES: &[&str] = &[
    "cloud-init",
    "tiny-cloud",
    "ignition",
    "openssh-server",
    "openssh",
    "openssh-server-pam",
    "bash",
    "dash",
    "busybox",
    "sudo",
    "doas",
    "opendoas",
    "systemd",
    "openrc",
    "shadow",
    "python3",
    "linux-virt",
    "linux-lts",
];

#[derive(Debug, Clone, Default)]
pub struct Container {
    pub format: String,
    pub version: Option<u32>,
    pub virtual_size: u64,
    pub cluster_size: Option<u64>,
    pub compression: Option<String>,
    pub extended_l2: bool,
    pub snapshots: u32,
}

#[derive(Debug, Clone)]
pub struct PartitionInfo {
    pub number: u32,
    pub kind: String,
    pub type_id: String,
    pub name: String,
    pub start: u64,
    pub size: u64,
    pub filesystem: String,
    pub label: Option<String>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Boot {
    /// An EFI System Partition exists: bootable under UEFI firmware (CLOUDHV.fd).
    pub uefi: bool,
    /// A BIOS path exists: a GPT BIOS boot partition, or MBR boot code.
    pub bios: bool,
    pub esp: Vec<u32>,
}

#[derive(Debug, Clone, Default)]
pub struct RootFs {
    pub partition: Option<u32>,
    pub filesystem: String,
    pub subvolume: Option<String>,
    pub ostree_deployment: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct OsRelease {
    pub id: String,
    pub version_id: String,
    pub id_like: String,
    pub name: String,
    pub pretty_name: String,
    pub version_codename: String,
    pub source: String,
}

#[derive(Debug, Clone, Default)]
pub struct Facts {
    pub os: OsRelease,
    pub etc_shells: Vec<String>,
    pub bash: Option<String>,
    pub sh_chain: Vec<String>,
    pub useradd_shell: Option<String>,
    pub sudo: Option<String>,
    pub doas: Option<String>,
    pub sudoers_d: bool,
    pub doas_d: bool,
    pub doas_conf: bool,
    pub init_system: String,
    pub init_chain: Vec<String>,
    pub systemd: Option<String>,
    pub openrc: Option<String>,
    /// `/etc/inittab` exists: an init that reads it (busybox init, sysvinit, OpenRC
    /// booted by either) starts the serial getty from there.
    pub inittab: bool,
    /// `/sbin/getty` symlink chain (canonical paths); on busybox systems it ends in
    /// `/bin/busybox`, whose getty takes different options from util-linux's.
    pub getty_chain: Vec<String>,
    /// util-linux `agetty`, which has `--autologin`.
    pub agetty: Option<String>,
    /// `login`, which a getty runs to start the session.
    pub login: Option<String>,
    pub sshd: Option<String>,
    pub sshd_pam: Option<String>,
    pub sshd_use_pam: Option<String>,
    pub sshd_includes_dropins: bool,
    pub cloud_init: Option<String>,
    pub cloud_init_version: Option<String>,
    pub cloud_init_version_source: Option<String>,
    pub cloud_init_datasources: Option<String>,
    pub tiny_cloud: Option<String>,
    pub ignition: Option<String>,
    pub packages: Option<Packages>,
}

#[derive(Debug, Clone, Default)]
pub struct Report {
    pub image: String,
    pub container: Container,
    pub table: String,
    pub partitions: Vec<PartitionInfo>,
    pub boot: Boot,
    pub root: Option<RootFs>,
    pub facts: Option<Facts>,
    pub warnings: Vec<String>,
}

/// The guest disk: qcow2 if it says so, otherwise raw.
pub fn open_disk(path: &Path, container: &mut Container) -> Result<Rc<dyn ReadAt>> {
    open_source(Rc::new(FileSource::open(path)?), container)
}

/// Same, over any byte source (the fuzz tests corrupt one in memory).
pub fn open_source(file: Rc<dyn ReadAt>, container: &mut Container) -> Result<Rc<dyn ReadAt>> {
    if qcow2::is_qcow2(&*file) {
        let q = Qcow2::open(file)?;
        let i = q.info.clone();
        *container = Container {
            format: "qcow2".into(),
            version: Some(i.version),
            virtual_size: i.virtual_size,
            cluster_size: Some(i.cluster_size),
            compression: Some(match i.compression {
                qcow2::Compression::Deflate => "deflate".into(),
                qcow2::Compression::Zstd => "zstd".into(),
            }),
            extended_l2: i.extended_l2,
            snapshots: i.snapshots,
        };
        return Ok(Rc::new(q));
    }
    *container = Container {
        format: "raw".into(),
        virtual_size: file.size(),
        ..Default::default()
    };
    Ok(file)
}

pub enum AnyFs {
    Ext4(Ext4),
    Xfs(Xfs),
    Btrfs(Btrfs),
}

impl AnyFs {
    pub fn open(dev: Rc<dyn ReadAt>, t: FsType) -> Option<Result<Self>> {
        Some(match t {
            FsType::Ext => Ext4::open(dev).map(AnyFs::Ext4),
            FsType::Xfs => Xfs::open(dev).map(AnyFs::Xfs),
            FsType::Btrfs => Btrfs::open(dev).map(AnyFs::Btrfs),
            _ => return None,
        })
    }

    pub fn fs(&self) -> &dyn FileSystem {
        match self {
            AnyFs::Ext4(f) => f,
            AnyFs::Xfs(f) => f,
            AnyFs::Btrfs(f) => f,
        }
    }

    pub fn label(&self) -> String {
        match self {
            AnyFs::Ext4(f) => f.label.clone(),
            AnyFs::Xfs(f) => f.label.clone(),
            AnyFs::Btrfs(f) => f.label.clone(),
        }
    }
}

/// Root candidates inside one filesystem: btrfs subvolumes (default first), and an
/// OSTree deployment when the filesystem is an OSTree sysroot.
fn root_candidates(fs: &mut AnyFs) -> Vec<(Option<u64>, Option<String>, NodeId)> {
    let mut subvols: Vec<Option<u64>> = vec![None];
    if let AnyFs::Btrfs(b) = fs {
        let mut ids = vec![b.default_subvolume, 5];
        ids.extend(b.subvolumes.iter().map(|s| s.id));
        ids.dedup();
        let mut seen = Vec::new();
        subvols = ids
            .into_iter()
            .filter(|i| {
                !seen.contains(i) && {
                    seen.push(*i);
                    true
                }
            })
            .map(Some)
            .collect();
    }
    let mut out = Vec::new();
    for sv in subvols {
        if let (Some(id), AnyFs::Btrfs(b)) = (sv, &mut *fs) {
            b.set_root_subvolume(id);
        }
        let f = fs.fs();
        let v = Vfs::new(f);
        if let Some(deploys) = v.list("/ostree/deploy") {
            for os in deploys {
                for d in v
                    .list(&format!("/ostree/deploy/{os}/deploy"))
                    .unwrap_or_default()
                {
                    let p = format!("/ostree/deploy/{os}/deploy/{d}");
                    if v.is_dir(&p) {
                        if let Ok(Some(n)) = v.resolve(&p, true) {
                            out.push((sv, Some(p), n));
                        }
                    }
                }
            }
        }
        out.push((sv, None, f.root()));
    }
    out
}

fn has_os_release(v: &Vfs) -> bool {
    v.is_file("/etc/os-release") || v.is_file("/usr/lib/os-release")
}

pub fn inspect(path: &Path) -> Result<Report> {
    let mut container = Container::default();
    let disk = open_disk(path, &mut container)?;
    let mut r = inspect_disk(disk)?;
    r.image = path.display().to_string();
    r.container = container;
    Ok(r)
}

pub fn inspect_disk(disk: Rc<dyn ReadAt>) -> Result<Report> {
    let mut r = Report::default();
    let table = partition::read_table(&*disk)?;
    r.table = match table.kind {
        TableKind::Gpt => "gpt",
        TableKind::Mbr => "mbr",
        TableKind::None => "none",
    }
    .into();

    let mut parts = table.partitions.clone();
    if table.kind == TableKind::None {
        parts.push(partition::Partition {
            number: 0,
            start: 0,
            len: disk.size(),
            kind: PartKind::Other,
            type_id: String::new(),
            name: "(whole disk)".into(),
            bootable_flag: false,
        });
    }
    r.boot.esp = parts
        .iter()
        .filter(|p| p.kind == PartKind::Esp)
        .map(|p| p.number)
        .collect();
    r.boot.uefi = !r.boot.esp.is_empty();
    r.boot.bios = parts.iter().any(|p| p.kind == PartKind::BiosBoot)
        || (table.kind != TableKind::Gpt && table.mbr_boot_code);
    r.warnings.extend(table.warnings.iter().cloned());

    for p in &parts {
        let mut info = PartitionInfo {
            number: p.number,
            kind: p.kind.name().into(),
            type_id: p.type_id.clone(),
            name: p.name.clone(),
            start: p.start,
            size: p.len,
            filesystem: "unknown".into(),
            label: None,
            note: None,
        };
        let dev: Rc<dyn ReadAt> = match Window::new(disk.clone(), p.start, p.len) {
            Ok(w) => Rc::new(w),
            Err(e) => {
                info.note = Some(e.to_string());
                r.partitions.push(info);
                continue;
            }
        };
        let t = partition::probe(&*dev);
        info.filesystem = t.name().into();
        match AnyFs::open(dev, t) {
            None => {}
            Some(Err(e)) => info.note = Some(e.to_string()),
            Some(Ok(mut fs)) => {
                let label = fs.label();
                info.label = (!label.is_empty()).then_some(label);
                if let AnyFs::Ext4(e) = &fs {
                    if e.needs_recovery {
                        r.warnings.push(format!("partition {}: ext4 journal needs recovery; recent changes may be missing", p.number));
                    }
                }
                if r.facts.is_none() {
                    for (sv, ostree, node) in root_candidates(&mut fs) {
                        if let (Some(id), AnyFs::Btrfs(b)) = (sv, &mut fs) {
                            b.set_root_subvolume(id);
                        }
                        let f = fs.fs();
                        let v = Vfs::with_root(f, node);
                        if !has_os_release(&v) {
                            continue;
                        }
                        let subvolume = match (&fs, sv) {
                            (AnyFs::Btrfs(b), Some(id)) => Some(if id == 5 {
                                "(top level, id 5)".to_string()
                            } else {
                                format!("{} (id {id})", b.subvolume_path(id))
                            }),
                            _ => None,
                        };
                        let f = fs.fs();
                        let v = Vfs::with_root(f, node);
                        r.facts = Some(collect(&v));
                        r.root = Some(RootFs {
                            partition: Some(p.number),
                            filesystem: f.type_name().into(),
                            subvolume,
                            ostree_deployment: ostree,
                        });
                        break;
                    }
                }
            }
        }
        r.partitions.push(info);
    }
    if r.facts.is_none() {
        r.warnings
            .push("no partition holds a root filesystem with /etc/os-release".into());
    }
    Ok(r)
}

fn first_file(v: &Vfs, paths: &[&str]) -> Option<String> {
    paths.iter().find(|p| v.is_file(p)).map(|p| p.to_string())
}

fn first_existing(v: &Vfs, paths: &[&str]) -> Option<String> {
    paths.iter().find(|p| v.exists(p)).map(|p| p.to_string())
}

fn unquote(s: &str) -> String {
    let s = s.trim();
    let inner = if s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
    {
        &s[1..s.len() - 1]
    } else {
        s
    };
    inner
        .replace("\\\"", "\"")
        .replace("\\$", "$")
        .replace("\\\\", "\\")
}

fn os_release(v: &Vfs) -> OsRelease {
    let (source, text) = ["/etc/os-release", "/usr/lib/os-release"]
        .iter()
        .find_map(|p| v.read_string(p).map(|t| (p.to_string(), t)))
        .unwrap_or_default();
    let get = |k: &str| {
        text.lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .find_map(|l| l.strip_prefix(k).and_then(|r| r.strip_prefix('=')))
            .map(unquote)
            .unwrap_or_default()
    };
    OsRelease {
        id: get("ID"),
        version_id: get("VERSION_ID"),
        id_like: get("ID_LIKE"),
        name: get("NAME"),
        pretty_name: get("PRETTY_NAME"),
        version_codename: get("VERSION_CODENAME"),
        source,
    }
}

/// `UsePAM` as sshd would see it: first value wins, `Include` expanded in place.
fn sshd_use_pam(v: &Vfs) -> (Option<String>, bool) {
    // openSUSE ships the vendor file under /usr/etc and only optional overrides in /etc.
    let Some(main) = v
        .read_string("/etc/ssh/sshd_config")
        .or_else(|| v.read_string("/usr/etc/ssh/sshd_config"))
    else {
        return (None, false);
    };
    let mut includes = false;
    let mut lines: Vec<String> = Vec::new();
    for l in main.lines() {
        let t = l.trim();
        let mut words = t.split_whitespace();
        if words
            .next()
            .is_some_and(|w| w.eq_ignore_ascii_case("include"))
        {
            for pat in words {
                if let Some(dir) = pat.strip_suffix("/*.conf") {
                    includes = true;
                    let dir = if dir.starts_with('/') {
                        dir.to_string()
                    } else {
                        format!("/etc/ssh/{dir}")
                    };
                    for f in v
                        .list(&dir)
                        .unwrap_or_default()
                        .into_iter()
                        .filter(|f| f.ends_with(".conf"))
                    {
                        if let Some(c) = v.read_string(&format!("{dir}/{f}")) {
                            lines.extend(c.lines().map(str::to_string));
                        }
                    }
                }
            }
        } else {
            lines.push(t.to_string());
        }
    }
    let value = lines.iter().find_map(|l| {
        let l = l.trim();
        if l.starts_with('#') {
            return None;
        }
        let mut w = l.split_whitespace();
        if w.next()?.eq_ignore_ascii_case("usepam") {
            w.next().map(|x| x.to_ascii_lowercase())
        } else {
            None
        }
    });
    (value, includes)
}

fn cloud_init_version(v: &Vfs, pkgs: Option<&Packages>) -> (Option<String>, Option<String>) {
    if let Some(ver) = pkgs.and_then(|p| p.version("cloud-init")) {
        return (
            Some(ver),
            Some(format!("{} database", pkgs.unwrap().manager)),
        );
    }
    // Python package metadata: cloud_init-<version>.dist-info / .egg-info.
    let mut sites = vec!["/usr/lib/python3/dist-packages".to_string()];
    for d in v.list("/usr/lib").unwrap_or_default() {
        if d.starts_with("python3") {
            sites.push(format!("/usr/lib/{d}/site-packages"));
        }
    }
    for site in &sites {
        for entry in v.list(site).unwrap_or_default() {
            for prefix in ["cloud_init-", "cloudinit-"] {
                if let Some(rest) = entry.strip_prefix(prefix) {
                    if let Some(ver) = rest
                        .strip_suffix(".dist-info")
                        .or_else(|| rest.strip_suffix(".egg-info"))
                    {
                        let ver = ver.split("-py").next().unwrap_or(ver);
                        return (Some(ver.to_string()), Some(format!("{site}/{entry}")));
                    }
                }
            }
        }
        if let Some(text) = v.read_string(&format!("{site}/cloudinit/version.py")) {
            if let Some(ver) = text
                .lines()
                .find_map(|l| l.trim().strip_prefix("__VERSION__ = "))
            {
                let ver = ver.trim_matches('"').trim_matches('\'');
                if ver.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                    return (
                        Some(ver.to_string()),
                        Some(format!("{site}/cloudinit/version.py")),
                    );
                }
            }
        }
    }
    (None, None)
}

fn datasources(v: &Vfs) -> Option<String> {
    let mut files = vec!["/etc/cloud/cloud.cfg".to_string()];
    files.extend(
        v.list("/etc/cloud/cloud.cfg.d")
            .unwrap_or_default()
            .into_iter()
            .filter(|f| f.ends_with(".cfg"))
            .map(|f| format!("/etc/cloud/cloud.cfg.d/{f}")),
    );
    // Later files override earlier ones, as cloud-init merges them.
    let mut last = None;
    for f in files {
        if let Some(text) = v.read_string(&f) {
            for l in text.lines() {
                if let Some(rest) = l.trim().strip_prefix("datasource_list:") {
                    last = Some(rest.trim().to_string());
                }
            }
        }
    }
    last
}

pub fn collect(v: &Vfs) -> Facts {
    let mut f = Facts {
        os: os_release(v),
        ..Default::default()
    };
    f.etc_shells = v
        .read_string("/etc/shells")
        .or_else(|| v.read_string("/usr/etc/shells"))
        .map(|t| {
            t.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    f.bash = first_file(v, &["/bin/bash", "/usr/bin/bash"]);
    f.sh_chain = v.link_chain("/bin/sh");
    if !v.exists("/bin/sh") {
        f.sh_chain.clear();
    }
    f.useradd_shell = v
        .read_string("/etc/default/useradd")
        .or_else(|| v.read_string("/usr/etc/default/useradd"))
        .and_then(|t| {
            t.lines().find_map(|l| {
                l.trim()
                    .strip_prefix("SHELL=")
                    .map(|s| s.trim().to_string())
            })
        });

    f.sudo = first_file(v, &["/usr/bin/sudo", "/bin/sudo", "/usr/sbin/sudo"]);
    f.doas = first_file(v, &["/usr/bin/doas", "/bin/doas", "/usr/sbin/doas"]);
    f.sudoers_d = v.is_dir("/etc/sudoers.d");
    f.doas_d = v.is_dir("/etc/doas.d");
    f.doas_conf = v.is_file("/etc/doas.conf");

    f.systemd = first_file(v, &["/usr/lib/systemd/systemd", "/lib/systemd/systemd"]);
    f.openrc = first_file(v, &["/sbin/openrc", "/usr/sbin/openrc", "/sbin/openrc-run"]);
    f.init_chain = v.link_chain("/sbin/init");
    if !v.exists("/sbin/init") {
        f.init_chain = v.link_chain("/usr/sbin/init");
        if !v.exists("/usr/sbin/init") {
            f.init_chain.clear();
        }
    }
    let init_target = f.init_chain.last().cloned().unwrap_or_default();
    f.init_system = if init_target.ends_with("/systemd") {
        "systemd".into()
    } else if f.openrc.is_some()
        && (init_target.ends_with("/openrc-init") || v.is_file("/etc/inittab"))
    {
        "openrc".into()
    } else if init_target.ends_with("/runit-init") || init_target.ends_with("/runit") {
        "runit".into()
    } else if init_target.ends_with("/busybox") {
        "busybox-init".into()
    } else if f.systemd.is_some() {
        "systemd".into()
    } else if !init_target.is_empty() {
        "sysvinit-or-other".into()
    } else {
        "unknown".into()
    };

    f.inittab = v.is_file("/etc/inittab");
    f.getty_chain = v.link_chain("/sbin/getty");
    if !v.exists("/sbin/getty") {
        f.getty_chain.clear();
    }
    f.agetty = first_file(v, &["/sbin/agetty", "/usr/sbin/agetty", "/usr/bin/agetty"]);
    f.login = first_file(v, &["/bin/login", "/usr/bin/login", "/usr/sbin/login"]);

    f.sshd = first_file(v, &["/usr/sbin/sshd", "/usr/bin/sshd", "/sbin/sshd"]);
    f.sshd_pam = first_file(v, &["/usr/sbin/sshd.pam"]);
    let (use_pam, includes) = sshd_use_pam(v);
    f.sshd_use_pam = use_pam;
    f.sshd_includes_dropins = includes;

    f.packages = pkgdb::read(v);
    f.cloud_init = first_file(
        v,
        &[
            "/usr/bin/cloud-init",
            "/bin/cloud-init",
            "/usr/local/bin/cloud-init",
        ],
    );
    if f.cloud_init.is_some() {
        let (ver, src) = cloud_init_version(v, f.packages.as_ref());
        f.cloud_init_version = ver;
        f.cloud_init_version_source = src;
        f.cloud_init_datasources = datasources(v);
    }
    f.tiny_cloud = first_existing(
        v,
        &[
            "/sbin/tiny-cloud",
            "/usr/sbin/tiny-cloud",
            "/usr/lib/tiny-cloud",
            "/lib/tiny-cloud",
        ],
    );
    f.ignition = first_existing(
        v,
        &[
            "/usr/lib/dracut/modules.d/30ignition",
            "/usr/lib/dracut/modules.d/35ignition",
            "/usr/bin/ignition",
            "/usr/lib/ignition",
        ],
    )
    .or_else(|| {
        v.list("/usr/lib/dracut/modules.d")
            .unwrap_or_default()
            .into_iter()
            .find(|d| d.contains("ignition"))
            .map(|d| format!("/usr/lib/dracut/modules.d/{d}"))
    });
    f
}

/// Open the image and run `f` on a filesystem view: the auto-detected root, or an
/// explicit partition (and btrfs subvolume id). Used by the `ls`/`cat`/`export`
/// subcommands.
pub fn with_view<T>(
    path: &Path,
    partition: Option<u32>,
    subvol: Option<u64>,
    f: impl FnOnce(&Vfs) -> T,
) -> Result<T> {
    let mut container = Container::default();
    let disk = open_disk(path, &mut container)?;
    with_view_of(disk, partition, subvol, f)
}

pub fn with_view_of<T>(
    disk: Rc<dyn ReadAt>,
    partition: Option<u32>,
    subvol: Option<u64>,
    f: impl FnOnce(&Vfs) -> T,
) -> Result<T> {
    let table = partition::read_table(&*disk)?;
    let mut parts = table.partitions.clone();
    if parts.is_empty() {
        parts.push(partition::Partition {
            number: 0,
            start: 0,
            len: disk.size(),
            kind: PartKind::Other,
            type_id: String::new(),
            name: String::new(),
            bootable_flag: false,
        });
    }
    for p in parts {
        if partition.is_some_and(|n| n != p.number) {
            continue;
        }
        let dev: Rc<dyn ReadAt> = Rc::new(Window::new(disk.clone(), p.start, p.len)?);
        let t = partition::probe(&*dev);
        let Some(opened) = AnyFs::open(dev, t) else {
            continue;
        };
        let mut fs = opened?;
        if let Some(id) = subvol {
            match &mut fs {
                AnyFs::Btrfs(b) => b.set_root_subvolume(id),
                _ => {
                    return crate::error::unsupported("--subvol on a filesystem that is not btrfs")
                }
            }
            let v = Vfs::new(fs.fs());
            return Ok(f(&v));
        }
        if partition.is_some() {
            let v = Vfs::new(fs.fs());
            return Ok(f(&v));
        }
        for (sv, _, node) in root_candidates(&mut fs) {
            if let (Some(id), AnyFs::Btrfs(b)) = (sv, &mut fs) {
                b.set_root_subvolume(id);
            }
            let v = Vfs::with_root(fs.fs(), node);
            if has_os_release(&v) {
                return Ok(f(&v));
            }
        }
    }
    crate::error::corrupt("no matching filesystem (try --partition N)")
}
