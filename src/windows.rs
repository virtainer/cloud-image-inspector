//! Windows facts from registry and executable metadata, never OS defaults.
use crate::bytes::{le16, le32, slice, to_usize};
use crate::error::{corrupt, limit, unsupported, Error, Result};
use crate::fs::Kind;
use crate::json::J;
use crate::registry::{utf16, Hive, Value};
use crate::vfs::Vfs;
use std::collections::HashSet;

const CURRENT_VERSION: &str = "Microsoft\\Windows NT\\CurrentVersion";
const BOOTMGR: &str = "{9dea862c-5cdd-4e70-acc1-f32b344d4795}";

#[derive(Debug, Clone, Default)]
pub struct Driver {
    pub present: Option<bool>,
    pub start: Option<u32>,
    pub file: Option<bool>,
    pub version: Option<String>,
}
#[derive(Debug, Clone, Default)]
pub struct WindowsFacts {
    pub product_name: Option<String>,
    pub edition_id: Option<String>,
    pub installation_type: Option<String>,
    pub build: Option<u32>,
    pub ubr: Option<u32>,
    pub arch: Option<String>,
    pub viostor: Driver,
    pub netkvm: Driver,
    pub viosock: Driver,
    pub virtainer_agent: Driver,
    pub image_state: Option<String>,
    pub bootems: Option<bool>,
    pub ems_enabled: Option<bool>,
    pub rtc_is_universal: Option<bool>,
    pub hibernation: Option<bool>,
    pub fast_startup: Option<bool>,
    pub system_hive_dirty: Option<bool>,
    pub software_hive_dirty: Option<bool>,
    pub ntfs_volume_dirty: Option<bool>,
}

pub fn opt_bool(v: Option<bool>) -> J {
    v.map(J::Bool).unwrap_or(J::Null)
}
fn opt_int(v: Option<u32>) -> J {
    v.map(|n| J::Int(n as i128)).unwrap_or(J::Null)
}
impl WindowsFacts {
    pub fn json(&self) -> J {
        let driver = |d: &Driver, agent: bool| {
            let mut fields = vec![
                ("present", opt_bool(d.present)),
                ("start", opt_int(d.start)),
                ("file", opt_bool(d.file)),
            ];
            if agent {
                fields.push(("version", J::opt_str(&d.version)));
            }
            J::obj(fields)
        };
        J::obj(vec![
            ("product_name", J::opt_str(&self.product_name)),
            ("edition_id", J::opt_str(&self.edition_id)),
            ("installation_type", J::opt_str(&self.installation_type)),
            ("build", opt_int(self.build)),
            ("ubr", opt_int(self.ubr)),
            ("arch", J::opt_str(&self.arch)),
            (
                "drivers",
                J::obj(vec![
                    ("viostor", driver(&self.viostor, false)),
                    ("netkvm", driver(&self.netkvm, false)),
                    ("viosock", driver(&self.viosock, false)),
                    ("virtainer_agent", driver(&self.virtainer_agent, true)),
                ]),
            ),
            (
                "sysprep",
                J::obj(vec![("image_state", J::opt_str(&self.image_state))]),
            ),
            (
                "ems",
                J::obj(vec![
                    ("bootems", opt_bool(self.bootems)),
                    ("ems_enabled", opt_bool(self.ems_enabled)),
                ]),
            ),
            ("rtc_is_universal", opt_bool(self.rtc_is_universal)),
            ("hibernation", opt_bool(self.hibernation)),
            ("fast_startup", opt_bool(self.fast_startup)),
            (
                "dirty",
                J::obj(vec![
                    ("system_hive", opt_bool(self.system_hive_dirty)),
                    ("software_hive", opt_bool(self.software_hive_dirty)),
                    ("ntfs_volume", opt_bool(self.ntfs_volume_dirty)),
                ]),
            ),
        ])
    }
}

fn observed<T>(r: Result<T>, context: &str, warnings: &mut Vec<String>) -> Option<T> {
    match r {
        Ok(v) => Some(v),
        Err(e) => {
            if warnings.len() < 256 {
                warnings.push(format!("Windows {context}: {e}"));
            }
            None
        }
    }
}
fn load(v: &Vfs, path: &str, warnings: &mut Vec<String>) -> (Option<Hive>, Option<bool>) {
    let Some(b) = observed(v.read_max(path, crate::vfs::MAX_FILE), path, warnings).flatten() else {
        return (None, None);
    };
    let dirty = observed(Hive::header_dirty(&b), path, warnings);
    if dirty == Some(true) {
        warnings.push(format!(
            "Windows {path}: hive sequence numbers differ; transaction logs are not replayed"
        ));
    }
    (observed(Hive::open(b), path, warnings), dirty)
}
fn value(h: Option<&Hive>, key: &str, name: &str, warnings: &mut Vec<String>) -> Option<Value> {
    observed(h?.value(key, name), &format!("{key}\\{name}"), warnings).flatten()
}
fn string(h: Option<&Hive>, key: &str, name: &str, warnings: &mut Vec<String>) -> Option<String> {
    let v = value(h, key, name, warnings)?;
    let s = v.string()?;
    if s.len() > 32768 {
        warnings.push(format!("Windows {key}\\{name}: string exceeds 32768 bytes"));
        return None;
    }
    Some(s.to_string())
}
fn dword(h: Option<&Hive>, key: &str, name: &str, warnings: &mut Vec<String>) -> Option<u32> {
    value(h, key, name, warnings)?.dword()
}
fn boolean(h: Option<&Hive>, key: &str, name: &str, warnings: &mut Vec<String>) -> Option<bool> {
    match value(h, key, name, warnings)? {
        Value::Dword(n) => Some(n != 0),
        Value::Qword(n) => Some(n != 0),
        _ => None,
    }
}
fn file(v: &Vfs, path: &str) -> Result<bool> {
    match v.resolve(path, true)? {
        None => Ok(false),
        Some(n) => Ok(v.fs.stat(n)?.kind == Kind::File),
    }
}

/// Recognize a Windows tree even when either hive's contents are unreadable.
pub fn is_windows(v: &Vfs) -> bool {
    v.is_dir("/Windows/System32/config")
        && (v.is_file("/Windows/System32/config/SYSTEM")
            || v.is_file("/Windows/System32/config/SOFTWARE")
            || v.is_file("/Windows/System32/ntoskrnl.exe"))
}

// ImagePath is interpreted only within the selected image volume. Its drive is
// mapped only when SOFTWARE's SystemRoot identifies that volume's drive.
fn image_path(raw: &str, system_root: Option<&str>, program_files: Option<&str>) -> Result<String> {
    if raw.len() > 32768 {
        return limit("Windows: ImagePath length");
    }
    let raw = raw.trim();
    let path = if let Some(rest) = raw.strip_prefix('"') {
        rest.split_once('"')
            .ok_or_else(|| Error::Corrupt("Windows: unterminated ImagePath quote".into()))?
            .0
    } else {
        // An unquoted path containing spaces is ambiguous to the service manager.
        if raw.contains(char::is_whitespace) {
            return unsupported("Windows: ambiguous unquoted ImagePath");
        }
        raw
    };
    if path.split(['/', '\\']).any(|c| c == "..") {
        return unsupported("Windows: parent traversal in ImagePath");
    }
    let mut p = path.replace('\\', "/");
    for prefix in ["/??/", "//?/"] {
        if p.starts_with(prefix) {
            p = p[prefix.len()..].to_string();
        }
    }
    let upper = p.to_ascii_uppercase();
    for prefix in ["%SYSTEMROOT%/", "%WINDIR%/", "/SYSTEMROOT/"] {
        if upper.starts_with(prefix) {
            p = format!("/Windows/{}", &p[prefix.len()..]);
            break;
        }
    }
    if upper.starts_with("%PROGRAMFILES%/") {
        let base = program_files
            .ok_or_else(|| Error::Unsupported("Windows: ProgramFilesDir unavailable".into()))?;
        p = format!("{base}/{}", &p[15..]);
        p = p.replace('\\', "/");
    }
    if p.contains('%') || p.starts_with("//") || p.starts_with("/Device/") {
        return unsupported("Windows: unresolved ImagePath");
    }
    if p.as_bytes().get(1) == Some(&b':') {
        let root = system_root
            .ok_or_else(|| Error::Unsupported("Windows: SystemRoot drive unavailable".into()))?;
        if root.as_bytes().get(1) != Some(&b':')
            || !p[..2].eq_ignore_ascii_case(&root[..2])
            || p.as_bytes().get(2) != Some(&b'/')
        {
            return unsupported("Windows: ImagePath on another or unknown drive");
        }
        p = p[2..].to_string();
    } else if upper.starts_with("SYSTEM32/") {
        p = format!("/Windows/{p}");
    } else if !p.starts_with('/') {
        return unsupported("Windows: relative ImagePath");
    }
    if p.split('/').any(|c| c == "..") {
        return unsupported("Windows: parent traversal in ImagePath");
    }
    Ok(p)
}
fn service(
    v: &Vfs,
    h: Option<&Hive>,
    cs: Option<&str>,
    software: Option<&Hive>,
    name: &str,
    warnings: &mut Vec<String>,
) -> Driver {
    let agent = name == "virtainer_agent";
    let fallback = (!agent).then(|| format!("/Windows/System32/drivers/{name}.sys"));
    let mut d = Driver::default();
    let key = h.zip(cs).and_then(|(h, cs)| {
        let names: &[&str] = if agent {
            &[
                "virtainer-guest-agent",
                "virtainer_agent",
                "virtainer_guest_agent",
            ]
        } else if name == "viosock" {
            // virtio-win's viosock.inf registers the service as `VirtioSocket`; the driver
            // file keeps the `viosock` name.
            &["VirtioSocket", "viosock"]
        } else {
            &[name]
        };
        let mut found = Vec::new();
        for n in names {
            let path = format!("{cs}\\Services\\{n}");
            let result = observed(h.key(&path), &path, warnings)?;
            if result.is_some() {
                found.push(path);
            }
        }
        if found.len() > 1 {
            let what = if agent { "Windows agent" } else { name };
            warnings.push(format!(
                "{what}: multiple service aliases; state is unknown"
            ));
            return None;
        }
        d.present = Some(!found.is_empty());
        found.pop()
    });
    let mut path = None;
    if let Some(key) = key {
        d.start = dword(h, &key, "Start", warnings);
        match h.and_then(|h| observed(h.value(&key, "ImagePath"), &key, warnings)) {
            Some(Some(val)) => {
                let root = string(software, CURRENT_VERSION, "SystemRoot", warnings);
                let pf = string(
                    software,
                    "Microsoft\\Windows\\CurrentVersion",
                    "ProgramFilesDir",
                    warnings,
                );
                path = val.string().and_then(|s| {
                    observed(
                        image_path(s, root.as_deref(), pf.as_deref()),
                        "service ImagePath",
                        warnings,
                    )
                });
            }
            Some(None) => path = fallback,
            None => {
                path = None;
            }
        }
    }
    if let Some(path) = path {
        d.file = observed(file(v, &path), &path, warnings);
        if agent && d.file == Some(true) {
            if let Some(b) =
                observed(v.read_max(&path, 64 << 20), "agent executable", warnings).flatten()
            {
                d.version = observed(pe_version(&b), "agent version resource", warnings).flatten();
            }
        }
    }
    d
}

pub fn collect(v: &Vfs, volume_dirty: Option<bool>, warnings: &mut Vec<String>) -> WindowsFacts {
    let (system, system_hive_dirty) = load(v, "/Windows/System32/config/SYSTEM", warnings);
    let (software, software_hive_dirty) = load(v, "/Windows/System32/config/SOFTWARE", warnings);
    let s = software.as_ref();
    let h = system.as_ref();
    let cs = dword(h, "Select", "Current", warnings)
        .filter(|n| (1..=999).contains(n))
        .map(|n| format!("ControlSet{n:03}"));
    let build = string(s, CURRENT_VERSION, "CurrentBuildNumber", warnings)
        .or_else(|| string(s, CURRENT_VERSION, "CurrentBuild", warnings))
        .and_then(|n| n.parse().ok());
    let mut f = WindowsFacts {
        product_name: string(s, CURRENT_VERSION, "ProductName", warnings),
        edition_id: string(s, CURRENT_VERSION, "EditionID", warnings),
        installation_type: string(s, CURRENT_VERSION, "InstallationType", warnings),
        build,
        ubr: dword(s, CURRENT_VERSION, "UBR", warnings),
        image_state: string(
            s,
            "Microsoft\\Windows\\CurrentVersion\\Setup\\State",
            "ImageState",
            warnings,
        ),
        system_hive_dirty,
        software_hive_dirty,
        ntfs_volume_dirty: volume_dirty,
        ..Default::default()
    };
    f.arch = observed(
        pe_arch(v, "/Windows/System32/ntoskrnl.exe"),
        "kernel architecture",
        warnings,
    )
    .flatten();
    f.viostor = service(v, h, cs.as_deref(), s, "viostor", warnings);
    f.netkvm = service(v, h, cs.as_deref(), s, "netkvm", warnings);
    f.viosock = service(v, h, cs.as_deref(), s, "viosock", warnings);
    f.virtainer_agent = service(v, h, cs.as_deref(), s, "virtainer_agent", warnings);
    if let Some(cs) = cs {
        f.rtc_is_universal = boolean(
            h,
            &format!("{cs}\\Control\\TimeZoneInformation"),
            "RealTimeIsUniversal",
            warnings,
        );
        f.hibernation = boolean(
            h,
            &format!("{cs}\\Control\\Power"),
            "HibernateEnabled",
            warnings,
        );
        f.fast_startup = boolean(
            h,
            &format!("{cs}\\Control\\Session Manager\\Power"),
            "HiberbootEnabled",
            warnings,
        );
    }
    f
}

fn pe_arch(v: &Vfs, path: &str) -> Result<Option<String>> {
    let Some(node) = v.resolve(path, true)? else {
        return Ok(None);
    };
    let b = v.fs.read_range(node, 0, 64)?;
    if slice(&b, 0, 2)? != b"MZ" {
        return corrupt("PE: DOS signature");
    }
    let off = le32(&b, 60)? as u64;
    if !(64..=1 << 20).contains(&off) {
        return limit("PE: header offset");
    }
    let header = v.fs.read_range(node, off, 24)?;
    if slice(&header, 0, 4)? != b"PE\0\0" {
        return corrupt("PE: signature");
    }
    Ok(match le16(&header, 4)? {
        0x8664 => Some("amd64".into()),
        0x14c => Some("x86".into()),
        0xaa64 => Some("arm64".into()),
        0x1c4 => Some("arm".into()),
        _ => None,
    })
}

/// Decode the fixed file version only from a PE RT_VERSION resource.
pub fn pe_version(b: &[u8]) -> Result<Option<String>> {
    if b.len() > 64 << 20 {
        return limit("PE: file size");
    }
    if slice(b, 0, 2)? != b"MZ" {
        return corrupt("PE: DOS signature");
    }
    let off = le32(b, 60)? as usize;
    if off > 1 << 20 || slice(b, off, 4)? != b"PE\0\0" {
        return corrupt("PE: header");
    }
    let count = le16(b, off + 6)? as usize;
    if count > 96 {
        return limit("PE: section count");
    }
    let optional = le16(b, off + 20)? as usize;
    let opt = slice(b, off + 24, optional)?;
    let dd = match le16(opt, 0)? {
        0x10b => 96,
        0x20b => 112,
        _ => return unsupported("PE: optional header format"),
    };
    if le32(opt, dd - 4)? < 3 {
        return Ok(None);
    }
    let resource_rva = le32(opt, dd + 16)? as u64;
    let resource_size = le32(opt, dd + 20)? as usize;
    if resource_rva == 0 || resource_size == 0 {
        return Ok(None);
    }
    if resource_size > 16 << 20 {
        return limit("PE: resource size");
    }
    let sections = slice(b, off + 24 + optional, count * 40)?;
    let map = |rva: u64, size: usize| -> Result<&[u8]> {
        let mut found = None;
        for s in sections.chunks_exact(40) {
            let start = le32(s, 12)? as u64;
            let raw_size = le32(s, 16)? as u64;
            if rva >= start && rva - start < raw_size && (size as u64) <= raw_size - (rva - start) {
                if found.is_some() {
                    return corrupt("PE: overlapping section mapping");
                }
                found = Some(slice(
                    b,
                    to_usize(le32(s, 20)? as u64 + rva - start, "PE file offset")?,
                    size,
                )?);
            }
        }
        found.ok_or_else(|| Error::Corrupt("PE: resource RVA outside raw sections".into()))
    };
    let resource = map(resource_rva, resource_size)?;
    let mut todo = vec![(0usize, 0usize)];
    let mut seen = HashSet::new();
    let mut versions = HashSet::new();
    while let Some((offset, depth)) = todo.pop() {
        if depth > 2 || seen.len() >= 1024 {
            return limit("PE: resource directory budget");
        }
        if !seen.insert(offset) {
            return corrupt("PE: resource directory cycle/alias");
        }
        let dir = slice(resource, offset, 16)?;
        let entries = le16(dir, 12)? as usize + le16(dir, 14)? as usize;
        if entries > 1024 {
            return limit("PE: resource entries");
        }
        let list = slice(resource, offset + 16, entries * 8)?;
        for e in list.chunks_exact(8) {
            let id = le32(e, 0)?;
            if depth == 0 && id != 16 {
                continue;
            }
            let next = le32(e, 4)?;
            if next & 0x80000000 != 0 {
                if depth == 2 || todo.len() >= 1024 {
                    return corrupt("PE: resource directory depth");
                }
                todo.push(((next & 0x7fffffff) as usize, depth + 1));
            } else {
                if depth != 2 {
                    return corrupt("PE: version resource depth");
                }
                let data = slice(resource, next as usize, 16)?;
                let payload = map(le32(data, 0)? as u64, le32(data, 4)? as usize)?;
                let size = le16(payload, 0)? as usize;
                let p = slice(payload, 0, size)?;
                if le16(p, 2)? != 52 || le16(p, 4)? != 0 {
                    return corrupt("PE: fixed version value size/type");
                }
                let key: Vec<u8> = "VS_VERSION_INFO\0"
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect();
                if slice(p, 6, key.len())? != key {
                    return corrupt("PE: version resource key");
                }
                let fixed = (6 + key.len()).div_ceil(4) * 4;
                let v = slice(p, fixed, 52)?;
                if le32(v, 0)? != 0xfeef04bd || le32(v, 4)? != 0x10000 {
                    return corrupt("PE: fixed version signature");
                }
                let ms = le32(v, 8)?;
                let ls = le32(v, 12)?;
                versions.insert(format!(
                    "{}.{}.{}.{}",
                    ms >> 16,
                    ms & 65535,
                    ls >> 16,
                    ls & 65535
                ));
            }
        }
    }
    if versions.len() > 1 {
        return unsupported("PE: conflicting language version resources");
    }
    Ok(versions.into_iter().next())
}

fn bcd_value(h: &Hive, object: &str, element: &str) -> Result<Option<Vec<u8>>> {
    match h.value(
        &format!("Objects\\{object}\\Elements\\{element}"),
        "Element",
    )? {
        None => Ok(None),
        Some(Value::Binary(b)) => Ok(Some(b)),
        Some(Value::String(s)) if element.as_bytes().get(1) == Some(&b'3') => Ok(Some(
            format!("{s}\0")
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect(),
        )),
        Some(Value::MultiString(items)) if element.as_bytes().get(1) == Some(&b'4') => Ok(Some(
            format!("{}\0\0", items.join("\0"))
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect(),
        )),
        _ => corrupt("BCD: unexpected Element registry type"),
    }
}
fn guids(b: &[u8]) -> Result<Vec<String>> {
    // BCD object and object-list elements store UTF-16 GUID strings.
    let text = utf16(b)?;
    let mut result = Vec::new();
    for s in text.split('\0').filter(|s| !s.is_empty()) {
        if s.len() != 38
            || !s.starts_with('{')
            || !s.ends_with('}')
            || !s.bytes().enumerate().all(|(i, c)| match i {
                0 => c == b'{',
                37 => c == b'}',
                9 | 14 | 19 | 24 => c == b'-',
                _ => c.is_ascii_hexdigit(),
            })
        {
            return corrupt("BCD: malformed object GUID");
        }
        if result.len() >= 128 {
            return limit("BCD: object list");
        }
        result.push(s.to_ascii_lowercase());
    }
    Ok(result)
}
fn bcd_bool(
    h: &Hive,
    object: &str,
    element: &str,
    active: &mut HashSet<String>,
    depth: usize,
    visits: &mut usize,
) -> Result<Option<bool>> {
    *visits += 1;
    if depth > 16 || *visits > 256 {
        return limit("BCD: inheritance budget");
    }
    let id = object.to_ascii_lowercase();
    if !active.insert(id.clone()) {
        return corrupt("BCD: inheritance cycle");
    }
    let result = (|| {
        if h.key(&format!("Objects\\{object}"))?.is_none() {
            return corrupt("BCD: missing referenced object");
        }
        if let Some(b) = bcd_value(h, object, element)? {
            return match b.as_slice() {
                [0] => Ok(Some(false)),
                [1] => Ok(Some(true)),
                _ => corrupt("BCD: boolean encoding"),
            };
        }
        let Some(list) = bcd_value(h, object, "14000006")? else {
            return Ok(None);
        };
        let mut result = None;
        for parent in guids(&list)? {
            if let Some(b) = bcd_bool(h, &parent, element, active, depth + 1, visits)? {
                if result.is_some_and(|old| old != b) {
                    return unsupported("BCD: conflicting inherited EMS settings");
                }
                result = Some(b);
            }
        }
        Ok(result)
    })();
    active.remove(&id);
    result
}
fn default_ems(h: &Hive) -> Result<Option<bool>> {
    let Some(default) = bcd_value(h, BOOTMGR, "23000003")? else {
        return Ok(None);
    };
    let ids = guids(&default)?;
    if ids.len() != 1 {
        return corrupt("BCD: default object count");
    }
    match h.value(&format!("Objects\\{}\\Description", ids[0]), "Type")? {
        Some(Value::Dword(0x10200003)) => {}
        None => return Ok(None),
        _ => return unsupported("BCD: default entry is not a Windows OS loader"),
    }
    bcd_bool(h, &ids[0], "260000b0", &mut HashSet::new(), 0, &mut 0)
}
/// Boot-manager bootems and default OS-loader ems. Missing settings stay unknown.
pub fn ems(h: &Hive) -> Result<(Option<bool>, Option<bool>)> {
    if h.dirty {
        return unsupported("BCD: dirty hive; effective boot selection unknown");
    }
    let bootems = bcd_bool(h, BOOTMGR, "16000020", &mut HashSet::new(), 0, &mut 0)?;
    Ok((bootems, default_ems(h)?))
}

pub fn read_ems(v: &Vfs, warnings: &mut Vec<String>) -> Option<(Option<bool>, Option<bool>)> {
    let (h, _) = load(v, "/EFI/Microsoft/Boot/BCD", warnings);
    let h = h.as_ref()?;
    if h.dirty {
        warnings.push("Windows BCD: dirty hive; EMS selection is unknown".into());
        return None;
    }
    let bootems = observed(
        bcd_bool(h, BOOTMGR, "16000020", &mut HashSet::new(), 0, &mut 0),
        "BCD bootems",
        warnings,
    )
    .flatten();
    let enabled = observed(default_ems(h), "BCD default-loader ems", warnings).flatten();
    Some((bootems, enabled))
}
