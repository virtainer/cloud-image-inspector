//! Text and JSON renderings of a `Report`.

use std::fmt::Write;

use crate::facts::{Facts, Report, KEY_PACKAGES};
use crate::json::J;

fn yes(o: &Option<String>) -> String {
    match o {
        Some(p) => format!("yes ({p})"),
        None => "no".into(),
    }
}

fn human(n: u64) -> String {
    const U: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i + 1 < U.len() {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", U[i])
    }
}

pub fn text(r: &Report) -> String {
    let mut s = String::new();
    let c = &r.container;
    let _ = writeln!(s, "== {}", r.image);
    let mut cont = c.format.to_string();
    if let Some(v) = c.version {
        let _ = write!(cont, " v{v}");
    }
    let _ = write!(cont, ", virtual size {}", human(c.virtual_size));
    if let Some(cs) = c.cluster_size {
        let _ = write!(cont, ", {} clusters", human(cs));
    }
    if let Some(comp) = &c.compression {
        let _ = write!(cont, ", {comp} compression");
    }
    if c.extended_l2 {
        cont.push_str(", extended L2");
    }
    let _ = writeln!(s, "container      {cont}");
    let _ = writeln!(s, "partitions     {} table", r.table);
    for p in &r.partitions {
        let label = p
            .label
            .as_ref()
            .map(|l| format!(" label={l:?}"))
            .unwrap_or_default();
        let name = if p.name.is_empty() {
            String::new()
        } else {
            format!(" name={:?}", p.name)
        };
        let _ = writeln!(
            s,
            "  {:>2}  {:<11} {:<8} {:>10}{label}{name}",
            p.number,
            p.kind,
            p.filesystem,
            human(p.size)
        );
        if let Some(n) = &p.note {
            let _ = writeln!(s, "      note: {n}");
        }
    }
    let boot = match (r.boot.uefi, r.boot.bios) {
        (true, true) => "UEFI and BIOS".to_string(),
        (true, false) => "UEFI only".to_string(),
        (false, true) => {
            "BIOS only (no EFI System Partition: will not boot under UEFI firmware)".to_string()
        }
        (false, false) => "no boot path found".to_string(),
    };
    let _ = writeln!(s, "boot           {boot}");
    if let Some(root) = &r.root {
        let mut where_ = format!(
            "partition {} ({})",
            root.partition.unwrap_or(0),
            root.filesystem
        );
        if let Some(sv) = &root.subvolume {
            let _ = write!(where_, ", subvolume {sv}");
        }
        if let Some(d) = &root.ostree_deployment {
            let _ = write!(where_, ", OSTree deployment {d}");
        }
        let _ = writeln!(s, "root           {where_}");
    }
    if let Some(f) = &r.facts {
        text_facts(&mut s, f);
    }
    for w in &r.warnings {
        let _ = writeln!(s, "warning        {w}");
    }
    s
}

fn text_facts(s: &mut String, f: &Facts) {
    let o = &f.os;
    let _ = writeln!(
        s,
        "os             {} {} (ID={} VERSION_ID={}{})",
        o.name,
        o.version_id,
        o.id,
        o.version_id,
        if o.id_like.is_empty() {
            String::new()
        } else {
            format!(" ID_LIKE={}", o.id_like)
        }
    );
    if !o.pretty_name.is_empty() {
        let _ = writeln!(s, "               {}", o.pretty_name);
    }
    let _ = writeln!(s, "shells         bash: {}", yes(&f.bash));
    let _ = writeln!(
        s,
        "               /bin/sh: {}",
        if f.sh_chain.is_empty() {
            "missing".into()
        } else {
            f.sh_chain.join(" -> ")
        }
    );
    let _ = writeln!(
        s,
        "               /etc/shells: {}",
        if f.etc_shells.is_empty() {
            "(none)".into()
        } else {
            f.etc_shells.join(" ")
        }
    );
    let _ = writeln!(
        s,
        "               useradd default SHELL: {}",
        f.useradd_shell.as_deref().unwrap_or("(unset)")
    );
    let _ = writeln!(
        s,
        "privilege      sudo: {}   doas: {}",
        yes(&f.sudo),
        yes(&f.doas)
    );
    let _ = writeln!(
        s,
        "               /etc/sudoers.d: {}   /etc/doas.d: {}   /etc/doas.conf: {}",
        f.sudoers_d, f.doas_d, f.doas_conf
    );
    let _ = writeln!(
        s,
        "init           {} (/sbin/init: {})",
        f.init_system,
        if f.init_chain.is_empty() {
            "missing".into()
        } else {
            f.init_chain.join(" -> ")
        }
    );
    let _ = writeln!(
        s,
        "               systemd: {}   openrc: {}",
        yes(&f.systemd),
        yes(&f.openrc)
    );
    let _ = writeln!(
        s,
        "sshd           sshd: {}   PAM build: {}",
        yes(&f.sshd),
        yes(&f.sshd_pam)
    );
    let _ = writeln!(
        s,
        "               UsePAM: {}   sshd_config.d included: {}",
        f.sshd_use_pam.as_deref().unwrap_or("(default: no)"),
        f.sshd_includes_dropins
    );
    let ver = f
        .cloud_init_version
        .as_ref()
        .map(|v| {
            format!(
                ", version {v} (from {})",
                f.cloud_init_version_source.as_deref().unwrap_or("?")
            )
        })
        .unwrap_or_default();
    let _ = writeln!(s, "first boot     cloud-init: {}{ver}", yes(&f.cloud_init));
    if let Some(ds) = &f.cloud_init_datasources {
        let _ = writeln!(s, "               datasource_list: {ds}");
    }
    let _ = writeln!(
        s,
        "               tiny-cloud: {}   Ignition: {}",
        yes(&f.tiny_cloud),
        yes(&f.ignition)
    );
    match &f.packages {
        Some(p) => {
            let _ = writeln!(
                s,
                "packages       {} ({} installed, {})",
                p.manager,
                p.count(),
                p.database
            );
            if let Some(n) = &p.note {
                let _ = writeln!(s, "               note: {n}");
            }
            for name in KEY_PACKAGES {
                if let Some(v) = p.version(name) {
                    let _ = writeln!(s, "               {name:<20} {v}");
                }
            }
        }
        None => {
            let _ = writeln!(s, "packages       no package database found");
        }
    }
}

pub fn json(r: &Report, all_packages: bool) -> J {
    let c = &r.container;
    let facts = r
        .facts
        .as_ref()
        .map(|f| facts_json(f, all_packages))
        .unwrap_or(J::Null);
    J::obj(vec![
        ("image", J::str(&r.image)),
        (
            "container",
            J::obj(vec![
                ("format", J::str(&c.format)),
                (
                    "version",
                    c.version.map(|v| J::Int(v as i128)).unwrap_or(J::Null),
                ),
                ("virtual_size", J::Int(c.virtual_size as i128)),
                (
                    "cluster_size",
                    c.cluster_size.map(|v| J::Int(v as i128)).unwrap_or(J::Null),
                ),
                ("compression", J::opt_str(&c.compression)),
                ("extended_l2", J::Bool(c.extended_l2)),
                ("snapshots", J::Int(c.snapshots as i128)),
            ]),
        ),
        ("partition_table", J::str(&r.table)),
        (
            "partitions",
            J::Arr(
                r.partitions
                    .iter()
                    .map(|p| {
                        J::obj(vec![
                            ("number", J::Int(p.number as i128)),
                            ("kind", J::str(&p.kind)),
                            ("type", J::str(&p.type_id)),
                            ("name", J::str(&p.name)),
                            ("start", J::Int(p.start as i128)),
                            ("size", J::Int(p.size as i128)),
                            ("filesystem", J::str(&p.filesystem)),
                            ("label", J::opt_str(&p.label)),
                            ("note", J::opt_str(&p.note)),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "boot",
            J::obj(vec![
                ("uefi", J::Bool(r.boot.uefi)),
                ("bios", J::Bool(r.boot.bios)),
                (
                    "esp_partitions",
                    J::Arr(r.boot.esp.iter().map(|n| J::Int(*n as i128)).collect()),
                ),
            ]),
        ),
        (
            "root",
            r.root
                .as_ref()
                .map(|x| {
                    J::obj(vec![
                        (
                            "partition",
                            x.partition.map(|n| J::Int(n as i128)).unwrap_or(J::Null),
                        ),
                        ("filesystem", J::str(&x.filesystem)),
                        ("subvolume", J::opt_str(&x.subvolume)),
                        ("ostree_deployment", J::opt_str(&x.ostree_deployment)),
                    ])
                })
                .unwrap_or(J::Null),
        ),
        ("facts", facts),
        ("warnings", J::strs(&r.warnings)),
    ])
}

fn facts_json(f: &Facts, all_packages: bool) -> J {
    let o = &f.os;
    let pkgs = f.packages.as_ref().map(|p| {
        let key: Vec<(String, J)> = KEY_PACKAGES
            .iter()
            .filter_map(|n| p.installed.get(*n).map(|v| (n.to_string(), J::strs(v))))
            .collect();
        let mut fields = vec![
            ("manager", J::str(&p.manager)),
            ("database", J::str(&p.database)),
            ("count", J::Int(p.count() as i128)),
            ("key", J::Obj(key)),
            ("note", J::opt_str(&p.note)),
        ];
        if all_packages {
            fields.push((
                "installed",
                J::Obj(
                    p.installed
                        .iter()
                        .map(|(k, v)| (k.clone(), J::strs(v)))
                        .collect(),
                ),
            ));
        }
        J::obj(fields)
    });
    J::obj(vec![
        (
            "os_release",
            J::obj(vec![
                ("id", J::str(&o.id)),
                ("version_id", J::str(&o.version_id)),
                ("id_like", J::str(&o.id_like)),
                ("name", J::str(&o.name)),
                ("pretty_name", J::str(&o.pretty_name)),
                ("version_codename", J::str(&o.version_codename)),
                ("source", J::str(&o.source)),
            ]),
        ),
        (
            "shells",
            J::obj(vec![
                ("bash", J::opt_str(&f.bash)),
                ("bin_sh", J::strs(&f.sh_chain)),
                ("etc_shells", J::strs(&f.etc_shells)),
                ("useradd_default_shell", J::opt_str(&f.useradd_shell)),
            ]),
        ),
        (
            "privilege",
            J::obj(vec![
                ("sudo", J::opt_str(&f.sudo)),
                ("doas", J::opt_str(&f.doas)),
                ("sudoers_d", J::Bool(f.sudoers_d)),
                ("doas_d", J::Bool(f.doas_d)),
                ("doas_conf", J::Bool(f.doas_conf)),
            ]),
        ),
        (
            "init",
            J::obj(vec![
                ("system", J::str(&f.init_system)),
                ("sbin_init", J::strs(&f.init_chain)),
                ("systemd", J::opt_str(&f.systemd)),
                ("openrc", J::opt_str(&f.openrc)),
            ]),
        ),
        (
            "sshd",
            J::obj(vec![
                ("sshd", J::opt_str(&f.sshd)),
                ("pam_build", J::opt_str(&f.sshd_pam)),
                ("use_pam", J::opt_str(&f.sshd_use_pam)),
                ("includes_sshd_config_d", J::Bool(f.sshd_includes_dropins)),
            ]),
        ),
        (
            "first_boot",
            J::obj(vec![
                ("cloud_init", J::opt_str(&f.cloud_init)),
                ("cloud_init_version", J::opt_str(&f.cloud_init_version)),
                (
                    "cloud_init_version_source",
                    J::opt_str(&f.cloud_init_version_source),
                ),
                (
                    "cloud_init_datasource_list",
                    J::opt_str(&f.cloud_init_datasources),
                ),
                ("tiny_cloud", J::opt_str(&f.tiny_cloud)),
                ("ignition", J::opt_str(&f.ignition)),
            ]),
        ),
        ("packages", pkgs.unwrap_or(J::Null)),
    ])
}
