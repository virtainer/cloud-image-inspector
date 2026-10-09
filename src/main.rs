//! `cloud-image-inspector`: what is inside a cloud image, without booting it.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use cloud_image_inspector::facts::{inspect, with_view};
use cloud_image_inspector::fs::{Kind, NodeId};
use cloud_image_inspector::json::J;
use cloud_image_inspector::report;
use cloud_image_inspector::vfs::{Vfs, MAX_FILE};

const USAGE: &str = "\
usage:
  cloud-image-inspector [--json] [--all-packages] IMAGE...
  cloud-image-inspector ls     [--partition N] [--subvol ID] IMAGE PATH
  cloud-image-inspector cat    [--partition N] [--subvol ID] IMAGE PATH
  cloud-image-inspector stat   [--partition N] [--subvol ID] IMAGE PATH
  cloud-image-inspector export [--partition N] [--subvol ID] IMAGE PATH DEST

IMAGE is qcow2 (v2/v3; zlib or zstd clusters) or raw. Filesystems: ext2/3/4, XFS,
btrfs, FAT12/16/32, NTFS. Without --partition, file commands use the detected root filesystem.";

struct Opts {
    json: bool,
    all_packages: bool,
    partition: Option<u32>,
    subvol: Option<u64>,
    args: Vec<String>,
}

fn parse() -> Result<Opts, String> {
    let mut o = Opts {
        json: false,
        all_packages: false,
        partition: None,
        subvol: None,
        args: Vec::new(),
    };
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--json" => o.json = true,
            "--all-packages" => o.all_packages = true,
            "--partition" => {
                o.partition = Some(
                    it.next()
                        .and_then(|v| v.parse().ok())
                        .ok_or("--partition needs a number")?,
                )
            }
            "--subvol" => {
                o.subvol = Some(
                    it.next()
                        .and_then(|v| v.parse().ok())
                        .ok_or("--subvol needs a subvolume id")?,
                )
            }
            "-h" | "--help" => return Err(String::new()),
            s if s.starts_with("--") => return Err(format!("unknown option {s}")),
            _ => o.args.push(a),
        }
    }
    if o.args.is_empty() {
        return Err(String::new());
    }
    Ok(o)
}

fn export(
    v: &Vfs,
    node: NodeId,
    dest: &Path,
    depth: usize,
    count: &mut u64,
) -> std::io::Result<()> {
    if depth > 256 {
        return Ok(());
    }
    let entries = match v.fs.read_dir(node) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("warning: {}: {e}", dest.display());
            return Ok(());
        }
    };
    for e in entries {
        if e.name == b"." || e.name == b".." || e.name.contains(&b'/') {
            continue;
        }
        let out = dest.join(String::from_utf8_lossy(&e.name).as_ref());
        let st = match v.fs.stat(e.node) {
            Ok(s) => s,
            Err(err) => {
                eprintln!("warning: {}: {err}", out.display());
                continue;
            }
        };
        *count += 1;
        match st.kind {
            Kind::Dir => {
                std::fs::create_dir_all(&out)?;
                export(v, e.node, &out, depth + 1, count)?;
            }
            Kind::File => {
                use std::io::Write;
                let mut f = std::fs::File::create(&out)?;
                let chunk = 16u64 << 20;
                let mut off = 0;
                while off < st.size || (off == 0 && st.size == 0) {
                    match v.fs.read_range(e.node, off, chunk) {
                        Ok(data) if !data.is_empty() => f.write_all(&data)?,
                        Ok(_) => break,
                        Err(err) => {
                            eprintln!("warning: {}: {err}", out.display());
                            break;
                        }
                    }
                    off += chunk;
                }
            }
            Kind::Symlink => match v.fs.read_link(e.node) {
                Ok(t) => std::os::unix::fs::symlink(String::from_utf8_lossy(&t).as_ref(), &out)?,
                Err(err) => eprintln!("warning: {}: {err}", out.display()),
            },
            Kind::Other => {}
        }
    }
    Ok(())
}

fn raw(image: &Path, out: &Path) -> Result<(), String> {
    use std::io::Write;
    let mut c = cloud_image_inspector::facts::Container::default();
    let disk = cloud_image_inspector::facts::open_disk(image, &mut c).map_err(|e| e.to_string())?;
    let mut f = std::fs::File::create(out).map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; 4 << 20];
    let mut off = 0u64;
    while off < disk.size() {
        let n = buf.len().min((disk.size() - off) as usize);
        disk.read_at(off, &mut buf[..n])
            .map_err(|e| e.to_string())?;
        f.write_all(&buf[..n]).map_err(|e| e.to_string())?;
        off += n as u64;
    }
    print_stats();
    Ok(())
}

fn file_command(o: &Opts) -> Result<(), String> {
    let cmd = o.args[0].as_str();
    let need = if cmd == "export" { 4 } else { 3 };
    if o.args.len() != need {
        return Err(format!("{cmd}: wrong number of arguments"));
    }
    let image = PathBuf::from(&o.args[1]);
    let path = o.args[2].clone();
    let dest = o.args.get(3).map(PathBuf::from);
    let result = with_view(&image, o.partition, o.subvol, |v| -> Result<(), String> {
        match cmd {
            "ls" => {
                let names = v.list(&path).ok_or(format!("{path}: not a directory"))?;
                for n in names {
                    let full = format!("{}/{n}", path.trim_end_matches('/'));
                    let kind = match v
                        .fs
                        .stat(v.resolve(&full, false).ok().flatten().ok_or("vanished")?)
                        .map(|s| s.kind)
                    {
                        Ok(Kind::Dir) => "d",
                        Ok(Kind::Symlink) => "l",
                        Ok(Kind::File) => "-",
                        _ => "?",
                    };
                    let link = v
                        .read_link(&full)
                        .map(|t| format!(" -> {t}"))
                        .unwrap_or_default();
                    println!("{kind} {n}{link}");
                }
            }
            "cat" => {
                let data = v
                    .read_max(&path, MAX_FILE)
                    .map_err(|e| e.to_string())?
                    .ok_or(format!("{path}: not a regular file"))?;
                use std::io::Write;
                std::io::stdout()
                    .write_all(&data)
                    .map_err(|e| e.to_string())?;
            }
            "stat" => {
                let node = v
                    .resolve(&path, false)
                    .map_err(|e| e.to_string())?
                    .ok_or(format!("{path}: not found"))?;
                let st = v.fs.stat(node).map_err(|e| e.to_string())?;
                println!(
                    "{path}: {:?} mode {:o} size {} node {:?}",
                    st.kind, st.mode, st.size, node
                );
            }
            "export" => {
                let node = v
                    .resolve(&path, true)
                    .map_err(|e| e.to_string())?
                    .ok_or(format!("{path}: not found"))?;
                let dest = dest.unwrap();
                std::fs::create_dir_all(&dest).map_err(|e| e.to_string())?;
                let mut count = 0;
                export(v, node, &dest, 0, &mut count).map_err(|e| e.to_string())?;
                eprintln!("exported {count} entries to {}", dest.display());
            }
            _ => unreachable!(),
        }
        Ok(())
    });
    result.map_err(|e| e.to_string())?
}

fn main() -> ExitCode {
    let o = match parse() {
        Ok(o) => o,
        Err(e) => {
            if !e.is_empty() {
                eprintln!("error: {e}");
            }
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    if o.args[0] == "raw" && o.args.len() == 3 {
        // Hidden: the guest disk as raw bytes, for checking the container layer
        // against `qemu-img convert -O raw`.
        return match raw(Path::new(&o.args[1]), Path::new(&o.args[2])) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(1)
            }
        };
    }
    if matches!(o.args[0].as_str(), "ls" | "cat" | "stat" | "export") {
        let r = file_command(&o);
        print_stats();
        return match r {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(1)
            }
        };
    }
    let mut failed = false;
    let mut docs = Vec::new();
    for image in &o.args {
        // Parsers are written not to panic; this keeps one bad image from taking down
        // a batch if one ever does.
        let outcome = std::panic::catch_unwind(|| inspect(Path::new(image)));
        match outcome {
            Ok(Ok(r)) => {
                if o.json {
                    docs.push(report::json(&r, o.all_packages));
                } else {
                    print!("{}", report::text(&r));
                    println!();
                }
            }
            Ok(Err(e)) => {
                failed = true;
                eprintln!("{image}: {e}");
                if o.json {
                    docs.push(J::obj(vec![
                        ("image", J::str(image)),
                        ("error", J::str(e.to_string())),
                    ]));
                }
            }
            Err(_) => {
                failed = true;
                eprintln!("{image}: internal error (parser panic)");
            }
        }
    }
    if o.json {
        let out = if docs.len() == 1 {
            docs.pop().unwrap()
        } else {
            J::Arr(docs)
        };
        print!("{}", out.render());
    }
    print_stats();
    if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn print_stats() {
    if std::env::var_os("CII_STATS").is_some() {
        eprintln!("stats: {}", cloud_image_inspector::stats::report());
    }
}
