//! Decoders against reference-compressor output (see tools/make-vectors.py).
//! Skips when the vectors have not been generated.

use std::fs;
use std::path::PathBuf;

use cloud_image_inspector::compress::{inflate, lzo, zstd};

fn vectors() -> Option<PathBuf> {
    let dir = std::env::var("CII_VECTORS")
        .map(PathBuf::from)
        .unwrap_or_else(|_| "fixtures/out/vectors".into());
    dir.is_dir().then_some(dir)
}

#[test]
fn every_vector_round_trips() {
    let Some(dir) = vectors() else {
        assert!(
            std::env::var_os("CII_REQUIRE").is_none(),
            "vectors missing; run tools/make-vectors.py first"
        );
        eprintln!("no vectors; run tools/make-vectors.py");
        return;
    };
    let mut checked = 0;
    let mut failures = Vec::new();
    for case in fs::read_dir(&dir).unwrap() {
        let case = case.unwrap().path();
        let plain = fs::read(case.join("plain")).unwrap();
        let max = plain.len() + 1024;
        for f in fs::read_dir(&case).unwrap() {
            let f = f.unwrap().path();
            let name = f.file_name().unwrap().to_string_lossy().into_owned();
            if name == "plain" {
                continue;
            }
            let data = fs::read(&f).unwrap();
            let got = if name.starts_with("deflate") {
                inflate::inflate(&data, max).map(|r| r.0)
            } else if name.starts_with("zlib") {
                inflate::zlib_decompress(&data, max)
            } else if name.starts_with("zstd") {
                let want_max = if name == "zstd-twoframes" {
                    2 * plain.len() + 1024
                } else {
                    max
                };
                zstd::decompress(&data, want_max)
            } else if name.starts_with("lzo") {
                lzo::lzo1x_decompress(&data, max)
            } else {
                continue;
            };
            let want: Vec<u8> = if name == "zstd-twoframes" {
                [plain.clone(), plain.clone()].concat()
            } else {
                plain.clone()
            };
            match got {
                Ok(v) if v == want => {}
                Ok(v) => failures.push(format!(
                    "{}/{name}: {} bytes, expected {}",
                    case.display(),
                    v.len(),
                    want.len()
                )),
                Err(e) => failures.push(format!("{}/{name}: {e}", case.display())),
            }
            checked += 1;
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {checked} failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
    assert!(checked > 100, "only {checked} vectors found");
    eprintln!("{checked} vectors decoded correctly");
}

#[test]
fn corrupted_vectors_never_panic() {
    let Some(dir) = vectors() else {
        assert!(std::env::var_os("CII_REQUIRE").is_none(), "vectors missing");
        return;
    };
    let mut seed = 0x1234_5678u64;
    let mut rand = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for case in ["text", "mixed", "elf"] {
        for codec in [
            "deflate-l6-w15",
            "zstd-l19-check",
            "lzo1x-999",
            "zstd-l3-nocheck",
            "zstd-l1-check",
        ] {
            let data = fs::read(dir.join(case).join(codec))
                .unwrap_or_else(|_| panic!("missing vector {case}/{codec}"));
            for _ in 0..300 {
                let mut d = data.clone();
                for _ in 0..1 + rand() % 8 {
                    let i = (rand() as usize) % d.len();
                    d[i] ^= 1 << (rand() % 8);
                }
                if rand() % 4 == 0 {
                    let cut = (rand() as usize) % d.len();
                    d.truncate(cut);
                }
                let max = 4 << 20;
                let outcome = std::panic::catch_unwind(|| match codec.as_bytes()[0] {
                    b'd' => drop(inflate::inflate(&d, max)),
                    b'z' => drop(zstd::decompress(&d, max)),
                    _ => drop(lzo::lzo1x_decompress(&d, max)),
                });
                assert!(outcome.is_ok(), "panic decoding corrupted {case}/{codec}");
            }
        }
    }
}
