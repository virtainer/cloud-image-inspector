//! SQLite rpmdb reading against databases made by SQLite itself
//! (tools/make-vectors.py): overflow chains at every page size, and a live WAL
//! with committed and uncommitted frames.

use std::fs;
use std::path::PathBuf;

use cloud_image_inspector::pkgdb::rpm_sqlite;

#[test]
fn rpmdb_sqlite_fixtures() {
    let dir = std::env::var("CII_SQLITE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| "fixtures/out/sqlite".into());
    if !dir.is_dir() {
        assert!(
            std::env::var_os("CII_REQUIRE").is_none(),
            "sqlite fixtures missing; run tools/make-vectors.py first"
        );
        eprintln!("no sqlite fixtures; run tools/make-vectors.py");
        return;
    }
    let mut n = 0;
    for e in fs::read_dir(&dir).unwrap() {
        let p = e.unwrap().path();
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        if !name.ends_with(".sqlite") || name.starts_with("wal-live") {
            continue;
        }
        let main = fs::read(&p).unwrap();
        let wal = fs::read(p.with_file_name(format!("{name}-wal"))).ok();
        let got = rpm_sqlite(main, wal).unwrap_or_else(|e| panic!("{name}: {e}"));
        let text: String = got
            .iter()
            .flat_map(|(k, vs)| vs.iter().map(move |v| format!("{k}\t{v}\n")))
            .collect();
        let want = fs::read_to_string(p.with_file_name(format!("{name}.expected"))).unwrap();
        assert_eq!(text, want, "{name}");
        n += 1;
    }
    assert!(n >= 5, "only {n} sqlite fixtures");

    // The WAL matters: without it only the 150 checkpointed rows exist; with it the
    // 100 committed in the WAL appear and the 80 uncommitted spilled frames do not.
    let snap = dir.join("wal-snapshot.sqlite");
    let main = fs::read(&snap).unwrap();
    let rows = |m: &std::collections::BTreeMap<String, Vec<String>>| {
        m.values().map(Vec::len).sum::<usize>()
    };
    assert_eq!(rows(&rpm_sqlite(main.clone(), None).unwrap()), 150);
    let wal = fs::read(dir.join("wal-snapshot.sqlite-wal")).unwrap();
    assert!(wal.len() > 32, "WAL should hold frames");
    assert_eq!(rows(&rpm_sqlite(main, Some(wal)).unwrap()), 250);
    let stats = cloud_image_inspector::stats::report();
    let count = |k: &str| {
        stats
            .split(' ')
            .find_map(|kv| kv.strip_prefix(&format!("{k}=")))
            .unwrap()
            .parse::<u64>()
            .unwrap()
    };
    assert!(
        count("sqlite_overflow_page") > 1000,
        "overflow chains were not exercised: {stats}"
    );
    assert!(
        count("sqlite_wal_frame") > 0,
        "WAL frames were not applied: {stats}"
    );
    eprintln!(
        "overflow pages followed: {}, WAL frames applied: {}",
        count("sqlite_overflow_page"),
        count("sqlite_wal_frame")
    );
}
