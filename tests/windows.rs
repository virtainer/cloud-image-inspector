//! Self-contained fixtures: no Windows binaries or disk images are distributed.
mod windows_fixtures;
use cloud_image_inspector::facts::{inspect_disk, OsFamily};
use cloud_image_inspector::fs::{fat::Fat, ntfs::Ntfs, FileSystem, NodeId};
use cloud_image_inspector::registry::{Hive, Value};
use cloud_image_inspector::vfs::Vfs;
use cloud_image_inspector::{report, windows};
use windows_fixtures::*;

#[test]
fn fat_variants_long_names_nested_directories_and_ranges() {
    let mut tree = Tree::default();
    let payload: Vec<u8> = (0..1700).map(|n| n as u8).collect();
    tree.insert("EFI/Microsoft/Boot/BCD", bcd(false));
    tree.insert("virtainer-provision.json", payload.clone());
    tree.insert("empty.txt", vec![]);
    for bits in [12, 16, 32] {
        let fs = Fat::open(dev(fat(bits, &tree))).unwrap();
        let v = Vfs::new(&fs);
        assert_eq!(v.read("/VIRTAINER-PROVISION.JSON").unwrap(), payload);
        let node = v
            .resolve("/virtainer-provision.json", true)
            .unwrap()
            .unwrap();
        assert_eq!(fs.read_range(node, 500, 600).unwrap(), payload[500..1100]);
        assert_eq!(v.read("/empty.txt").unwrap(), Vec::<u8>::new());
        assert!(Hive::open(v.read("/efi/microsoft/boot/bcd").unwrap()).is_ok());
        assert_eq!(v.resolve("/missing", true).unwrap(), None);
    }
}
#[test]
fn fat_rejects_cycles_bad_geometry_and_lfn_checksums() {
    let mut tree = Tree::default();
    tree.insert("long seed filename.txt", vec![1; 1024]);
    let clean = fat(12, &tree);
    let mut b = clean.clone();
    b[13] = 0;
    assert!(Fat::open(dev(b)).is_err());
    let mut b = clean.clone();
    p16(&mut b, 512 + 3, 2 | (3 << 12));
    let fs = Fat::open(dev(b)).unwrap();
    assert!(Vfs::new(&fs)
        .read_max("/long seed filename.txt", 2048)
        .is_err());
    let mut b = clean;
    let root = (1 + 6) * 512;
    b[root + 13] ^= 1;
    let fs = Fat::open(dev(b)).unwrap();
    assert!(fs.read_dir(fs.root()).is_err());
}
#[test]
fn registry_indexes_types_inline_big_data_and_dirty_sequence() {
    for sig in [*b"lf", *b"lh", *b"li", *b"ri"] {
        let mut h = HiveBuilder::default();
        h.index = sig;
        h.sz("A\\B", "Text", "Windows");
        h.set("A\\B", "Expand", 2, wide("%SystemRoot%\0"));
        h.set("A\\B", "Many", 7, wide("one\0two\0\0"));
        h.dw("A\\B", "Number", 42);
        h.set("A\\B", "Wide", 11, 123456789u64.to_le_bytes().to_vec());
        h.set("A\\B", "Bytes", 3, vec![0xaa; 35000]);
        let h = Hive::open(h.finish(sig == *b"ri")).unwrap();
        assert_eq!(h.dirty, sig == *b"ri");
        assert_eq!(
            h.value("a\\b", "TEXT").unwrap(),
            Some(Value::String("Windows".into()))
        );
        assert_eq!(
            h.value("A\\B", "Expand").unwrap(),
            Some(Value::ExpandString("%SystemRoot%".into()))
        );
        assert_eq!(
            h.value("A\\B", "Many").unwrap(),
            Some(Value::MultiString(vec!["one".into(), "two".into()]))
        );
        assert_eq!(h.value("A\\B", "Number").unwrap(), Some(Value::Dword(42)));
        assert_eq!(
            h.value("A\\B", "Wide").unwrap(),
            Some(Value::Qword(123456789))
        );
        assert_eq!(
            h.value("A\\B", "Bytes").unwrap(),
            Some(Value::Binary(vec![0xaa; 35000]))
        );
        assert_eq!(h.value("A\\B", "Missing").unwrap(), None);
    }
}
#[test]
fn registry_rejects_invalid_cells_checksums_free_references_and_cycles() {
    let mut h = HiveBuilder::default();
    h.dw("A\\B", "Value", 1);
    let clean = h.finish(false);
    let mut b = clean.clone();
    b[508] ^= 1;
    assert!(Hive::open(b).is_err());
    let mut b = clean.clone();
    p32(&mut b, 4096 + 32, 0x80000000);
    assert!(Hive::open(b).is_err());
    let mut b = clean.clone();
    p32(&mut b, 36, 33);
    checksum(&mut b);
    assert!(Hive::open(b).is_err());
    let mut b = clean;
    let pos = b.windows(2).position(|x| x == b"lh").unwrap();
    b[pos..pos + 2].copy_from_slice(b"ri");
    p16(&mut b, pos + 2, 1);
    p32(&mut b, pos + 4, (pos - 4100) as u32);
    let h = Hive::open(b).unwrap();
    assert!(h.key("A\\B").is_err());
}
#[test]
fn registry_large_software_hive_looks_up_facts_without_walking_unrelated_trees() {
    let mut builder = HiveBuilder::default();
    let cv = "Microsoft\\Windows NT\\CurrentVersion";
    builder.sz(cv, "ProductName", "Windows Server 2022 Datacenter");
    builder.sz(cv, "EditionID", "ServerDatacenter");
    builder.sz(cv, "CurrentBuildNumber", "20348");
    builder.sz(
        "Microsoft\\Windows\\CurrentVersion\\Setup\\State",
        "ImageState",
        "IMAGE_STATE_GENERALIZE_RESEAL_TO_OOBE",
    );
    // Component registrations provide hundreds of thousands of keys and more
    // than a million cells, spread across ordinary small bins and short lists.
    for vendor in 0..512 {
        for component in 0..512 {
            let path = format!("Classes\\Vendor{vendor:04}\\Component{component:04}");
            builder.dw(&path, "Version", 1);
            builder.dw(&path, "Flags", 0);
        }
    }
    let mut bytes = builder.finish(false);
    assert!(bytes.len() > 48 << 20);
    let mut cells = 0;
    let mut bin = 4096;
    while bin < bytes.len() {
        let size = u32::from_le_bytes(bytes[bin + 8..bin + 12].try_into().unwrap()) as usize;
        let mut pos = bin + 32;
        while pos < bin + size {
            cells += 1;
            let len = i32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap());
            pos += len.unsigned_abs() as usize;
        }
        bin += size;
    }
    assert!(cells > 1_000_000);
    let hive = Hive::open(bytes.clone()).unwrap();
    assert_eq!(
        hive.value(cv, "ProductName").unwrap(),
        Some(Value::String("Windows Server 2022 Datacenter".into()))
    );
    assert_eq!(
        hive.value(cv, "EditionID").unwrap(),
        Some(Value::String("ServerDatacenter".into()))
    );
    assert_eq!(
        hive.value(cv, "CurrentBuildNumber").unwrap(),
        Some(Value::String("20348".into()))
    );
    assert_eq!(
        hive.value("Classes\\Vendor0511\\Component0511", "Version")
            .unwrap(),
        Some(Value::Dword(1))
    );
    let unrelated = hive
        .key("Classes\\Vendor0000\\Component0000")
        .unwrap()
        .unwrap();
    drop(hive);
    // An invalid cell in an unrelated registration must not hide OS facts,
    // and must still fail explicitly when that registration is queried.
    p32(&mut bytes, 4096 + unrelated as usize, 0);
    let hive = Hive::open(bytes).unwrap();
    assert!(hive
        .value("Classes\\Vendor0000\\Component0000", "Version")
        .is_err());
    assert_eq!(
        hive.value(cv, "CurrentBuildNumber").unwrap(),
        Some(Value::String("20348".into()))
    );
    assert_eq!(
        hive.value(
            "Microsoft\\Windows\\CurrentVersion\\Setup\\State",
            "ImageState"
        )
        .unwrap(),
        Some(Value::String(
            "IMAGE_STATE_GENERALIZE_RESEAL_TO_OOBE".into()
        ))
    );
}

#[test]
fn registry_ignores_stale_volatile_counts_and_pointers_in_saved_hives() {
    let mut tree = windows_tree(false, false);
    for name in ["SYSTEM", "SOFTWARE"] {
        let mut bytes = tree.children["Windows"].children["System32"].children["config"].children
            [name]
            .data
            .clone()
            .unwrap();
        let hive = Hive::open(bytes.clone()).unwrap();
        let root = hive.key("").unwrap().unwrap();
        p32(&mut bytes, 4096 + root as usize + 4 + 24, 1);
        p32(&mut bytes, 4096 + root as usize + 4 + 32, u32::MAX);
        tree.insert(&format!("Windows/System32/config/{name}"), bytes);
    }
    let r = inspect_disk(dev(ntfs(&tree))).unwrap();
    let w = r.windows.as_ref().unwrap();
    assert_eq!(
        w.product_name.as_deref(),
        Some("Windows Server 2022 Datacenter")
    );
    assert_eq!(w.build, Some(20348));
    assert_eq!(w.viostor.present, Some(true));
    assert_eq!(w.viostor.start, Some(0));
    assert_eq!(w.viostor.file, Some(true));
    assert_eq!(w.virtainer_agent.present, Some(false));
    assert!(r.warnings.is_empty());
    assert!(report::json(&r, false)
        .render()
        .contains("\"build\": 20348"));
    assert!(report::text(&r).contains("build: 20348"));
    // No persistent children: even maximal stale metadata is ignored.
    let mut bytes = HiveBuilder::default().finish(false);
    p32(&mut bytes, 4096 + 32 + 4 + 24, u32::MAX);
    p32(&mut bytes, 4096 + 32 + 4 + 32, 33);
    assert_eq!(Hive::open(bytes).unwrap().key("missing").unwrap(), None);
}

#[test]
fn registry_bounds_subkey_value_and_index_lists_per_lookup() {
    let mut builder = HiveBuilder::default();
    builder.dw("A", "Value", 1);
    let clean = builder.finish(false);
    let hive = Hive::open(clean.clone()).unwrap();
    let root = hive.key("").unwrap().unwrap();
    let key = hive.key("A").unwrap().unwrap();
    for (offset, count) in [(root as usize + 20, 131073), (key as usize + 36, 65537)] {
        let mut bytes = clean.clone();
        p32(&mut bytes, 4100 + offset, count);
        let hive = Hive::open(bytes).unwrap();
        assert!(matches!(
            hive.value("A", "Value"),
            Err(cloud_image_inspector::error::Error::Limit(_))
        ));
    }
    // A declared index length larger than its cell must fail before traversal.
    let mut bytes = clean.clone();
    let list = u32::from_le_bytes(
        bytes[4100 + root as usize + 28..4100 + root as usize + 32]
            .try_into()
            .unwrap(),
    );
    p16(&mut bytes, 4100 + list as usize + 2, u16::MAX);
    assert!(Hive::open(bytes).unwrap().key("A").is_err());
    // A key that lists itself cannot turn a cyclic path into a valid lookup.
    let mut bytes = clean.clone();
    p32(&mut bytes, 4100 + root as usize + 16, root);
    p32(&mut bytes, 4100 + list as usize + 4, root);
    assert!(Hive::open(bytes).unwrap().key("ROOT").is_err());
    // Free cells cannot become valid key references.
    let mut bytes = clean.clone();
    let root_size = i32::from_le_bytes(
        bytes[4096 + root as usize..4100 + root as usize]
            .try_into()
            .unwrap(),
    );
    p32(&mut bytes, 4096 + root as usize, root_size.unsigned_abs());
    assert!(Hive::open(bytes).is_err());
    // Even aligned, convincing nk bytes inside a data cell are not a cell.
    let mut builder = HiveBuilder::default();
    let mut payload = vec![0; 128];
    payload[..4].copy_from_slice(b"fake");
    p32(&mut payload, 4, (-88i32) as u32);
    payload[8..10].copy_from_slice(b"nk");
    builder.set("A", "Payload", 3, payload);
    let mut bytes = builder.finish(false);
    let pos = bytes.windows(4).position(|w| w == b"fake").unwrap() + 4;
    p32(&mut bytes, 36, (pos - 4096) as u32);
    checksum(&mut bytes);
    assert!(Hive::open(bytes).is_err());
}

#[test]
fn registry_large_subkey_lists_use_bounded_indirect_indexes() {
    let mut builder = HiveBuilder::default();
    for n in 0..70000 {
        builder.dw(&format!("Services\\Service{n:05}"), "Start", 3);
    }
    let hive = Hive::open(builder.finish(false)).unwrap();
    assert_eq!(
        hive.value("Services\\Service69999", "Start").unwrap(),
        Some(Value::Dword(3))
    );
    assert_eq!(hive.key("Services\\missing").unwrap(), None);
}

#[test]
fn registry_lookup_cell_scan_budget_rejects_a_dense_bin() {
    let mut bytes = HiveBuilder::default().finish(false);
    let root = bytes[4128..4216].to_vec();
    let size = (36 << 20) as usize;
    bytes.resize(4096 + size, 0);
    p32(&mut bytes, 40, size as u32);
    p32(&mut bytes, 4104, size as u32);
    let root_offset = size - root.len();
    p32(&mut bytes, 36, root_offset as u32);
    for pos in (4128..4096 + root_offset).step_by(8) {
        p32(&mut bytes, pos, 8);
    }
    bytes[4096 + root_offset..].copy_from_slice(&root);
    checksum(&mut bytes);
    assert!(matches!(
        Hive::open(bytes),
        Err(cloud_image_inspector::error::Error::Limit(_))
    ));
}

#[test]
fn registry_fact_errors_preserve_other_facts_and_unknown_report_fields() {
    let mut tree = windows_tree(false, false);
    let mut software = HiveBuilder::default();
    let cv = "Microsoft\\Windows NT\\CurrentVersion";
    software.set(cv, "ProductName", 1, vec![0, 0xd8]);
    software.sz(cv, "EditionID", "ServerDatacenter");
    software.sz(cv, "CurrentBuildNumber", "20348");
    software.dw(cv, "UBR", 2700);
    tree.insert("Windows/System32/config/SOFTWARE", software.finish(false));
    let mut system = HiveBuilder::default();
    system.dw("Select", "Current", 2);
    // The wrong registry type makes only this service's Start unknown.
    system.sz("ControlSet002\\Services\\viostor", "Start", "automatic");
    system.dw("ControlSet002\\Services\\netkvm", "Start", 3);
    system.set(
        "ControlSet002\\Services\\netkvm",
        "ImagePath",
        1,
        vec![0, 0xd8],
    );
    system.dw("ControlSet002\\Control\\Power", "HibernateEnabled", 0);
    tree.insert("Windows/System32/config/SYSTEM", system.finish(false));
    let r = inspect_disk(dev(ntfs(&tree))).unwrap();
    let w = r.windows.as_ref().unwrap();
    assert_eq!(w.product_name, None);
    assert_eq!(w.edition_id.as_deref(), Some("ServerDatacenter"));
    assert_eq!(w.build, Some(20348));
    assert_eq!(w.ubr, Some(2700));
    assert_eq!(w.arch.as_deref(), Some("amd64"));
    assert_eq!(w.viostor.present, Some(true));
    assert_eq!(w.viostor.start, None);
    assert_eq!(w.viostor.file, Some(true));
    assert_eq!(w.netkvm.present, Some(true));
    assert_eq!(w.netkvm.start, Some(3));
    assert_eq!(w.netkvm.file, None);
    assert_eq!(w.viosock.present, Some(false));
    assert_eq!(w.hibernation, Some(false));
    assert!(r.warnings.iter().any(|w| w.contains("ProductName")));
    assert!(r.warnings.iter().any(|w| w.contains("Services\\netkvm")));
    let json = report::json(&r, false).render();
    assert!(json.contains("\"product_name\": null"));
    assert!(json.contains("\"build\": 20348"));
    assert!(json.contains("\"start\": null"));
    assert!(json.contains("\"present\": false"));
    let text = report::text(&r);
    assert!(text.contains("os             unknown (Windows, amd64)"));
    assert!(text.contains("build: 20348"));
    assert!(text.contains("viostor: present: yes   Start: unknown   file: yes"));
    assert!(text.contains("netkvm: present: yes   Start: 3   file: unknown"));
    assert!(text.contains("viosock: present: no   Start: unknown   file: unknown"));
}

#[test]
fn ntfs_resident_and_nonresident_files_directory_lookup_and_volume_dirty() {
    let tree = windows_tree(false, true);
    let fs = Ntfs::open(dev(ntfs(&tree))).unwrap();
    let v = Vfs::new(&fs);
    assert!(windows::is_windows(&v));
    assert!(!fs.dirty().unwrap());
    assert_eq!(
        v.read("/WINDOWS/system32/drivers/VIOSTOR.SYS").unwrap(),
        b"driver"
    );
    let h = Hive::open(v.read("/Windows/System32/config/SYSTEM").unwrap()).unwrap();
    assert_eq!(h.value("Select", "Current").unwrap(), Some(Value::Dword(2)));
    let n = v
        .resolve("/Windows/System32/config/SYSTEM", true)
        .unwrap()
        .unwrap();
    let full = fs.read_file(n, 1 << 20).unwrap();
    assert_eq!(fs.read_range(n, 509, 100).unwrap(), full[509..609]);
    assert!(fs.read_file(n, 64).is_err());
}
#[test]
fn ntfs_sparse_negative_runs_and_initialized_tail_are_read_correctly() {
    let mut b = NtfsBuilder::new();
    b.bytes[256 * 512..257 * 512].fill(b'A');
    b.bytes[258 * 512..259 * 512].fill(b'B');
    let runs = [0x21, 1, 2, 1, 0x11, 1, 0xfe, 0x01, 1, 0];
    b.put(
        24,
        record(
            false,
            0,
            vec![nonresident(0x80, "", 0, 0, 2, 1536, 1100, 0x8000, &runs)],
        ),
    );
    let fs = Ntfs::open(dev(b.bytes)).unwrap();
    let data = fs.read_file(NodeId(1, 24), 2048).unwrap();
    assert_eq!(&data[..512], &[b'B'; 512]);
    assert_eq!(&data[512..1024], &[b'A'; 512]);
    assert!(data[1024..].iter().all(|b| *b == 0));
}
#[test]
fn ntfs_attribute_list_follows_extension_records() {
    let mut b = NtfsBuilder::new();
    b.bytes[256 * 512..257 * 512].fill(1);
    b.bytes[257 * 512..258 * 512].fill(2);
    let mut list = vec![0u8; 64];
    for (i, (id, vcn, recordid)) in [(0, 0, 24), (3, 1, 25)].iter().enumerate() {
        p32(&mut list, i * 32, 0x80);
        p16(&mut list, i * 32 + 4, 32);
        p64(&mut list, i * 32 + 8, *vcn);
        p64(&mut list, i * 32 + 16, (1 << 48) | recordid);
        p16(&mut list, i * 32 + 24, *id);
    }
    b.put(
        24,
        record(
            false,
            0,
            vec![
                nonresident(0x80, "", 0, 0, 0, 1024, 1024, 0, &[0x21, 1, 0, 1, 0]),
                resident(0x20, "", 1, &list),
            ],
        ),
    );
    b.put(
        25,
        record(
            false,
            (1 << 48) | 24,
            vec![nonresident(0x80, "", 3, 1, 1, 0, 0, 0, &[0x21, 1, 1, 1, 0])],
        ),
    );
    let fs = Ntfs::open(dev(b.bytes.clone())).unwrap();
    let result = fs.read_file(NodeId(1, 24), 2048).unwrap();
    assert_eq!(&result[..512], &[1; 512]);
    assert_eq!(&result[512..], &[2; 512]);
    p64(&mut b.bytes, 2048 + 25 * 1024 + 32, (1 << 48) | 26);
    let fs = Ntfs::open(dev(b.bytes)).unwrap();
    assert!(fs.read_file(NodeId(1, 24), 2048).is_err());
}
#[test]
fn ntfs_index_allocation_fixups_bitmap_and_cycle_checks() {
    let mut b = NtfsBuilder::new();
    let block = index_block(&[index_entry("file.txt", 24, None), index_end(None)], 0);
    let c = b.store(&block);
    let root = index_root(&[index_end(Some(0))]);
    let attrs = vec![
        resident(0x90, "$I30", 0, &root),
        nonresident(
            0xa0,
            "$I30",
            1,
            0,
            1,
            1024,
            1024,
            0,
            &[0x21, 2, c as u8, (c >> 8) as u8, 0],
        ),
        resident(0xb0, "$I30", 2, &[1]),
    ];
    b.put(5, record(true, 0, attrs));
    b.put(24, record(false, 0, vec![resident(0x80, "", 0, b"hello")]));
    let fs = Ntfs::open(dev(b.bytes.clone())).unwrap();
    assert_eq!(Vfs::new(&fs).read("/FILE.TXT").unwrap(), b"hello");
    let mut torn = b.bytes.clone();
    torn[c as usize * 512 + 510] ^= 1;
    let fs = Ntfs::open(dev(torn)).unwrap();
    assert!(fs.read_dir(fs.root()).is_err());
    let cycle = index_block(&[index_end(Some(0))], 0);
    b.bytes[c as usize * 512..c as usize * 512 + 1024].copy_from_slice(&cycle);
    let fs = Ntfs::open(dev(b.bytes)).unwrap();
    assert!(fs.read_dir(fs.root()).is_err());
}
#[test]
fn ntfs_compressed_encrypted_stale_and_corrupt_runs_are_errors() {
    for flags in [1, 0x4000] {
        let mut b = NtfsBuilder::new();
        b.put(
            24,
            record(
                false,
                0,
                vec![nonresident(
                    0x80,
                    "",
                    0,
                    0,
                    0,
                    512,
                    512,
                    flags,
                    &[0x21, 1, 0, 1, 0],
                )],
            ),
        );
        let fs = Ntfs::open(dev(b.bytes)).unwrap();
        assert!(matches!(
            fs.read_file(NodeId(1, 24), 1024),
            Err(cloud_image_inspector::error::Error::Unsupported(_))
        ));
    }
    let mut b = NtfsBuilder::new();
    b.put(
        24,
        record(
            false,
            0,
            vec![nonresident(
                0x80,
                "",
                0,
                0,
                0,
                512,
                512,
                0,
                &[0x11, 0, 1, 0],
            )],
        ),
    );
    let fs = Ntfs::open(dev(b.bytes)).unwrap();
    assert!(fs.read_file(NodeId(1, 24), 1024).is_err());
    assert!(fs.stat(NodeId(2, 24)).is_err());
    let mut b = ntfs(&windows_tree(false, false));
    b[2048 + 510] ^= 1;
    assert!(Ntfs::open(dev(b)).is_err());
}
#[test]
fn pe_version_reads_only_version_resources_and_checks_bounds() {
    assert_eq!(
        windows::pe_version(&pe(0x8664, true)).unwrap(),
        Some("0.3.0.4".into())
    );
    assert_eq!(windows::pe_version(&pe(0x8664, false)).unwrap(), None);
    for len in [0, 2, 63, 90, 511, 640, 700] {
        assert!(windows::pe_version(&pe(0x8664, true)[..len]).is_err());
    }
    let mut b = pe(0x8664, true);
    p32(&mut b, 532, 0x80000000);
    assert!(windows::pe_version(&b).is_err());
}
#[test]
fn bcd_explicit_and_inherited_ems_use_the_default_loader() {
    assert_eq!(
        windows::ems(&Hive::open(bcd(false)).unwrap()).unwrap(),
        (Some(true), Some(false))
    );
    assert_eq!(
        windows::ems(&Hive::open(bcd(true)).unwrap()).unwrap(),
        (Some(true), Some(true))
    );
    let mut h = HiveBuilder::default();
    h.set(
        "Objects\\{9dea862c-5cdd-4e70-acc1-f32b344d4795}\\Elements\\16000020",
        "Element",
        3,
        vec![0],
    );
    assert_eq!(
        windows::ems(&Hive::open(h.finish(false)).unwrap()).unwrap(),
        (Some(false), None)
    );
}
#[test]
fn complete_windows_report_matches_contract_including_esp() {
    let mut esp = Tree::default();
    esp.insert("EFI/Microsoft/Boot/BCD", bcd(true));
    let r = inspect_disk(dev(disk(ntfs(&windows_tree(false, true)), fat(12, &esp)))).unwrap();
    assert_eq!(r.os_family, OsFamily::Windows);
    assert!(r.facts.is_none());
    assert!(r.boot.uefi);
    assert_eq!(r.root.as_ref().unwrap().partition, Some(2));
    let w = r.windows.as_ref().unwrap();
    assert_eq!(
        w.product_name.as_deref(),
        Some("Windows Server 2022 Datacenter")
    );
    assert_eq!(w.edition_id.as_deref(), Some("ServerDatacenter"));
    assert_eq!(w.installation_type.as_deref(), Some("Server"));
    assert_eq!(w.build, Some(20348));
    assert_eq!(w.ubr, Some(2700));
    assert_eq!(w.arch.as_deref(), Some("amd64"));
    assert_eq!(w.viostor.start, Some(0));
    assert_eq!(w.netkvm.start, Some(3));
    assert_eq!(w.viosock.start, Some(3));
    assert_eq!(w.viostor.present, Some(true));
    assert_eq!(w.viostor.file, Some(true));
    assert_eq!(w.virtainer_agent.present, Some(true));
    assert_eq!(w.virtainer_agent.file, Some(true));
    assert_eq!(w.virtainer_agent.start, Some(2));
    assert_eq!(w.virtainer_agent.version.as_deref(), Some("0.3.0.4"));
    assert_eq!(
        w.image_state.as_deref(),
        Some("IMAGE_STATE_GENERALIZE_RESEAL_TO_OOBE")
    );
    assert_eq!(w.bootems, Some(true));
    assert_eq!(w.ems_enabled, Some(true));
    assert_eq!(w.rtc_is_universal, Some(true));
    assert_eq!(w.hibernation, Some(false));
    assert_eq!(w.fast_startup, Some(false));
    assert_eq!(w.system_hive_dirty, Some(false));
    assert_eq!(w.software_hive_dirty, Some(false));
    assert_eq!(w.ntfs_volume_dirty, Some(false));
    assert!(r.warnings.is_empty(), "{:?}", r.warnings);
    let json = report::json(&r, false).render();
    for key in [
        "os_family",
        "windows",
        "product_name",
        "edition_id",
        "installation_type",
        "build",
        "ubr",
        "arch",
        "drivers",
        "viostor",
        "netkvm",
        "viosock",
        "virtainer_agent",
        "present",
        "start",
        "file",
        "version",
        "sysprep",
        "image_state",
        "ems",
        "bootems",
        "ems_enabled",
        "rtc_is_universal",
        "hibernation",
        "fast_startup",
        "dirty",
        "system_hive",
        "software_hive",
        "ntfs_volume",
    ] {
        assert!(json.contains(&format!("\"{key}\":")), "{key}");
    }
    assert!(
        report::text(&r).contains("drivers        viostor: present: yes   Start: 0   file: yes")
    );
}
#[test]
fn unknown_values_remain_null_and_dirty_hive_is_reported() {
    let mut tree = windows_tree(true, false);
    tree.insert("Windows/System32/config/SOFTWARE", vec![0; 8192]);
    let r = inspect_disk(dev(ntfs(&tree))).unwrap();
    let w = r.windows.as_ref().unwrap();
    assert_eq!(w.system_hive_dirty, Some(true));
    assert_eq!(w.software_hive_dirty, None);
    assert_eq!(w.product_name, None);
    assert_eq!(w.virtainer_agent.present, Some(false));
    assert_eq!(w.virtainer_agent.file, None);
    assert_eq!(w.bootems, None);
    assert_eq!(w.ems_enabled, None);
    assert!(!r.warnings.is_empty());
    assert!(report::json(&r, false)
        .render()
        .contains("\"product_name\": null"));
    let r = inspect_disk(dev(vec![0; 8192])).unwrap();
    assert_eq!(r.os_family, OsFamily::Unknown);
    assert!(r.windows.is_none());
}
#[test]
fn corrupted_windows_corpus_never_panics_or_hangs() {
    use std::time::Duration;
    let (tx, rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let mut tree = Tree::default();
        tree.insert("EFI/Microsoft/Boot/BCD", bcd(true));
        let corpus = [
            fat(12, &tree),
            ntfs(&windows_tree(false, true)),
            bcd(true),
            pe(0x8664, true),
        ];
        let mut seed = 0x987654321u64;
        let rng = |s: &mut u64| {
            *s ^= *s << 13;
            *s ^= *s >> 7;
            *s ^= *s << 17;
            *s
        };
        for (kind, clean) in corpus.iter().enumerate() {
            for i in 0..250 {
                let mut b = clean.clone();
                for _ in 0..1 + i % 8 {
                    let region = if i % 2 == 0 {
                        b.len().min(if kind == 1 { 65536 } else { 16384 })
                    } else {
                        b.len()
                    };
                    let off = rng(&mut seed) as usize % region;
                    b[off] = rng(&mut seed) as u8;
                }
                if i % 17 == 0 {
                    let n = rng(&mut seed) as usize % b.len();
                    b.truncate(n);
                }
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    if kind == 0 {
                        if let Ok(f) = Fat::open(dev(b.clone())) {
                            let v = Vfs::new(&f);
                            let _ = f.read_dir(f.root());
                            let _ = v.read("/EFI/Microsoft/Boot/BCD");
                        }
                    }
                    if kind == 1 {
                        if let Ok(f) = Ntfs::open(dev(b.clone())) {
                            let v = Vfs::new(&f);
                            let _ = f.read_dir(f.root());
                            let _ = windows::collect(&v, f.dirty().ok(), &mut Vec::new());
                        }
                    }
                    if kind == 2 {
                        if let Ok(h) = Hive::open(b.clone()) {
                            let _ = windows::ems(&h);
                            let _ = h.key("Objects");
                        }
                    }
                    if kind == 3 {
                        let _ = windows::pe_version(&b);
                    }
                    if kind < 2 {
                        let _ = inspect_disk(dev(b));
                    }
                }));
                assert!(result.is_ok(), "panic in corpus {kind}, iteration {i}");
            }
        }
        tx.send(()).unwrap();
    });
    rx.recv_timeout(Duration::from_secs(45))
        .expect("corruption corpus watchdog expired or worker panicked");
    worker.join().unwrap();
}
#[test]
#[ignore = "local Windows image required; set CII_WINDOWS_IMAGE"]
fn local_windows_image() {
    let path = std::env::var_os("CII_WINDOWS_IMAGE")
        .expect("set CII_WINDOWS_IMAGE to a local Windows raw or qcow2 image");
    let r = cloud_image_inspector::facts::inspect(std::path::Path::new(&path)).unwrap();
    assert_eq!(r.os_family, OsFamily::Windows);
    let w = r.windows.as_ref().unwrap();
    assert!(w.product_name.is_some());
    assert!(w.build.is_some());
    assert!(w.arch.is_some());
    print!("{}", report::json(&r, false).render());
}

#[test]
fn ntfs_mft_bootstrap_reads_a_fragmented_mft() {
    let mut b = NtfsBuilder::new();
    let mut list = vec![0u8; 64];
    for (i, (id, vcn, recordid)) in [(0, 0, 0), (1, 64, 24)].iter().enumerate() {
        p32(&mut list, i * 32, 0x80);
        p16(&mut list, i * 32 + 4, 32);
        p64(&mut list, i * 32 + 8, *vcn);
        p64(&mut list, i * 32 + 16, (1 << 48) | recordid);
        p16(&mut list, i * 32 + 24, *id);
    }
    b.put(
        0,
        record(
            false,
            0,
            vec![
                nonresident(0x80, "", 0, 0, 63, 65536, 65536, 0, &[0x21, 64, 4, 0, 0]),
                resident(0x20, "", 2, &list),
            ],
        ),
    );
    b.put(
        24,
        record(
            false,
            1 << 48,
            vec![nonresident(
                0x80,
                "",
                1,
                64,
                127,
                0,
                0,
                0,
                &[0x21, 64, 128, 0, 0],
            )],
        ),
    );
    b.put(
        5,
        record(
            true,
            0,
            vec![resident(
                0x90,
                "$I30",
                0,
                &index_root(&[index_entry("fragment.txt", 40, None), index_end(None)]),
            )],
        ),
    );
    let target = 128 * 512 + (40 * 1024 - 32768);
    let r = record(false, 0, vec![resident(0x80, "", 0, b"fragmented MFT")]);
    b.bytes[target..target + 1024].copy_from_slice(&r);
    let fs = Ntfs::open(dev(b.bytes.clone())).unwrap();
    assert_eq!(
        Vfs::new(&fs).read("/fragment.txt").unwrap(),
        b"fragmented MFT"
    );
    b.bytes[2048 + 24 * 1024 + 510] ^= 1;
    assert!(Ntfs::open(dev(b.bytes)).is_err());
}
#[test]
fn ntfs_nonresident_attribute_list_and_unicode_upcase() {
    let mut b = NtfsBuilder::new();
    let mut list = vec![0u8; 32];
    p32(&mut list, 0, 0x80);
    p16(&mut list, 4, 32);
    p64(&mut list, 16, (1 << 48) | 24);
    p16(&mut list, 24, 0);
    let c = b.store(&list);
    b.put(
        24,
        record(
            false,
            0,
            vec![
                resident(0x80, "", 0, b"unicode"),
                nonresident(
                    0x20,
                    "",
                    1,
                    0,
                    0,
                    list.len() as u64,
                    list.len() as u64,
                    0,
                    &[0x21, 1, c as u8, (c >> 8) as u8, 0],
                ),
            ],
        ),
    );
    b.put(
        5,
        record(
            true,
            0,
            vec![resident(
                0x90,
                "$I30",
                0,
                &index_root(&[index_entry("\u{e9}cole.txt", 24, None), index_end(None)]),
            )],
        ),
    );
    let mut table = Vec::with_capacity(131072);
    for n in 0..65536u32 {
        let folded = if n == 0xe9 {
            0xc9
        } else if (97..=122).contains(&n) {
            n - 32
        } else {
            n
        };
        table.extend_from_slice(&(folded as u16).to_le_bytes());
    }
    let c = b.store(&table);
    b.put(
        10,
        record(
            false,
            0,
            vec![nonresident(
                0x80,
                "",
                0,
                0,
                255,
                131072,
                131072,
                0,
                &[0x22, 0, 1, c as u8, (c >> 8) as u8, 0],
            )],
        ),
    );
    let fs = Ntfs::open(dev(b.bytes)).unwrap();
    assert_eq!(Vfs::new(&fs).read("/\u{c9}COLE.TXT").unwrap(), b"unicode");
}
#[test]
fn unreadable_index_does_not_become_a_missing_driver() {
    let mut tree = windows_tree(false, false);
    tree.insert("Windows/System32/drivers/extra.sys", vec![1]);
    let bytes = ntfs(&tree);
    let fs = Ntfs::open(dev(bytes.clone())).unwrap();
    let dir = Vfs::new(&fs)
        .resolve("/Windows/System32/drivers", true)
        .unwrap()
        .unwrap();
    let mut bytes = bytes;
    bytes[2048 + dir.1 as usize * 1024 + 510] ^= 1;
    let fs = Ntfs::open(dev(bytes)).unwrap();
    let w = windows::collect(&Vfs::new(&fs), fs.dirty().ok(), &mut Vec::new());
    assert_eq!(w.viostor.present, Some(true));
    assert_eq!(w.viostor.file, None);
}
#[test]
fn missing_values_and_files_are_distinct_from_read_errors() {
    let mut tree = windows_tree(false, true);
    tree.children
        .get_mut("Windows")
        .unwrap()
        .children
        .get_mut("System32")
        .unwrap()
        .children
        .get_mut("drivers")
        .unwrap()
        .children
        .remove("netkvm.sys");
    tree.children
        .get_mut("Program Files")
        .unwrap()
        .children
        .get_mut("Virtainer")
        .unwrap()
        .children
        .remove("virtainer-guest-agent.exe");
    let r = inspect_disk(dev(ntfs(&tree))).unwrap();
    let w = r.windows.unwrap();
    assert_eq!(w.netkvm.present, Some(true));
    assert_eq!(w.netkvm.file, Some(false));
    assert_eq!(w.virtainer_agent.file, Some(false));
    assert_eq!(w.virtainer_agent.version, None);
    let mut system = HiveBuilder::default();
    system.dw("Select", "Current", 2);
    system.dw("ControlSet001\\Services\\viostor", "Start", 0);
    tree.insert("Windows/System32/config/SYSTEM", system.finish(false));
    let r = inspect_disk(dev(ntfs(&tree))).unwrap();
    let w = r.windows.unwrap();
    assert_eq!(w.viostor.present, Some(false));
    assert_eq!(w.viostor.start, None);
    assert_eq!(w.rtc_is_universal, None);
    assert_eq!(w.hibernation, None);
    assert_eq!(w.fast_startup, None);
}
#[test]
fn report_detects_non_amd64_architecture_and_dirty_volume() {
    let mut tree = windows_tree(false, false);
    tree.insert("Windows/System32/ntoskrnl.exe", pe(0xaa64, false));
    let mut bytes = ntfs(&tree); // Volume info's resident value starts at record + 80.
    let pos = 2048 + 3 * 1024 + 80 + 10;
    p16(&mut bytes, pos, 1);
    let r = inspect_disk(dev(bytes)).unwrap();
    let w = r.windows.unwrap();
    assert_eq!(w.arch.as_deref(), Some("arm64"));
    assert_eq!(w.ntfs_volume_dirty, Some(true));
}
#[test]
fn cli_json_text_and_file_commands_use_the_windows_root() {
    let mut esp = Tree::default();
    esp.insert("EFI/Microsoft/Boot/BCD", bcd(false));
    let path = std::env::temp_dir().join(format!("cii-windows-{}.raw", std::process::id()));
    std::fs::write(&path, disk(ntfs(&windows_tree(false, true)), fat(12, &esp))).unwrap();
    let binary = env!("CARGO_BIN_EXE_cloud-image-inspector");
    let json = std::process::Command::new(binary)
        .arg("--json")
        .arg(&path)
        .output()
        .unwrap();
    assert!(json.status.success());
    let json = String::from_utf8(json.stdout).unwrap();
    assert!(json.contains("\"os_family\": \"windows\""));
    assert!(json.contains("\"bootems\": true"));
    let text = std::process::Command::new(binary)
        .arg(&path)
        .output()
        .unwrap();
    assert!(text.status.success());
    assert!(String::from_utf8(text.stdout)
        .unwrap()
        .contains("Windows Server 2022 Datacenter"));
    let cat = std::process::Command::new(binary)
        .arg("cat")
        .arg(&path)
        .arg("/Windows/System32/drivers/viostor.sys")
        .output()
        .unwrap();
    assert!(cat.status.success());
    assert_eq!(cat.stdout, b"driver");
    let ls = std::process::Command::new(binary)
        .arg("ls")
        .arg("--partition")
        .arg("1")
        .arg(&path)
        .arg("/EFI/Microsoft/Boot")
        .output()
        .unwrap();
    assert!(ls.status.success());
    assert!(String::from_utf8(ls.stdout).unwrap().contains("BCD"));
    std::fs::remove_file(path).unwrap();
}

#[test]
fn bcd_inheritance_dags_cycles_and_partial_evidence() {
    let mut h = HiveBuilder::default();
    let mgr = "Objects\\{9dea862c-5cdd-4e70-acc1-f32b344d4795}\\Elements";
    let id = "{12345678-1234-1234-1234-123456789abc}";
    let a = "{aaaaaaaa-1234-1234-1234-123456789abc}";
    let z = "{bbbbbbbb-1234-1234-1234-123456789abc}";
    let common = "{cccccccc-1234-1234-1234-123456789abc}";
    h.set(&format!("{mgr}\\16000020"), "Element", 3, vec![1]);
    h.sz(&format!("{mgr}\\23000003"), "Element", id);
    h.dw(&format!("Objects\\{id}\\Description"), "Type", 0x10200003);
    h.set(
        &format!("Objects\\{id}\\Elements\\14000006"),
        "Element",
        7,
        wide(&format!("{a}\0{z}\0\0")),
    );
    for parent in [a, z] {
        h.set(
            &format!("Objects\\{parent}\\Elements\\14000006"),
            "Element",
            7,
            wide(&format!("{common}\0\0")),
        );
    }
    h.set(
        &format!("Objects\\{common}\\Elements\\260000b0"),
        "Element",
        3,
        vec![1],
    );
    assert_eq!(
        windows::ems(&Hive::open(h.finish(false)).unwrap()).unwrap(),
        (Some(true), Some(true))
    );
    let mut h = HiveBuilder::default();
    h.sz(&format!("{mgr}\\23000003"), "Element", id);
    h.dw(&format!("Objects\\{id}\\Description"), "Type", 0x10200003);
    h.set(&format!("{mgr}\\16000020"), "Element", 3, vec![1]);
    h.set(
        &format!("Objects\\{id}\\Elements\\14000006"),
        "Element",
        7,
        wide(&format!("{id}\0\0")),
    );
    let b = h.finish(false);
    assert!(windows::ems(&Hive::open(b.clone()).unwrap()).is_err());
    let mut tree = Tree::default();
    tree.insert("EFI/Microsoft/Boot/BCD", b);
    let f = Fat::open(dev(fat(12, &tree))).unwrap();
    let mut warnings = Vec::new();
    assert_eq!(
        windows::read_ems(&Vfs::new(&f), &mut warnings),
        Some((Some(true), None))
    );
    assert!(!warnings.is_empty());
    let mut b = bcd(false);
    p32(&mut b, 8, 3);
    checksum(&mut b);
    assert!(windows::ems(&Hive::open(b).unwrap()).is_err());
}
#[test]
fn registry_big_data_and_multi_string_limits_are_enforced() {
    let mut h = HiveBuilder::default();
    h.set("A", "Bytes", 3, vec![7; 35000]);
    let mut b = h.finish(false);
    let pos = b.windows(2).position(|w| w == b"db").unwrap();
    p16(&mut b, pos + 2, 65535);
    let h = Hive::open(b).unwrap();
    assert!(h.value("A", "Bytes").is_err());
    let mut h = HiveBuilder::default();
    h.set("A", "Many", 7, wide(&format!("{}\0", "a\0".repeat(65537))));
    let h = Hive::open(h.finish(false)).unwrap();
    assert!(matches!(
        h.value("A", "Many"),
        Err(cloud_image_inspector::error::Error::Limit(_))
    ));
    let mut h = HiveBuilder::default();
    h.set("A", "Text", 1, vec![0xd8, 0]);
    let h = Hive::open(h.finish(false)).unwrap();
    assert_eq!(
        h.value("A", "Text").unwrap(),
        Some(Value::String("\u{d8}".into()))
    );
    let mut h = HiveBuilder::default();
    h.set("A", "Text", 1, vec![0, 0xd8]);
    let h = Hive::open(h.finish(false)).unwrap();
    assert!(h.value("A", "Text").is_err());
}
#[test]
fn ntfs_short_child_entries_and_unallocated_bitmap_are_rejected() {
    let mut b = NtfsBuilder::new();
    let mut end = index_end(None);
    p16(&mut end, 12, 3);
    let mut root = index_root(&[end]);
    root[28] = 1;
    b.put(5, record(true, 0, vec![resident(0x90, "$I30", 0, &root)]));
    let fs = Ntfs::open(dev(b.bytes)).unwrap();
    assert!(fs.read_dir(fs.root()).is_err());
    let mut b = NtfsBuilder::new();
    let block = index_block(&[index_end(None)], 0);
    let c = b.store(&block);
    let attrs = vec![
        resident(0x90, "$I30", 0, &index_root(&[index_end(Some(0))])),
        nonresident(
            0xa0,
            "$I30",
            1,
            0,
            1,
            1024,
            1024,
            0,
            &[0x21, 2, c as u8, (c >> 8) as u8, 0],
        ),
        resident(0xb0, "$I30", 2, &[0]),
    ];
    b.put(5, record(true, 0, attrs));
    let fs = Ntfs::open(dev(b.bytes)).unwrap();
    assert!(fs.read_dir(fs.root()).is_err());
}
#[test]
fn ambiguous_windows_roots_and_esps_do_not_choose_a_boot_store() {
    let mut esp = Tree::default();
    esp.insert("EFI/Microsoft/Boot/BCD", bcd(true));
    let clean = disk(ntfs(&windows_tree(false, false)), fat(12, &esp));
    let mut b = clean.clone();
    let copy = b[446..462].to_vec();
    b[478..494].copy_from_slice(&copy);
    let r = inspect_disk(dev(b)).unwrap();
    assert_eq!(r.os_family, OsFamily::Windows);
    assert_eq!(r.windows.as_ref().unwrap().bootems, None);
    assert!(r.warnings.iter().any(|w| w.contains("multiple EFI")));
    let mut b = clean;
    let copy = b[462..478].to_vec();
    b[478..494].copy_from_slice(&copy);
    let r = inspect_disk(dev(b)).unwrap();
    assert_eq!(r.os_family, OsFamily::Unknown);
    assert!(r.windows.is_none());
    assert!(r.root.is_none());
}
#[test]
fn agent_paths_require_a_known_drive_and_unambiguous_executable() {
    for path in [
        "D:\\elsewhere\\virtainer-guest-agent.exe",
        "C:\\Program Files\\Virtainer\\virtainer-guest-agent.exe --service",
        "%SystemRoot%\\..\\virtainer-guest-agent.exe",
    ] {
        let mut tree = windows_tree(false, true);
        let mut h = HiveBuilder::default();
        h.dw("Select", "Current", 2);
        h.dw("ControlSet002\\Services\\virtainer-guest-agent", "Start", 2);
        h.sz(
            "ControlSet002\\Services\\virtainer-guest-agent",
            "ImagePath",
            path,
        );
        tree.insert("Windows/System32/config/SYSTEM", h.finish(false));
        let r = inspect_disk(dev(ntfs(&tree))).unwrap();
        let w = r.windows.unwrap();
        assert_eq!(w.virtainer_agent.present, Some(true));
        assert_eq!(w.virtainer_agent.file, None, "{path}");
        assert_eq!(w.virtainer_agent.version, None);
    }
}
#[test]
fn windows_file_paths_accept_backslashes_and_refuse_reparse_data() {
    let fs = Ntfs::open(dev(ntfs(&windows_tree(false, false)))).unwrap();
    let v = Vfs::new(&fs);
    assert_eq!(
        v.read("\\Windows\\System32\\drivers\\viostor.sys").unwrap(),
        b"driver"
    );
    let mut b = NtfsBuilder::new();
    b.put(
        24,
        record(
            false,
            0,
            vec![
                resident(0x80, "", 0, b"placeholder"),
                resident(0xc0, "", 1, &[0; 8]),
            ],
        ),
    );
    let fs = Ntfs::open(dev(b.bytes)).unwrap();
    assert!(matches!(
        fs.read_file(NodeId(1, 24), 64),
        Err(cloud_image_inspector::error::Error::Unsupported(_))
    ));
}

#[test]
fn sparse_allocation_unit_is_not_compression() {
    for flags in [0x8000, 0x8001] {
        let mut b = NtfsBuilder::new();
        b.bytes[256 * 512..257 * 512].fill(b'A');
        b.bytes[257 * 512..258 * 512].fill(b'B');
        // Physical data, a hole, and more physical data in the same allocation unit.
        let mut attr = nonresident(
            0x80,
            "",
            0,
            0,
            2,
            1536,
            1536,
            flags,
            &[0x21, 1, 0, 1, 0x01, 1, 0x11, 1, 1, 0],
        );
        p16(&mut attr, 34, 4);
        // Sparse/compressed streams carry an extended allocation-size header.
        attr.splice(64..64, [0u8; 8]);
        let attr_len = attr.len();
        p32(&mut attr, 4, attr_len as u32);
        p16(&mut attr, 32, 72);
        p64(&mut attr, 64, 1024);
        b.put(24, record(false, 0, vec![attr]));
        let fs = Ntfs::open(dev(b.bytes)).unwrap();
        let node = NodeId(1, 24);
        if flags & 1 != 0 {
            assert!(matches!(
                fs.read_file(node, 2048),
                Err(cloud_image_inspector::error::Error::Unsupported(_))
            ));
            assert!(matches!(
                fs.read_range(node, 500, 550),
                Err(cloud_image_inspector::error::Error::Unsupported(_))
            ));
        } else {
            let expected = [vec![b'A'; 512], vec![0; 512], vec![b'B'; 512]].concat();
            assert_eq!(fs.read_file(node, 2048).unwrap(), expected);
            assert_eq!(fs.read_range(node, 500, 550).unwrap(), expected[500..1050]);
        }
    }
}

#[test]
fn index_vcns_use_512_byte_units_on_4kn_volumes() {
    let clean = large_sector_ntfs_index();
    let fs = Ntfs::open(dev(clean.clone())).unwrap();
    let entries = fs.read_dir(fs.root()).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, b"file.txt");
    assert_eq!(
        Vfs::new(&fs).read("/FILE.TXT").unwrap(),
        b"large-sector index"
    );
    let mut torn = clean.clone();
    torn[2 * 65536 + 4096 + 510] ^= 1;
    let fs = Ntfs::open(dev(torn)).unwrap();
    assert!(fs.read_dir(fs.root()).is_err());
    let mut wrong_vcn = clean;
    p64(&mut wrong_vcn, 2 * 65536 + 4096 + 16, 2);
    let fs = Ntfs::open(dev(wrong_vcn)).unwrap();
    assert!(fs.read_dir(fs.root()).is_err());
}

#[test]
fn ambiguous_file_commands_require_a_partition() {
    use cloud_image_inspector::facts::with_view_of;
    let bytes = two_windows_installations();
    let r = inspect_disk(dev(bytes.clone())).unwrap();
    assert_eq!(r.os_family, OsFamily::Unknown);
    assert!(r.root.is_none());
    for subvol in [None, Some(5)] {
        let called = std::cell::Cell::new(false);
        let result = with_view_of(dev(bytes.clone()), None, subvol, |_| called.set(true));
        assert!(result.is_err());
        assert!(
            !called.get(),
            "ambiguous root must be rejected before the callback"
        );
        assert!(result.unwrap_err().to_string().contains("--partition"));
    }
    for (number, expected) in [(1, b"installation one"), (2, b"installation two")] {
        let data = with_view_of(dev(bytes.clone()), Some(number), None, |v| {
            v.read("/Windows/System32/drivers/viostor.sys")
        })
        .unwrap()
        .unwrap();
        assert_eq!(data, expected);
    }
    let path = std::env::temp_dir().join(format!("cii-ambiguous-{}.raw", std::process::id()));
    let dest = std::env::temp_dir().join(format!("cii-ambiguous-export-{}", std::process::id()));
    std::fs::write(&path, bytes).unwrap();
    let binary = env!("CARGO_BIN_EXE_cloud-image-inspector");
    for command in ["cat", "ls", "stat", "export"] {
        let image_path = if matches!(command, "ls" | "export") {
            "/Windows/System32/drivers"
        } else {
            "/Windows/System32/drivers/viostor.sys"
        };
        let mut cmd = std::process::Command::new(binary);
        cmd.arg(command).arg(&path).arg(image_path);
        if command == "export" {
            cmd.arg(&dest);
        }
        let output = cmd.output().unwrap();
        assert!(
            !output.status.success(),
            "automatic {command} must reject ambiguity"
        );
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8(output.stderr)
            .unwrap()
            .contains("--partition"));
        assert!(!dest.exists());
        let mut cmd = std::process::Command::new(binary);
        cmd.arg(command)
            .arg("--partition")
            .arg("2")
            .arg(&path)
            .arg(image_path);
        if command == "export" {
            cmd.arg(&dest);
        }
        let output = cmd.output().unwrap();
        assert!(
            output.status.success(),
            "explicit {command}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        if command == "cat" {
            assert_eq!(output.stdout, b"installation two");
        }
        if command == "export" {
            assert_eq!(
                std::fs::read(dest.join("viostor.sys")).unwrap(),
                b"installation two"
            );
        }
    }
    std::fs::remove_file(path).unwrap();
    std::fs::remove_dir_all(dest).unwrap();
}

#[test]
fn system_root_expansion_preserves_unknown_path_evidence() {
    for prefix in ["%SystemRoot%", "%WINDIR%", "\\SystemRoot"] {
        for literal_exists in [false, true] {
            let mut tree = windows_tree(false, true);
            let mut h = HiveBuilder::default();
            h.dw("Select", "Current", 2);
            h.dw("ControlSet002\\Services\\virtainer-guest-agent", "Start", 2);
            h.sz(
                "ControlSet002\\Services\\virtainer-guest-agent",
                "ImagePath",
                &format!("{prefix}\\%AGENT_DIR%\\agent.exe"),
            );
            tree.insert("Windows/System32/config/SYSTEM", h.finish(false));
            if literal_exists {
                tree.insert("Windows/%AGENT_DIR%/agent.exe", pe(0x8664, true));
            }
            let r = inspect_disk(dev(ntfs(&tree))).unwrap();
            let w = r.windows.unwrap();
            assert_eq!(w.virtainer_agent.present, Some(true));
            assert_eq!(w.virtainer_agent.start, Some(2));
            assert_eq!(
                w.virtainer_agent.file, None,
                "{prefix}, literal exists: {literal_exists}"
            );
            assert_eq!(w.virtainer_agent.version, None);
            assert!(r
                .warnings
                .iter()
                .any(|w| w.contains("unresolved ImagePath")));
        }
        let mut tree = windows_tree(false, true);
        let mut h = HiveBuilder::default();
        h.dw("Select", "Current", 2);
        h.dw("ControlSet002\\Services\\virtainer-guest-agent", "Start", 2);
        h.sz(
            "ControlSet002\\Services\\virtainer-guest-agent",
            "ImagePath",
            &format!("{prefix}\\agent.exe"),
        );
        tree.insert("Windows/System32/config/SYSTEM", h.finish(false));
        tree.insert("Windows/agent.exe", pe(0x8664, true));
        let w = inspect_disk(dev(ntfs(&tree))).unwrap().windows.unwrap();
        assert_eq!(w.virtainer_agent.file, Some(true));
        assert_eq!(w.virtainer_agent.version.as_deref(), Some("0.3.0.4"));
    }
}

#[test]
fn service_lookup_failures_preserve_null_file_evidence() {
    let mut missing_select = HiveBuilder::default();
    missing_select.dw("ControlSet002\\Services\\netkvm", "Start", 3);
    let mut corrupt_services = HiveBuilder::default();
    corrupt_services.dw("Select", "Current", 2);
    corrupt_services.dw("ControlSet002\\Services\\netkvm", "Start", 3);
    let mut corrupt_services = corrupt_services.finish(false);
    let services = Hive::open(corrupt_services.clone())
        .unwrap()
        .key("ControlSet002\\Services")
        .unwrap()
        .unwrap();
    p32(
        &mut corrupt_services,
        4096 + services as usize + 4 + 28,
        u32::MAX,
    );
    let h = Hive::open(corrupt_services.clone()).unwrap();
    assert_eq!(h.value("Select", "Current").unwrap(), Some(Value::Dword(2)));
    assert!(h.key("ControlSet002\\Services\\netkvm").is_err());
    for system in [
        vec![0; 8192],
        missing_select.finish(false),
        corrupt_services,
    ] {
        let mut tree = windows_tree(false, true);
        tree.insert("Windows/System32/config/SYSTEM", system);
        tree.children
            .get_mut("Windows")
            .unwrap()
            .children
            .get_mut("System32")
            .unwrap()
            .children
            .get_mut("drivers")
            .unwrap()
            .children
            .remove("viostor.sys");
        let r = inspect_disk(dev(ntfs(&tree))).unwrap();
        let w = r.windows.as_ref().unwrap();
        for d in [&w.viostor, &w.netkvm, &w.viosock, &w.virtainer_agent] {
            assert_eq!(d.present, None);
            assert_eq!(d.start, None);
            assert_eq!(d.file, None);
            assert_eq!(d.version, None);
        }
        let json = w.json().render();
        assert_eq!(json.matches("\"file\": null").count(), 4);
    }
    // A readable service with no ImagePath establishes the conventional path.
    let mut tree = windows_tree(false, false);
    tree.children
        .get_mut("Windows")
        .unwrap()
        .children
        .get_mut("System32")
        .unwrap()
        .children
        .get_mut("drivers")
        .unwrap()
        .children
        .remove("viostor.sys");
    let w = inspect_disk(dev(ntfs(&tree))).unwrap().windows.unwrap();
    assert_eq!(w.viostor.file, Some(false));
    assert_eq!(w.netkvm.file, Some(true));
    // A missing service key provides no registered executable location.
    let mut h = HiveBuilder::default();
    h.dw("Select", "Current", 2);
    tree.insert("Windows/System32/config/SYSTEM", h.finish(false));
    let w = inspect_disk(dev(ntfs(&tree))).unwrap().windows.unwrap();
    assert_eq!(w.netkvm.present, Some(false));
    assert_eq!(w.netkvm.file, None);
}

#[test]
fn explicit_subvolume_reads_data_without_an_os_root() {
    use cloud_image_inspector::facts::with_view_of;
    let raw = btrfs_data(b"top-level data");
    let fs = cloud_image_inspector::fs::btrfs::Btrfs::open(dev(raw.clone())).unwrap();
    assert_eq!(Vfs::new(&fs).read("/file").unwrap(), b"top-level data");
    let r = inspect_disk(dev(raw.clone())).unwrap();
    assert_eq!(r.os_family, OsFamily::Unknown);
    assert!(r.root.is_none());
    let mut other = Tree::default();
    other.insert("seed.txt", b"seed".to_vec());
    let single = partitioned_volumes(&[(0xef, fat(12, &other)), (0x83, raw.clone())]);
    for bytes in [raw.clone(), single] {
        assert!(with_view_of(dev(bytes.clone()), None, None, |_| ()).is_err());
        for (id, expected) in [
            (5, b"top-level data".as_slice()),
            (256, b"nested subvolume data".as_slice()),
        ] {
            let data = with_view_of(dev(bytes.clone()), None, Some(id), |v| v.read("/file"))
                .unwrap()
                .unwrap();
            assert_eq!(data, expected);
        }
    }
    let ambiguous =
        partitioned_volumes(&[(0x83, raw.clone()), (0x83, btrfs_data(b"second volume"))]);
    let called = std::cell::Cell::new(false);
    let err =
        with_view_of(dev(ambiguous.clone()), None, Some(5), |_| called.set(true)).unwrap_err();
    assert!(!called.get());
    assert!(err.to_string().contains("--partition"));
    let data = with_view_of(dev(ambiguous.clone()), Some(2), Some(5), |v| {
        v.read("/file")
    })
    .unwrap()
    .unwrap();
    assert_eq!(data, b"second volume");
    let path = std::env::temp_dir().join(format!("cii-subvol-{}.raw", std::process::id()));
    let binary = env!("CARGO_BIN_EXE_cloud-image-inspector");
    std::fs::write(&path, raw).unwrap();
    let out = std::process::Command::new(binary)
        .args(["cat", "--subvol", "5"])
        .arg(&path)
        .arg("/file")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"top-level data");
    std::fs::write(&path, ambiguous).unwrap();
    let out = std::process::Command::new(binary)
        .args(["cat", "--subvol", "5"])
        .arg(&path)
        .arg("/file")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--partition"));
    let out = std::process::Command::new(binary)
        .args(["cat", "--partition", "2", "--subvol", "5"])
        .arg(&path)
        .arg("/file")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"second volume");
    std::fs::remove_file(path).unwrap();
}

#[test]
fn fat_short_aliases_resolve_to_the_same_files_as_long_names() {
    let mut tree = Tree::default();
    tree.insert("virtainer-provision.json", b"provision".to_vec());
    tree.insert("user-script.ps1", b"script".to_vec());
    for bits in [12, 16, 32] {
        let fs = Fat::open(dev(fat(bits, &tree))).unwrap();
        let v = Vfs::new(&fs);
        let mut by_alias = Vec::new();
        for i in 0..2 {
            let node = v.resolve(&format!("/F{i:07}.BIN"), true).unwrap();
            by_alias.push(node.expect("alias resolves"));
        }
        let long = v
            .resolve("/virtainer-provision.json", true)
            .unwrap()
            .unwrap();
        assert!(by_alias.contains(&long));
        assert_eq!(v.resolve("/F0000009.BIN", true).unwrap(), None);
        assert_eq!(fs.read_dir(fs.root()).unwrap().len(), 2);
    }
}
