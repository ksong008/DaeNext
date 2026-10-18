use super::*;

#[test]
fn real_native_bpf_objects_define_the_lpm_inner_abi() {
    let Some(path) = std::env::var_os("DAE_TEST_NATIVE_BPF_OBJECT") else {
        eprintln!("skip native object contract: DAE_TEST_NATIVE_BPF_OBJECT is unset");
        return;
    };
    let bytes = fs::read(&path).expect("read native BPF object");
    let object = aya_obj::Object::parse(&bytes).expect("parse native BPF object");
    let outer = &object.maps[LPM_ARRAY_MAP_NAME];
    let inner = outer
        .inner()
        .expect("LPM outer must encode an inner template");
    let catalog = |name| map_catalog().iter().find(|spec| spec.name == name).unwrap();
    let expected_outer = catalog(LPM_ARRAY_MAP_NAME);
    let expected_inner = catalog(UNUSED_LPM_TYPE_NAME);
    assert_eq!(outer.map_type(), BPF_MAP_TYPE_ARRAY_OF_MAPS);
    assert_eq!(inner.map_type(), BPF_MAP_TYPE_LPM_TRIE);
    for (map, expected) in [(outer, expected_outer), (&inner, expected_inner)] {
        assert_eq!(map.key_size(), expected.key_size);
        assert_eq!(map.value_size(), expected.value_size);
        assert_eq!(map.max_entries(), expected.max_entries);
        assert_eq!(map.map_flags(), expected.flags);
    }
    for expected in map_catalog() {
        assert!(
            object.maps.contains_key(expected.name),
            "missing map {}",
            expected.name
        );
    }
}

#[test]
fn aya_lpm_template_load_reuses_pin_and_cleans_failed_transaction_is_env_gated() {
    if std::env::var_os("DAE_RUN_AYA_LOAD_SMOKE").is_none() {
        return;
    }
    let object = PathBuf::from(
        std::env::var_os("DAE_TEST_NATIVE_BPF_OBJECT").expect("native BPF object required"),
    );
    let root = crate::default_bpffs_mount()
        .unwrap()
        .join(format!("dae-lpm-template-test-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(root.clone());
    let mut options = AyaUserspaceLoaderOptions::new(&object);
    options.map_pin_path = Some(&root);
    options.allow_unsupported_maps = false;
    let loaded =
        load_aya_userspace_object(options.clone()).expect("create outer map from BTF template");
    assert!(loaded.report.unsupported_map_names.is_empty());
    let probes = loaded
        .report
        .capability_probe
        .expect("startup capability evidence");
    assert_eq!(probes.entries.len(), 26);
    eprintln!(
        "capability probes: {} entries in {}us: {:?}",
        probes.entries.len(),
        probes.elapsed_micros,
        probes.entries
    );
    let id = MapData::from_pin(root.join(LPM_ARRAY_MAP_NAME))
        .unwrap()
        .info()
        .unwrap()
        .id();
    drop(loaded);
    let reloaded = load_aya_userspace_object(options).expect("reuse BTF outer pin");
    assert_eq!(
        MapData::from_pin(root.join(LPM_ARRAY_MAP_NAME))
            .unwrap()
            .info()
            .unwrap()
            .id(),
        id
    );
    assert!(
        std::ptr::eq(probes, reloaded.report.capability_probe.unwrap()),
        "reload must reuse the probe snapshot"
    );
    drop(reloaded);
    let report = prepin_lpm_array_map(&root).expect("reuse pre-existing map without replacement");
    assert_eq!(
        report.outer_max_entries,
        crate::map_catalog()
            .iter()
            .find(|map| map.name == LPM_ARRAY_MAP_NAME)
            .unwrap()
            .max_entries
    );
    assert_eq!(
        MapData::from_pin(root.join(LPM_ARRAY_MAP_NAME))
            .unwrap()
            .info()
            .unwrap()
            .id(),
        id
    );
    let mut bad = AyaUserspaceBytesLoaderOptions::new("invalid-object", b"invalid");
    bad.map_pin_path = Some(&root);
    bad.prepin_lpm_array_map = true;
    assert!(load_aya_userspace_object_bytes(bad.clone()).is_err());
    assert_eq!(
        MapData::from_pin(root.join(LPM_ARRAY_MAP_NAME))
            .unwrap()
            .info()
            .unwrap()
            .id(),
        id
    );
    let fresh = root.join("failed");
    fs::create_dir(&fresh).unwrap();
    bad.map_pin_path = Some(&fresh);
    assert!(load_aya_userspace_object_bytes(bad).is_err());
    assert_eq!(
        fs::read_dir(&fresh).unwrap().count(),
        0,
        "failed load leaked pins"
    );
}
