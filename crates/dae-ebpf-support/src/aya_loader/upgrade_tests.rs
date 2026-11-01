use super::*;
use std::os::fd::AsFd;
use std::sync::atomic::{AtomicUsize, Ordering};

use aya_obj::generated::{BPF_F_RDONLY_PROG, bpf_map_type};

use crate::maps::RuntimeMapProfile;
use crate::runtime_maps::{lookup_map_elem_bytes, update_map_elem_bytes};

struct Pins(PathBuf);

impl Pins {
    fn new(label: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = crate::default_bpffs_mount().expect("root smoke requires bpffs");
        let path = root.join(format!(
            "dae-aya-upgrade-{}-{}-{label}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("create private pin directory");
        Self(path)
    }

    fn names(&self) -> BTreeSet<std::ffi::OsString> {
        fs::read_dir(&self.0)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect()
    }
}

impl Drop for Pins {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove only this test's pins");
    }
}

fn object() -> Option<PathBuf> {
    std::env::var_os("DAE_RUN_AYA_LOAD_SMOKE")?;
    Some(PathBuf::from(
        std::env::var_os("DAE_TEST_NATIVE_BPF_OBJECT").expect("real native object is required"),
    ))
}

fn options<'a>(object: &'a Path, pins: &'a Pins) -> AyaUserspaceLoaderOptions<'a> {
    let mut options = AyaUserspaceLoaderOptions::new(object);
    options.map_pin_path = Some(&pins.0);
    options.target_btf_required =
        std::env::var_os("DAE_TEST_NATIVE_BPF_TARGET_BTF_REQUIRED").is_some();
    options
}

fn load_error(options: AyaUserspaceLoaderOptions<'_>) -> String {
    match load_aya_userspace_object(options) {
        Ok(_) => panic!("expected object loading to fail"),
        Err(error) => error,
    }
}

fn check_entry(map: &MapData, key: &[u8], expected: &[u8]) {
    let mut actual = vec![0; expected.len()];
    lookup_map_elem_bytes(map.fd().as_fd().as_raw_fd(), key, &mut actual).unwrap();
    assert_eq!(
        actual, expected,
        "failed candidate changed existing map data"
    );
}

#[test]
fn aya_upgrade_incompatible_pins_preserve_data_and_remove_new_pins_is_env_gated() {
    let Some(object) = object() else { return };
    let catalog = map_catalog()
        .iter()
        .find(|spec| spec.name == "cookie_pid_map")
        .unwrap();
    let base = CreateBpfMapSpec {
        name: catalog.name,
        map_type: bpf_map_type::BPF_MAP_TYPE_LRU_HASH as u32,
        key_size: catalog.key_size,
        value_size: catalog.value_size,
        max_entries: catalog.max_entries,
        map_flags: catalog.flags,
        inner_map_fd: 0,
    };
    for property in [
        "map_type",
        "key_size",
        "value_size",
        "max_entries",
        "map_flags",
    ] {
        let pins = Pins::new(property);
        let mut spec = base;
        match property {
            "map_type" => spec.map_type = bpf_map_type::BPF_MAP_TYPE_HASH as u32,
            "key_size" => spec.key_size += 4,
            "value_size" => spec.value_size += 4,
            "max_entries" => spec.max_entries /= 2,
            "map_flags" => spec.map_flags |= BPF_F_RDONLY_PROG,
            _ => unreachable!(),
        }
        let fd = create_bpf_map(spec).expect("create a valid incompatible map");
        let key = vec![0x19; spec.key_size as usize];
        let value = vec![0xa5; spec.value_size as usize];
        update_map_elem_bytes(fd.as_raw_fd(), &key, &value).unwrap();
        let path = pins.0.join(catalog.name);
        pin_obj(fd.as_raw_fd(), &path).unwrap();
        let map = MapData::from_pin(&path).unwrap();
        let id = map.info().unwrap().id();
        let before = pins.names();
        for attempt in 0..3 {
            let error = load_error(options(&object, &pins));
            assert!(error.contains("IncompatiblePinnedMap"), "{error}");
            for detail in [catalog.name, property, "expected", "actual"] {
                assert!(error.contains(detail), "{error}");
            }
            assert_eq!(pins.names(), before, "new pins leaked after {property}");
            assert_eq!(MapData::from_pin(&path).unwrap().info().unwrap().id(), id);
            check_entry(&map, &key, &value);
            eprintln!("verified incompatible {property}, attempt {attempt}");
        }
    }
}

#[test]
fn aya_upgrade_profile_pin_reuse_survives_repeated_failed_candidates_is_env_gated() {
    let Some(object) = object() else { return };
    let profiles = [
        RuntimeMapProfile::LowMemory,
        RuntimeMapProfile::Balanced,
        RuntimeMapProfile::HighPerformance,
    ];
    for profile in profiles {
        let pins = Pins::new(profile.name());
        let mut original = options(&object, &pins);
        original.max_entries_overrides = profile.max_entries_overrides();
        let active = load_aya_userspace_object(original.clone()).unwrap();
        let path = pins.0.join("cookie_pid_map");
        let map = MapData::from_pin(&path).unwrap();
        let info = map.info().unwrap();
        let key = vec![0x29; info.key_size() as usize];
        let value = vec![0x5a; info.value_size() as usize];
        update_map_elem_bytes(map.fd().as_fd().as_raw_fd(), &key, &value).unwrap();
        let before = pins.names();
        for candidate in profiles.into_iter().filter(|other| *other != profile) {
            for _ in 0..3 {
                let mut changed = original.clone();
                changed.max_entries_overrides = candidate.max_entries_overrides();
                let error = load_error(changed);
                assert!(error.contains("IncompatiblePinnedMap"), "{error}");
                assert!(error.contains("max_entries"), "{error}");
                assert_eq!(pins.names(), before);
                assert_eq!(
                    MapData::from_pin(&path).unwrap().info().unwrap().id(),
                    info.id()
                );
                check_entry(&map, &key, &value);
            }
        }
        let reloaded = load_aya_userspace_object(original).unwrap();
        assert_eq!(
            MapData::from_pin(&path).unwrap().info().unwrap().id(),
            info.id()
        );
        check_entry(&map, &key, &value);
        assert_eq!(pins.names(), before);
        drop(reloaded);
        drop(active);
        eprintln!(
            "verified profile reuse and candidate recovery: {}",
            profile.name()
        );
    }
}

#[test]
fn aya_upgrade_all_l2_tc_roles_pass_the_kernel_verifier_is_env_gated() {
    let Some(object) = object() else { return };
    let pins = Pins::new("all-tc-roles");
    let mut options = options(&object, &pins);
    options.param = Some(crate::build_dae_param(crate::DaeParamInput {
        tproxy_port: 12345,
        control_plane_pid: std::process::id(),
        dae0_ifindex: 1,
        dae_netns_id: 49,
        dae0peer_mac: [1, 2, 3, 4, 5, 6],
        has_bpf_get_current_task: false,
        task_struct_mm_offset: 0,
        mm_struct_arg_start_offset: 0,
    }));
    options.max_entries_overrides = RuntimeMapProfile::Balanced.max_entries_overrides();
    let mut loaded = load_aya_userspace_object(options).unwrap();
    let mut names = BTreeSet::new();
    {
        let matrix = crate::dae_tc_attach_matrix(crate::DaeTcAttachMatrixInput {
            object: object.display().to_string(),
            lan_iface: "unused-lan".into(),
            wan_iface: "unused-wan".into(),
            host_iface: "unused-host".into(),
            peer_iface: "unused-peer".into(),
            peer_netns: "unused-netns".into(),
            section_prefix: crate::TcAttachSectionPrefix::Classifier,
            link_layer: crate::TcAttachLayer::L2,
            flip: 0,
            is_reload: false,
        });
        for line in matrix {
            let name = line.native.program_name;
            if names.insert(name.clone()) {
                let classifier: &mut SchedClassifier =
                    loaded.ebpf.program_mut(&name).unwrap().try_into().unwrap();
                classifier
                    .load()
                    .unwrap_or_else(|error| panic!("kernel verifier rejected {name}: {error:?}"));
                eprintln!("verified TC program: {name}");
            }
        }
    }
    assert_eq!(names.len(), 6, "cover every LAN/WAN and daemon TC role");
}

#[test]
fn aya_upgrade_required_btf_failure_rolls_back_precreated_pins_is_env_gated() {
    if std::env::var_os("DAE_RUN_AYA_INVALID_BTF_SMOKE").is_none() {
        return;
    }
    // The harness masks target BTF only in a private mount namespace.
    let object = object().expect("BTF smoke requires a real native object");
    let pins = Pins::new("target-btf");
    let mut required = options(&object, &pins);
    required.target_btf_required = true;
    required.prepin_lpm_array_map = true;
    let error = load_error(required.clone());
    assert!(error.contains("target BTF required"), "{error}");
    assert!(
        error.contains("missing_target_btf")
            || error.contains("target_btf_mismatch_or_parse_failed"),
        "{error}"
    );
    assert!(
        pins.names().is_empty(),
        "BTF failure leaked the precreated LPM pin"
    );
    required.target_btf_required = false;
    let loaded = load_aya_userspace_object(required).expect("default object needs no forced BTF");
    drop(loaded);
}

#[test]
fn interface_lookup_rejects_bad_names_before_tc_attachment() {
    assert!(
        tc_attach::current_netns_interface_index("bad\0name")
            .unwrap_err()
            .contains("interior NUL")
    );
    assert!(tc_attach::current_netns_interface_index("dae-no-iface").is_err());
}
