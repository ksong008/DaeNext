use super::*;
#[allow(clippy::too_many_arguments)]
pub fn aya_userspace_load_report(
    object: &Path,
    param_global_set: bool,
    map_pin_path: Option<&Path>,
    allow_unsupported_maps: bool,
    allowed_unsupported_map_names: &[&str],
    mut loaded_map_names: Vec<String>,
    mut loaded_map_specs: Vec<AyaLoadedMapSpec>,
    mut loaded_program_names: Vec<String>,
    max_entries_overrides: &[(&str, u32)],
    map_in_map_pins: Vec<AyaMapInMapPinReport>,
) -> AyaUserspaceLoadReport {
    loaded_map_names.sort();
    loaded_map_specs.sort_by(|a, b| a.name.cmp(&b.name));
    loaded_program_names.sort();
    let missing_catalog_maps = map_catalog()
        .iter()
        .filter(|spec| !loaded_map_names.iter().any(|name| name == spec.name))
        .map(|spec| spec.name)
        .collect::<Vec<_>>();
    let map_spec_mismatches = loaded_map_spec_mismatches(&loaded_map_specs);
    let unsupported_map_names = loaded_map_specs
        .iter()
        .filter(|spec| spec.unsupported)
        .map(|spec| spec.name.clone())
        .collect::<Vec<_>>();
    let unexpected_unsupported_map_names = unsupported_map_names
        .iter()
        .filter(|name| {
            !allowed_unsupported_map_names
                .iter()
                .any(|allowed| allowed == &name.as_str())
        })
        .cloned()
        .collect::<Vec<_>>();
    let pinned_reuse_maps_present = pinned_reuse_maps()
        .iter()
        .filter(|name| loaded_map_names.iter().any(|loaded| loaded == **name))
        .map(|name| (*name).to_owned())
        .collect::<Vec<_>>();
    AyaUserspaceLoadReport {
        object: object.to_owned(),
        param_global_set,
        map_pin_path: map_pin_path.map(Path::to_owned),
        allow_unsupported_maps,
        allowed_unsupported_map_names: allowed_unsupported_map_names
            .iter()
            .map(|name| (*name).to_owned())
            .collect(),
        max_entries_overrides: max_entries_overrides
            .iter()
            .map(|(name, max_entries)| ((*name).to_owned(), *max_entries))
            .collect(),
        map_in_map_pins,
        listen_socket_map_present: loaded_map_names
            .iter()
            .any(|name| RuntimeMapRole::for_map_name(name) == RuntimeMapRole::SocketHandoff),
        loaded_map_names,
        loaded_map_specs,
        loaded_program_names,
        missing_catalog_maps,
        map_spec_mismatches,
        unsupported_map_names,
        unexpected_unsupported_map_names,
        pinned_reuse_maps_present,
        loader_backend: LoaderBackend::AyaUserspace,
        default_attach_backend: AttachBackend::Auto,
        external_ebpf_object_required: false,
        command_attach_backend_required: false,
    }
}

fn loaded_map_spec_mismatches(loaded: &[AyaLoadedMapSpec]) -> Vec<AyaMapSpecMismatch> {
    let mut mismatches = Vec::new();
    for expected in map_catalog() {
        let Some(actual) = loaded.iter().find(|actual| actual.name == expected.name) else {
            continue;
        };
        push_mismatch(
            &mut mismatches,
            expected.name,
            "type",
            expected.map_type,
            &actual.map_type,
        );
        push_mismatch(
            &mut mismatches,
            expected.name,
            "keySize",
            expected.key_size,
            actual.key_size,
        );
        push_mismatch(
            &mut mismatches,
            expected.name,
            "valueSize",
            expected.value_size,
            actual.value_size,
        );
        push_mismatch(
            &mut mismatches,
            expected.name,
            "maxEntries",
            expected.max_entries,
            actual.max_entries,
        );
        push_mismatch(
            &mut mismatches,
            expected.name,
            "flags",
            expected.flags,
            actual.flags,
        );
    }
    mismatches
}

fn push_mismatch(
    mismatches: &mut Vec<AyaMapSpecMismatch>,
    name: &str,
    field: &'static str,
    expected: impl ToString,
    actual: impl ToString,
) {
    let expected = expected.to_string();
    let actual = actual.to_string();
    if expected != actual {
        mismatches.push(AyaMapSpecMismatch {
            name: name.to_owned(),
            field,
            expected,
            actual,
        });
    }
}
