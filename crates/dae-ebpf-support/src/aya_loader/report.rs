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
    target_btf: AyaTargetBtfReport,
) -> AyaUserspaceLoadReport {
    loaded_map_names.sort();
    loaded_map_specs.sort_by(|a, b| a.name.cmp(&b.name));
    loaded_program_names.sort();
    let missing_catalog_maps = map_catalog()
        .iter()
        .filter(|spec| !loaded_map_names.iter().any(|name| name == spec.name))
        .map(|spec| spec.name)
        .collect::<Vec<_>>();
    let map_spec_mismatches = loaded_map_spec_mismatches(&loaded_map_specs, max_entries_overrides);
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
        target_btf,
    }
}

fn loaded_map_spec_mismatches(
    loaded: &[AyaLoadedMapSpec],
    max_entries_overrides: &[(&str, u32)],
) -> Vec<AyaMapSpecMismatch> {
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
        let expected_max_entries = max_entries_overrides
            .iter()
            .find_map(|(name, max_entries)| (*name == expected.name).then_some(*max_entries))
            .unwrap_or(expected.max_entries);
        push_mismatch(
            &mut mismatches,
            expected.name,
            "maxEntries",
            expected_max_entries,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RuntimeMapProfile;

    #[test]
    fn configured_capacity_overrides_are_part_of_the_loaded_map_contract() {
        let overrides = RuntimeMapProfile::Balanced.max_entries_overrides();
        let loaded = map_catalog()
            .iter()
            .map(|spec| AyaLoadedMapSpec {
                name: spec.name.to_owned(),
                map_type: spec.map_type.to_owned(),
                key_size: spec.key_size,
                value_size: spec.value_size,
                max_entries: overrides
                    .iter()
                    .find_map(|(name, capacity)| (*name == spec.name).then_some(*capacity))
                    .unwrap_or(spec.max_entries),
                flags: spec.flags,
                unsupported: false,
            })
            .collect::<Vec<_>>();

        assert!(loaded_map_spec_mismatches(&loaded, overrides).is_empty());
        let mismatches = loaded_map_spec_mismatches(&loaded, &[]);
        assert!(
            mismatches
                .iter()
                .any(|mismatch| mismatch.field == "maxEntries")
        );
    }
}
