pub fn aya_userspace_load_report(
    object: &Path,
    param_global_set: bool,
    map_pin_path: Option<&Path>,
    allow_unsupported_maps: bool,
    mut loaded_map_names: Vec<String>,
    mut loaded_program_names: Vec<String>,
    max_entries_overrides: &[(&str, u32)],
    map_in_map_pins: Vec<AyaMapInMapPinReport>,
) -> AyaUserspaceLoadReport {
    loaded_map_names.sort();
    loaded_program_names.sort();
    let missing_catalog_maps = map_catalog()
        .iter()
        .filter(|spec| !loaded_map_names.iter().any(|name| name == spec.name))
        .map(|spec| spec.name)
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
        max_entries_overrides: max_entries_overrides
            .iter()
            .map(|(name, max_entries)| ((*name).to_owned(), *max_entries))
            .collect(),
        map_in_map_pins,
        listen_socket_map_present: loaded_map_names
            .iter()
            .any(|name| RuntimeMapRole::for_map_name(name) == RuntimeMapRole::SocketHandoff),
        loaded_map_names,
        loaded_program_names,
        missing_catalog_maps,
        pinned_reuse_maps_present,
        loader_backend: LoaderBackend::AyaUserspace,
        default_attach_backend: AttachBackend::TcCommandFallback,
        c_ebpf_object_fallback_required: true,
        command_fallback_required: true,
    }
}
