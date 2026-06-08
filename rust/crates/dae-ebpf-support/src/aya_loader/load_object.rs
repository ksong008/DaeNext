pub fn load_aya_userspace_object(
    options: AyaUserspaceLoaderOptions<'_>,
) -> Result<AyaUserspaceLoadedObject, String> {
    let map_in_map_pins = if options.prepin_lpm_array_map {
        let map_pin_path = options
            .map_pin_path
            .ok_or_else(|| "aya userspace lpm_array_map prepin requires map_pin_path".to_owned())?;
        vec![
            prepin_lpm_array_map(map_pin_path)
                .map_err(|err| format!("aya userspace lpm_array_map prepin failed: {err}"))?,
        ]
    } else {
        Vec::new()
    };

    let mut loader = aya::EbpfLoader::new();
    if options.allow_unsupported_maps {
        loader.allow_unsupported_maps();
    }
    if let Some(map_pin_path) = options.map_pin_path {
        loader.map_pin_path(map_pin_path);
    }
    if let Some(param) = options.param.as_ref() {
        loader.set_global("PARAM", param, true);
    }
    for (map_name, max_entries) in options.max_entries_overrides {
        loader.set_max_entries(map_name, *max_entries);
    }

    let ebpf = loader
        .load_file(options.object)
        .map_err(|err| format!("aya userspace object load failed: {err:?}"))?;
    let loaded_map_names = ebpf
        .maps()
        .map(|(name, _)| name.to_owned())
        .collect::<Vec<_>>();
    let loaded_program_names = ebpf
        .programs()
        .map(|(name, _)| name.to_owned())
        .collect::<Vec<_>>();
    let report = aya_userspace_load_report(
        options.object,
        options.param.is_some(),
        options.map_pin_path,
        options.allow_unsupported_maps,
        loaded_map_names,
        loaded_program_names,
        options.max_entries_overrides,
        map_in_map_pins,
    );
    Ok(AyaUserspaceLoadedObject { ebpf, report })
}

pub fn pin_aya_loaded_object_for_go_adoption(
    loaded: &mut AyaUserspaceLoadedObject,
    adoption_pin_root: &Path,
) -> Result<AyaGoAdoptionPinReport, String> {
    let map_pin_root = adoption_pin_root.join("maps");
    let program_pin_root = adoption_pin_root.join("programs");
    fs::create_dir_all(&map_pin_root)
        .map_err(|err| format!("create Go adoption map pin root failed: {err}"))?;
    fs::create_dir_all(&program_pin_root)
        .map_err(|err| format!("create Go adoption program pin root failed: {err}"))?;

    let expected_maps = map_catalog()
        .iter()
        .filter(|spec| spec.role() != RuntimeMapRole::ParamRodata)
        .map(|spec| spec.name)
        .collect::<BTreeSet<_>>();
    let mut maps = Vec::new();
    for (name, map) in loaded.ebpf.maps() {
        if !expected_maps.contains(name) {
            continue;
        }
        let path = map_pin_root.join(name);
        remove_existing_pin(&path)?;
        map.pin(&path)
            .map_err(|err| format!("pin map {name} for Go adoption failed: {err:?}"))?;
        maps.push(AyaPinnedObject {
            name: name.to_owned(),
            path,
        });
    }
    let pinned_map_names = maps
        .iter()
        .map(|pin| pin.name.as_str())
        .collect::<BTreeSet<_>>();
    let missing_maps = expected_maps
        .iter()
        .filter(|name| !pinned_map_names.contains(**name))
        .copied()
        .collect::<Vec<_>>();
    if !missing_maps.is_empty() {
        return Err(format!(
            "Go adoption missing loaded catalog maps: {}",
            missing_maps.join(",")
        ));
    }

    let mut programs = Vec::new();
    for (name, program) in loaded.ebpf.programs_mut() {
        let name = name.to_owned();
        ensure_program_loaded_for_go_adoption(&name, program)?;
        let path = program_pin_root.join(&name);
        remove_existing_pin(&path)?;
        program
            .pin(&path)
            .map_err(|err| format!("pin program {name} for Go adoption failed: {err:?}"))?;
        programs.push(AyaPinnedObject { name, path });
    }

    maps.sort_by(|a, b| a.name.cmp(&b.name));
    programs.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(AyaGoAdoptionPinReport {
        adoption_pin_root: adoption_pin_root.to_owned(),
        map_pin_root,
        program_pin_root,
        maps,
        programs,
    })
}
