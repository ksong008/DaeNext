use super::*;
pub fn load_aya_userspace_object(
    options: AyaUserspaceLoaderOptions<'_>,
) -> Result<AyaUserspaceLoadedObject, String> {
    load_aya_userspace_object_from_source(
        AyaUserspaceLoadSource::File(options.object),
        LoadCommonOptions {
            param: options.param,
            map_pin_path: options.map_pin_path,
            allow_unsupported_maps: options.allow_unsupported_maps,
            allowed_unsupported_map_names: options.allowed_unsupported_map_names,
            max_entries_overrides: options.max_entries_overrides,
            prepin_lpm_array_map: options.prepin_lpm_array_map,
        },
    )
}

pub fn load_aya_userspace_object_bytes(
    options: AyaUserspaceBytesLoaderOptions<'_>,
) -> Result<AyaUserspaceLoadedObject, String> {
    load_aya_userspace_object_from_source(
        AyaUserspaceLoadSource::Bytes {
            label: options.object_label,
            data: options.object_data,
        },
        LoadCommonOptions {
            param: options.param,
            map_pin_path: options.map_pin_path,
            allow_unsupported_maps: options.allow_unsupported_maps,
            allowed_unsupported_map_names: options.allowed_unsupported_map_names,
            max_entries_overrides: options.max_entries_overrides,
            prepin_lpm_array_map: options.prepin_lpm_array_map,
        },
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AyaUserspaceLoadSource<'a> {
    File(&'a Path),
    Bytes { label: &'a str, data: &'a [u8] },
}

impl AyaUserspaceLoadSource<'_> {
    fn report_identity(self) -> PathBuf {
        match self {
            Self::File(path) => path.to_owned(),
            Self::Bytes { label, .. } => PathBuf::from(label),
        }
    }
}

struct LoadCommonOptions<'a> {
    param: Option<BpfDaeParam>,
    map_pin_path: Option<&'a Path>,
    allow_unsupported_maps: bool,
    allowed_unsupported_map_names: &'a [&'a str],
    max_entries_overrides: &'a [(&'a str, u32)],
    prepin_lpm_array_map: bool,
}

fn load_aya_userspace_object_from_source(
    source: AyaUserspaceLoadSource<'_>,
    options: LoadCommonOptions<'_>,
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

    let ebpf = match source {
        AyaUserspaceLoadSource::File(path) => loader.load_file(path),
        AyaUserspaceLoadSource::Bytes { data, .. } => load_aligned_bytes(&mut loader, data),
    }
    .map_err(|err| format!("aya userspace object load failed: {err:?}"))?;
    let loaded_map_names = ebpf
        .maps()
        .map(|(name, _)| name.to_owned())
        .collect::<Vec<_>>();
    let loaded_map_specs = loaded_map_specs(&ebpf)?;
    let loaded_program_names = ebpf
        .programs()
        .map(|(name, _)| name.to_owned())
        .collect::<Vec<_>>();
    let object_identity = source.report_identity();
    let report = aya_userspace_load_report(
        &object_identity,
        options.param.is_some(),
        options.map_pin_path,
        options.allow_unsupported_maps,
        options.allowed_unsupported_map_names,
        loaded_map_names,
        loaded_map_specs,
        loaded_program_names,
        options.max_entries_overrides,
        map_in_map_pins,
    );
    if !report.unexpected_unsupported_map_names.is_empty() {
        return Err(format!(
            "aya userspace object contains unexpected unsupported maps: {}",
            report.unexpected_unsupported_map_names.join(",")
        ));
    }
    if !report.map_spec_mismatches.is_empty() {
        let summary = report
            .map_spec_mismatches
            .iter()
            .map(|mismatch| {
                format!(
                    "{}.{} expected {} got {}",
                    mismatch.name, mismatch.field, mismatch.expected, mismatch.actual
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        return Err(format!("aya userspace object map spec mismatch: {summary}"));
    }
    Ok(AyaUserspaceLoadedObject { ebpf, report })
}

fn load_aligned_bytes(
    loader: &mut aya::EbpfLoader,
    data: &[u8],
) -> Result<aya::Ebpf, aya::EbpfError> {
    let words = data.len().div_ceil(std::mem::size_of::<u64>());
    let mut aligned = vec![0_u64; words];
    // SAFETY: the backing allocation is alive for this call and has at least data.len() bytes.
    let aligned_bytes =
        unsafe { std::slice::from_raw_parts_mut(aligned.as_mut_ptr().cast::<u8>(), data.len()) };
    aligned_bytes.copy_from_slice(data);
    loader.load(aligned_bytes)
}

fn loaded_map_specs(ebpf: &aya::Ebpf) -> Result<Vec<AyaLoadedMapSpec>, String> {
    ebpf.maps()
        .map(|(name, map)| loaded_map_spec(name, map))
        .collect()
}

fn loaded_map_spec(name: &str, map: &Map) -> Result<AyaLoadedMapSpec, String> {
    let (data, unsupported) = map_data_and_support(map);
    let info = data
        .info()
        .map_err(|err| format!("inspect loaded aya map {name}: {err:?}"))?;
    let map_type = info
        .map_type()
        .map(map_type_name)
        .unwrap_or_else(|_| "Unknown".to_owned());
    Ok(AyaLoadedMapSpec {
        name: name.to_owned(),
        map_type,
        key_size: info.key_size(),
        value_size: info.value_size(),
        max_entries: info.max_entries(),
        flags: info.map_flags(),
        unsupported,
    })
}

fn map_data_and_support(map: &Map) -> (&MapData, bool) {
    match map {
        Map::Array(data)
        | Map::BloomFilter(data)
        | Map::CpuMap(data)
        | Map::DevMap(data)
        | Map::DevMapHash(data)
        | Map::HashMap(data)
        | Map::LpmTrie(data)
        | Map::LruHashMap(data)
        | Map::PerCpuArray(data)
        | Map::PerCpuHashMap(data)
        | Map::PerCpuLruHashMap(data)
        | Map::PerfEventArray(data)
        | Map::ProgramArray(data)
        | Map::Queue(data)
        | Map::RingBuf(data)
        | Map::SockHash(data)
        | Map::SockMap(data)
        | Map::Stack(data)
        | Map::StackTraceMap(data)
        | Map::XskMap(data) => (data, false),
        Map::Unsupported(data) => (data, true),
    }
}

fn map_type_name(map_type: MapType) -> String {
    match map_type {
        MapType::Hash => "Hash",
        MapType::Array => "Array",
        MapType::LruHash => "LRUHash",
        MapType::LpmTrie => "LPMTrie",
        MapType::ArrayOfMaps => "ArrayOfMaps",
        MapType::SockMap => "SockMap",
        MapType::SockHash => "SockHash",
        other => return format!("{other:?}"),
    }
    .to_owned()
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
