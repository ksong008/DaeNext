use super::*;
unsafe fn slice_from_raw<'a, T>(ptr: *const T, len: usize) -> Result<&'a [T], String> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err("nonnull pointer required when length is nonzero".to_owned());
    }
    Ok(unsafe { slice::from_raw_parts(ptr, len) })
}

unsafe fn str_from_raw<'a>(ptr: *const u8, len: usize, name: &str) -> Result<&'a str, String> {
    let bytes = unsafe { slice_from_raw(ptr, len)? };
    std::str::from_utf8(bytes).map_err(|err| format!("{name} is not UTF-8: {err}"))
}

unsafe fn routing_plan_from_ffi(
    routing_entries: *const FfiRoutingMapEntry,
    routing_entries_len: usize,
    lpm_maps: *const FfiLpmMapBuildSpec,
    lpm_maps_len: usize,
) -> Result<RoutingNativeBuildPlan, String> {
    let routing_entries = unsafe { slice_from_raw(routing_entries, routing_entries_len)? };
    let lpm_maps = unsafe { slice_from_raw(lpm_maps, lpm_maps_len)? };
    let routing_entries = routing_entries
        .iter()
        .map(|entry| RoutingMapEntry {
            index: entry.index,
            value: entry.value,
        })
        .collect::<Vec<_>>();
    let lpm_maps = lpm_maps
        .iter()
        .map(|spec| {
            let entries = unsafe { slice_from_raw(spec.entries, spec.entries_len)? };
            let entries = entries
                .iter()
                .map(|entry| LpmMapEntry {
                    key: entry.key,
                    value: entry.value,
                })
                .collect::<Vec<_>>();
            Ok(LpmMapBuildSpec {
                index: spec.index,
                flags: spec.flags,
                max_entries: spec.max_entries,
                key_size: spec.key_size,
                value_size: spec.value_size,
                entries,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(RoutingNativeBuildPlan {
        routing_entries,
        lpm_maps,
    })
}
