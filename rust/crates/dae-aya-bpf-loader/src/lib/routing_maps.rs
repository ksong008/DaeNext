use super::*;
pub fn run_routing_map_apply_json(input: &str) -> LoaderOutput {
    let request = match parse_routing_map_apply_request(input) {
        Ok(request) => request,
        Err(err) => return LoaderOutput::usage(err),
    };
    match dae_ebpf_support::apply_routing_maps_with_lpm_build_by_id(
        request.routing_map_id,
        request.lpm_array_map_id,
        &request.routing_entries,
        &request.lpm_entries,
        &request.lpm_maps,
    ) {
        Ok(report) => LoaderOutput::ok(format!(
            "{}\n",
            json!({
                "status": "pass",
                "loader": "rust",
                "scope": "routing-map-apply",
                "routing_map_id": request.routing_map_id,
                "lpm_array_map_id": request.lpm_array_map_id,
                "routing_entries_updated": report.routing_entries_updated,
                "lpm_entries_updated": report.lpm_entries_updated,
                "lpm_maps_created": report.lpm_maps_created,
            })
        )),
        Err(err) => LoaderOutput::error(format!("routing map apply failed: {err}")),
    }
}

pub fn run_domain_routing_map_apply_json(input: &str) -> LoaderOutput {
    let request = match parse_domain_routing_map_apply_request(input) {
        Ok(request) => request,
        Err(err) => return LoaderOutput::usage(err),
    };
    match dae_ebpf_support::apply_domain_routing_map_by_id(
        request.map_id,
        &request.updates,
        &request.deletes,
    ) {
        Ok(report) => LoaderOutput::ok(format!(
            "{}\n",
            json!({
                "status": "pass",
                "loader": "rust",
                "scope": "domain-routing-map-apply",
                "map_id": request.map_id,
                "entries_updated": report.entries_updated,
                "entries_deleted": report.entries_deleted,
            })
        )),
        Err(err) => LoaderOutput::error(format!("domain routing map apply failed: {err}")),
    }
}

pub fn run_domain_routing_map_serve<R, W>(reader: R, mut writer: W) -> io::Result<()>
where
    R: BufRead,
    W: Write,
{
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let response = handle_domain_routing_map_serve_line(&line);
        writer.write_all(response.as_bytes())?;
        writer.write_all(b"\n")?;
        writer.flush()?;
    }
    Ok(())
}

pub fn run_domain_routing_map_owner_serve<R, W>(reader: R, mut writer: W) -> io::Result<()>
where
    R: BufRead,
    W: Write,
{
    let mut owner = dae_control::DomainRoutingOwner::default();
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let response = handle_domain_routing_map_owner_serve_line(&mut owner, &line);
        writer.write_all(response.as_bytes())?;
        writer.write_all(b"\n")?;
        writer.flush()?;
    }
    Ok(())
}

pub(super) fn handle_domain_routing_map_serve_line(line: &str) -> String {
    let output = run_domain_routing_map_apply_json(line);
    if output.exit_code == 0 {
        return output.stdout.trim_end().to_owned();
    }
    json!({
        "status": "error",
        "loader": "rust",
        "scope": "domain-routing-map-apply",
        "error": output.stderr.trim(),
    })
    .to_string()
}

pub(super) fn handle_domain_routing_map_owner_serve_line(
    owner: &mut dae_control::DomainRoutingOwner,
    line: &str,
) -> String {
    match parse_domain_routing_map_owner_request(line)
        .and_then(|request| apply_domain_routing_map_owner_request(owner, request))
    {
        Ok(response) => response.to_string(),
        Err(err) => json!({
            "status": "error",
            "loader": "rust",
            "scope": "domain-routing-map-owner",
            "owner": "dae-control",
            "error": err,
        })
        .to_string(),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RoutingMapApplyRequest {
    pub(super) routing_map_id: u32,
    pub(super) lpm_array_map_id: u32,
    pub(super) routing_entries: Vec<dae_ebpf_support::RoutingMapEntry>,
    pub(super) lpm_entries: Vec<dae_ebpf_support::LpmArrayMapEntry>,
    pub(super) lpm_maps: Vec<dae_ebpf_support::LpmMapBuildSpec>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct DomainRoutingMapApplyRequest {
    pub(super) map_id: u32,
    pub(super) updates: Vec<dae_ebpf_support::DomainRoutingMapEntry>,
    pub(super) deletes: Vec<[u32; 4]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum DomainRoutingOwnerRequest {
    SyncOwner {
        map_id: u32,
        owner_key: String,
        bitmap: [u32; 32],
        ips: Vec<[u32; 4]>,
    },
    PrepareReload {
        map_id: u32,
        existing_keys: Vec<[u32; 4]>,
    },
}

pub(super) fn parse_routing_map_apply_request(
    input: &str,
) -> Result<RoutingMapApplyRequest, String> {
    let value: Value =
        serde_json::from_str(input).map_err(|err| format!("bad routing-map request: {err}"))?;
    let object = value
        .as_object()
        .ok_or_else(|| "bad routing-map request: expected JSON object".to_owned())?;
    let routing_entries = json_array(object.get("routing_entries"), "routing_entries")?
        .iter()
        .map(parse_routing_map_entry)
        .collect::<Result<Vec<_>, _>>()?;
    let lpm_entries = json_array(object.get("lpm_entries"), "lpm_entries")?
        .iter()
        .map(parse_lpm_array_map_entry)
        .collect::<Result<Vec<_>, _>>()?;
    let lpm_maps = optional_json_array(object.get("lpm_maps"))?
        .iter()
        .map(parse_lpm_map_build_spec)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(RoutingMapApplyRequest {
        routing_map_id: json_u32(object.get("routing_map_id"), "routing_map_id")?,
        lpm_array_map_id: json_u32(object.get("lpm_array_map_id"), "lpm_array_map_id")?,
        routing_entries,
        lpm_entries,
        lpm_maps,
    })
}

pub(super) fn parse_domain_routing_map_apply_request(
    input: &str,
) -> Result<DomainRoutingMapApplyRequest, String> {
    let value: Value = serde_json::from_str(input)
        .map_err(|err| format!("bad domain-routing-map request: {err}"))?;
    let object = value
        .as_object()
        .ok_or_else(|| "bad domain-routing-map request: expected JSON object".to_owned())?;
    let updates = json_array(object.get("updates"), "updates")?
        .iter()
        .map(parse_domain_routing_map_entry)
        .collect::<Result<Vec<_>, _>>()?;
    let deletes = json_array(object.get("deletes"), "deletes")?
        .iter()
        .map(|value| json_u32_array_4(Some(value), "deletes[]"))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(DomainRoutingMapApplyRequest {
        map_id: json_u32(object.get("map_id"), "map_id")?,
        updates,
        deletes,
    })
}

pub(super) fn parse_domain_routing_map_owner_request(
    input: &str,
) -> Result<DomainRoutingOwnerRequest, String> {
    let value: Value = serde_json::from_str(input)
        .map_err(|err| format!("bad domain-routing-map owner request: {err}"))?;
    let object = value
        .as_object()
        .ok_or_else(|| "bad domain-routing-map owner request: expected JSON object".to_owned())?;
    let op = json_string(object.get("op"), "op")?;
    let map_id = json_u32(object.get("map_id"), "map_id")?;
    match op.as_str() {
        "sync_owner" => {
            let owner_key = json_string(object.get("owner_key"), "owner_key")?;
            let ips = optional_json_array(object.get("ips"))?
                .iter()
                .map(|value| json_u32_array_4(Some(value), "ips[]"))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(DomainRoutingOwnerRequest::SyncOwner {
                map_id,
                owner_key,
                bitmap: json_u32_array_32(object.get("bitmap"), "bitmap")?,
                ips,
            })
        }
        "prepare_reload" => {
            let existing_keys = optional_json_array(object.get("existing_keys"))?
                .iter()
                .map(|value| json_u32_array_4(Some(value), "existing_keys[]"))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(DomainRoutingOwnerRequest::PrepareReload {
                map_id,
                existing_keys,
            })
        }
        _ => Err(format!(
            "unsupported domain-routing-map owner op: {op}; want sync_owner or prepare_reload"
        )),
    }
}

pub(super) fn apply_domain_routing_map_owner_request(
    owner: &mut dae_control::DomainRoutingOwner,
    request: DomainRoutingOwnerRequest,
) -> Result<Value, String> {
    match request {
        DomainRoutingOwnerRequest::SyncOwner {
            map_id,
            owner_key,
            bitmap,
            ips,
        } => {
            let report = owner
                .apply_owner_snapshot_by_id(
                    map_id,
                    &owner_key,
                    dae_control::DomainRoutingOwnerSnapshot::from_keys(&bitmap, &ips),
                )
                .map_err(|err| format!("domain routing owner apply failed: {err}"))?;
            Ok(json!({
                "status": "pass",
                "loader": "rust",
                "scope": "domain-routing-map-owner",
                "owner": "dae-control",
                "op": "sync_owner",
                "map_id": report.map_id,
                "map_id_changed": report.map_id_changed,
                "skipped": report.skipped,
                "entries_updated": report.entries_updated,
                "entries_deleted": report.entries_deleted,
                "owner_count": report.owner_count,
                "ip_count": report.ip_count,
            }))
        }
        DomainRoutingOwnerRequest::PrepareReload {
            map_id,
            existing_keys,
        } => {
            let report = owner
                .prepare_reload_map_by_id(map_id, existing_keys)
                .map_err(|err| format!("domain routing owner prepare reload failed: {err}"))?;
            Ok(json!({
                "status": "pass",
                "loader": "rust",
                "scope": "domain-routing-map-owner",
                "owner": "dae-control",
                "op": "prepare_reload",
                "map_id": report.map_id,
                "map_id_changed": report.map_id_changed,
                "entries_updated": 0,
                "entries_deleted": report.deletes.len(),
                "owner_count": report.owner_count,
                "ip_count": report.ip_count,
            }))
        }
    }
}

pub(super) fn parse_routing_map_entry(
    value: &Value,
) -> Result<dae_ebpf_support::RoutingMapEntry, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "bad routing entry: expected JSON object".to_owned())?;
    Ok(dae_ebpf_support::RoutingMapEntry {
        index: json_u32(object.get("index"), "routing_entries[].index")?,
        value: parse_bpf_match_set(
            object
                .get("value")
                .ok_or_else(|| "missing routing_entries[].value".to_owned())?,
        )?,
    })
}

pub(super) fn parse_lpm_array_map_entry(
    value: &Value,
) -> Result<dae_ebpf_support::LpmArrayMapEntry, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "bad lpm entry: expected JSON object".to_owned())?;
    Ok(dae_ebpf_support::LpmArrayMapEntry {
        index: json_u32(object.get("index"), "lpm_entries[].index")?,
        map_id: json_u32(object.get("map_id"), "lpm_entries[].map_id")?,
    })
}

pub(super) fn parse_lpm_map_build_spec(
    value: &Value,
) -> Result<dae_ebpf_support::LpmMapBuildSpec, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "bad lpm map build spec: expected JSON object".to_owned())?;
    let entries = json_array(object.get("entries"), "lpm_maps[].entries")?
        .iter()
        .map(parse_lpm_map_entry)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(dae_ebpf_support::LpmMapBuildSpec {
        index: json_u32(object.get("index"), "lpm_maps[].index")?,
        flags: json_u32(object.get("flags"), "lpm_maps[].flags")?,
        max_entries: json_u32(object.get("max_entries"), "lpm_maps[].max_entries")?,
        key_size: json_u32(object.get("key_size"), "lpm_maps[].key_size")?,
        value_size: json_u32(object.get("value_size"), "lpm_maps[].value_size")?,
        entries,
    })
}

pub(super) fn parse_lpm_map_entry(value: &Value) -> Result<dae_ebpf_support::LpmMapEntry, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "bad lpm map entry: expected JSON object".to_owned())?;
    let key = object
        .get("key")
        .and_then(Value::as_object)
        .ok_or_else(|| "bad lpm map entry key: expected JSON object".to_owned())?;
    Ok(dae_ebpf_support::LpmMapEntry {
        key: dae_ebpf_support::BpfLpmKey {
            prefix_len: json_u32(key.get("prefix_len"), "lpm_maps[].entries[].key.prefix_len")?,
            data: json_u32_array_4(key.get("data"), "lpm_maps[].entries[].key.data")?,
        },
        value: json_u32(object.get("value"), "lpm_maps[].entries[].value")?,
    })
}

pub(super) fn parse_domain_routing_map_entry(
    value: &Value,
) -> Result<dae_ebpf_support::DomainRoutingMapEntry, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "bad domain routing entry: expected JSON object".to_owned())?;
    Ok(dae_ebpf_support::DomainRoutingMapEntry {
        key: json_u32_array_4(object.get("key"), "updates[].key")?,
        value: dae_ebpf_support::BpfDomainRouting {
            bitmap: json_u32_array_32(object.get("bitmap"), "updates[].bitmap")?,
        },
    })
}

pub(super) fn parse_bpf_match_set(value: &Value) -> Result<dae_ebpf_support::BpfMatchSet, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "bad match set: expected JSON object".to_owned())?;
    Ok(dae_ebpf_support::BpfMatchSet {
        value: json_u8_array_16(object.get("value"), "match_set.value")?,
        not: u8::from(json_bool(object.get("not"), "match_set.not")?),
        kind: json_u8(
            object.get("type").or_else(|| object.get("kind")),
            "match_set.type",
        )?,
        outbound: json_u8(object.get("outbound"), "match_set.outbound")?,
        must: u8::from(json_bool(object.get("must"), "match_set.must")?),
        mark: json_u32(object.get("mark"), "match_set.mark")?,
    })
}

pub(super) fn json_array<'a>(
    value: Option<&'a Value>,
    name: &str,
) -> Result<&'a Vec<Value>, String> {
    value
        .and_then(Value::as_array)
        .ok_or_else(|| format!("missing or non-array field: {name}"))
}

pub(super) fn optional_json_array(value: Option<&Value>) -> Result<Vec<Value>, String> {
    match value {
        Some(value) => value
            .as_array()
            .cloned()
            .ok_or_else(|| "optional field is not an array".to_owned()),
        None => Ok(Vec::new()),
    }
}

pub(super) fn json_string(value: Option<&Value>, name: &str) -> Result<String, String> {
    value
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("missing or non-string field: {name}"))
}

pub(super) fn json_u32_array_4(value: Option<&Value>, name: &str) -> Result<[u32; 4], String> {
    let values = json_array(value, name)?;
    if values.len() != 4 {
        return Err(format!("bad {name}: got {} values, want 4", values.len()));
    }
    let mut out = [0_u32; 4];
    for (index, value) in values.iter().enumerate() {
        out[index] = json_u32(Some(value), name)?;
    }
    Ok(out)
}

pub(super) fn json_u32_array_32(value: Option<&Value>, name: &str) -> Result<[u32; 32], String> {
    let values = json_array(value, name)?;
    if values.len() != 32 {
        return Err(format!("bad {name}: got {} values, want 32", values.len()));
    }
    let mut out = [0_u32; 32];
    for (index, value) in values.iter().enumerate() {
        out[index] = json_u32(Some(value), name)?;
    }
    Ok(out)
}

pub(super) fn json_u8_array_16(value: Option<&Value>, name: &str) -> Result<[u8; 16], String> {
    let values = json_array(value, name)?;
    if values.len() != 16 {
        return Err(format!("bad {name}: got {} values, want 16", values.len()));
    }
    let mut out = [0_u8; 16];
    for (index, value) in values.iter().enumerate() {
        out[index] = json_u8(Some(value), name)?;
    }
    Ok(out)
}
