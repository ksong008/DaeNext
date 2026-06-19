use super::*;
pub(super) fn discover_routing_tuple_map(
    native_runtime: &NativeEbpfRuntimeState,
    handoff: &LiveLoadedTproxyListenSocketMap,
) -> Result<RoutingTupleMapDiscovery, String> {
    discover_reusable_map(native_runtime, handoff, ROUTING_TUPLES_MAP_NAME)
}

pub(super) fn discover_domain_routing_map(
    native_runtime: &NativeEbpfRuntimeState,
    handoff: &LiveLoadedTproxyListenSocketMap,
) -> Result<DomainRoutingMapDiscovery, String> {
    discover_reusable_map(native_runtime, handoff, DOMAIN_ROUTING_MAP_NAME)
}

pub(super) fn discover_reusable_map(
    native_runtime: &NativeEbpfRuntimeState,
    handoff: &LiveLoadedTproxyListenSocketMap,
    name: &'static str,
) -> Result<ReusableMapDiscovery, String> {
    if let Some(id) = native_runtime.loaded_map_id(name) {
        return Ok(ReusableMapDiscovery {
            name,
            id: Some(id),
            source: "native-runtime",
            candidate_map_ids: Vec::new(),
        });
    }
    let handoff_snapshot = RuntimeMapSnapshot::from_ids(&handoff.new_map_ids)
        .map_err(|err| format!("resident reusable handoff map snapshot failed: {err}"))?;
    let id = loaded_map_id_by_name_in_snapshot(&handoff_snapshot, &handoff.new_map_ids, name);
    if let Some(id) = id {
        return Ok(ReusableMapDiscovery {
            name,
            id: Some(id),
            source: "loaded-map-handoff",
            candidate_map_ids: handoff.new_map_ids.clone(),
        });
    }
    let current_snapshot = RuntimeMapSnapshot::collect()
        .map_err(|err| format!("resident reusable map snapshot failed: {err}"))?;
    if let Some(id) = latest_loaded_map_id_by_name_in_snapshot(&current_snapshot, name) {
        return Ok(ReusableMapDiscovery {
            name,
            id: Some(id),
            source: "runtime-map-snapshot",
            candidate_map_ids: vec![id],
        });
    }
    Ok(ReusableMapDiscovery {
        name,
        id: None,
        source: "missing",
        candidate_map_ids: handoff.new_map_ids.clone(),
    })
}

pub(super) fn resident_reusable_maps_evidence(
    native_runtime: &NativeEbpfRuntimeState,
    handoff: Option<&LiveLoadedTproxyListenSocketMap>,
) -> Vec<Value> {
    let Some(handoff) = handoff else {
        return RESIDENT_REUSABLE_MAP_NAMES
            .iter()
            .map(|name| {
                json!({
                    "name": name,
                    "status": "skipped",
                    "source": "missing",
                    "reason": "resident tproxy listener handoff is unavailable",
                    "pinning": catalog_pinning(name),
                })
            })
            .collect();
    };

    RESIDENT_REUSABLE_MAP_NAMES
        .iter()
        .copied()
        .map(
            |name| match discover_reusable_map(native_runtime, handoff, name) {
                Ok(discovery) => reusable_map_discovery_json(native_runtime, &discovery),
                Err(err) => json!({
                    "name": name,
                    "status": "fail",
                    "source": "discovery-error",
                    "pinning": catalog_pinning(name),
                    "error": err,
                }),
            },
        )
        .collect()
}

pub(super) fn reusable_map_discovery_json(
    native_runtime: &NativeEbpfRuntimeState,
    discovery: &ReusableMapDiscovery,
) -> Value {
    let pin_path = catalog_pin_path(native_runtime, discovery.name);
    let pin_path_status =
        reusable_map_pin_path_status(discovery.name, discovery.id, pin_path.as_ref());
    let mut value = json!({
        "name": discovery.name,
        "status": if discovery.id.is_some() { "pass" } else { "missing" },
        "id": discovery.id,
        "source": discovery.source,
        "generation": "resident-start",
        "reuseState": reusable_map_reuse_state(discovery.source, discovery.id),
        "pinning": catalog_pinning(discovery.name),
        "pinPath": pin_path,
        "pinPathStatus": pin_path_status,
        "candidateMapIds": discovery.candidate_map_ids,
    });
    if let Some(id) = discovery.id {
        let capacity_result = if exact_reusable_map_capacity_enabled() {
            map_capacity_by_id(id)
        } else {
            map_capacity_fast_by_id(id)
        };
        let capacity = match capacity_result {
            Ok(capacity) => runtime_map_capacity_json(&capacity, discovery.source),
            Err(err) => json!({
                "status": "fail",
                "source": discovery.source,
                "id": id,
                "error": err.to_string(),
            }),
        };
        if let Value::Object(map) = &mut value {
            map.insert("capacity".to_owned(), capacity);
        }
    }
    value
}

pub(super) fn runtime_map_capacity_json(capacity: &RuntimeMapCapacity, source: &str) -> Value {
    json!({
        "status": "pass",
        "source": source,
        "id": capacity.info.id,
        "name": capacity.info.name,
        "mapType": capacity.info.map_type,
        "keySize": capacity.info.key_size,
        "valueSize": capacity.info.value_size,
        "maxEntries": capacity.info.max_entries,
        "entries": capacity.entries,
        "entriesExact": capacity.entries_exact,
        "entryCountMode": if capacity.entries_exact { "exact" } else { "fast" },
        "usageRatio": capacity.usage_ratio,
        "pressureApplicable": capacity.pressure_applicable,
        "warning": capacity.warning,
        "pressure": capacity.pressure,
        "nearCapacity": capacity.near_capacity,
        "flags": capacity.info.flags,
        "pinning": catalog_pinning(&capacity.info.name),
    })
}

fn reusable_map_reuse_state(source: &str, id: Option<u32>) -> &'static str {
    match (source, id) {
        (_, None) => "missing",
        ("runtime-map-snapshot", Some(_)) => "recovered-existing",
        ("loaded-map-handoff", Some(_)) | ("native-runtime", Some(_)) => "current-load",
        _ => "unknown",
    }
}

fn reusable_map_pin_path_status(
    name: &str,
    id: Option<u32>,
    pin_path: Option<&String>,
) -> &'static str {
    if !catalog_pinned_by_name(name) {
        return "not-pinned";
    }
    if id.is_none() {
        return "missing";
    }
    if pin_path.is_some() {
        "known"
    } else {
        "not-observable-from-runtime-snapshot"
    }
}

fn catalog_pinning(name: &str) -> Value {
    map_catalog()
        .iter()
        .find(|spec| kernel_visible_map_name_matches(name, spec.name))
        .map(|spec| json!(spec.pinning))
        .unwrap_or(Value::Null)
}

fn catalog_pinned_by_name(name: &str) -> bool {
    map_catalog()
        .iter()
        .find(|spec| kernel_visible_map_name_matches(name, spec.name))
        .map(|spec| spec.pinned_by_name())
        .unwrap_or(false)
}

fn catalog_pin_path(native_runtime: &NativeEbpfRuntimeState, name: &str) -> Option<String> {
    if !catalog_pinned_by_name(name) {
        return None;
    }
    native_runtime
        .pin_root()
        .map(|root| path_string(&root.join(name)))
}

fn exact_reusable_map_capacity_enabled() -> bool {
    std::env::var("RESIDENT_BPF_EXACT_MAP_CAPACITY")
        .or_else(|_| std::env::var("DAE_RUST_RESIDENT_BPF_EXACT_MAP_CAPACITY"))
        .is_ok_and(|value| matches!(value.as_str(), "1" | "true" | "yes" | "on"))
}

fn loaded_map_id_by_name_in_snapshot(
    snapshot: &RuntimeMapSnapshot,
    candidate_map_ids: &[u32],
    name: &str,
) -> Option<u32> {
    snapshot
        .all_by_name_in_ids(candidate_map_ids, name)
        .first()
        .map(|info| info.id)
}

fn latest_loaded_map_id_by_name_in_snapshot(
    snapshot: &RuntimeMapSnapshot,
    name: &str,
) -> Option<u32> {
    snapshot.latest_by_name(name).map(|info| info.id)
}

pub(super) fn kernel_visible_map_name_matches(actual: &str, expected: &str) -> bool {
    runtime_map_name_matches(actual, expected)
}

pub(super) fn startup_evidence_from_report(start_report: &Value) -> Value {
    let native_object = start_report
        .get("native_object")
        .filter(|value| !value.is_null())
        .or_else(|| {
            start_report
                .get("native_object_embedded")
                .and_then(Value::as_bool)
                .and_then(|embedded| {
                    embedded
                        .then(|| start_report.get("native_object_identity"))
                        .flatten()
                })
        });
    let bpf_loader = native_object.map(|object| {
        let kernel_rewrite = start_report
            .pointer("/native_param_image/rewritten_param_matches")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        json!({
            "objectSource": "rust-aya-loader",
            "defaultObjectSource": "rust-aya-loader",
            "kernelEbpfProgramRewrite": kernel_rewrite,
            "objectPath": object,
            "paramObjectPath": start_report["native_param_object"].clone(),
        })
    });
    let bindings = startup_attach_bindings(start_report);
    let loaded_map_count = start_report
        .pointer("/loaded_map_handoff/new_map_ids")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or_else(|| {
            start_report
                .get("discovered_map_id")
                .filter(|value| !value.is_null())
                .map(|_| 1)
                .unwrap_or(0)
                + start_report
                    .get("discovered_routing_map_ids")
                    .and_then(Value::as_array)
                    .map(|ids| ids.iter().filter(|id| !id.is_null()).count())
                    .unwrap_or(0)
        });
    json!({
        "bpfLoader": bpf_loader,
        "loadedEbpf": {
            "status": if start_report["status"].as_str() == Some("pass") { "pass" } else { "fail" },
            "programCount": bindings.len(),
            "mapCount": loaded_map_count,
        },
        "bindings": bindings,
        "routingMatchSets": startup_routing_match_sets(start_report),
        "mapCapacity": start_report
            .get("resident_reusable_maps")
            .cloned()
            .unwrap_or_else(|| json!([])),
        "cgroupPname": start_report
            .pointer("/resident_cgroup_attach/pname")
            .cloned()
            .unwrap_or(Value::Null),
        "cgroupLinkLifecycle": start_report
            .pointer("/resident_cgroup_attach/linkLifecycle")
            .cloned()
            .unwrap_or(Value::Null),
        "residentInterfaceState": start_report
            .get("resident_interface_monitor")
            .cloned()
            .unwrap_or(Value::Null),
    })
}

pub(super) fn startup_attach_bindings(start_report: &Value) -> Vec<Value> {
    let Some(steps) = start_report.get("executed_steps").and_then(Value::as_array) else {
        return Vec::new();
    };
    steps
        .iter()
        .filter(|step| step["status"].as_str() == Some("pass"))
        .filter_map(|step| {
            let native_attach = step.get("native_attach")?;
            let program_name = native_attach.get("program_name").and_then(Value::as_str)?;
            let interface = native_attach
                .get("iface")
                .and_then(Value::as_str)
                .or_else(|| step.get("interface").and_then(Value::as_str))?;
            let backend = native_attach
                .get("backend")
                .and_then(Value::as_str)
                .or_else(|| step.get("backend").and_then(Value::as_str))
                .unwrap_or("aya");
            Some(json!({
                "programName": program_name,
                "interface": interface,
                "backend": backend,
                "role": step["role"].clone(),
                "direction": native_attach["direction"].clone(),
                "priority": native_attach["priority"].clone(),
                "handle": native_attach["handle"].clone(),
                "linkLayer": step["link_layer"].clone(),
            }))
        })
        .collect()
}

pub(super) fn startup_routing_match_sets(start_report: &Value) -> Vec<Value> {
    let Some(routings) = start_report
        .get("resident_lan_routing")
        .and_then(Value::as_array)
    else {
        return Vec::new();
    };
    routings
        .iter()
        .filter_map(|routing| {
            let update = routing.get("routing_map_update")?;
            let map = update.get("map")?;
            Some(json!({
                "interface": routing["interface"].clone(),
                "status": update["status"].clone(),
                "len": update["match_set_count"].clone(),
                "maxEntries": map["max_entries"].clone(),
                "mapId": map["id"].clone(),
                "mapName": map["name"].clone(),
            }))
        })
        .collect()
}

pub(super) fn selected_netns_link_mode(start_report: &Value) -> Option<String> {
    start_report["executed_steps"]
        .as_array()?
        .iter()
        .rev()
        .find(|step| step["name"].as_str() == Some("select-production-netns-link-mode"))
        .and_then(|step| step["selected"].as_str())
        .map(str::to_owned)
}

pub(super) fn actual_resident_attach_backend(start_report: &Value) -> Option<String> {
    let mut saw_tcx = false;
    let mut saw_tc = false;
    for backend in resident_actual_backend_values(start_report) {
        match backend {
            "tcx" => saw_tcx = true,
            "tc" | "tc_netlink" | "tc-command" | "tc_command" => saw_tc = true,
            _ => {}
        }
    }
    match (saw_tcx, saw_tc) {
        (true, true) => Some("tcx+tc".to_owned()),
        (true, false) => Some("tcx".to_owned()),
        (false, true) => Some("tc".to_owned()),
        (false, false) => None,
    }
}

pub(super) fn resident_actual_backend_values(start_report: &Value) -> Vec<&str> {
    let mut out = Vec::new();
    if let Some(wan) = start_report["resident_wan_attach"].as_array() {
        for attach in wan {
            if let Some(directions) = attach["directions"].as_array() {
                for direction in directions {
                    if let Some(backend) = direction["backend"].as_str() {
                        out.push(backend);
                    }
                }
            }
        }
    }
    if let Some(lan) = start_report["resident_lan_attach"].as_array() {
        for attach in lan {
            if let Some(backend) = attach["backend"].as_str() {
                out.push(backend);
            }
            if let Some(backend) = attach.pointer("/egress/backend").and_then(Value::as_str) {
                out.push(backend);
            }
        }
    }
    out
}
