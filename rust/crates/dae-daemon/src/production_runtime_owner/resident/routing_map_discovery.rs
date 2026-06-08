use super::*;
pub(super) fn discover_routing_tuple_map(
    native_runtime: &NativeEbpfRuntimeState,
    handoff: &LiveLoadedTproxyListenSocketMap,
) -> Result<RoutingTupleMapDiscovery, String> {
    if let Some(id) = native_runtime.loaded_map_id(ROUTING_TUPLES_MAP_NAME) {
        return Ok(RoutingTupleMapDiscovery {
            id: Some(id),
            source: "native-runtime",
            candidate_map_ids: Vec::new(),
        });
    }
    let id = loaded_map_id_by_name(&handoff.new_map_ids, ROUTING_TUPLES_MAP_NAME)?;
    if let Some(id) = id {
        return Ok(RoutingTupleMapDiscovery {
            id: Some(id),
            source: "loaded-map-handoff",
            candidate_map_ids: handoff.new_map_ids.clone(),
        });
    }
    let current_map_ids =
        map_ids().map_err(|err| format!("resident routing tuple map snapshot failed: {err}"))?;
    if let Some(id) = latest_loaded_map_id_by_name(&current_map_ids, ROUTING_TUPLES_MAP_NAME)? {
        return Ok(RoutingTupleMapDiscovery {
            id: Some(id),
            source: "runtime-map-snapshot",
            candidate_map_ids: vec![id],
        });
    }
    Ok(RoutingTupleMapDiscovery {
        id: None,
        source: "missing",
        candidate_map_ids: handoff.new_map_ids.clone(),
    })
}

pub(super) fn loaded_map_id_by_name(
    candidate_map_ids: &[u32],
    name: &str,
) -> Result<Option<u32>, String> {
    for id in candidate_map_ids {
        let fd = match open_map_fd(*id) {
            Ok(fd) => fd,
            Err(err) if is_transient_missing_map_id(&err) => continue,
            Err(err) => {
                return Err(format!(
                    "open loaded BPF map id {id} while finding {name}: {err}"
                ));
            }
        };
        let info = match map_info(fd.as_raw_fd()) {
            Ok(info) => info,
            Err(err) if is_transient_missing_map_id(&err) => continue,
            Err(err) => {
                return Err(format!(
                    "inspect loaded BPF map id {id} while finding {name}: {err}"
                ));
            }
        };
        if kernel_visible_map_name_matches(&info.name, name) {
            return Ok(Some(info.id));
        }
    }
    Ok(None)
}

pub(super) fn latest_loaded_map_id_by_name(
    candidate_map_ids: &[u32],
    name: &str,
) -> Result<Option<u32>, String> {
    let mut selected = None;
    for id in candidate_map_ids {
        let fd = match open_map_fd(*id) {
            Ok(fd) => fd,
            Err(err) if is_transient_missing_map_id(&err) => continue,
            Err(err) => {
                return Err(format!(
                    "open loaded BPF map id {id} while finding latest {name}: {err}"
                ));
            }
        };
        let info = match map_info(fd.as_raw_fd()) {
            Ok(info) => info,
            Err(err) if is_transient_missing_map_id(&err) => continue,
            Err(err) => {
                return Err(format!(
                    "inspect loaded BPF map id {id} while finding latest {name}: {err}"
                ));
            }
        };
        if kernel_visible_map_name_matches(&info.name, name)
            && selected.is_none_or(|selected_id| info.id > selected_id)
        {
            selected = Some(info.id);
        }
    }
    Ok(selected)
}

pub(super) fn kernel_visible_map_name_matches(actual: &str, expected: &str) -> bool {
    actual == expected || actual == truncated_bpf_name(expected)
}

pub(super) fn truncated_bpf_name(name: &str) -> String {
    const BPF_OBJ_NAME_MAX_VISIBLE_LEN: usize = 15;
    name.chars().take(BPF_OBJ_NAME_MAX_VISIBLE_LEN).collect()
}

pub(super) fn is_transient_missing_map_id(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::NotFound
}

pub(super) fn startup_evidence_from_report(start_report: &Value) -> Value {
    let native_object = start_report
        .get("native_object")
        .filter(|value| !value.is_null());
    let bpf_loader = native_object.map(|object| {
        let kernel_rewrite = start_report
            .pointer("/native_param_image/rewritten_param_matches")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        json!({
            "objectSource": "rust-aya-skeleton",
            "defaultObjectSource": if cfg!(feature = "native-ebpf") {
                "rust-aya-skeleton"
            } else {
                "c-aya"
            },
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
            "tc"
            | "tc_netlink"
            | "tc-command-fallback"
            | "tc_command_fallback"
            | "tc-command"
            | "tc_command" => saw_tc = true,
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
