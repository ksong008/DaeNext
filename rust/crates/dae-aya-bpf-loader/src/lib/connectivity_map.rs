fn run_connectivity_map_update(options: ConnectivityMapUpdateOptions) -> LoaderOutput {
    let event = dae_ebpf_support::ConnectivityEvent {
        key: dae_ebpf_support::ConnectivityKey {
            outbound: options.outbound,
            l4proto: options.l4_proto,
            ipversion: options.ip_version,
        },
        alive: options.alive,
        is_init: options.is_init,
        dryrun: options.dryrun,
    };
    let plan = match dae_ebpf_support::update_connectivity_map_by_id(options.map_id, event) {
        Ok(plan) => plan,
        Err(err) => return LoaderOutput::error(format!("connectivity map update failed: {err}")),
    };
    LoaderOutput::ok(format!(
        "{}\n",
        connectivity_map_pass_response(options.map_id, plan, options.dryrun, options.is_init)
    ))
}

pub fn run_connectivity_map_serve<R, W>(reader: R, mut writer: W) -> io::Result<()>
where
    R: BufRead,
    W: Write,
{
    let mut owner = dae_control::OutboundConnectivityMapOwner::default();
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let response = handle_connectivity_map_serve_line(&mut owner, &line);
        writer.write_all(response.as_bytes())?;
        writer.write_all(b"\n")?;
        writer.flush()?;
    }
    Ok(())
}

pub fn run_connectivity_map_serve_binary<R, W>(mut reader: R, mut writer: W) -> io::Result<()>
where
    R: Read,
    W: Write,
{
    let mut owner = dae_control::OutboundConnectivityMapOwner::default();
    let mut request = [0_u8; 8];
    loop {
        match reader.read_exact(&mut request) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(err) => return Err(err),
        }
        let response = handle_connectivity_map_serve_binary_request(&mut owner, request);
        writer.write_all(&response)?;
        writer.flush()?;
    }
}

fn handle_connectivity_map_serve_binary_request(
    owner: &mut dae_control::OutboundConnectivityMapOwner,
    request: [u8; 8],
) -> [u8; 8] {
    let map_id = u32::from_le_bytes([request[0], request[1], request[2], request[3]]);
    let flags = request[7];
    let event = dae_ebpf_support::ConnectivityEvent {
        key: dae_ebpf_support::ConnectivityKey {
            outbound: request[4],
            l4proto: request[5],
            ipversion: request[6],
        },
        alive: flags & 0x01 != 0,
        is_init: flags & 0x02 != 0,
        dryrun: flags & 0x04 != 0,
    };
    let mut response = [0_u8; 8];
    response[4..8].copy_from_slice(&map_id.to_le_bytes());
    match owner.apply_event_by_id(map_id, event) {
        Ok(report) => {
            response[0] = 0;
            response[1] = u8::from(report.entries_updated > 0);
            response[2] = u8::from(report.map_id_changed);
            response[3] = u8::from(report.accepted);
        }
        Err(_) => {
            response[0] = 1;
        }
    }
    response
}

fn handle_connectivity_map_serve_line(
    owner: &mut dae_control::OutboundConnectivityMapOwner,
    line: &str,
) -> String {
    let options = match parse_connectivity_map_serve_request(line) {
        Ok(options) => options,
        Err(err) => return connectivity_map_error_response(err).to_string(),
    };
    let event = dae_ebpf_support::ConnectivityEvent {
        key: dae_ebpf_support::ConnectivityKey {
            outbound: options.outbound,
            l4proto: options.l4_proto,
            ipversion: options.ip_version,
        },
        alive: options.alive,
        is_init: options.is_init,
        dryrun: options.dryrun,
    };
    match owner.apply_event_by_id(options.map_id, event) {
        Ok(report) => {
            connectivity_map_owner_pass_response(options.map_id, event, report).to_string()
        }
        Err(err) => {
            connectivity_map_error_response(format!("connectivity map update failed: {err}"))
                .to_string()
        }
    }
}

fn connectivity_map_owner_pass_response(
    map_id: u32,
    event: dae_ebpf_support::ConnectivityEvent,
    report: dae_control::ConnectivityOwnerApplyReport,
) -> Value {
    json!({
        "status": "pass",
        "loader": "rust",
        "owner": "dae-control",
        "scope": "outbound-connectivity-map-update",
        "map_id": map_id,
        "map_id_changed": report.map_id_changed,
        "written": report.entries_updated > 0,
        "entries_updated": report.entries_updated,
        "state_entries": report.len,
        "key": {
            "outbound": event.key.outbound,
            "l4proto": event.key.l4proto,
            "ipversion": event.key.ipversion,
        },
        "value": u32::from(event.alive),
        "accepted": report.accepted,
        "changed": report.changed,
        "dryrun": event.dryrun,
        "is_init": event.is_init,
    })
}

fn connectivity_map_pass_response(
    map_id: u32,
    plan: dae_ebpf_support::ConnectivityWritePlan,
    dryrun: bool,
    is_init: bool,
) -> Value {
    json!({
        "status": "pass",
        "loader": "rust",
        "scope": "outbound-connectivity-map-update",
        "map_id": map_id,
        "written": plan.written,
        "key": {
            "outbound": plan.key.outbound,
            "l4proto": plan.key.l4proto,
            "ipversion": plan.key.ipversion,
        },
        "value": plan.value,
        "changed": plan.changed,
        "dryrun": dryrun,
        "is_init": is_init,
    })
}

fn connectivity_map_error_response(message: impl Into<String>) -> Value {
    json!({
        "status": "error",
        "loader": "rust",
        "scope": "outbound-connectivity-map-update",
        "error": message.into(),
    })
}

fn parse_connectivity_map_serve_request(
    line: &str,
) -> Result<ConnectivityMapUpdateOptions, String> {
    let value: Value =
        serde_json::from_str(line).map_err(|err| format!("bad connectivity-map request: {err}"))?;
    let object = value
        .as_object()
        .ok_or_else(|| "bad connectivity-map request: expected JSON object".to_owned())?;
    Ok(ConnectivityMapUpdateOptions {
        map_id: json_u32(object.get("map_id"), "map_id")?,
        outbound: json_u8(object.get("outbound"), "outbound")?,
        l4_proto: json_u8(
            object.get("l4_proto").or_else(|| object.get("l4proto")),
            "l4_proto",
        )?,
        ip_version: json_u8(
            object.get("ip_version").or_else(|| object.get("ipversion")),
            "ip_version",
        )?,
        alive: json_bool(object.get("alive"), "alive")?,
        is_init: json_bool(object.get("is_init"), "is_init")?,
        dryrun: json_bool(object.get("dryrun"), "dryrun")?,
    })
}

fn json_u32(value: Option<&Value>, name: &str) -> Result<u32, String> {
    let raw = value
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing or non-u32 connectivity-map field: {name}"))?;
    u32::try_from(raw).map_err(|_| format!("connectivity-map field out of u32 range: {name}"))
}

fn json_u8(value: Option<&Value>, name: &str) -> Result<u8, String> {
    let raw = json_u32(value, name)?;
    u8::try_from(raw).map_err(|_| format!("connectivity-map field out of u8 range: {name}"))
}

fn json_bool(value: Option<&Value>, name: &str) -> Result<bool, String> {
    value
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("missing or non-bool connectivity-map field: {name}"))
}
