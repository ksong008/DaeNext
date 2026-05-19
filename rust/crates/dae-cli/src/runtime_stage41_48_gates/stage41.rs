use super::utils::*;
use super::*;

pub(super) struct Stage41Options {
    source_object: PathBuf,
    output_object: PathBuf,
    write_image: bool,
    pub(super) require_admission: bool,
    param: ParamOptions,
}

impl Default for Stage41Options {
    fn default() -> Self {
        Self {
            source_object: PathBuf::from(DEFAULT_SOURCE_OBJECT),
            output_object: PathBuf::from(DEFAULT_STAGE41_OUTPUT),
            write_image: false,
            require_admission: false,
            param: ParamOptions::default(),
        }
    }
}

impl Stage41Options {
    pub(super) fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        parse_common_args(args, "stage41", |flag, value| match flag {
            "--object" => {
                opts.source_object = PathBuf::from(value);
                Ok(())
            }
            "--output" => {
                opts.output_object = PathBuf::from(value);
                Ok(())
            }
            "--write-image" => {
                opts.write_image = true;
                Ok(())
            }
            "--require-admission" => {
                opts.require_admission = true;
                Ok(())
            }
            _ => parse_param_arg(&mut opts.param, flag, value),
        })?;
        Ok(opts)
    }
}

pub(super) fn stage41_report(opts: &Stage41Options) -> Value {
    let mut blockers = Vec::new();
    let mut checks = Vec::new();
    let param = build_dae_param(opts.param.input());
    let payload = build_dae_param_payload(opts.param.input());

    push_check(
        &mut checks,
        "real-dae-object-present",
        opts.source_object.exists(),
        json!({"path": path_string(&opts.source_object)}),
        &mut blockers,
        "stage41 source eBPF object is missing",
    );
    let symbol = locate_param_symbol_in_object(&opts.source_object);
    let symbol_json = match &symbol {
        Ok(location) => json!({
            "symbol": location.symbol,
            "section": location.section,
            "symbol_size": location.symbol_size,
            "file_offset": location.file_offset,
            "section_offset": location.section_offset,
            "symbol_value": location.symbol_value,
        }),
        Err(err) => json!({"error": err.to_string()}),
    };
    push_check(
        &mut checks,
        "param-symbol-locatable",
        symbol.is_ok(),
        symbol_json.clone(),
        &mut blockers,
        "stage41 cannot locate PARAM symbol in source object",
    );
    let source_param = read_param_from_object(&opts.source_object);
    push_check(
        &mut checks,
        "source-param-is-zero-baseline",
        source_param
            .as_ref()
            .map(|value| *value == Default::default())
            .unwrap_or(false),
        json!({
            "status": if source_param.is_ok() { "read" } else { "error" },
            "error": source_param.as_ref().err().map(ToString::to_string),
        }),
        &mut blockers,
        "stage41 source object PARAM baseline is not zero or cannot be read",
    );

    let mut rewrite_report = Value::Null;
    let mut rewritten_param = Value::Null;
    let mut write_passed = !opts.write_image;
    if opts.write_image && blockers.is_empty() {
        match write_param_aware_object(&opts.source_object, &opts.output_object, param) {
            Ok(report) => {
                write_passed = report.rewritten_param_matches;
                rewritten_param = match read_param_from_object(&opts.output_object) {
                    Ok(value) => json!({
                        "tproxy_port": value.tproxy_port,
                        "control_plane_pid": value.control_plane_pid,
                        "dae0_ifindex": value.dae0_ifindex,
                        "dae_netns_id": value.dae_netns_id,
                        "dae0peer_mac": mac_string(value.dae0peer_mac),
                        "has_bpf_get_current_task": value.has_bpf_get_current_task,
                        "padding": value.padding,
                    }),
                    Err(err) => json!({"error": err.to_string()}),
                };
                rewrite_report = json!({
                    "source_len": report.source_len,
                    "output_len": report.output_len,
                    "expected_param_size": report.expected_param_size,
                    "previous_param_was_zero": report.previous_param_was_zero,
                    "rewritten_param_matches": report.rewritten_param_matches,
                    "location": {
                        "symbol": report.location.symbol,
                        "section": report.location.section,
                        "symbol_size": report.location.symbol_size,
                        "file_offset": report.location.file_offset,
                    },
                });
            }
            Err(err) => {
                write_passed = false;
                rewrite_report = json!({"status": "fail", "error": err.to_string()});
            }
        }
    }
    if opts.write_image && !write_passed {
        blockers.push("stage41 PARAM-aware object image rewrite failed".to_owned());
    }

    let param_object_image_admitted = blockers.is_empty() && write_passed;
    json!({
        "name": "stage41-param-object-image-admission",
        "stage": "stage41",
        "evidence_class": "param-aware-bpf-object-image-writer",
        "read_only": !opts.write_image,
        "blocked": !blockers.is_empty(),
        "blockers": blockers,
        "checks": checks,
        "source_object": path_string(&opts.source_object),
        "output_object": path_string(&opts.output_object),
        "param_symbol": symbol_json,
        "param_payload": {
            "symbol": DAE_PARAM_SYMBOL,
            "rust_layout_size": DAE_PARAM_SYMBOL_SIZE,
            "tproxy_port_host": payload.tproxy_port_host,
            "tproxy_port_big_endian": payload.tproxy_port_big_endian,
            "control_plane_pid": payload.control_plane_pid,
            "dae0_ifindex": payload.dae0_ifindex,
            "dae_netns_id": payload.dae_netns_id,
            "dae0peer_mac": mac_string(payload.dae0peer_mac),
            "has_bpf_get_current_task": payload.has_bpf_get_current_task,
        },
        "param_object_image_write_requested": opts.write_image,
        "param_object_image_written": opts.write_image && write_passed,
        "param_object_image_admitted": param_object_image_admitted,
        "rewrite_report": rewrite_report,
        "rewritten_param": rewritten_param,
        "active_tproxy_traffic_executed": false,
        "default_switch_allowed": false,
        "product_chain_switch_allowed": false,
        "true_rust_default_daemon_admitted": false,
        "go_default_path_preserved": true,
        "go_fallback_required": true,
        "remaining_blockers": [
            "PARAM-aware object image must still be loaded and attached in an isolated smoke",
            "active tproxy TCP UDP DNS traffic evidence is still missing",
            "outbound true dataplane admission is still incomplete",
            "matched Go default daemon vs true Rust candidate benchmark is still missing",
            "clean dae-wing and daed product-chain recertification is still missing"
        ],
    })
}
