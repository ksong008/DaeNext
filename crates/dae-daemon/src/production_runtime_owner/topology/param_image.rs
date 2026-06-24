use super::*;
pub(crate) fn write_param_image(
    options: &ProductionRuntimeOwnerOptions,
    param_object: &Path,
    dae0_ifindex: u32,
    dae0peer_mac: [u8; 6],
    dae_netns_id: u32,
) -> Value {
    let param = build_dae_param(DaeParamInput {
        tproxy_port: options.tproxy_port,
        control_plane_pid: std::process::id(),
        dae0_ifindex,
        dae_netns_id,
        dae0peer_mac,
        has_bpf_get_current_task: false,
        task_struct_mm_offset: 0,
        mm_struct_arg_start_offset: 0,
    });
    match write_param_aware_object(&options.source_object, param_object, param) {
        Ok(report) => json!({
            "status": "pass",
            "path": path_string(param_object),
            "rewritten_param_matches": report.rewritten_param_matches,
            "previous_param_was_zero": report.previous_param_was_zero,
            "source_len": report.source_len,
            "output_len": report.output_len,
            "param": {
                "tproxy_port": param.tproxy_port,
                "control_plane_pid": param.control_plane_pid,
                "dae0_ifindex": param.dae0_ifindex,
                "dae_netns_id": param.dae_netns_id,
                "dae0peer_mac": mac_string(param.dae0peer_mac),
                "has_bpf_get_current_task": param.has_bpf_get_current_task,
                "task_struct_mm_offset": param.task_struct_mm_offset,
                "mm_struct_arg_start_offset": param.mm_struct_arg_start_offset,
            },
            "location": {
                "symbol": report.location.symbol,
                "section": report.location.section,
                "symbol_size": report.location.symbol_size,
                "file_offset": report.location.file_offset,
            },
        }),
        Err(err) => json!({
            "status": "fail",
            "path": path_string(param_object),
            "error": err.to_string(),
        }),
    }
}
