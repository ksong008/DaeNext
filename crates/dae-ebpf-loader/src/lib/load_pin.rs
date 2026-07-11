use super::*;
#[cfg(feature = "native-ebpf")]
pub(super) fn run_load_pin(options: BpfLoaderLoadPinOptions) -> LoaderOutput {
    use dae_ebpf_support::{
        AyaUserspaceBytesLoaderOptions, DaeParamInput, build_dae_param,
        load_aya_userspace_object_bytes, pin_aya_loaded_object_for_native_runtime,
    };

    const EMBEDDED_OBJECT_LABEL: &str = "memory:native-ebpf-object";

    let param = build_dae_param(DaeParamInput {
        tproxy_port: options.tproxy_port,
        control_plane_pid: options.control_plane_pid,
        dae0_ifindex: options.dae0_ifindex,
        dae_netns_id: options.dae_netns_id,
        dae0peer_mac: options.dae0peer_mac,
        has_bpf_get_current_task: options.has_bpf_get_current_task,
        task_struct_mm_offset: 0,
        mm_struct_arg_start_offset: 0,
    });
    let map_pin_root = options.pin_root.join("maps");
    let redirect_generation =
        dae_ebpf_support::redirect_runtime_generation(param.control_plane_pid, param.dae0_ifindex);
    let mut loaded = match load_aya_userspace_object_bytes(AyaUserspaceBytesLoaderOptions {
        object_label: EMBEDDED_OBJECT_LABEL,
        object_data: embedded_native_aya_object(),
        param: Some(param),
        map_pin_path: Some(&map_pin_root),
        allow_unsupported_maps: true,
        allowed_unsupported_map_names: dae_ebpf_support::DEFAULT_ALLOWED_UNSUPPORTED_MAP_NAMES,
        max_entries_overrides: &[],
        prepin_lpm_array_map: true,
        target_btf_required: false,
    }) {
        Ok(loaded) => loaded,
        Err(err) => return LoaderOutput::error(err),
    };
    let pin_report = match pin_aya_loaded_object_for_native_runtime(&mut loaded, &options.pin_root)
    {
        Ok(report) => report,
        Err(err) => return LoaderOutput::error(err),
    };
    LoaderOutput::ok(format!(
        "{}\n",
        json!({
            "status": "pass",
            "loader": "rust-aya",
            "object": EMBEDDED_OBJECT_LABEL,
            "object_source": RUST_AYA_LOADER_OBJECT_SOURCE,
            "default_object_source": RUST_AYA_LOADER_OBJECT_SOURCE,
            "kernel_ebpf_program_rewrite": true,
            "rust_aya_loader_runtime_source": true,
            "pin_root": pin_report.native_pin_root,
            "map_pin_root": pin_report.map_pin_root,
            "program_pin_root": pin_report.program_pin_root,
            "maps": pin_report.maps.iter().map(|pin| json!({
                "name": pin.name,
                "path": pin.path,
            })).collect::<Vec<_>>(),
            "programs": pin_report.programs.iter().map(|pin| json!({
                "name": pin.name,
                "path": pin.path,
            })).collect::<Vec<_>>(),
            "param": {
                "tproxy_port": param.tproxy_port,
                "control_plane_pid": param.control_plane_pid,
                "dae0_ifindex": param.dae0_ifindex,
                "dae_netns_id": param.dae_netns_id,
                "dae0peer_mac": mac_string(param.dae0peer_mac),
                "has_bpf_get_current_task": param.has_bpf_get_current_task,
                "task_struct_mm_offset": param.task_struct_mm_offset,
                "mm_struct_arg_start_offset": param.mm_struct_arg_start_offset,
                "abi_version": param.abi_version,
                "udp_state_saturation_policy": param.udp_state_saturation_policy,
                "udp_state_idle_timeout_ns": param.udp_state_idle_timeout_ns.to_string(),
                "redirect_track_abi_version": dae_ebpf_support::REDIRECT_TRACK_ABI_VERSION,
                "redirect_track_generation": redirect_generation.to_string(),
            },
            "native_runtime_pinning_ready": true,
        })
    ))
}

#[cfg(not(feature = "native-ebpf"))]
pub(super) fn run_load_pin(_options: BpfLoaderLoadPinOptions) -> LoaderOutput {
    LoaderOutput::error("bpf-loader load-pin requires dae-ebpf-loader feature native-ebpf")
}
