use super::*;

#[cfg(feature = "native-ebpf")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EmbeddedPnameObject {
    CurrentComm,
    CurrentTaskArgv0,
}

#[cfg(feature = "native-ebpf")]
impl EmbeddedPnameObject {
    const fn for_request(has_bpf_get_current_task: bool) -> Self {
        if has_bpf_get_current_task {
            Self::CurrentTaskArgv0
        } else {
            Self::CurrentComm
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::CurrentComm => "memory:native-ebpf-object",
            Self::CurrentTaskArgv0 => "memory:native-ebpf-object-pname-core",
        }
    }

    fn data(self) -> &'static [u8] {
        match self {
            Self::CurrentComm => embedded_native_aya_object(),
            Self::CurrentTaskArgv0 => embedded_native_aya_object_pname_core(),
        }
    }

    const fn target_btf_required(self) -> bool {
        matches!(self, Self::CurrentTaskArgv0)
    }

    const fn source(self) -> &'static str {
        match self {
            Self::CurrentComm => "bpf_get_current_comm",
            Self::CurrentTaskArgv0 => "current_task_argv0_basename",
        }
    }
}

#[cfg(feature = "native-ebpf")]
pub(super) fn run_load_pin(options: BpfLoaderLoadPinOptions) -> LoaderOutput {
    use dae_ebpf_support::{
        AyaUserspaceBytesLoaderOptions, DaeParamInput, build_dae_param,
        load_aya_userspace_object_bytes, pin_aya_loaded_object_for_native_runtime,
    };

    let object = EmbeddedPnameObject::for_request(options.has_bpf_get_current_task);
    let (task_struct_mm_offset, mm_struct_arg_start_offset, target_btf_report) =
        if object.target_btf_required() {
            let target_btf = dae_ebpf_support::discover_aya_target_btf(true);
            if target_btf.btf.is_none() {
                return LoaderOutput::error(format!(
                    "pname-core load-pin requires target BTF: path={} parse_error={} candidates={}",
                    target_btf
                        .report
                        .path
                        .as_deref()
                        .map(|path| path.display().to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    target_btf.report.parse_error.as_deref().unwrap_or("none"),
                    target_btf
                        .report
                        .candidate_paths
                        .iter()
                        .map(|path| path.display().to_string())
                        .collect::<Vec<_>>()
                        .join(",")
                ));
            }
            let offsets = match dae_ebpf_support::resolve_pname_btf_offsets(&target_btf.report) {
                Ok(offsets) => offsets,
                Err(err) => {
                    return LoaderOutput::error(format!(
                        "pname-core load-pin target BTF offset resolution failed: {err}"
                    ));
                }
            };
            (
                offsets.task_struct_mm_offset,
                offsets.mm_struct_arg_start_offset,
                Some(target_btf.report),
            )
        } else {
            (0, 0, None)
        };

    let param = build_dae_param(DaeParamInput {
        tproxy_port: options.tproxy_port,
        control_plane_pid: options.control_plane_pid,
        dae0_ifindex: options.dae0_ifindex,
        dae_netns_id: options.dae_netns_id,
        dae0peer_mac: options.dae0peer_mac,
        has_bpf_get_current_task: options.has_bpf_get_current_task,
        task_struct_mm_offset,
        mm_struct_arg_start_offset,
    });
    let map_pin_root = options.pin_root.join("maps");
    let redirect_generation =
        dae_ebpf_support::redirect_runtime_generation(param.control_plane_pid, param.dae0_ifindex);
    let mut loaded = match load_aya_userspace_object_bytes(AyaUserspaceBytesLoaderOptions {
        object_label: object.label(),
        object_data: object.data(),
        param: Some(param),
        map_pin_path: Some(&map_pin_root),
        allow_unsupported_maps: true,
        allowed_unsupported_map_names: dae_ebpf_support::DEFAULT_ALLOWED_UNSUPPORTED_MAP_NAMES,
        max_entries_overrides: &[],
        prepin_lpm_array_map: true,
        target_btf_required: object.target_btf_required(),
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
            "object": object.label(),
            "object_source": RUST_AYA_LOADER_OBJECT_SOURCE,
            "default_object_source": RUST_AYA_LOADER_OBJECT_SOURCE,
            "pname_source": object.source(),
            "target_btf": target_btf_report.as_ref().map(|report| json!({
                "required": report.required,
                "source": report.source.as_str(),
                "path": report.path,
                "canonical_path": report.canonical_path,
                "parse_ok": report.parse_ok,
                "parse_error": report.parse_error,
                "candidate_paths": report.candidate_paths,
            })),
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

#[cfg(all(test, feature = "native-ebpf"))]
mod tests {
    use super::EmbeddedPnameObject;

    #[test]
    fn load_pin_selects_object_and_btf_contract_from_pname_request() {
        let default = EmbeddedPnameObject::for_request(false);
        assert_eq!(default.label(), "memory:native-ebpf-object");
        assert_eq!(default.source(), "bpf_get_current_comm");
        assert!(!default.target_btf_required());

        let core = EmbeddedPnameObject::for_request(true);
        assert_eq!(core.label(), "memory:native-ebpf-object-pname-core");
        assert_eq!(core.source(), "current_task_argv0_basename");
        assert!(core.target_btf_required());
    }
}
