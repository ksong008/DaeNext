use super::*;
#[cfg(feature = "native-ebpf")]
pub(super) fn run_load_pin(options: BpfLoaderLoadPinOptions) -> LoaderOutput {
    use dae_ebpf_support::{
        AyaUserspaceLoaderOptions, DaeParamInput, build_dae_param, load_aya_userspace_object,
        pin_aya_loaded_object_for_go_adoption,
    };

    let requested_object_source = options.object_source;
    let (object, mut cleanup_object) = match options.object {
        Some(object) => (object, None),
        None => match write_embedded_native_aya_object() {
            Ok((object, cleanup)) => (object, Some(cleanup)),
            Err(err) => return LoaderOutput::error(err),
        },
    };
    let param = build_dae_param(DaeParamInput {
        tproxy_port: options.tproxy_port,
        control_plane_pid: options.control_plane_pid,
        dae0_ifindex: options.dae0_ifindex,
        dae_netns_id: options.dae_netns_id,
        dae0peer_mac: options.dae0peer_mac,
        has_bpf_get_current_task: options.has_bpf_get_current_task,
    });
    let map_pin_root = options.pin_root.join("maps");
    let mut loaded = match load_aya_userspace_object(AyaUserspaceLoaderOptions {
        object: &object,
        param: Some(param),
        map_pin_path: Some(&map_pin_root),
        allow_unsupported_maps: true,
        max_entries_overrides: &[],
        prepin_lpm_array_map: true,
    }) {
        Ok(loaded) => loaded,
        Err(err) => {
            if let Some(cleanup) = cleanup_object.take() {
                cleanup();
            }
            return LoaderOutput::error(err);
        }
    };
    let pin_report = match pin_aya_loaded_object_for_go_adoption(&mut loaded, &options.pin_root) {
        Ok(report) => report,
        Err(err) => {
            if let Some(cleanup) = cleanup_object.take() {
                cleanup();
            }
            return LoaderOutput::error(err);
        }
    };
    let object_source = requested_object_source
        .map(BpfObjectSource::as_str)
        .unwrap_or(if cleanup_object.is_some() {
            BpfObjectSource::RustAyaSkeleton.as_str()
        } else {
            "explicit"
        });
    if let Some(cleanup) = cleanup_object.take() {
        cleanup();
    }
    LoaderOutput::ok(format!(
        "{}\n",
        json!({
            "status": "pass",
            "loader": "rust-aya",
            "object": object,
            "object_source": object_source,
            "default_object_source": BpfObjectSource::RustAyaSkeleton.as_str(),
            "kernel_ebpf_program_rewrite": object_source == BpfObjectSource::RustAyaSkeleton.as_str(),
            "rust_aya_skeleton_opt_in": object_source == BpfObjectSource::RustAyaSkeleton.as_str(),
            "pin_root": pin_report.adoption_pin_root,
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
            },
            "go_adoption_ready": true,
        })
    ))
}

#[cfg(feature = "native-ebpf")]
pub(super) fn write_embedded_native_aya_object() -> Result<(PathBuf, impl FnOnce()), String> {
    let path = std::env::temp_dir().join(format!(
        "dae-native-bpf-{}-{}.o",
        std::process::id(),
        fastrand::u64(..)
    ));
    std::fs::write(&path, EMBEDDED_NATIVE_AYA_OBJECT).map_err(|err| {
        format!(
            "write embedded native Aya object {} failed: {err}",
            path.display()
        )
    })?;
    let cleanup_path = path.clone();
    Ok((path, move || {
        let _ = std::fs::remove_file(cleanup_path);
    }))
}

#[cfg(not(feature = "native-ebpf"))]
pub(super) fn run_load_pin(_options: BpfLoaderLoadPinOptions) -> LoaderOutput {
    LoaderOutput::error("bpf-loader load-pin requires dae-aya-bpf-loader feature native-ebpf")
}
