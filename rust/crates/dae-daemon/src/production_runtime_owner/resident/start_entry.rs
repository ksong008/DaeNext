use super::*;
pub fn start_resident_production_runtime(
    config: &Config,
) -> Result<ResidentProductionRuntime, String> {
    let artifact_dir = PathBuf::from(format!(
        "/tmp/dae-daemon-resident-runtime-{}",
        std::process::id()
    ));
    if artifact_dir.exists() {
        fs::remove_dir_all(&artifact_dir).map_err(|err| {
            format!(
                "failed to remove resident production runtime artifact dir {}: {err}",
                path_string(&artifact_dir)
            )
        })?;
    }
    fs::create_dir_all(&artifact_dir).map_err(|err| {
        format!(
            "failed to create resident production runtime artifact dir {}: {err}",
            path_string(&artifact_dir)
        )
    })?;

    let native_object = resolve_native_object(&artifact_dir)?;
    let source_object = match native_object.as_ref() {
        Some(path) => path.clone(),
        None => resolve_source_object(&artifact_dir)?,
    };
    let native_ebpf_opt_in = native_object.is_some();
    let native_ebpf_backend = resolve_native_backend()?;
    let netns_link_mode = resolve_netns_link_mode_from_env()?;
    let options = ProductionRuntimeOwnerOptions {
        execute: true,
        ack_root_gate: true,
        source_object,
        tproxy_port: config.global.tproxy_port,
        dae_netns_id: DEFAULT_DAE_NETNS_ID,
        netns_link_mode,
        peer_section: DEFAULT_PEER_SECTION.to_owned(),
        host_section: DEFAULT_HOST_SECTION.to_owned(),
        native_ebpf_opt_in,
        native_ebpf_backend,
        native_ebpf_completed_a3_admission: native_ebpf_opt_in,
        native_ebpf_object: native_object,
        ..ProductionRuntimeOwnerOptions::default()
    };

    let start_file = artifact_dir.join("resident-production-runtime-start.json");
    let cleanup_file = artifact_dir.join("resident-production-runtime-cleanup.json");
    let lan_ifaces = configured_lan_ifaces(config);
    let wan_ifaces = configured_wan_ifaces(config);
    start_with_options(
        options,
        artifact_dir,
        start_file,
        cleanup_file,
        config,
        lan_ifaces,
        wan_ifaces,
    )
}
