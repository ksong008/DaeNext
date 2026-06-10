use super::*;
pub fn start_resident_production_runtime(
    config: &Config,
) -> Result<ResidentProductionRuntime, String> {
    let artifact_dir = resident_runtime_artifact_dir(std::process::id());
    cleanup_stale_resident_runtime_artifacts(&artifact_dir);
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

    let native_ebpf_opt_in = resident_native_ebpf_enabled();
    let native_object = resolve_native_object()?;
    let source_object = if native_ebpf_opt_in {
        match native_object.as_ref() {
            Some(path) => path.clone(),
            #[cfg(feature = "native-ebpf")]
            None => PathBuf::from(EMBEDDED_NATIVE_OBJECT_IDENTITY),
            #[cfg(not(feature = "native-ebpf"))]
            None => resolve_source_object(&artifact_dir)?,
        }
    } else {
        resolve_source_object(&artifact_dir)?
    };
    let native_ebpf_embedded_object = native_ebpf_opt_in && native_object.is_none();
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
        native_ebpf_embedded_object,
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

fn resident_runtime_artifact_dir(pid: u32) -> PathBuf {
    PathBuf::from("/run/daed/runtime").join(pid.to_string())
}

fn cleanup_stale_resident_runtime_artifacts(current_artifact_dir: &Path) {
    let _ = fs::create_dir_all("/run/daed/runtime");
    cleanup_runtime_artifact_root(Path::new("/run/daed"), "resident-runtime-", None);
    cleanup_runtime_artifact_root(
        Path::new("/run/daed/runtime"),
        "",
        Some(current_artifact_dir),
    );
}

fn cleanup_runtime_artifact_root(root: &Path, prefix: &str, current_artifact_dir: Option<&Path>) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        cleanup_runtime_artifact_entry(entry.path(), prefix, current_artifact_dir);
    }
}

fn cleanup_runtime_artifact_entry(
    path: PathBuf,
    prefix: &str,
    current_artifact_dir: Option<&Path>,
) {
    if Some(path.as_path()) == current_artifact_dir {
        return;
    }
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return;
    };
    let Some(pid_text) = name.strip_prefix(prefix) else {
        return;
    };
    let Ok(pid) = pid_text.parse::<u32>() else {
        return;
    };
    if Path::new(&format!("/proc/{pid}")).exists() {
        return;
    }
    let _ = fs::remove_dir_all(path);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resident_runtime_artifact_dir_uses_run_daed() {
        assert_eq!(
            resident_runtime_artifact_dir(42),
            PathBuf::from("/run/daed/runtime/42")
        );
    }
}
