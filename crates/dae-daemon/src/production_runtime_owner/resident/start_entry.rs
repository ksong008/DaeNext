use super::*;
#[allow(dead_code)]
pub(crate) fn start_resident_production_runtime_with_latency_seed(
    config: &Config,
    latency_seed: &[Value],
) -> Result<ResidentProductionRuntime, String> {
    start_resident_production_runtime_with_latency_seed_and_dns_reload_snapshot(
        config,
        latency_seed,
        None,
    )
}

pub(crate) fn start_resident_production_runtime_with_latency_seed_and_dns_reload_snapshot(
    config: &Config,
    latency_seed: &[Value],
    dns_reload_snapshot: Option<ResidentDnsReloadSnapshot>,
) -> Result<ResidentProductionRuntime, String> {
    let prepared =
        prepare_resident_production_generation(Arc::new(config.clone()), Vec::<PathBuf>::new())?;
    start_prepared_resident_production_runtime(prepared, latency_seed, dns_reload_snapshot)
}

pub fn start_resident_production_runtime_with_asset_dirs(
    config: &Config,
    geodata_asset_dirs: impl IntoIterator<Item = impl Into<PathBuf>>,
) -> Result<ResidentProductionRuntime, String> {
    let prepared =
        prepare_resident_production_generation(Arc::new(config.clone()), geodata_asset_dirs)?;
    start_prepared_resident_production_runtime(prepared, &[], None)
}

pub(crate) fn start_prepared_resident_production_runtime(
    prepared: ResidentPreparedGeneration,
    latency_seed: &[Value],
    dns_reload_snapshot: Option<ResidentDnsReloadSnapshot>,
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

    let options = resident_runtime_options(
        &prepared.config,
        prepared.geodata_asset_dirs.clone(),
        &artifact_dir,
    )?;

    let start_file = artifact_dir.join("resident-production-runtime-start.json");
    let cleanup_file = artifact_dir.join("resident-production-runtime-cleanup.json");
    let lan_ifaces = configured_lan_ifaces(&prepared.config);
    let wan_ifaces = configured_wan_ifaces(&prepared.config)?;
    let ResidentPreparedGeneration {
        config,
        geodata_asset_dirs: _,
        geodata,
        dataplane,
    } = prepared;
    start_with_options(ResidentRuntimeStartContext {
        options,
        artifacts: ResidentRuntimeArtifactPaths {
            artifact_dir,
            start_file,
            cleanup_file,
        },
        config,
        geodata,
        dataplane,
        interfaces: ResidentRuntimeStartInterfaces {
            lan: lan_ifaces,
            wan: wan_ifaces,
        },
        latency_seed,
        dns_reload_snapshot,
    })
}

pub(super) fn resident_runtime_options(
    config: &Config,
    geodata_asset_dirs: Vec<PathBuf>,
    artifact_dir: &Path,
) -> Result<ProductionRuntimeOwnerOptions, String> {
    let native_ebpf_requested = resident_native_ebpf_enabled();
    let source_object = if native_ebpf_requested {
        #[cfg(feature = "native-ebpf")]
        {
            PathBuf::from(EMBEDDED_NATIVE_OBJECT_IDENTITY)
        }
        #[cfg(not(feature = "native-ebpf"))]
        {
            resolve_source_object(artifact_dir)?
        }
    } else {
        resolve_source_object(artifact_dir)?
    };
    let native_ebpf_embedded_object = native_ebpf_requested;
    let native_ebpf_backend = resolve_native_backend()?;
    let netns_link_mode = resolve_netns_link_mode_from_env()?;
    Ok(ProductionRuntimeOwnerOptions {
        execute: true,
        ack_root_gate: true,
        source_object,
        geodata_asset_dirs,
        tproxy_port: config.global.tproxy_port,
        tproxy_port_protect: config.global.tproxy_port_protect,
        dae_netns_id: DEFAULT_DAE_NETNS_ID,
        netns_link_mode,
        peer_section: DEFAULT_PEER_SECTION.to_owned(),
        host_section: DEFAULT_HOST_SECTION.to_owned(),
        native_ebpf_requested,
        native_ebpf_backend,
        native_ebpf_completed_a3_admission: native_ebpf_requested,
        native_ebpf_embedded_object,
        ..ProductionRuntimeOwnerOptions::default()
    })
}

pub(super) fn resident_runtime_artifact_dir(pid: u32) -> PathBuf {
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
