use super::*;
pub(super) fn setup_runtime_topology(
    executed_steps: &mut Vec<Value>,
    options: &ProductionRuntimeOwnerOptions,
) -> bool {
    super::super::topology::setup_production_topology(executed_steps, options)
}

fn env_var_with_legacy(
    primary: &'static str,
    legacy: &'static str,
) -> Option<(&'static str, String)> {
    env::var(primary)
        .map(|value| (primary, value))
        .or_else(|_| env::var(legacy).map(|value| (legacy, value)))
        .ok()
}

pub(super) fn resolve_source_object(artifact_dir: &Path) -> Result<PathBuf, String> {
    if let Some((env_name, path)) =
        env_var_with_legacy(DEFAULT_SOURCE_OBJECT_ENV, DEFAULT_SOURCE_OBJECT_LEGACY_ENV)
    {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Ok(path);
        }
        return Err(format!(
            "{env_name} points to a missing source object: {}",
            path_string(&path)
        ));
    }
    let repo_relative = PathBuf::from("control/bpf_bpfel.o");
    if repo_relative.is_file() {
        return Ok(repo_relative);
    }
    #[cfg(feature = "native-ebpf")]
    {
        let _ = artifact_dir;
        return Err(
            "legacy C eBPF source object is unavailable in native-ebpf resident build".to_owned(),
        );
    }
    #[cfg(not(feature = "native-ebpf"))]
    {
        let embedded = artifact_dir.join("bpf_bpfel.embedded.o");
        fs::write(&embedded, EMBEDDED_SOURCE_OBJECT).map_err(|err| {
            format!(
                "failed to write embedded resident source object {}: {err}",
                path_string(&embedded)
            )
        })?;
        fs::set_permissions(&embedded, fs::Permissions::from_mode(0o644)).map_err(|err| {
            format!(
                "failed to chmod embedded resident source object {}: {err}",
                path_string(&embedded)
            )
        })?;
        Ok(embedded)
    }
}

#[cfg(feature = "native-ebpf")]
pub(super) fn resolve_native_object(artifact_dir: &Path) -> Result<Option<PathBuf>, String> {
    if !resident_native_ebpf_enabled() {
        return Ok(None);
    }
    if let Some((env_name, path)) =
        env_var_with_legacy(DEFAULT_NATIVE_OBJECT_ENV, DEFAULT_NATIVE_OBJECT_LEGACY_ENV)
    {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Ok(Some(path));
        }
        return Err(format!(
            "{env_name} points to a missing native object: {}",
            path_string(&path)
        ));
    }
    let embedded = artifact_dir.join("bpf_bpfel.native-embedded.o");
    fs::write(&embedded, EMBEDDED_NATIVE_OBJECT).map_err(|err| {
        format!(
            "failed to write embedded resident native object {}: {err}",
            path_string(&embedded)
        )
    })?;
    fs::set_permissions(&embedded, fs::Permissions::from_mode(0o644)).map_err(|err| {
        format!(
            "failed to chmod embedded resident native object {}: {err}",
            path_string(&embedded)
        )
    })?;
    Ok(Some(embedded))
}

#[cfg(not(feature = "native-ebpf"))]
pub(super) fn resolve_native_object(_artifact_dir: &Path) -> Result<Option<PathBuf>, String> {
    Ok(None)
}

#[cfg(feature = "native-ebpf")]
pub(super) fn resident_native_ebpf_enabled() -> bool {
    env_var_with_legacy(DEFAULT_NATIVE_EBPF_ENV, DEFAULT_NATIVE_EBPF_LEGACY_ENV)
        .map(|(_, value)| value)
        .map(|value| {
            !matches!(
                value.as_str(),
                "0" | "false" | "FALSE" | "off" | "OFF" | "no" | "NO"
            )
        })
        .unwrap_or(true)
}

pub(super) fn resident_dataplane_enabled() -> bool {
    env::var(DEFAULT_RESIDENT_DATAPLANE_ENV)
        .or_else(|_| env::var(DEFAULT_RESIDENT_DATAPLANE_LEGACY_ENV))
        .map(|value| {
            matches!(
                value.as_str(),
                "1" | "true" | "TRUE" | "on" | "ON" | "yes" | "YES"
            )
        })
        .unwrap_or(false)
}

#[cfg(feature = "native-ebpf")]
pub(super) fn resolve_native_backend() -> Result<AttachBackend, String> {
    let Some((env_name, raw)) = env_var_with_legacy(
        DEFAULT_NATIVE_BACKEND_ENV,
        DEFAULT_NATIVE_BACKEND_LEGACY_ENV,
    ) else {
        return Ok(default_native_backend());
    };
    parse_native_backend(&raw).ok_or_else(|| {
        format!(
            "{env_name} must be one of auto, tcx, tc-netlink, tc_netlink, tc-command-fallback, tc_command_fallback; got {raw}"
        )
    })
}

#[cfg(feature = "native-ebpf")]
pub(super) fn default_native_backend() -> AttachBackend {
    AttachBackend::Auto
}

#[cfg(not(feature = "native-ebpf"))]
pub(super) fn resolve_native_backend() -> Result<AttachBackend, String> {
    Ok(AttachBackend::TcNetlink)
}

#[cfg(feature = "native-ebpf")]
pub(super) fn parse_native_backend(value: &str) -> Option<AttachBackend> {
    match value {
        "auto" => Some(AttachBackend::Auto),
        "tcx" => Some(AttachBackend::Tcx),
        "tc-netlink" | "tc_netlink" => Some(AttachBackend::TcNetlink),
        "tc-command-fallback" | "tc_command_fallback" => Some(AttachBackend::TcCommandFallback),
        _ => None,
    }
}

pub(super) fn write_json_file(path: &Path, label: &str, value: Value) -> Result<(), String> {
    let encoded = serde_json::to_vec_pretty(&value)
        .map_err(|err| format!("failed to encode {label}: {err}"))?;
    fs::write(path, encoded).map_err(|err| format!("failed to write {}: {err}", path_string(path)))
}
