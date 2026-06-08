use super::*;
pub(super) fn ensure_safe_run_root(root: &Path) -> Result<(), String> {
    if !root.is_absolute() {
        return Err(format!("run root must be absolute: {}", path_string(root)));
    }
    let root_string = path_string(root);
    if !root_string.starts_with("/tmp/dae-daemon") {
        return Err(format!(
            "run root must be under /tmp/dae-daemon*: {root_string}"
        ));
    }
    Ok(())
}

pub(super) fn ensure_safe_output_path(path: &Path, root: &Path, label: &str) -> Result<(), String> {
    if !path.is_absolute() && !path.starts_with(root) {
        return Err(format!("{label} must be absolute or under run root"));
    }
    if path.is_absolute() && !path.starts_with(root) {
        let path_string = path_string(path);
        if !path_string.starts_with("/tmp/") {
            return Err(format!("{label} outside run root must be under /tmp"));
        }
    }
    Ok(())
}

pub(super) fn derived_support_root(prefix: &str, root: &Path) -> PathBuf {
    let suffix = root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("run");
    PathBuf::from(format!("{prefix}-{suffix}"))
}

#[allow(clippy::too_many_arguments)]

pub(super) fn write_progress(path: &Path, byte: u8, suffix: &str) -> Result<(), String> {
    let mut content = vec![byte];
    content.extend_from_slice(suffix.as_bytes());
    fs::write(path, content).map_err(|err| format!("failed to write progress file: {err}"))
}

pub(super) fn required_bool(value: &Value, key: &str, source: &Path) -> Result<bool, String> {
    value[key].as_bool().ok_or_else(|| {
        format!(
            "product-chain admission evidence {} is missing boolean field {key}",
            path_string(source)
        )
    })
}

pub(super) fn path_string(path: &Path) -> String {
    path.display().to_string()
}
