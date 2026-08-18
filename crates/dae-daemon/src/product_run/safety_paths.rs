use super::*;
pub(super) fn ensure_safe_run_root(root: &Path) -> Result<(), String> {
    if !root.is_absolute() {
        return Err(format!("run root must be absolute: {}", path_string(root)));
    }
    let mut components = root.components();
    let Some(std::path::Component::RootDir) = components.next() else {
        return Err(format!(
            "run root must start at filesystem root: {}",
            path_string(root)
        ));
    };
    match components.next() {
        Some(std::path::Component::Normal(segment)) if segment == "tmp" => {}
        _ => {
            return Err(format!(
                "run root must be directly under /tmp: {}",
                path_string(root)
            ));
        }
    }
    let Some(std::path::Component::Normal(leaf)) = components.next() else {
        return Err(format!(
            "run root must be /tmp/<leaf>: {}",
            path_string(root)
        ));
    };
    let leaf = leaf.to_string_lossy();
    if !leaf.starts_with("dae") {
        return Err(format!(
            "run root leaf must start with dae: {}",
            path_string(root)
        ));
    }
    if components.next().is_some() {
        return Err(format!(
            "run root must be exactly /tmp/<leaf> (no nesting): {}",
            path_string(root)
        ));
    }
    Ok(())
}

pub(super) fn ensure_safe_output_path(path: &Path, root: &Path, label: &str) -> Result<(), String> {
    if !path.is_absolute() {
        return Err(format!("{label} must be absolute: {}", path_string(path)));
    }
    if !path.starts_with(root) {
        return Err(format!(
            "{label} must be under run root {}: {}",
            path_string(root),
            path_string(path)
        ));
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

pub(super) fn write_progress(path: &Path, byte: u8, suffix: &str) -> Result<(), String> {
    let mut content = vec![byte];
    content.extend_from_slice(suffix.as_bytes());
    fs::write(path, content).map_err(|err| format!("failed to write progress file: {err}"))
}

pub(super) fn path_string(path: &Path) -> String {
    path.display().to_string()
}
