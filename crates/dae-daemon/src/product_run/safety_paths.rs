use super::*;
/// F-01/F-02: run root 必须是固定父目录（/tmp）下的直接子目录，
/// 且词法上不得含 `..` 逃逸。
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
    // 第一级必须是 /tmp（固定父目录），第二级是自动生成的 leaf，
    // 且整体不得出现 ParentDir（`..`）逃逸。
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

/// F-02: 输出/服务路径必须位于 run root（或其已知派生目录）内；
/// 不再允许"绝对路径在 root 外但以 /tmp 开头"的宽松分支。
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
