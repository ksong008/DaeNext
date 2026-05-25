use std::path::Path;

pub(super) fn ensure_safe_run_root(root: &Path) -> Result<(), String> {
    if !root.is_absolute() {
        return Err(format!(
            "product-chain recertification run root must be absolute: {}",
            path_string(root)
        ));
    }
    let root_string = path_string(root);
    if !root_string.starts_with("/tmp/dae-daemon") {
        return Err(format!(
            "product-chain recertification run root must be under /tmp/dae-daemon*: {root_string}"
        ));
    }
    Ok(())
}

pub(super) fn path_string(path: &Path) -> String {
    path.display().to_string()
}
