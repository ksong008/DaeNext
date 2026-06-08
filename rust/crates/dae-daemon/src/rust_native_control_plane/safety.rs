use super::*;
pub(super) fn ensure_safe_rust_native_control_plane_root(root: &Path) -> Result<(), String> {
    if !root.is_absolute() {
        return Err(format!(
            "rust-native-control-plane root must be absolute: {}",
            path_string(root)
        ));
    }
    let root_string = path_string(root);
    if !root_string.starts_with("/tmp/dae-rust-native-control-plane") {
        return Err(format!(
            "rust-native-control-plane root must be under /tmp/dae-rust-native-control-plane*: {root_string}"
        ));
    }
    Ok(())
}

pub(super) fn path_string(path: &Path) -> String {
    path.display().to_string()
}
