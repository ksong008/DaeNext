use super::*;
pub(super) fn remove_existing_pin(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    fs::remove_file(path)
        .map_err(|err| format!("remove existing BPF pin {} failed: {err}", path.display()))
}
