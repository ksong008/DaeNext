use super::*;

pub(crate) fn prepare_config_directory(path: &Path) -> Result<PathBuf, String> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(path)
                .map_err(|err| format!("create config directory {}: {err}", path_string(path)))?;
        }
        Err(err) => {
            return Err(format!(
                "inspect config directory {}: {err}",
                path_string(path)
            ));
        }
    }

    let canonical = fs::canonicalize(path)
        .map_err(|err| format!("canonicalize config directory {}: {err}", path_string(path)))?;
    let metadata = fs::metadata(&canonical).map_err(|err| {
        format!(
            "inspect canonical config directory {}: {err}",
            path_string(&canonical)
        )
    })?;
    if !metadata.is_dir() {
        return Err(format!(
            "config directory must be a directory, got {}",
            path_string(path)
        ));
    }
    if metadata.permissions().readonly() {
        return Err(format!(
            "config directory is not writable: {}",
            path_string(&canonical)
        ));
    }
    Ok(canonical)
}
