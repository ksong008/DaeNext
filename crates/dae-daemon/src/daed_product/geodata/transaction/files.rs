use super::*;

const GEODATA_INTERNAL_ARTIFACT_PURPOSES: [&str; 4] =
    ["download", "version", "data-backup", "version-backup"];

pub(super) fn write_version_stage(
    coordinator: &ProductGeodataUpdateCoordinator,
    dir: &Path,
    kind: GeodataKind,
    version: &str,
) -> io::Result<PathBuf> {
    if !super::super::status::is_valid_geodata_release_version(version) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid geodata release version: {version}"),
        ));
    }
    let path = coordinator.reserve_staging_path(dir, kind, "version")?;
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)?;
        file.write_all(version.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()
    })();
    if let Err(error) = result {
        let _ = remove_file_if_exists(&path);
        return Err(error);
    }
    Ok(path)
}

pub(super) fn backup_live_file(
    coordinator: &ProductGeodataUpdateCoordinator,
    dir: &Path,
    kind: GeodataKind,
    live_path: &Path,
    purpose: &str,
) -> io::Result<Option<PathBuf>> {
    match fs::metadata(live_path) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    }
    let backup_path = coordinator.reserve_staging_path(dir, kind, purpose)?;
    if let Err(error) = copy_file_durable(live_path, &backup_path) {
        let _ = remove_file_if_exists(&backup_path);
        return Err(error);
    }
    Ok(Some(backup_path))
}

pub(super) fn copy_file_durable(source: &Path, destination: &Path) -> io::Result<()> {
    fs::copy(source, destination)?;
    fs::File::open(destination)?.sync_all()
}

pub(super) fn sync_directory(path: &Path) -> io::Result<()> {
    fs::File::open(path)?.sync_all()
}

pub(super) fn remove_file_if_exists(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

pub(super) fn remove_paths_best_effort(paths: impl IntoIterator<Item = PathBuf>) {
    for path in paths {
        let _ = remove_file_if_exists(&path);
    }
}

pub(super) fn cleanup_orphaned_internal_artifacts(dir: &Path, kind: GeodataKind) -> io::Result<()> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    for entry in entries {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let internal = GEODATA_INTERNAL_ARTIFACT_PURPOSES
            .iter()
            .any(|purpose| name.starts_with(&format!(".{}.{}.tmp.", kind.file_name(), purpose)));
        if internal && entry.file_type()?.is_file() {
            remove_file_if_exists(&entry.path())?;
        }
    }
    Ok(())
}
