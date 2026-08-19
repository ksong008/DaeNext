use super::*;
use crate::daed_product::durable_commit::{
    cleanup_matching_artifacts, copy_regular_file_synced, write_reserved_file_synced,
};
pub(super) use crate::daed_product::durable_commit::{remove_file_if_exists, sync_directory};

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
    let result = write_reserved_file_synced(&path, format!("{version}\n").as_bytes());
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
    copy_regular_file_synced(source, destination)
}

pub(super) fn remove_paths_best_effort(paths: impl IntoIterator<Item = PathBuf>) {
    for path in paths {
        let _ = remove_file_if_exists(&path);
    }
}

pub(super) fn cleanup_orphaned_internal_artifacts(dir: &Path, kind: GeodataKind) -> io::Result<()> {
    cleanup_matching_artifacts(dir, |name| {
        GEODATA_INTERNAL_ARTIFACT_PURPOSES
            .iter()
            .any(|purpose| name.starts_with(&format!(".{}.{}.tmp.", kind.file_name(), purpose)))
    })
}
