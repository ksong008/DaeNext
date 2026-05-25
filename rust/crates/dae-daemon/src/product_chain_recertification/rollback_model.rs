use std::fs;
use std::path::Path;

use super::path_string;

pub(super) fn rollback_script_content(
    service_file: &Path,
    backup_service_file: &Path,
    backup_usr_bin_dae: &Path,
    backup_manifest_file: &Path,
) -> String {
    format!(
        r#"#!/bin/sh
set -eu

if [ "${{DAE_PRODUCTION_ROLLBACK_EXECUTE:-}}" != "1" ]; then
  echo "rollback artifact generated in read-only admission mode"
  echo "review backup manifest: {backup_manifest_file}"
  echo "set DAE_PRODUCTION_ROLLBACK_EXECUTE=1 only after manual approval"
  exit 2
fi

if [ -f {backup_service_file} ]; then
  cp {backup_service_file} {service_file}
fi

if [ -f {backup_usr_bin_dae} ]; then
  cp {backup_usr_bin_dae} /usr/bin/dae
fi

systemctl daemon-reload
"#,
        backup_manifest_file = shell_quote_path(backup_manifest_file),
        backup_service_file = shell_quote_path(backup_service_file),
        service_file = shell_quote_path(service_file),
        backup_usr_bin_dae = shell_quote_path(backup_usr_bin_dae),
    )
}

fn shell_quote_path(path: &Path) -> String {
    let raw = path_string(path);
    format!("'{}'", raw.replace('\'', "'\\''"))
}

#[cfg(unix)]
pub(super) fn make_user_executable(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = fs::metadata(path).map_err(|err| {
        format!(
            "failed to stat production run command artifact {}: {err}",
            path_string(path)
        )
    })?;
    let mut permissions = metadata.permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).map_err(|err| {
        format!(
            "failed to chmod production run command artifact {}: {err}",
            path_string(path)
        )
    })
}

#[cfg(not(unix))]
pub(super) fn make_user_executable(_path: &Path) -> Result<(), String> {
    Ok(())
}
