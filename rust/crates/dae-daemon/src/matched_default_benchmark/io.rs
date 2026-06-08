use super::*;
pub(super) fn materialize_secure_config(source: &Path, dest: &Path) -> Result<(), String> {
    let content = fs::read(source).map_err(|err| {
        format!(
            "read benchmark config {} failed: {err}",
            path_string(source)
        )
    })?;
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "create benchmark corpus dir {} failed: {err}",
                path_string(parent)
            )
        })?;
    }
    fs::write(dest, content)
        .map_err(|err| format!("write benchmark config {} failed: {err}", path_string(dest)))?;
    fs::set_permissions(dest, fs::Permissions::from_mode(0o600)).map_err(|err| {
        format!(
            "chmod benchmark config {} to 0600 failed: {err}",
            path_string(dest)
        )
    })
}

pub(super) fn parse_json_stdout(stdout: &str) -> Result<Value, String> {
    let trimmed = stdout.trim();
    serde_json::from_str(trimmed).or_else(|first_err| {
        stdout
            .lines()
            .rev()
            .map(str::trim)
            .find(|line| line.starts_with('{'))
            .ok_or_else(|| first_err.to_string())
            .and_then(|line| serde_json::from_str(line).map_err(|err| err.to_string()))
    })
}

pub(super) fn write_json(path: &Path, value: &Value) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("create parent {} failed: {err}", path_string(parent)))?;
    }
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|err| format!("encode JSON {} failed: {err}", path_string(path)))?;
    let mut file = File::create(path)
        .map_err(|err| format!("create JSON {} failed: {err}", path_string(path)))?;
    file.write_all(&bytes)
        .map_err(|err| format!("write JSON {} failed: {err}", path_string(path)))
}

pub(super) fn sanitize_suffix(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

pub(super) fn cap_text(value: &str) -> String {
    const MAX: usize = 4000;
    if value.len() <= MAX {
        return value.to_owned();
    }
    let truncated = value.chars().take(MAX).collect::<String>();
    format!(
        "{}...[truncated {} bytes]",
        truncated,
        value.len().saturating_sub(truncated.len())
    )
}

pub(super) fn path_string(path: &Path) -> String {
    path.display().to_string()
}
