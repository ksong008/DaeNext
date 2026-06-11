use super::*;
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

pub(super) fn path_string(path: &Path) -> String {
    path.display().to_string()
}
