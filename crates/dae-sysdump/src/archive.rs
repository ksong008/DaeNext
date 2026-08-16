use std::fmt;

pub const TAR_TYPE_REGULAR: u8 = b'0';
pub const TAR_TYPE_DIR: u8 = b'5';

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveEntry {
    pub name: String,
    pub typeflag: u8,
    pub regular: bool,
    pub content: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchivePathError {
    message: String,
}

impl ArchivePathError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ArchivePathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ArchivePathError {}

pub fn archive_header_name(
    base_name: &str,
    relative_path: &str,
) -> Result<String, ArchivePathError> {
    if !is_safe_archive_relative_path(relative_path) {
        return Err(ArchivePathError::new(format!(
            "unsafe sysdump archive path: {relative_path}"
        )));
    }
    // The base name is joined in front of the relative path and ends up in the
    // same tar header, so it must be held to the same traversal rules. Without
    // this check a base name like ".." or "/etc" would escape the archive root
    // even though the relative path itself is safe.
    if !is_safe_archive_relative_path(base_name) {
        return Err(ArchivePathError::new(format!(
            "unsafe sysdump archive base name: {base_name}"
        )));
    }

    let rel = relative_path.replace('\\', "/");
    Ok(format!("{base_name}/{rel}"))
}

/// A relative archive path is safe only when every component can never escape
/// the archive root: the path must be non-empty, must not be absolute, and
/// every '/' or '\\' separated component must be non-empty and different from
/// "." and "..". Rejecting empty components also rules out "//" spellings and
/// trailing separators.
pub fn is_safe_archive_relative_path(relative_path: &str) -> bool {
    if relative_path.is_empty() || relative_path.starts_with('/') || relative_path.starts_with('\\')
    {
        return false;
    }

    relative_path
        .split(['/', '\\'])
        .all(|component| !component.is_empty() && component != "." && component != "..")
}

pub fn modeled_archive_entries(base_name: &str) -> Vec<ArchiveEntry> {
    vec![
        dir(base_name, "empty-dir"),
        dir(base_name, "nested"),
        file(base_name, "nested/interfaces.txt", "if\n"),
        file(base_name, "routing.txt", "route\n"),
    ]
}

fn dir(base_name: &str, relative_path: &str) -> ArchiveEntry {
    ArchiveEntry {
        name: archive_header_name(base_name, relative_path).expect("static relative path is safe"),
        typeflag: TAR_TYPE_DIR,
        regular: false,
        content: None,
    }
}

fn file(base_name: &str, relative_path: &str, content: &'static str) -> ArchiveEntry {
    ArchiveEntry {
        name: archive_header_name(base_name, relative_path).expect("static relative path is safe"),
        typeflag: TAR_TYPE_REGULAR,
        regular: true,
        content: Some(content),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_name_is_held_to_the_same_traversal_rules_as_the_relative_path() {
        for base_name in [
            "", ".", "..", "/", "/etc", "\\etc", "a/..", "a//b", "a/./b", "a\\..\\b",
        ] {
            assert!(
                !is_safe_archive_relative_path(base_name),
                "base name {base_name:?} must be rejected"
            );
            let err = archive_header_name(base_name, "routing.txt").unwrap_err();
            assert!(
                err.to_string()
                    .starts_with("unsafe sysdump archive base name"),
                "base name {base_name:?} produced: {err}"
            );
        }
    }

    #[test]
    fn safe_base_names_pass_through_unchanged() {
        for base_name in ["sysdump-source", "dump-2026", "a_b.c"] {
            assert!(is_safe_archive_relative_path(base_name));
            assert_eq!(
                archive_header_name(base_name, "routing.txt").unwrap(),
                format!("{base_name}/routing.txt")
            );
        }
    }

    #[test]
    fn relative_path_component_checks_reject_dot_dotdot_and_double_slash() {
        for relative_path in [
            "",
            ".",
            "..",
            "/etc/passwd",
            "\\etc\\passwd",
            "../routing.txt",
            "a/../b",
            "a/./b",
            "a//b",
            "a/b/",
            "a\\b\\..\\c",
        ] {
            assert!(
                !is_safe_archive_relative_path(relative_path),
                "relative path {relative_path:?} must be rejected"
            );
        }
        assert!(is_safe_archive_relative_path("routing.txt"));
        assert!(is_safe_archive_relative_path("nested/interfaces.txt"));
        assert!(is_safe_archive_relative_path("a\\b\\c.txt"));
    }

    #[test]
    fn backslash_spellings_are_normalized_and_still_safe() {
        assert_eq!(
            archive_header_name("base", "nested\\interfaces.txt").unwrap(),
            "base/nested/interfaces.txt"
        );
    }
}
