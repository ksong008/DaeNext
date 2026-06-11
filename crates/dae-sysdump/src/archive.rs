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

    let rel = relative_path.replace('\\', "/");
    Ok(format!("{base_name}/{rel}"))
}

pub fn is_safe_archive_relative_path(relative_path: &str) -> bool {
    if relative_path.is_empty()
        || relative_path == "."
        || relative_path.starts_with('/')
        || relative_path.starts_with('\\')
    {
        return false;
    }

    !relative_path
        .split(['/', '\\'])
        .any(|component| component == "..")
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
